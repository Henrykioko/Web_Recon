import os
import re
import json
import shutil
import socket
import subprocess
import requests
import threading
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, request, send_from_directory, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

base = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(base, 'recon.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
reports = os.path.join(base, "reports")
os.makedirs(reports, exist_ok=True)


class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    joined        = db.Column(db.DateTime, default=datetime.utcnow)
    scans         = db.relationship("Scan", backref="user", lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Scan(db.Model):
    __tablename__ = "scans"
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain        = db.Column(db.String(255), nullable=False)
    ip            = db.Column(db.String(50))
    profile       = db.Column(db.String(50))
    risk          = db.Column(db.String(20))
    port_count    = db.Column(db.Integer, default=0)
    services      = db.Column(db.String(500))
    dns           = db.Column(db.Text)
    whois         = db.Column(db.Text)
    nmap          = db.Column(db.Text)
    whatweb       = db.Column(db.Text)
    cves          = db.Column(db.Text)
    subdomains    = db.Column(db.Text)
    report_txt    = db.Column(db.String(255))
    report_html   = db.Column(db.String(255))
    ran_at        = db.Column(db.DateTime, default=datetime.utcnow)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        user = db.session.get(User, session["uid"])
        if not user:
            session.clear()
            flash("Session expired.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def get_user():
    if "uid" not in session:
        return None
    return db.session.get(User, session["uid"])


def shell(cmd):
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}
        )
    except subprocess.CalledProcessError as e:
        return e.output
    except FileNotFoundError:
        return f"{cmd[0]} is not installed."


def valid_domain(domain):
    if not domain:
        return False
    if any(x in domain for x in ["localhost", "internal", "local"]):
        return False
    return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", domain)


def get_ip(dns_output):
    for line in dns_output.splitlines():
        if "Address:" in line and "#53" not in line and "Server:" not in line:
            parts = line.split()
            if parts:
                return parts[-1]
    return ""


def parse_nmap(output):
    ports, svcs = [], []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            ports.append(parts[0].split("/")[0])
            if len(parts) > 2:
                svcs.append(parts[2])

    risky = {"22", "3306", "3389", "5432", "6379", "27017"}
    if any(p in risky for p in ports):
        risk, reason = "High", "Sensitive ports are exposed."
    elif ports:
        risk, reason = "Medium", "Multiple open ports found."
    else:
        risk, reason = "Low", "No notable services detected."

    return {
        "count":    len(ports),
        "ports":    ports,
        "services": list(set(svcs)),
        "risk":     risk,
        "reason":   reason
    }


cve_cache = {}
cve_lock  = threading.Lock()

def fetch_cves(service):
    with cve_lock:
        if service in cve_cache:
            return cve_cache[service]
    try:
        res  = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": service, "resultsPerPage": 3},
            timeout=10
        )
        if res.status_code != 200:
            return []

        found, seen = [], set()
        for item in res.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            if cid in seen:
                continue
            seen.add(cid)

            severity = score = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = cve.get("metrics", {}).get(key, [])
                if entries:
                    d        = entries[0].get("cvssData", {})
                    severity = d.get("baseSeverity", "N/A")
                    score    = d.get("baseScore", "N/A")
                    break

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description."
            )
            found.append({
                "id":       cid,
                "service":  service,
                "severity": severity,
                "score":    score,
                "desc":     desc[:300] + ("..." if len(desc) > 300 else ""),
                "url":      f"https://nvd.nist.gov/vuln/detail/{cid}"
            })

        with cve_lock:
            cve_cache[service] = found
        return found
    except Exception:
        return []


def get_cves(services):
    results = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for r in ex.map(fetch_cves, services[:5]):
            results.extend(r)
    return results


fallback_subs = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "dev", "staging", "test", "api", "portal", "admin", "beta",
    "shop", "blog", "forum", "news", "static", "cdn", "media", "images",
    "secure", "login", "auth", "m", "mobile", "app", "dashboard", "docs",
    "support", "help", "status", "monitor", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "intranet", "server",
    "ns1", "ns2", "mx", "mx1", "mx2", "smtp1", "smtp2", "autodiscover"
]

wordlists = {
    "safe":     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "normal":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "advanced": "/usr/share/seclists/Discovery/DNS/subdomains-top1million.txt"
}

def socket_scan(domain):
    def check(sub):
        host = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(host)
            return host
        except socket.error:
            return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        return [r for r in ex.map(check, fallback_subs) if r]

def gobuster_scan(domain, profile):
    wl = wordlists.get(profile, wordlists["safe"])
    if not os.path.exists(wl):
        wl = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wl):
        return []

    out   = shell(["gobuster", "dns", "-d", domain, "-w", wl, "-t", "50", "--timeout", "3s", "-q", "--no-color"])
    found = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Found:"):
            found.append(line.replace("Found:", "").strip())
        elif domain in line and not line.startswith("["):
            found.append(line)
    return found

def get_subdomains(domain, profile):
    if shutil.which("gobuster"):
        result = gobuster_scan(domain, profile)
        if result:
            return result
    return socket_scan(domain)


def save_txt(scan, filename):
    path = os.path.join(reports, filename)
    with open(path, "w") as f:
        f.write(f"RECON REPORT — {scan.domain}\n{'='*40}\n\n")
        f.write(f"IP        : {scan.ip}\n")
        f.write(f"Profile   : {scan.profile}\n")
        f.write(f"Risk      : {scan.risk}\n")
        f.write(f"Time      : {scan.ran_at}\n\n")
        f.write(f"SUBDOMAINS\n{'-'*20}\n{scan.subdomains or 'None'}\n\n")
        f.write(f"DNS\n{'-'*20}\n{scan.dns or ''}\n\n")
        f.write(f"NMAP\n{'-'*20}\n{scan.nmap or ''}\n\n")
        f.write(f"WHATWEB\n{'-'*20}\n{scan.whatweb or ''}\n\n")
        f.write(f"WHOIS\n{'-'*20}\n{scan.whois or ''}\n")
    return filename

def save_html(scan, filename):
    path = os.path.join(reports, filename)
    subs = (scan.subdomains or "None").replace("\n", "<br>")
    with open(path, "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon — {scan.domain}</title>
    <style>
        body {{ font-family: monospace; margin: 40px; background: #111; color: #ccc; }}
        h1 {{ color: #fff; }} h2 {{ color: #aaa; border-bottom: 1px solid #333; padding-bottom: 6px; }}
        pre {{ background: #1a1a1a; padding: 12px; overflow-x: auto; }}
        .tag {{ display: inline-block; padding: 2px 8px; font-size: 12px; border: 1px solid #555; }}
    </style>
</head>
<body>
    <h1>{scan.domain}</h1>
    <p><span class="tag">{scan.ip}</span> &nbsp; <span class="tag">{scan.profile}</span> &nbsp; <span class="tag">Risk: {scan.risk}</span> &nbsp; <span class="tag">{scan.ran_at}</span></p>
    <h2>Subdomains</h2><p>{subs}</p>
    <h2>DNS</h2><pre>{scan.dns}</pre>
    <h2>Nmap</h2><pre>{scan.nmap}</pre>
    <h2>WhatWeb</h2><pre>{scan.whatweb}</pre>
    <h2>WHOIS</h2><pre>{scan.whois}</pre>
</body>
</html>""")
    return filename


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            flash("Fill in both fields.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("That username is taken.", "danger")
            return redirect(url_for("register"))
        u = User(username=username)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Account created. Log in.", "success")
        return redirect(url_for("login"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            session["uid"] = u.id
            return redirect(url_for("index"))
        flash("Wrong username or password.", "danger")
    return render_template("auth.html", mode="login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user  = get_user()
    data  = {}
    error = None

    if request.method == "POST":
        domain  = request.form["domain"].strip()
        profile = request.form.get("profile", "safe")

        if not valid_domain(domain):
            error = "Invalid domain."
        else:
            dns_out = shell(["nslookup", domain])
            ip      = get_ip(dns_out)

            def run_nmap():
                if profile == "normal" and ip:
                    return shell(["nmap", "-sV", "-p", "1-1000", "--min-rate", "5000", "--max-retries", "1", "--open", ip])
                elif profile == "advanced" and ip:
                    return shell(["nmap", "-p", "1-65535", "-sV", "--min-rate", "5000", "--max-retries", "1", "--open", ip])
                return "Skipped (safe profile)"

            with ThreadPoolExecutor(max_workers=4) as ex:
                fw = ex.submit(shell, ["whois", ip if ip else domain])
                fww = ex.submit(shell, ["whatweb", "-v", domain])
                fs = ex.submit(get_subdomains, domain, profile)
                fn = ex.submit(run_nmap)

                whois_out   = fw.result()
                whatweb_out = fww.result()
                subs        = fs.result()
                nmap_out    = fn.result()

            result  = parse_nmap(nmap_out)
            cve_list = get_cves(result["services"]) if result["services"] else []

            now       = datetime.utcnow()
            base_name = f"{domain}_{now.strftime('%Y%m%d_%H%M%S')}"

            scan = Scan(
                user_id    = user.id,
                domain     = domain,
                ip         = ip,
                profile    = profile,
                risk       = result["risk"],
                port_count = result["count"],
                services   = ", ".join(result["services"]),
                dns        = dns_out,
                whois      = whois_out,
                nmap       = nmap_out,
                whatweb    = whatweb_out,
                cves       = json.dumps(cve_list),
                subdomains = "\n".join(subs),
                report_txt = base_name + ".txt",
                report_html= base_name + ".html",
                ran_at     = now
            )
            db.session.add(scan)
            db.session.commit()

            save_txt(scan, scan.report_txt)
            save_html(scan, scan.report_html)

            data = {"scan": scan, "result": result, "cves": cve_list, "subs": subs}

    history = Scan.query.filter_by(user_id=user.id).order_by(Scan.ran_at.desc()).limit(10).all()
    return render_template("index.html", data=data, error=error, user=user, history=history)


@app.route("/dashboard")
@login_required
def dashboard():
    user  = get_user()
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.ran_at.desc()).all()
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for s in scans:
        risk_counts[s.risk] = risk_counts.get(s.risk, 0) + 1
    return render_template("dashboard.html", user=user, scans=scans, risk_counts=risk_counts)


@app.route("/report/view/<filename>")
@login_required
def view_report(filename):
    return send_from_directory(reports, filename)

@app.route("/report/download/<filename>")
@login_required
def download_report(filename):
    return send_from_directory(reports, filename, as_attachment=True)


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)