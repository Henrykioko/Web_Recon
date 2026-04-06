import os
import re
import json
import shutil
import socket
import subprocess
import requests
import threading
from datetime import datetime
from functools import wraps, lru_cache
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, request, send_from_directory, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production-xyz123")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'recon.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ── Models ──────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    scans         = db.relationship("Scan", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    __tablename__  = "scans"
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain         = db.Column(db.String(255), nullable=False)
    ip             = db.Column(db.String(50))
    profile        = db.Column(db.String(50))
    risk_level     = db.Column(db.String(20))
    open_ports     = db.Column(db.Integer, default=0)
    services       = db.Column(db.String(500))
    dns_output     = db.Column(db.Text)
    whois_output   = db.Column(db.Text)
    nmap_output    = db.Column(db.Text)
    whatweb_output = db.Column(db.Text)
    cve_output     = db.Column(db.Text)
    subdomains     = db.Column(db.Text)
    report_txt     = db.Column(db.String(255))
    report_html    = db.Column(db.String(255))
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)


# ── Auth helpers ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        # ✅ Fix: verify user actually exists in DB
        user = db.session.get(User, session["user_id"])
        if user is None:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if "user_id" not in session:
        return None
    # ✅ Modern SQLAlchemy 2.0 — no legacy warning
    return db.session.get(User, session["user_id"])


# ── Utilities ────────────────────────────────────────────
def run(cmd):
    # ✅ Longer timeout for full port scans
    timeout = 600 if "65535" in cmd else 120
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}  # ✅ faster output parsing
        )
    except subprocess.CalledProcessError as e:
        return e.output
    except FileNotFoundError:
        return f"Tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "Command timed out."

def validate_domain(domain):
    if not domain:
        return False
    blocked = ["localhost", "internal", "local"]
    if any(b in domain for b in blocked):
        return False
    return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", domain)

def extract_ip(dns_output):
    for line in dns_output.splitlines():
        if "Address:" in line and "#53" not in line and "Server:" not in line:
            parts = line.split()
            if parts:
                return parts[-1]
    return ""

def analyze_nmap(nmap_output):
    ports, services = [], []
    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            ports.append(parts[0].split("/")[0])
            if len(parts) > 2:
                services.append(parts[2])

    risk   = "Low"
    reason = "Only common public services detected."
    sensitive = {"22", "3306", "3389", "5432", "6379", "27017"}
    if any(p in sensitive for p in ports):
        risk   = "High"
        reason = "Sensitive service ports are exposed."
    elif ports:
        risk   = "Medium"
        reason = "Multiple open ports detected."

    return {
        "open_ports": len(ports),
        "port_list":  ports,
        "services":   list(set(services)) if services else [],
        "risk":       risk,
        "reason":     reason
    }


# ── CVE Lookup ───────────────────────────────────────────
_cve_cache = {}
_cve_lock  = threading.Lock()

def fetch_single_cve(service):
    # ✅ In-memory cache — avoids repeat API calls per service
    with _cve_lock:
        if service in _cve_cache:
            return _cve_cache[service]
    try:
        url    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": service, "resultsPerPage": 3}
        resp   = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            return []
        data   = resp.json()
        result = []
        seen   = set()
        for item in data.get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            if cve_id in seen:
                continue
            seen.add(cve_id)

            metrics  = cve.get("metrics", {})
            severity = score = "N/A"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    severity  = cvss_data.get("baseSeverity", "N/A")
                    score     = cvss_data.get("baseScore", "N/A")
                    break

            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description available."
            )
            result.append({
                "id":          cve_id,
                "service":     service,
                "severity":    severity,
                "score":       score,
                "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

        with _cve_lock:
            _cve_cache[service] = result
        return result

    except Exception:
        return []

def lookup_cves(services: list) -> list:
    all_cves = []
    # ✅ Fetch all services simultaneously
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(fetch_single_cve, services[:5])
        for r in results:
            all_cves.extend(r)
    return all_cves


# ── Subdomain Enumeration ────────────────────────────────
WORDLISTS = {
    "safe":     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "normal":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "advanced": "/usr/share/seclists/Discovery/DNS/subdomains-top1million.txt"
}

FALLBACK_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "dev", "staging", "test", "api", "portal", "admin", "beta",
    "shop", "blog", "forum", "news", "static", "cdn", "media", "images",
    "secure", "login", "auth", "m", "mobile", "app", "dashboard", "docs",
    "support", "help", "status", "monitor", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "intranet", "internal", "server",
    "ns1", "ns2", "mx", "mx1", "mx2", "smtp1", "smtp2", "autodiscover"
]

def gobuster_available():
    return shutil.which("gobuster") is not None

def run_gobuster(domain, profile="safe"):
    wordlist = WORDLISTS.get(profile, WORDLISTS["safe"])
    # Fallback wordlist paths if seclists not installed
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        return []

    result = run([
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", "50",        # 50 threads
        "--timeout", "3s",
        "-q",              # quiet mode
        "--no-color"
    ])

    found = []
    for line in result.splitlines():
        line = line.strip()
        if line.startswith("Found:"):
            sub = line.replace("Found:", "").strip()
            found.append(sub)
        elif domain in line and not line.startswith("[") and not line.startswith("Error"):
            found.append(line.strip())
    return found

def run_socket_method(domain):
    def check(sub):
        hostname = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)       # ✅ 2s max per lookup
            socket.gethostbyname(hostname)
            return hostname
        except socket.error:
            return None

    # ✅ All 50 DNS checks run simultaneously
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check, FALLBACK_WORDLIST)
        return [r for r in results if r is not None]

def enumerate_subdomains(domain, profile="safe"):
    # ✅ Use gobuster if available, fall back to socket method
    if gobuster_available():
        result = run_gobuster(domain, profile)
        if result:
            return result
    return run_socket_method(domain)


# ── Report Generators ────────────────────────────────────
def generate_txt_report(scan, filename):
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w") as f:
        f.write("WEB RECON REPORT\n" + "=" * 40 + "\n\n")
        f.write(f"Target    : {scan.domain}\n")
        f.write(f"IP Address: {scan.ip}\n")
        f.write(f"Profile   : {scan.profile}\n")
        f.write(f"Risk Level: {scan.risk_level}\n")
        f.write(f"Timestamp : {scan.timestamp}\n\n")
        f.write("SUBDOMAINS\n" + "-" * 20 + "\n" + (scan.subdomains or "None found") + "\n\n")
        f.write("DNS\n"        + "-" * 20 + "\n" + (scan.dns_output   or "") + "\n\n")
        f.write("NMAP\n"       + "-" * 20 + "\n" + (scan.nmap_output  or "") + "\n\n")
        f.write("WHATWEB\n"    + "-" * 20 + "\n" + (scan.whatweb_output or "") + "\n\n")
        f.write("WHOIS\n"      + "-" * 20 + "\n" + (scan.whois_output or "") + "\n")
    return filename

def generate_html_report(scan, filename):
    path = os.path.join(REPORT_DIR, filename)
    subs = (scan.subdomains or "").replace("\n", "<br>") or "None found"
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Recon – {scan.domain}</title>
    <style>
        body {{ font-family: monospace; margin: 40px; background: #0d0d0d; color: #00ff99; }}
        h1, h2 {{ color: #33ccff; }}
        pre {{ background: #1a1a1a; padding: 10px; border-left: 3px solid #00ff99; overflow-x: auto; }}
        p {{ color: #ccc; }}
    </style>
</head>
<body>
    <h1>Web Recon Report — {scan.domain}</h1>
    <p>IP: {scan.ip} | Profile: {scan.profile} | Risk: {scan.risk_level} | {scan.timestamp}</p>
    <h2>Subdomains</h2><p>{subs}</p>
    <h2>DNS</h2><pre>{scan.dns_output}</pre>
    <h2>Nmap</h2><pre>{scan.nmap_output}</pre>
    <h2>WhatWeb</h2><pre>{scan.whatweb_output}</pre>
    <h2>WHOIS</h2><pre>{scan.whois_output}</pre>
</body>
</html>"""
    with open(path, "w") as f:
        f.write(html)
    return filename


# ── Auth Routes ──────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials.", "danger")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ── Main Scan Route ──────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user = current_user()
    if user is None:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    data  = {}
    error = None

    if request.method == "POST":
        domain  = request.form["domain"].strip()
        profile = request.form.get("profile", "safe")

        if not validate_domain(domain):
            error = "Invalid domain format."
        else:
            # ── Step 1: DNS first (IP needed for nmap) ──────
            dns_out = run(["nslookup", domain])
            ip      = extract_ip(dns_out)

            # ── Step 2: nmap command based on profile ───────
            def get_nmap():
                if profile == "normal" and ip:
                    return run([
                        "nmap", "-sV", "-p", "1-1000",
                        "--min-rate", "5000",
                        "--max-retries", "1",
                        "--open", ip
                    ])
                elif profile == "advanced" and ip:
                    return run([
                        "nmap", "-p", "1-65535", "-sV",
                        "--min-rate", "5000",
                        "--max-retries", "1",
                        "--open", ip
                    ])
                return "Skipped (Safe profile)"

            # ── Step 3: Run everything in parallel ──────────
            with ThreadPoolExecutor(max_workers=4) as executor:
                f_whois   = executor.submit(run, ["whois", domain])
                f_whatweb = executor.submit(run, ["whatweb", "-v", domain])
                f_subs    = executor.submit(enumerate_subdomains, domain, profile)
                f_nmap    = executor.submit(get_nmap)

                whois_out   = f_whois.result()
                whatweb_out = f_whatweb.result()
                subdomains  = f_subs.result()
                nmap_out    = f_nmap.result()

            # ── Step 4: Analyze + CVE (after nmap done) ─────
            summary = analyze_nmap(nmap_out)
            cves    = lookup_cves(summary["services"]) if summary["services"] else []

            # ── Step 5: Save to database ─────────────────────
            timestamp = datetime.utcnow()
            base_name = f"{domain}_{timestamp.strftime('%Y%m%d_%H%M%S')}"

            scan = Scan(
                user_id        = user.id,
                domain         = domain,
                ip             = ip,
                profile        = profile,
                risk_level     = summary["risk"],
                open_ports     = summary["open_ports"],
                services       = ", ".join(summary["services"]),
                dns_output     = dns_out,
                whois_output   = whois_out,
                nmap_output    = nmap_out,
                whatweb_output = whatweb_out,
                cve_output     = json.dumps(cves),
                subdomains     = "\n".join(subdomains),
                report_txt     = base_name + ".txt",
                report_html    = base_name + ".html",
                timestamp      = timestamp
            )
            db.session.add(scan)
            db.session.commit()

            generate_txt_report(scan, scan.report_txt)
            generate_html_report(scan, scan.report_html)

            data = {
                "scan":       scan,
                "summary":    summary,
                "cves":       cves,
                "subdomains": subdomains
            }

    past_scans = Scan.query.filter_by(user_id=user.id)\
                           .order_by(Scan.timestamp.desc())\
                           .limit(10).all()

    return render_template("index.html", data=data, error=error, user=user, past_scans=past_scans)


# ── Dashboard ────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user  = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    scans = Scan.query.filter_by(user_id=user.id)\
                      .order_by(Scan.timestamp.desc()).all()

    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for s in scans:
        risk_counts[s.risk_level] = risk_counts.get(s.risk_level, 0) + 1

    return render_template("dashboard.html", user=user, scans=scans, risk_counts=risk_counts)


# ── Reports ──────────────────────────────────────────────
@app.route("/report/view/<filename>")
@login_required
def view_report(filename):
    return send_from_directory(REPORT_DIR, filename)

@app.route("/report/download/<filename>")
@login_required
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


# ── Init DB ──────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)