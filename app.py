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

from flask import (Flask, render_template, request, send_from_directory,
                   redirect, url_for, session, flash)
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


# ── Models ────────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    joined = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship("Scan", backref="user", lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(50))
    profile = db.Column(db.String(50))
    risk = db.Column(db.String(20))
    port_count = db.Column(db.Integer, default=0)
    services = db.Column(db.String(500))
    dns = db.Column(db.Text)
    whois = db.Column(db.Text)
    nmap = db.Column(db.Text)
    whatweb = db.Column(db.Text)
    cves = db.Column(db.Text)
    subdomains = db.Column(db.Text)
    intelligence = db.Column(db.Text)
    report_txt = db.Column(db.String(255))
    report_html = db.Column(db.String(255))
    ran_at = db.Column(db.DateTime, default=datetime.utcnow)


# ── Auth ──────────────────────────────────────────────────────────────────────

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


# ── Shell runners ─────────────────────────────────────────────────────────────

def shell(cmd):
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}
        )
    except subprocess.CalledProcessError as e:
        return e.output or ""
    except FileNotFoundError:
        return f"{cmd[0]} is not installed."


def shell_combined(cmd):
    """
    Run a command and always return its output regardless of exit code.
    Merges stdout and stderr. Used for tools like WhatWeb that exit non-zero
    on SSL/network warnings even when they produced valid findings output.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}
        )
        output = result.stdout or ""
        # Fall back to stderr only if stdout is completely empty
        if not output.strip():
            output = result.stderr or ""
        return output
    except FileNotFoundError:
        return "whatweb is not installed."
    except Exception as e:
        return f"Error running {cmd[0]}: {e}"


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


def run_whatweb(domain):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        result = shell_combined([
            "whatweb", "--color=never", "-v", "-a", "3", "--no-errors", url
        ])
        if result and "is not installed" not in result and result.strip():
            return result
    return "WhatWeb did not return usable output."


# ── Nmap parser ───────────────────────────────────────────────────────────────

def parse_nmap(output):
    ports, svcs, versions = [], [], []
    for line in output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_num = parts[0].split("/")[0]
            ports.append(port_num)
            svc = parts[2] if len(parts) > 2 else "unknown"
            ver = " ".join(parts[3:]) if len(parts) > 3 else ""
            svcs.append(svc)
            versions.append({"port": port_num, "service": svc, "version": ver})

    risky = {"22", "3306", "3389", "5432", "6379",
             "27017", "21", "23", "445", "1433", "8080", "8443"}
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
        "versions": versions,
        "risk":     risk,
        "reason":   reason
    }


# ── CVE lookup ────────────────────────────────────────────────────────────────

cve_cache = {}
cve_lock = threading.Lock()


def fetch_cves(service):
    with cve_lock:
        if service in cve_cache:
            return cve_cache[service]
    try:
        res = requests.get(
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
                    d = entries[0].get("cvssData", {})
                    severity = d.get("baseSeverity", "N/A")
                    score = d.get("baseScore", "N/A")
                    break
            desc = next(
                (d["value"]
                 for d in cve.get("descriptions", []) if d.get("lang") == "en"),
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
    result = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for r in ex.map(fetch_cves, services[:5]):
            result.extend(r)
    return result


# ── Subdomain enumeration ─────────────────────────────────────────────────────

fallback_subs = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote", "vpn", "dev",
    "staging", "test", "api", "portal", "admin", "beta", "shop", "blog", "forum",
    "news", "static", "cdn", "media", "images", "secure", "login", "auth", "m",
    "mobile", "app", "dashboard", "docs", "support", "help", "status", "monitor",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki", "intranet", "server",
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
    out = shell(["gobuster", "dns", "-d", domain, "-w", wl,
                 "-t", "50", "--timeout", "3s", "-q", "--no-color"])
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
        r = gobuster_scan(domain, profile)
        if r:
            return r
    return socket_scan(domain)


# ── Port knowledge base ───────────────────────────────────────────────────────
PORT_INTEL = {
    "21": {
        "name": "FTP",
        "risk": "High",
        "explanation": "FTP transmits data and credentials in plain text with no encryption. An attacker on the same network can intercept usernames, passwords, and all transferred files using a simple packet sniffer.",
        "attack": "Man-in-the-Middle, Credential Sniffing, Brute Force, Anonymous Login",
        "recommendation": "Disable FTP entirely and replace with SFTP (port 22) or FTPS. If FTP is required, restrict access by IP and enforce strong passwords.",
    },
    "22": {
        "name": "SSH",
        "risk": "Medium",
        "explanation": "SSH provides encrypted remote access but an exposed SSH port is a constant target for automated brute-force attacks. Weak passwords or outdated SSH versions can lead to full server compromise.",
        "attack": "Brute Force, Password Spraying, Exploits on outdated SSH versions",
        "recommendation": "Disable password authentication and use SSH key pairs only. Change the default port, restrict access with firewall rules, and keep SSH updated.",
    },
    "23": {
        "name": "Telnet",
        "risk": "Critical",
        "explanation": "Telnet sends everything including usernames, passwords, and commands in completely plain text. It has no encryption whatsoever. Any attacker who can observe network traffic will see everything.",
        "attack": "Credential Sniffing, Man-in-the-Middle, Session Hijacking",
        "recommendation": "Disable Telnet immediately. It should never be exposed on any modern system. Replace with SSH.",
    },
    "25": {
        "name": "SMTP",
        "risk": "Medium",
        "explanation": "An open SMTP port can be abused as an open mail relay, allowing attackers to send spam or phishing emails through your server and getting your IP blacklisted.",
        "attack": "Open Relay Abuse, Spam Campaigns, Email Spoofing",
        "recommendation": "Restrict SMTP to authenticated users only. Disable relaying for unauthenticated connections. Implement SPF, DKIM, and DMARC DNS records.",
    },
    "80": {
        "name": "HTTP",
        "risk": "Low",
        "explanation": "Unencrypted HTTP traffic can be intercepted. Users accessing your site over HTTP have their session cookies and form submissions exposed to anyone watching the network.",
        "attack": "Man-in-the-Middle, Session Hijacking, Content Injection",
        "recommendation": "Redirect all HTTP traffic to HTTPS. Implement HSTS to prevent protocol downgrade attacks.",
    },
    "443": {
        "name": "HTTPS",
        "risk": "Info",
        "explanation": "HTTPS is the expected encrypted web port. The main risks are misconfigured TLS settings or support for outdated TLS versions.",
        "attack": "SSL Stripping, Weak Cipher Exploitation",
        "recommendation": "Ensure TLS 1.2 or 1.3 only. Disable SSLv3 and TLS 1.0/1.1. Use strong cipher suites.",
    },
    "445": {
        "name": "SMB",
        "risk": "Critical",
        "explanation": "SMB exposed to the internet is extremely dangerous. It was the entry point for WannaCry and NotPetya ransomware attacks. Unauthenticated attackers can potentially execute code remotely.",
        "attack": "EternalBlue Exploit, WannaCry Ransomware, Remote Code Execution, Credential Theft",
        "recommendation": "Block port 445 at the firewall immediately. SMB should never be exposed to the public internet. Use a VPN for remote file access.",
    },
    "1433": {
        "name": "MSSQL",
        "risk": "Critical",
        "explanation": "Microsoft SQL Server directly exposed to the internet is a critical risk. Attackers scan for this port continuously. A successful breach gives complete database access.",
        "attack": "SQL Injection, Brute Force, SA Account Exploitation, xp_cmdshell Abuse",
        "recommendation": "Block port 1433 at the firewall. Database servers should never be publicly accessible.",
    },
    "3306": {
        "name": "MySQL",
        "risk": "Critical",
        "explanation": "MySQL exposed to the internet gives attackers direct access to attempt database login. A successful breach exposes all data and potentially allows command execution.",
        "attack": "Brute Force, SQL Injection, Data Exfiltration, Load_file/Into Outfile Abuse",
        "recommendation": "Block MySQL from public access entirely. Bind MySQL to 127.0.0.1 in my.cnf.",
    },
    "3389": {
        "name": "RDP",
        "risk": "Critical",
        "explanation": "Remote Desktop Protocol exposed to the internet has a long history of critical vulnerabilities including BlueKeep and DejaBlue which allow unauthenticated remote code execution.",
        "attack": "BlueKeep RCE, Brute Force, Pass-the-Hash, Ransomware Delivery",
        "recommendation": "Block RDP from the public internet immediately. Place RDP behind a VPN. Enable Network Level Authentication.",
    },
    "5432": {
        "name": "PostgreSQL",
        "risk": "Critical",
        "explanation": "PostgreSQL exposed to the internet allows attackers to attempt direct database authentication. Successful access exposes all stored data.",
        "attack": "Brute Force, Data Exfiltration, File System Access via COPY command",
        "recommendation": "Block PostgreSQL from public internet access. Bind to internal interfaces only.",
    },
    "6379": {
        "name": "Redis",
        "risk": "Critical",
        "explanation": "Redis has no authentication by default. Attackers can read all cached data and in some configurations achieve remote code execution by writing to cron or SSH authorized_keys.",
        "attack": "Unauthenticated Access, Data Theft, Remote Code Execution via cron injection",
        "recommendation": "Add requirepass authentication. Bind to 127.0.0.1. Block port 6379 at the firewall.",
    },
    "8080": {
        "name": "HTTP Alternate",
        "risk": "Medium",
        "explanation": "Alternative HTTP port often used for development servers or admin panels that are frequently misconfigured or left with default credentials.",
        "attack": "Default Credentials, Unpatched Admin Panels, Proxy Abuse",
        "recommendation": "Determine what service is running. If a development server, block public access. Enforce strong authentication.",
    },
    "27017": {
        "name": "MongoDB",
        "risk": "Critical",
        "explanation": "MongoDB with no authentication exposed to the internet has led to thousands of data breaches. Attackers continuously scan for open MongoDB instances and can access all data without credentials.",
        "attack": "Unauthenticated Access, Data Exfiltration, Database Deletion",
        "recommendation": "Enable MongoDB authentication. Bind to internal IPs only. Block port 27017 at the firewall.",
    },
}

# ── Technology knowledge base ─────────────────────────────────────────────────

TECH_INTEL = {
    "wordpress": {
        "risk": "Medium",
        "explanation": "WordPress is the most targeted CMS on the internet. Outdated WordPress core, themes, or plugins are the most common website compromise vector.",
        "recommendation": "Keep WordPress core, themes, and plugins updated. Use a security plugin like Wordfence. Hide the WordPress version number. Restrict wp-admin by IP.",
    },
    "drupal": {
        "risk": "Medium",
        "explanation": "Drupal has had critical remote code execution vulnerabilities (Drupalgeddon). An outdated Drupal installation can be compromised automatically by scanners.",
        "recommendation": "Keep Drupal and all modules updated. Subscribe to Drupal security advisories.",
    },
    "joomla": {
        "risk": "Medium",
        "explanation": "Joomla has a history of critical vulnerabilities. Outdated installations and vulnerable extensions are commonly exploited for defacement and data theft.",
        "recommendation": "Update Joomla core and all extensions. Disable unused extensions. Restrict admin panel access by IP.",
    },
    "apache": {
        "risk": "Low",
        "explanation": "The Apache version disclosed in headers allows attackers to look up known vulnerabilities for that exact version. Outdated Apache versions have critical unpatched CVEs.",
        "recommendation": "Update Apache. Set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf to hide version information.",
    },
    "nginx": {
        "risk": "Low",
        "explanation": "Nginx version disclosure in headers allows targeted version-specific attacks.",
        "recommendation": "Set 'server_tokens off' in nginx.conf to hide version. Keep Nginx updated.",
    },
    "iis": {
        "risk": "Low",
        "explanation": "IIS version disclosure exposes the exact Windows Server version, helping attackers narrow their attack to known Windows-specific exploits.",
        "recommendation": "Hide IIS version via custom headers. Keep IIS and Windows Server fully patched.",
    },
    "php": {
        "risk": "Medium",
        "explanation": "PHP version exposed in headers reveals the exact runtime version. PHP versions below 8.1 are end-of-life and receive no security updates.",
        "recommendation": "Update to PHP 8.2 or later. Set 'expose_php = Off' in php.ini to hide the version.",
    },
    "jquery": {
        "risk": "Low",
        "explanation": "Outdated jQuery versions have known XSS and prototype pollution vulnerabilities. jQuery below 3.5 is particularly affected.",
        "recommendation": "Update jQuery to the latest version (3.7+).",
    },
    "bootstrap": {
        "risk": "Info",
        "explanation": "Outdated Bootstrap versions may have XSS vulnerabilities in certain JavaScript components.",
        "recommendation": "Update Bootstrap to the latest version.",
    },
    "x-powered-by": {
        "risk": "Low",
        "explanation": "The X-Powered-By header reveals the server technology stack (e.g. PHP/7.4, ASP.NET). This helps attackers identify the exact software and look up known exploits.",
        "recommendation": "Remove the X-Powered-By header. In PHP: set 'expose_php = Off'. In Express.js: app.disable('x-powered-by').",
    },
    "x-aspnet-version": {
        "risk": "Low",
        "explanation": "The X-AspNet-Version header reveals the exact .NET runtime version, helping attackers identify version-specific vulnerabilities.",
        "recommendation": "Remove the header by adding '<remove name=\"X-AspNet-Version\"/>' in Web.config under system.webServer/httpProtocol/customHeaders.",
    },
    "httpserver": {
        "risk": "Low",
        "explanation": "The Server header reveals the web server type and version. This is unnecessary information that helps attackers identify vulnerable software.",
        "recommendation": "Configure your web server to suppress or generalise the Server response header.",
    },
}

# ── Missing security headers ──────────────────────────────────────────────────

HEADER_INTEL = {
    "content-security-policy": {
        "explanation": "No Content-Security-Policy header was detected. CSP prevents Cross-Site Scripting (XSS) attacks by specifying which sources of scripts, styles, and other resources the browser should trust.",
        "attack": "Cross-Site Scripting (XSS), Code Injection",
        "recommendation": "Add the header to your server config. Start with: Content-Security-Policy: default-src 'self'",
    },
    "x-frame-options": {
        "explanation": "No X-Frame-Options header was detected. Without this, attackers can embed your site in a hidden iframe on a malicious page and trick users into clicking on your site's buttons (Clickjacking).",
        "attack": "Clickjacking, UI Redressing",
        "recommendation": "Add header: X-Frame-Options: DENY  (or SAMEORIGIN if you need to embed your own pages)",
    },
    "x-content-type-options": {
        "explanation": "No X-Content-Type-Options header was detected. Without this, browsers may guess (sniff) the content type of responses, which can allow XSS attacks via uploaded files.",
        "attack": "MIME Sniffing, XSS via file upload",
        "recommendation": "Add header: X-Content-Type-Options: nosniff",
    },
    "strict-transport-security": {
        "explanation": "No HSTS (HTTP Strict Transport Security) header was detected. Without this, attackers can force your users' browsers to use HTTP instead of HTTPS and intercept all traffic (SSL Stripping).",
        "attack": "SSL Stripping, Protocol Downgrade Attack, Man-in-the-Middle",
        "recommendation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "referrer-policy": {
        "explanation": "No Referrer-Policy header was detected. By default, browsers send the full page URL as a referrer when a user clicks a link, which can leak sensitive URL parameters such as session tokens to third-party sites.",
        "attack": "Information Disclosure, Session Token Leakage",
        "recommendation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "explanation": "No Permissions-Policy header was detected. This header lets you control which browser features (camera, microphone, geolocation) third-party scripts embedded in your page are allowed to use.",
        "attack": "Feature Abuse, Privacy Violation via embedded scripts",
        "recommendation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}


# ── Analysis modules ──────────────────────────────────────────────────────────

def analyse_ports(nmap_result):
    findings = []
    for v in nmap_result.get("versions", []):
        port = v["port"]
        svc = v["service"]
        ver = v["version"]
        intel = PORT_INTEL.get(port)
        if not intel:
            findings.append({
                "source":         "Nmap",
                "type":           "open_port",
                "title":          f"Port {port} Open ({svc})",
                "risk":           "Low",
                "explanation":    f"Port {port} is open running {svc}. Every unnecessary open port increases your attack surface and gives attackers another potential entry point.",
                "attack":         "Service Exploitation, Information Disclosure",
                "recommendation": f"If {svc} on port {port} is not needed, close it in your firewall. Verify this service is intentional and kept updated.",
                "version":        ver,
            })
        else:
            explanation = intel["explanation"]
            if ver:
                explanation += f" Detected version: {ver}."
            findings.append({
                "source":         "Nmap",
                "type":           "open_port",
                "title":          f"Port {port} Open — {intel['name']}",
                "risk":           intel["risk"],
                "explanation":    explanation,
                "attack":         intel.get("attack", ""),
                "recommendation": intel["recommendation"],
                "version":        ver,
            })
    return findings


def analyse_whatweb(whatweb_output):
    """
    Parse WhatWeb -v output properly.
    Plugin names appear as [ PluginName ] in the output.
    We extract all plugin names and match them against our knowledge base.
    We also check the raw text for header strings.
    """
    findings = []
    text_lower = whatweb_output.lower()

    # Extract all plugin names from [ PluginName ] patterns
    plugin_names = set(
        m.lower().strip()
        for m in re.findall(r'\[\s*([A-Za-z0-9_\-\.]+)\s*\]', whatweb_output)
    )

    # Also check the Summary line for comma-separated items
    summary_match = re.search(r'Summary\s*:\s*(.+)', whatweb_output)
    if summary_match:
        for item in summary_match.group(1).split(","):
            plugin_names.add(item.strip().lower().split("[")[0].strip())

    # Match against technology knowledge base
    already_reported = set()
    for tech, intel in TECH_INTEL.items():
        matched = tech in plugin_names
        if not matched:
            matched = tech in text_lower
        if matched and tech not in already_reported:
            already_reported.add(tech)
            label = tech.upper() if len(tech) <= 4 else tech.replace("-", " ").title()
            findings.append({
                "source":         "WhatWeb",
                "type":           "technology",
                "title":          f"Detected: {label}",
                "risk":           intel["risk"],
                "explanation":    intel["explanation"],
                "recommendation": intel["recommendation"],
            })

    # Check for missing security headers
    for header, intel in HEADER_INTEL.items():
        header_variants = [
            header,
            header.replace("-", ""),
            header.replace("-", " "),
        ]
        present = any(
            v in plugin_names or v in text_lower for v in header_variants)
        if not present:
            findings.append({
                "source":         "Headers",
                "type":           "missing_header",
                "title":          f"Missing Security Header: {header.title()}",
                "risk":           "Medium",
                "explanation":    intel["explanation"],
                "attack":         intel["attack"],
                "recommendation": intel["recommendation"],
            })

    return findings


def analyse_whois(whois_output, domain):
    findings = []
    text = whois_output.lower()

    expiry_patterns = [
        r"expir(?:y|ation|es)[^\n:]*:\s*([^\n]+)",
        r"paid-till:\s*([^\n]+)",
        r"registry expiry date:\s*([^\n]+)",
        r"registrar registration expiration date:\s*([^\n]+)",
    ]
    expiry_str = None
    for pat in expiry_patterns:
        m = re.search(pat, text)
        if m:
            expiry_str = m.group(1).strip()
            break

    if expiry_str:
        try:
            from dateutil import parser as dateparser
            expiry_date = dateparser.parse(expiry_str, ignoretz=True)
            days_left = (expiry_date - datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    "source":         "WHOIS",
                    "type":           "domain_expiry",
                    "title":          "CRITICAL: Domain Has Expired",
                    "risk":           "Critical",
                    "explanation":    f"The domain {domain} expired {abs(days_left)} days ago. An expired domain can be registered by anyone — including attackers — who can then host malicious content, intercept emails, or impersonate your organisation.",
                    "attack":         "Domain Hijacking, Phishing, Email Interception",
                    "recommendation": "Renew the domain immediately through your registrar. Check if it has already been taken over.",
                    "expiry_date":    str(expiry_date.date()),
                    "days_left":      days_left,
                })
            elif days_left <= 7:
                findings.append({
                    "source":         "WHOIS",
                    "type":           "domain_expiry",
                    "title":          f"URGENT: Domain Expires in {days_left} Days",
                    "risk":           "Critical",
                    "explanation":    f"Your domain expires in {days_left} days. If it lapses even briefly, an attacker can register it and impersonate your organisation, host phishing pages, or intercept all emails sent to your domain.",
                    "attack":         "Domain Hijacking, Phishing, Email Interception",
                    "recommendation": "Renew the domain today. Enable auto-renew at your registrar. Set up expiry alerts.",
                    "expiry_date":    str(expiry_date.date()),
                    "days_left":      days_left,
                })
            elif days_left <= 30:
                findings.append({
                    "source":         "WHOIS",
                    "type":           "domain_expiry",
                    "title":          f"Warning: Domain Expires in {days_left} Days",
                    "risk":           "High",
                    "explanation":    f"Your domain expires in {days_left} days. Domains that lapse can be hijacked by attackers.",
                    "attack":         "Domain Hijacking",
                    "recommendation": "Renew the domain soon and enable auto-renew at your registrar.",
                    "expiry_date":    str(expiry_date.date()),
                    "days_left":      days_left,
                })
            elif days_left <= 90:
                findings.append({
                    "source":         "WHOIS",
                    "type":           "domain_expiry",
                    "title":          f"Notice: Domain Expires in {days_left} Days",
                    "risk":           "Low",
                    "explanation":    f"Your domain expires in {days_left} days (on {expiry_date.date()}). No immediate risk but worth noting.",
                    "recommendation": "Consider renewing soon and enabling auto-renew.",
                    "expiry_date":    str(expiry_date.date()),
                    "days_left":      days_left,
                })
            else:
                findings.append({
                    "source":         "WHOIS",
                    "type":           "domain_expiry",
                    "title":          f"Domain Valid — Expires in {days_left} Days",
                    "risk":           "Info",
                    "explanation":    f"Domain is registered and valid until {expiry_date.date()}. No action required.",
                    "recommendation": "Ensure auto-renew is enabled at your registrar.",
                    "expiry_date":    str(expiry_date.date()),
                    "days_left":      days_left,
                })
        except Exception:
            pass

    if "redacted for privacy" in text or "gdpr" in text or "data protected" in text:
        findings.append({
            "source":         "WHOIS",
            "type":           "whois_privacy",
            "title":          "WHOIS Privacy Enabled",
            "risk":           "Info",
            "explanation":    "Registrant contact details are hidden. This is good practice as it prevents personal information from being harvested.",
            "recommendation": "Good — keep WHOIS privacy enabled.",
        })
    else:
        if re.search(r"\b[a-z._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", text):
            findings.append({
                "source":         "WHOIS",
                "type":           "whois_exposure",
                "title":          "Registrant Email Exposed in WHOIS",
                "risk":           "Low",
                "explanation":    "Your registrant email is publicly visible in WHOIS. This email can be harvested for phishing and social engineering attacks targeting your domain administrator.",
                "attack":         "Phishing, Social Engineering, Spam",
                "recommendation": "Enable WHOIS privacy protection at your registrar to hide personal contact details.",
            })

    ns_count = len(re.findall(r"name server:", text))
    if 0 < ns_count < 2:
        findings.append({
            "source":         "WHOIS",
            "type":           "dns_resilience",
            "title":          "Single Nameserver Configured",
            "risk":           "Medium",
            "explanation":    "Only one nameserver is configured. If it goes down, your entire domain becomes unreachable. DNS standards recommend at least two nameservers in different locations.",
            "attack":         "Single Point of Failure, DNS Outage",
            "recommendation": "Add a secondary nameserver at a different hosting provider for redundancy.",
        })

    return findings


def analyse_dns(dns_output, domain):
    findings = []
    text = dns_output.lower()

    if "wildcard" in text or "* " in dns_output:
        findings.append({
            "source":         "DNS",
            "type":           "misconfiguration",
            "title":          "Wildcard DNS Record Detected",
            "risk":           "Medium",
            "explanation":    "A wildcard DNS record (*) resolves all subdomains to the same IP. This means any subdomain — including ones you never created — will point to your server. Attackers can craft convincing phishing URLs using your domain name.",
            "attack":         "Phishing via crafted subdomains, Subdomain Takeover",
            "recommendation": "Remove wildcard DNS records unless explicitly required. Use specific subdomain records instead.",
        })

    try:
        axfr = shell(["dig", "AXFR", domain, f"@{domain}"])
        if ("Transfer failed" not in axfr
                and "connection timed out" not in axfr
                and len(axfr.strip()) > 100):
            findings.append({
                "source":         "DNS",
                "type":           "misconfiguration",
                "title":          "DNS Zone Transfer Enabled (AXFR)",
                "risk":           "High",
                "explanation":    "Your DNS server allows zone transfers. This lets anyone download a complete list of all your DNS records, revealing your full internal network structure, all IP addresses, mail servers, and every subdomain you have configured.",
                "attack":         "Full Network Mapping, Targeted Infrastructure Attacks",
                "recommendation": "Restrict zone transfers to authorised secondary nameservers only. In BIND add: allow-transfer { <secondary-ip>; }; to your zone config.",
            })
    except Exception:
        pass

    return findings


def analyse_subdomains(subdomains, domain):
    findings = []
    flagged = []
    sensitive = {
        "admin":      ("Administrative Panel Exposed",        "Admin portals are high-value targets. A compromise gives full control over the application.", "High"),
        "vpn":        ("VPN Portal Exposed",                  "An exposed VPN portal is subject to credential brute-force. Compromise gives internal network access.", "High"),
        "dev":        ("Development Server Exposed",          "Dev servers often have debug mode enabled, weak credentials, and unpatched software.", "High"),
        "staging":    ("Staging Server Exposed",              "Staging environments often contain real data copies and weaker security configurations.", "High"),
        "test":       ("Test Server Exposed",                 "Test servers are often poorly secured and may contain vulnerabilities absent from production.", "Medium"),
        "jenkins":    ("CI/CD Server Exposed (Jenkins)",      "Jenkins exposed to the internet can allow attackers to execute arbitrary code on your build infrastructure.", "Critical"),
        "gitlab":     ("GitLab Instance Exposed",             "An exposed GitLab instance may leak source code, API keys, passwords, and secrets stored in repositories.", "High"),
        "git":        ("Git Service Exposed",                 "An exposed version control system may leak source code and stored secrets.", "High"),
        "jira":       ("Issue Tracker Exposed (Jira)",        "Jira often contains sensitive project details, employee information, and internal system architecture.", "Medium"),
        "confluence": ("Wiki Exposed (Confluence)",           "Confluence may contain internal documentation, credentials, and architecture details not meant to be public.", "Medium"),
        "mail":       ("Mail Server Subdomain Detected",      "Ensure the mail server enforces SPF, DKIM, and DMARC records to prevent email spoofing.", "Low"),
        "ftp":        ("FTP Subdomain Detected",              "FTP subdomains may indicate an insecure unencrypted file transfer service.", "Medium"),
        "db":         ("Database Subdomain Detected",         "A database subdomain suggests a database server may be directly internet-exposed — a critical risk.", "Critical"),
        "database":   ("Database Subdomain Detected",         "A database subdomain suggests a database server may be directly internet-exposed.", "Critical"),
    }

    for sub in subdomains:
        for keyword, (title, explanation, risk) in sensitive.items():
            if keyword in sub.lower() and keyword not in flagged:
                flagged.append(keyword)
                findings.append({
                    "source":         "Subdomains",
                    "type":           "sensitive_subdomain",
                    "title":          f"Sensitive Subdomain: {sub}",
                    "risk":           risk,
                    "explanation":    explanation,
                    "attack":         "Targeted Attack, Credential Brute Force, Information Disclosure",
                    "recommendation": f"Restrict access to {sub} via firewall rules or authentication. Keep it updated and monitored. Consider whether it needs to be publicly accessible at all.",
                })
    return findings


# ── CVE findings ──────────────────────────────────────────────────────────────

def cve_findings(cve_list):
    findings = []
    seen_ids = set()
    for cve in cve_list:
        cid = cve.get("id", "")
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        try:
            score_val = float(cve.get("score", 0) or 0)
        except (ValueError, TypeError):
            score_val = 0
        svc = cve.get("service", "")
        if score_val >= 9.0:
            findings.append({
                "source":         "CVE",
                "type":           "cve",
                "title":          f"Critical CVE: {cid} ({svc})",
                "risk":           "Critical",
                "explanation":    cve["desc"],
                "attack":         f"CVSS score {cve.get('score')} — see NVD for full details",
                "recommendation": f"Patch or update {svc} immediately to address {cid}. Check the vendor advisory at {cve.get('url', '')}",
            })
        elif score_val >= 7.0:
            findings.append({
                "source":         "CVE",
                "type":           "cve",
                "title":          f"High Severity CVE: {cid} ({svc})",
                "risk":           "High",
                "explanation":    cve["desc"],
                "attack":         f"CVSS score {cve.get('score')} — see NVD for full details",
                "recommendation": f"Apply security patches for {svc} to address {cid}.",
            })
        elif score_val >= 4.0:
            findings.append({
                "source":         "CVE",
                "type":           "cve",
                "title":          f"Medium CVE: {cid} ({svc})",
                "risk":           "Medium",
                "explanation":    cve["desc"],
                "attack":         f"CVSS score {cve.get('score')}",
                "recommendation": f"Review and apply available patches for {svc} regarding {cid}.",
            })
    return findings


# ── Master intelligence function ──────────────────────────────────────────────

def run_intelligence(domain, nmap_result, whatweb_output,
                     whois_output, dns_output, subdomains, cve_list):

    all_findings = []
    all_findings += analyse_ports(nmap_result)
    all_findings += analyse_whatweb(whatweb_output)
    all_findings += analyse_whois(whois_output, domain)
    all_findings += analyse_dns(dns_output, domain)
    all_findings += analyse_subdomains(subdomains, domain)
    all_findings += cve_findings(cve_list)

    risk_order = ["Critical", "High", "Medium", "Low", "Info"]
    risk_label = "Low"
    for lvl in risk_order:
        if any(f.get("risk") == lvl for f in all_findings):
            risk_label = lvl
            break

    severity_counts = {"Critical": 0, "High": 0,
                       "Medium": 0, "Low": 0, "Info": 0}
    for f in all_findings:
        r = f.get("risk", "Info")
        if r in severity_counts:
            severity_counts[r] += 1

    return {
        "findings":        all_findings,
        "risk_label":      risk_label,
        "severity_counts": severity_counts,
        "total_findings":  len(all_findings),
    }


# ── Report generators ─────────────────────────────────────────────────────────

def save_txt(scan, filename, intel):
    path = os.path.join(reports, filename)
    with open(path, "w") as f:
        f.write(f"WEBRECON SECURITY REPORT — {scan.domain}\n{'='*60}\n\n")
        f.write(f"IP        : {scan.ip}\n")
        f.write(f"Profile   : {scan.profile}\n")
        f.write(f"Risk Level: {intel['risk_label']}\n")
        f.write(f"Findings  : {intel['total_findings']}\n")
        f.write(f"Time      : {scan.ran_at}\n\n")
        f.write(f"FINDINGS ({intel['total_findings']} total)\n{'-'*40}\n")
        for fd in intel["findings"]:
            f.write(f"\n[{fd['risk']}] {fd['title']}\n")
            f.write(f"Source : {fd['source']}\n")
            f.write(f"Explain: {fd['explanation']}\n")
            if fd.get("attack"):
                f.write(f"Attacks: {fd['attack']}\n")
            f.write(f"Fix    : {fd['recommendation']}\n")
        f.write(f"\nRAW SCAN DATA\n{'-'*40}\n")
        f.write(f"SUBDOMAINS\n{scan.subdomains or 'None'}\n\n")
        f.write(f"DNS\n{scan.dns or ''}\n\n")
        f.write(f"NMAP\n{scan.nmap or ''}\n\n")
        f.write(f"WHATWEB\n{scan.whatweb or ''}\n\n")
        f.write(f"WHOIS\n{scan.whois or ''}\n")
    return filename


def save_html(scan, filename, intel):
    path = os.path.join(reports, filename)
    risk_color = {
        "Critical": "#E74C3C", "High":   "#E67E22",
        "Medium":   "#F39C12", "Low":    "#27AE60", "Info": "#3498DB"
    }
    label_col = risk_color.get(intel["risk_label"], "#888")

    findings_html = ""
    for fd in intel["findings"]:
        col = risk_color.get(fd["risk"], "#888")
        attack_row = f"<tr><td><b>Attack types</b></td><td>{fd.get('attack', '')}</td></tr>" if fd.get(
            "attack") else ""
        version_row = f"<tr><td><b>Version</b></td><td>{fd.get('version', '')}</td></tr>" if fd.get(
            "version") else ""
        exp_row = fd.get("expiry_date", "")
        expiry_row = f"<tr><td><b>Expiry</b></td><td>{exp_row} ({fd.get('days_left', '')} days)</td></tr>" if exp_row else ""
        findings_html += f"""
        <div class="finding">
            <div class="finding-header" style="border-left:4px solid {col}">
                <span class="badge" style="background:{col}">{fd['risk']}</span>
                <b>{fd['title']}</b>
                <span class="source-tag">{fd['source']}</span>
            </div>
            <table class="finding-table">
                <tr><td><b>Explanation</b></td><td>{fd['explanation']}</td></tr>
                {attack_row}{version_row}{expiry_row}
                <tr><td><b>Fix</b></td><td>{fd['recommendation']}</td></tr>
            </table>
        </div>"""

    sc = intel["severity_counts"]
    subs = (scan.subdomains or "None").replace("\n", "<br>")

    html = f"""<!DOCTYPE html>
<html><head><title>Security Report — {scan.domain}</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;background:#0f1117;color:#ccc;}}
h1{{color:#fff;}} h2{{color:#3B9EE8;border-bottom:1px solid #222;padding-bottom:8px;}}
.risk-label{{display:inline-block;padding:8px 20px;font-size:1.4rem;font-weight:bold;
  border-radius:6px;color:#fff;background:{label_col};margin:8px 0;}}
.finding{{background:#161b22;border-radius:6px;margin:12px 0;overflow:hidden;}}
.finding-header{{padding:12px 16px;display:flex;align-items:center;gap:10px;background:#1a2130;}}
.badge{{padding:2px 8px;border-radius:4px;color:#fff;font-size:12px;font-weight:bold;}}
.source-tag{{margin-left:auto;font-size:11px;color:#888;background:#222;padding:2px 8px;border-radius:4px;}}
.finding-table{{width:100%;border-collapse:collapse;font-size:13px;}}
.finding-table td{{padding:8px 16px;border-bottom:1px solid #222;vertical-align:top;}}
.finding-table td:first-child{{width:120px;color:#888;white-space:nowrap;}}
.sev-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0;}}
.sev-card{{text-align:center;padding:12px;border-radius:6px;background:#161b22;}}
.sev-card .num{{font-size:1.8rem;font-weight:bold;}}
pre{{background:#161b22;padding:12px;overflow-x:auto;font-size:12px;border-radius:4px;}}
</style></head><body>
<h1>Security Report — {scan.domain}</h1>
<p>IP: {scan.ip} | Profile: {scan.profile} | Scanned: {scan.ran_at}</p>
<h2>Overall Risk</h2>
<div class="risk-label">{intel['risk_label']}</div>
<p style="color:#888">{intel['total_findings']} findings</p>
<div class="sev-grid">
  <div class="sev-card"><div class="num" style="color:#E74C3C">{sc['Critical']}</div><div>Critical</div></div>
  <div class="sev-card"><div class="num" style="color:#E67E22">{sc['High']}</div><div>High</div></div>
  <div class="sev-card"><div class="num" style="color:#F39C12">{sc['Medium']}</div><div>Medium</div></div>
  <div class="sev-card"><div class="num" style="color:#27AE60">{sc['Low']}</div><div>Low</div></div>
  <div class="sev-card"><div class="num" style="color:#3498DB">{sc['Info']}</div><div>Info</div></div>
</div>
<h2>Findings ({intel['total_findings']})</h2>
{findings_html}
<h2>Raw Scan Data</h2>
<h3>Subdomains</h3><p>{subs}</p>
<h3>DNS</h3><pre>{scan.dns}</pre>
<h3>Nmap</h3><pre>{scan.nmap}</pre>
<h3>WhatWeb</h3><pre>{scan.whatweb}</pre>
<h3>WHOIS</h3><pre>{scan.whois}</pre>
</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    return filename


# ── Auth routes ───────────────────────────────────────────────────────────────

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


# ── Main scan route ───────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user = get_user()
    data = {}
    error = None

    if request.method == "POST":
        domain = request.form["domain"].strip()
        profile = request.form.get("profile", "safe")

        if not valid_domain(domain):
            error = "Invalid domain."
        else:
            dns_out = shell(["nslookup", domain])
            ip = get_ip(dns_out)

            def run_nmap():
                if profile == "normal" and ip:
                    return shell(["nmap", "-sV", "-p", "1-1000",
                                  "--min-rate", "5000", "--max-retries", "1",
                                  "--open", ip])
                elif profile == "advanced" and ip:
                    return shell(["nmap", "-p", "1-65535", "-sV",
                                  "--min-rate", "5000", "--max-retries", "1",
                                  "--open", ip])
                return "Skipped (safe profile)"

            with ThreadPoolExecutor(max_workers=4) as ex:
                fw = ex.submit(shell,          ["whois", ip if ip else domain])
                fww = ex.submit(run_whatweb,    domain)
                fs = ex.submit(get_subdomains, domain, profile)
                fn = ex.submit(run_nmap)
                whois_out = fw.result()
                whatweb_out = fww.result()
                subs = fs.result()
                nmap_out = fn.result()

            result = parse_nmap(nmap_out)
            cve_list = get_cves(
                result["services"]) if result["services"] else []
            intel = run_intelligence(domain, result, whatweb_out,
                                     whois_out, dns_out, subs, cve_list)

            now = datetime.utcnow()
            base_name = f"{domain}_{now.strftime('%Y%m%d_%H%M%S')}"

            scan = Scan(
                user_id=user.id,
                domain=domain,
                ip=ip,
                profile=profile,
                risk=intel["risk_label"],
                port_count=result["count"],
                services=", ".join(result["services"]),
                dns=dns_out,
                whois=whois_out,
                nmap=nmap_out,
                whatweb=whatweb_out,
                cves=json.dumps(cve_list),
                subdomains="\n".join(subs),
                intelligence=json.dumps(intel),
                report_txt=base_name + ".txt",
                report_html=base_name + ".html",
                ran_at=now
            )
            db.session.add(scan)
            db.session.commit()

            save_txt(scan, scan.report_txt, intel)
            save_html(scan, scan.report_html, intel)

            data = {
                "scan":   scan,
                "result": result,
                "cves":   cve_list,
                "subs":   subs,
                "intel":  intel,
            }

    history = (Scan.query
               .filter_by(user_id=user.id)
               .order_by(Scan.ran_at.desc())
               .limit(10).all())
    return render_template("index.html",
                           data=data, error=error, user=user, history=history)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    scans = (Scan.query
             .filter_by(user_id=user.id)
             .order_by(Scan.ran_at.desc()).all())
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for s in scans:
        risk_counts[s.risk] = risk_counts.get(s.risk, 0) + 1
    return render_template("dashboard.html",
                           user=user, scans=scans, risk_counts=risk_counts)


# ── Reports ───────────────────────────────────────────────────────────────────

@app.route("/report/view/<filename>")
@login_required
def view_report(filename):
    return send_from_directory(reports, filename)


@app.route("/report/download/<filename>")
@login_required
def download_report(filename):
    return send_from_directory(reports, filename, as_attachment=True)


# ── Init ──────────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
