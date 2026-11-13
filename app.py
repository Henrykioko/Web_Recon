import os
import re
import json
import html
import shutil
import socket
import string
import random
import time
import ipaddress
import platform
import subprocess
import threading
import tempfile
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

import requests

from flask import (
    Flask, render_template, render_template_string, request,
    send_from_directory, redirect, url_for, session, flash, abort, jsonify
)

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, inspect as sa_inspect, text
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from dateutil import parser as dateparser
except ImportError:  # a built-in fallback parser is used instead
    dateparser = None


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = "Templates" if (
    BASE_DIR / "Templates").is_dir() else "templates"

app = Flask(__name__, template_folder=TEMPLATE_DIR)

APP_ENV = (
    os.environ.get("WEBRECON_ENV")
    or os.environ.get("FLASK_ENV")
    or "development"
).lower()

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if APP_ENV == "production":
        raise RuntimeError(
            "Set a strong SECRET_KEY environment variable before production.")
    SECRET_KEY = "local-development-only-change-before-deployment"
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{BASE_DIR / 'recon.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "connect_args": {"check_same_thread": False, "timeout": 30}
}

db = SQLAlchemy(app)

IS_WINDOWS = platform.system().lower() == "windows"

TOOL_TIMEOUT = 180
NMAP_TIMEOUT = 600
GOBUSTER_TIMEOUT = 300
WHATWEB_TIMEOUT = 90

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
# Without an API key NVD allows ~5 requests / 30 s, so keep lookups bounded.
MAX_CPE_LOOKUPS = 30 if NVD_API_KEY else 12

HTTP_TIMEOUT = 15

MAX_CONCURRENT_SCANS = int(os.environ.get("WEBRECON_MAX_JOBS", "2"))
STALE_SCAN_MINUTES = 45


def utcnow():
    """Naive UTC timestamp (replacement for the deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    joined = db.Column(db.DateTime, default=utcnow)

    scans = db.relationship("Scan", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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

    # Background-job tracking
    status = db.Column(db.String(20), default="queued")
    stage = db.Column(db.String(120))
    progress = db.Column(db.Text)
    error = db.Column(db.Text)

    ran_at = db.Column(db.DateTime, default=utcnow)
    finished_at = db.Column(db.DateTime)


# ============================================================
# AUTHENTICATION
# ============================================================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        user = db.session.get(User, session["uid"])
        if not user:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return wrapper


def get_user():
    if "uid" not in session:
        return None
    return db.session.get(User, session["uid"])


# ============================================================
# TOOL DETECTION AND COMMAND EXECUTION
# ============================================================

def find_tool(name):
    return shutil.which(name)


def tool_installed(name):
    return find_tool(name) is not None


def build_command(command):
    """Windows .CMD/.BAT files are launched through cmd.exe."""
    if not command:
        return command

    command = [str(part) for part in command]
    executable = command[0]

    if IS_WINDOWS and executable.lower().endswith((".cmd", ".bat")):
        return ["cmd.exe", "/d", "/c", subprocess.list2cmdline(command)]

    return command


def run_command(command, timeout=TOOL_TIMEOUT):
    """Run an external command without a shell."""
    if not command:
        return "No command provided."

    command = [str(part) for part in command]
    executable = command[0]

    resolved = find_tool(executable)
    if resolved:
        command[0] = resolved
    elif not Path(executable).is_file():
        return f"{executable} is not installed or is not available in PATH."

    try:
        result = subprocess.run(
            build_command(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
            env=os.environ.copy()
        )

        output = result.stdout or ""
        if result.stderr:
            output += ("\n" if output else "") + result.stderr

        if not output.strip():
            return (
                f"Command completed with exit code "
                f"{result.returncode}, but returned no output."
            )

        return output.strip()

    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds."
    except FileNotFoundError:
        return f"{executable} could not be found."
    except Exception as exc:
        return f"Error running {executable}: {exc}"


def tool_status():
    tools = ["nmap", "whatweb", "whois", "gobuster"]
    return {
        name: {"installed": tool_installed(name), "path": find_tool(name)}
        for name in tools
    }


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def tool_missing(output):
    lower = (output or "").lower()[:200]
    return "not installed" in lower or "could not be found" in lower


# ============================================================
# DOMAIN VALIDATION AND DNS
# ============================================================

def valid_domain(domain):
    """Validate a DNS hostname (not a URL, IP literal, or shell fragment)."""
    if not isinstance(domain, str):
        return False
    domain = domain.strip().rstrip(".")
    if not domain or len(domain) > 253 or "://" in domain or "/" in domain:
        return False
    if any(ch.isspace() for ch in domain) or "@" in domain or "\\" in domain:
        return False
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return False
    except ValueError:
        pass
    labels = domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return False
    if any(label.lower() in {"localhost", "local", "internal", "lan"} for label in labels):
        return False
    return all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
        for x in labels
    )


def resolve_public_ips(domain):
    """Resolve every A/AAAA record; reject the target if any address is non-global."""
    try:
        answers = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    ips = sorted({item[4][0].split("%", 1)[0] for item in answers})
    if not ips:
        return []
    for value in ips:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return []
        if not address.is_global:
            return []
    return ips


def resolve_ip(domain):
    addresses = resolve_public_ips(domain)
    return addresses[0] if addresses else ""


def resolve_host_ips(host):
    """Return the set of A/AAAA addresses for a host (no public-IP policy applied)."""
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return set()
    return {item[4][0].split("%", 1)[0] for item in answers}


def get_dns(domain):
    output = []

    if IS_WINDOWS:
        commands = [["nslookup", domain]]
    else:
        commands = []
        if tool_installed("dig"):
            commands.append(["dig", domain, "A", "+noall", "+answer"])
        if tool_installed("nslookup"):
            commands.append(["nslookup", domain])

    for command in commands:
        result = run_command(command, timeout=15)
        if result and "not installed" not in result.lower():
            output.append(result)

    ip = resolve_ip(domain)
    if ip:
        output.append(f"\nResolved IPv4 address: {ip}")
    else:
        output.append("\nNo IPv4 address could be resolved.")

    return "\n\n".join(output)


# ============================================================
# WORDLIST DISCOVERY
# ============================================================

def get_wordlist(profile):
    custom = os.environ.get("WEBRECON_WORDLIST")
    candidates = []

    if custom:
        candidates.append(Path(custom))

    if IS_WINDOWS:
        candidates.extend([
            Path(r"C:\SecLists\Discovery\DNS\subdomains-top1million-5000.txt"),
            Path(r"C:\SecLists\Discovery\DNS\subdomains-top1million-20000.txt"),
            Path(r"C:\Tools\SecLists\Discovery\DNS\subdomains-top1million-5000.txt"),
            Path.home() / "SecLists" / "Discovery" / "DNS" /
            "subdomains-top1million-5000.txt"
        ])
    else:
        candidates.extend([
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
            Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million.txt"),
            Path("/usr/share/wordlists/dnsmap.txt")
        ])

    existing = [path for path in candidates if path.is_file()]
    if not existing:
        return None

    if profile == "advanced":
        return str(existing[-1])
    if profile == "normal":
        return str(existing[min(1, len(existing) - 1)])
    return str(existing[0])


# ============================================================
# WHATWEB
# ============================================================

def run_whatweb(domain):
    whatweb_path = find_tool("whatweb")
    if not whatweb_path:
        return "WhatWeb is not installed or is not available in PATH."

    for scheme in ("https", "http"):
        result = run_command(
            [whatweb_path, "--color=never", "-v", "-a", "3",
             "--no-errors", f"{scheme}://{domain}"],
            timeout=WHATWEB_TIMEOUT
        )
        if not result:
            continue

        lower_result = result.lower()
        if (
            "not installed" not in lower_result
            and "could not be found" not in lower_result
            and "timed out" not in lower_result
            and "error running" not in lower_result
        ):
            return result

    return "WhatWeb could not retrieve usable results from the target."


# ============================================================
# WHOIS
# ============================================================

def run_whois(domain):
    whois_path = find_tool("whois")
    if not whois_path:
        return "WHOIS is not installed or is not available in PATH."
    return run_command([whois_path, domain], timeout=30)


# ============================================================
# NMAP
# ============================================================

def parse_nmap(output):
    """Parse Nmap XML into structured observations. Never infer vulnerabilities from an open port."""
    result = {"count": 0, "ports": [], "services": [], "versions": [],
              "risk": "Info", "reason": "No valid Nmap results were returned."}
    if not output:
        return result
    try:
        root = ET.fromstring(output)
        if root.tag != "nmaprun":
            raise ET.ParseError("Unexpected XML root")
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = service_el.get(
                "name", "unknown") if service_el is not None else "unknown"
            product = service_el.get(
                "product", "") if service_el is not None else ""
            version_num = service_el.get(
                "version", "") if service_el is not None else ""
            extra = service_el.get(
                "extrainfo", "") if service_el is not None else ""
            version = " ".join(x for x in (product, version_num, extra) if x)
            cpes = [e.text.strip() for e in service_el.findall(
                "cpe") if e.text] if service_el is not None else []
            result["ports"].append(number)
            result["services"].append(service)
            result["versions"].append({"port": number, "protocol": protocol, "service": service,
                                      "product": product, "version": version_num, "version_text": version, "cpes": cpes})
        result["count"] = len(result["ports"])
        result["services"] = sorted(set(result["services"]))
        result["risk"] = "Info"
        result["reason"] = "Open ports are observations; their security impact requires service and configuration review."
        return result
    except ET.ParseError:
        # Plain text fallback is explicitly lower-confidence and has no CPE data.
        for line in output.splitlines():
            match = re.match(
                r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line, re.I)
            if not match:
                continue
            number, proto, service, version = match.groups()
            result["ports"].append(number)
            result["services"].append(service)
            result["versions"].append({"port": number, "protocol": proto.lower(
            ), "service": service, "product": "", "version": "", "version_text": version or "", "cpes": []})
        result["count"] = len(result["ports"])
        result["services"] = sorted(set(result["services"]))
        result["reason"] = "Parsed from Nmap text output; version/CPE evidence may be incomplete."
        return result


def run_nmap(domain, profile):
    """
    Run Nmap once, producing normal output (-oN, for reports) and
    XML (-oX -, for parsing). XML is never shown as the report.
    """
    data = {"xml": "", "normal": "", "error": "",
            "returncode": None, "skipped": False}

    nmap_path = find_tool("nmap")
    if not nmap_path:
        message = "Nmap is not installed or is not available in PATH."
        data["normal"] = data["error"] = message
        return data

    if profile == "safe":
        data["normal"] = "Skipped (safe profile)."
        data["skipped"] = True
        return data

    if profile == "normal":
        port_range = "1-1000"
    elif profile == "advanced":
        port_range = "1-65535"
    else:
        message = "Invalid scan profile."
        data["normal"] = data["error"] = message
        return data

    normal_path = None

    try:
        descriptor, normal_path = tempfile.mkstemp(
            prefix="webrecon_nmap_", suffix=".txt")
        os.close(descriptor)

        command = [
            nmap_path, "-sV", "-p", port_range, "--min-rate", "5000",
            "--open", "-oN", normal_path, "-oX", "-", domain
        ]

        process = subprocess.run(
            build_command(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=NMAP_TIMEOUT,
            shell=False,
            env=os.environ.copy()
        )

        data["xml"] = process.stdout or ""
        data["returncode"] = process.returncode
        data["normal"] = read_text_file(normal_path)

        stderr_output = (process.stderr or "").strip()
        if stderr_output:
            data["error"] = stderr_output
            if data["normal"]:
                data["normal"] += "\n\nNmap messages:\n" + stderr_output
            else:
                data["normal"] = stderr_output

        if process.returncode != 0:
            message = f"Nmap exited with code {process.returncode}."
            data["error"] = message + \
                ("\n" + data["error"] if data["error"] else "")
            if not data["normal"]:
                data["normal"] = message

        if not data["normal"]:
            data["normal"] = "Nmap completed but did not produce normal output."

        return data

    except subprocess.TimeoutExpired as exc:
        partial_xml = exc.stdout or ""
        if isinstance(partial_xml, bytes):
            partial_xml = partial_xml.decode("utf-8", errors="replace")
        data["xml"] = partial_xml

        message = f"Nmap scan timed out after {NMAP_TIMEOUT} seconds."
        data["error"] = message

        existing = read_text_file(normal_path) if normal_path else ""
        data["normal"] = (existing + "\n\n" + message) if existing else message
        return data

    except FileNotFoundError:
        message = "Nmap executable could not be found."
        data["normal"] = data["error"] = message
        return data

    except Exception as exc:
        message = f"Error running Nmap: {exc}"
        data["normal"] = data["error"] = message
        return data

    finally:
        if normal_path and os.path.exists(normal_path):
            try:
                os.remove(normal_path)
            except OSError:
                pass


# ============================================================
# SUBDOMAIN ENUMERATION
# ============================================================

FALLBACK_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap",
    "webmail", "remote", "vpn", "dev", "staging",
    "test", "api", "portal", "admin", "beta",
    "shop", "blog", "forum", "news", "static",
    "cdn", "media", "images", "secure", "login",
    "auth", "mobile", "app", "dashboard", "docs",
    "support", "help", "status", "monitor", "git",
    "gitlab", "jenkins", "jira", "confluence",
    "wiki", "intranet", "server", "ns1", "ns2",
    "mx", "mx1", "mx2", "autodiscover"
]


def detect_wildcard_ips(domain):
    """Resolve random labels; any answer means the zone has a wildcard record."""
    ips = set()
    for _ in range(2):
        label = "wc-" + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=14))
        ips |= resolve_host_ips(f"{label}.{domain}")
    return ips


def is_wildcard_hit(host, wildcard_ips):
    if not wildcard_ips:
        return False
    ips = resolve_host_ips(host)
    return bool(ips) and ips <= wildcard_ips


def socket_scan(domain, wildcard_ips=None):
    wildcard_ips = wildcard_ips or set()

    def check(subdomain):
        host = f"{subdomain}.{domain}"
        ips = resolve_host_ips(host)
        if not ips:
            return None
        if wildcard_ips and ips <= wildcard_ips:
            return None
        return host

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check, FALLBACK_SUBDOMAINS))

    return sorted(set(result for result in results if result))


def gobuster_scan(domain, profile):
    gobuster_path = find_tool("gobuster")
    if not gobuster_path:
        return []

    wordlist = get_wordlist(profile)
    if not wordlist:
        return []

    output = run_command(
        [gobuster_path, "dns", "-d", domain, "-w", wordlist,
         "-t", "30", "--timeout", "5s", "-q", "--no-color"],
        timeout=GOBUSTER_TIMEOUT
    )

    if (
        not output
        or "error running" in output.lower()
        or "timed out" in output.lower()
        or "not installed" in output.lower()
    ):
        return []

    found = []
    for line in output.splitlines():
        match = re.search(
            r"(?:Found:\s*)?([a-zA-Z0-9.-]+\." + re.escape(domain) + r")",
            line.strip(),
            re.IGNORECASE
        )
        if match:
            found.append(match.group(1).lower())

    return sorted(set(found))


def get_subdomains(domain, profile):
    """Return (subdomains, metadata). Wildcard DNS results are filtered out."""
    wildcard_ips = detect_wildcard_ips(domain)
    meta = {"wildcard": bool(wildcard_ips),
            "wildcard_ips": sorted(wildcard_ips), "method": "socket"}
    results = []

    # Gobuster refuses to run against wildcard zones, so only use it otherwise.
    if not wildcard_ips and tool_installed("gobuster") and get_wordlist(profile):
        results = gobuster_scan(domain, profile)
        if results:
            meta["method"] = "gobuster"

    if not results:
        results = socket_scan(domain, wildcard_ips)
        meta["method"] = "socket"

    if wildcard_ips:
        results = [h for h in results if not is_wildcard_hit(h, wildcard_ips)]

    return sorted(set(results)), meta


# ============================================================
# CVE LOOKUP
# ============================================================

cve_cache = {}
cve_lock = threading.Lock()
nvd_lock = threading.Lock()
nvd_last_request = [0.0]

CPE_PLACEHOLDERS = {"", "*", "-"}


def split_cpe(value, keep_escape=False):
    """Split a CPE string on unescaped colons."""
    parts, buf, escaped = [], [], False
    for ch in value:
        if escaped:
            buf.append(("\\" + ch) if keep_escape else ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if escaped:
        buf.append("\\")
    parts.append("".join(buf))
    return parts


def legacy_cpe_to_23(cpe):
    """
    Convert a CPE 2.2 URI to a CPE 2.3 formatted string.
    Returns None for CPEs without a concrete version: NVD's cpeName lookup
    needs a fully specified name, and versionless CPEs would match nothing useful.
    """
    if not isinstance(cpe, str) or not cpe.strip():
        return None
    cpe = cpe.strip()

    if cpe.startswith("cpe:2.3:"):
        parts = split_cpe(cpe, keep_escape=True)
        if len(parts) != 13 or parts[5] in CPE_PLACEHOLDERS:
            return None
        return cpe

    if not cpe.startswith("cpe:/"):
        return None

    parts = split_cpe(cpe[5:])
    # part, vendor, product, version are required.
    if len(parts) < 4 or len(parts) > 7:
        return None
    if parts[3] in CPE_PLACEHOLDERS:
        return None
    parts += ["*"] * (7 - len(parts))

    components = []
    for part in parts[:7]:
        if part in ("", "*") or part.startswith("~"):
            components.append("*")
        else:
            components.append(part.replace(" ", "\\ ").replace(":", "\\:"))
    return "cpe:2.3:" + ":".join(components + ["*"] * 4)


def extract_vulnerable_cpe_matches(node):
    """Return NVD vulnerable CPE match objects, retaining version-bound metadata."""
    matches = []
    if isinstance(node, dict):
        for item in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch", []), list) else []:
            if isinstance(item, dict) and item.get("vulnerable") is True:
                matches.append(item)
        for value in node.values():
            if isinstance(value, (dict, list)):
                matches.extend(extract_vulnerable_cpe_matches(value))
    elif isinstance(node, list):
        for item in node:
            matches.extend(extract_vulnerable_cpe_matches(item))
    return matches


def nvd_throttle():
    interval = 0.7 if NVD_API_KEY else 6.5
    with nvd_lock:
        delay = nvd_last_request[0] + interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        nvd_last_request[0] = time.monotonic()


def nvd_get(params):
    """GET with throttling and backoff. Returns (json, error_message)."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    last_error = "unknown NVD error"

    for attempt in range(4):
        nvd_throttle()
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            last_error = f"network error ({exc.__class__.__name__})"
            time.sleep(2 ** attempt)
            continue

        if response.status_code in (403, 429, 503):
            last_error = f"NVD rate limit or service error (HTTP {response.status_code})"
            retry_after = response.headers.get("Retry-After", "")
            pause = int(retry_after) if retry_after.isdigit(
            ) else 10 * (attempt + 1)
            time.sleep(min(pause, 60))
            continue

        if response.status_code == 404:
            # NVD answers 404 when it does not know the CPE name.
            return {"vulnerabilities": [], "totalResults": 0}, None

        try:
            response.raise_for_status()
            return response.json(), None
        except (requests.RequestException, ValueError) as exc:
            return None, f"NVD error ({exc.__class__.__name__})"

    return None, last_error


def cvss_label(score, fallback="Unknown"):
    if score is None:
        return fallback
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def fetch_cves_for_cpe(cpe23):
    """Query NVD by CPE with pagination. Returns (candidates, error_message)."""
    with cve_lock:
        if cpe23 in cve_cache:
            return [dict(item) for item in cve_cache[cpe23]], None

    found, start_index, total = [], 0, None

    while total is None or start_index < total:
        payload, error = nvd_get({"cpeName": cpe23, "resultsPerPage": 100,
                                  "startIndex": start_index})
        if error:
            return [], error  # never cache failures as a clean zero-CVE result

        vulnerabilities = payload.get("vulnerabilities", [])
        total = int(payload.get("totalResults", len(vulnerabilities)))

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            matches = extract_vulnerable_cpe_matches(
                cve.get("configurations", []))
            if not matches:
                continue

            metrics = cve.get("metrics", {})
            score, severity, metric_version = None, "Unknown", None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss = entries[0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or "Unknown"
                    metric_version = cvss.get("version")
                    break

            description = next(
                (d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"),
                "No description available.")

            found.append({
                "id": cid, "cpe": cpe23, "severity": severity, "score": score,
                "metric_version": metric_version, "desc": description[:1000],
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "match_criteria": [
                    {k: m.get(k) for k in (
                        "criteria", "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                        "matchCriteriaId", "vulnerable")}
                    for m in matches],
                "verification_status": "Potential - NVD CPE match; installed patch state not verified"
            })

        if not vulnerabilities:
            break
        start_index += len(vulnerabilities)
        if len(vulnerabilities) < 100:
            break

    with cve_lock:
        cve_cache[cpe23] = found
    return [dict(item) for item in found], None


def service_label(item):
    base = item.get("service", "unknown")
    where = f"{item.get('protocol', 'tcp')}/{item.get('port', '?')}"
    version = item.get("version_text") or ""
    return f"{base} - {version} ({where})" if version else f"{base} ({where})"


def get_cves(versions):
    """
    Collect NVD candidates only from versioned CPEs that Nmap reported.
    Returns {"cves", "errors", "lookups", "skipped_unversioned", "truncated"}.
    """
    targets, skipped = {}, 0
    for item in versions or []:
        label = service_label(item)
        for raw_cpe in item.get("cpes", []):
            cpe23 = legacy_cpe_to_23(raw_cpe)
            if cpe23:
                targets.setdefault(cpe23, set()).add(label)
            else:
                skipped += 1

    info = {"cves": [], "errors": [], "lookups": 0,
            "skipped_unversioned": skipped, "truncated": False}
    if not targets:
        return info

    ordered = sorted(targets.items())
    if len(ordered) > MAX_CPE_LOOKUPS:
        info["truncated"] = True
        ordered = ordered[:MAX_CPE_LOOKUPS]

    unique = {}
    for cpe23, labels in ordered:
        candidates, error = fetch_cves_for_cpe(cpe23)
        info["lookups"] += 1
        if error:
            info["errors"].append(f"{cpe23}: {error}")
            continue
        label = ", ".join(sorted(labels))
        for item in candidates:
            item["service"] = label
            unique[(item["id"], item["cpe"])] = item

    info["cves"] = list(unique.values())
    return info


# ============================================================
# SECURITY INTELLIGENCE DATA
# ============================================================

def _pi(name, risk, explanation, attack, recommendation):
    return {"name": name, "risk": risk, "explanation": explanation,
            "attack": attack, "recommendation": recommendation}


PORT_INTEL = {
    "21": _pi("FTP", "High", "FTP may transmit credentials and data without encryption.",
              "Credential sniffing, brute force, anonymous access",
              "Disable FTP where possible and use SFTP or FTPS."),
    "22": _pi("SSH", "Medium", "Exposed SSH services may be targeted by automated login attacks.",
              "Brute force, password spraying",
              "Use SSH keys, disable password login where practical, and restrict access."),
    "23": _pi("Telnet", "Critical", "Telnet transmits credentials and commands without encryption.",
              "Credential interception, session hijacking", "Disable Telnet and use SSH."),
    "25": _pi("SMTP", "Medium", "An improperly configured SMTP server may be abused for spam or email spoofing.",
              "Open relay abuse, phishing", "Restrict relaying and configure SPF, DKIM and DMARC."),
    "80": _pi("HTTP", "Low", "HTTP traffic is not encrypted.",
              "Traffic interception, content injection", "Redirect HTTP traffic to HTTPS."),
    "135": _pi("MS RPC", "High", "Windows RPC endpoint mapper exposed to the internet.",
               "Remote enumeration, exploitation of RPC services", "Block RPC at the perimeter."),
    "139": _pi("NetBIOS", "High", "NetBIOS session service exposed to the internet.",
               "Information disclosure, credential attacks", "Block NetBIOS at the perimeter."),
    "443": _pi("HTTPS", "Info", "HTTPS is expected for public websites. TLS configuration should still be reviewed.",
               "Weak TLS configuration", "Use modern TLS versions and secure cipher suites."),
    "445": _pi("SMB", "Critical", "Publicly exposed SMB services can expose file-sharing infrastructure.",
               "Remote exploitation, credential theft", "Block public SMB access."),
    "1433": _pi("MSSQL", "Critical", "Direct database exposure increases the risk of unauthorised access.",
                "Brute force, data theft", "Restrict database access to trusted networks."),
    "1521": _pi("Oracle DB", "Critical", "Direct database exposure increases the risk of unauthorised access.",
                "Brute force, data theft", "Restrict database access to trusted networks."),
    "2375": _pi("Docker API", "Critical", "An unauthenticated Docker API grants control of the host.",
                "Remote container creation, host takeover", "Never expose the Docker API publicly; use TLS and firewalling."),
    "3306": _pi("MySQL", "Critical", "Public database access can expose sensitive records.",
                "Brute force, data exfiltration", "Restrict MySQL to trusted interfaces."),
    "3389": _pi("RDP", "Critical", "Exposed Remote Desktop services are common targets for attackers.",
                "Brute force, remote exploitation", "Place RDP behind a VPN and enforce strong authentication."),
    "5432": _pi("PostgreSQL", "Critical", "Public database access can expose stored information.",
                "Brute force, data theft", "Restrict PostgreSQL to trusted networks."),
    "5900": _pi("VNC", "High", "Remote desktop (VNC) exposed to the internet, often weakly authenticated.",
                "Brute force, unauthorised remote control", "Place VNC behind a VPN and enforce strong authentication."),
    "6379": _pi("Redis", "Critical", "An exposed Redis instance may allow unauthorised access to cached data.",
                "Unauthorised access, data theft", "Require authentication and restrict network access."),
    "8080": _pi("HTTP Alternate", "Medium", "Alternative HTTP ports may expose development or administrative services.",
                "Default credentials, information disclosure",
                "Identify the service and restrict access where necessary."),
    "9200": _pi("Elasticsearch", "Critical", "An exposed Elasticsearch API may allow unauthorised data access.",
                "Data theft, index deletion", "Enable authentication and restrict network access."),
    "11211": _pi("Memcached", "High", "Exposed memcached can leak cached data and be abused for amplification.",
                 "Data theft, DDoS amplification", "Bind to localhost or a private network."),
    "27017": _pi("MongoDB", "Critical", "An exposed MongoDB service may allow unauthorised database access.",
                 "Data theft, unauthorised database access",
                 "Enable authentication and restrict network access."),
}

# Nmap -sV service names mapped to PORT_INTEL keys (works on non-standard ports).
SERVICE_TO_INTEL_KEY = {
    "telnet": "23", "ftp": "21", "microsoft-ds": "445", "netbios-ssn": "139",
    "msrpc": "135", "ms-wbt-server": "3389", "mysql": "3306",
    "postgresql": "5432", "redis": "6379", "mongodb": "27017",
    "ms-sql-s": "1433", "vnc": "5900", "memcached": "11211",
    "oracle-tns": "1521", "docker": "2375",
}

# Services that should normally NOT be reachable from the public internet.
RESTRICTED_KEYS = {"21", "23", "135", "139", "445", "1433", "1521", "2375",
                   "3306", "3389", "5432", "5900", "6379", "9200", "11211",
                   "27017"}

RISK_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def lower_risk(risk, cap):
    """Return whichever of the two ratings is less severe."""
    ri = RISK_ORDER.index(risk) if risk in RISK_ORDER else len(RISK_ORDER)
    ci = RISK_ORDER.index(cap) if cap in RISK_ORDER else len(RISK_ORDER)
    return RISK_ORDER[max(ri, ci)] if max(ri, ci) < len(RISK_ORDER) else "Info"


TECH_INTEL = {
    "wordpress": ("Medium", "WordPress installations should be kept updated.", "Update WordPress, themes and plugins."),
    "drupal": ("Medium", "Outdated Drupal installations may contain known vulnerabilities.", "Update Drupal core and modules."),
    "joomla": ("Medium", "Outdated Joomla installations may contain known vulnerabilities.", "Update Joomla and its extensions."),
    "apache": ("Low", "Server version disclosure can help attackers identify software versions.", "Keep Apache updated and minimise version disclosure."),
    "nginx": ("Low", "Server version disclosure can assist targeted reconnaissance.", "Keep Nginx updated and minimise version disclosure."),
    "iis": ("Low", "IIS version disclosure may reveal server information.", "Keep IIS updated and review exposed headers."),
    "php": ("Medium", "Outdated PHP versions may contain known security vulnerabilities.", "Use a supported PHP version."),
    "jquery": ("Low", "Outdated jQuery versions may contain known vulnerabilities.", "Update jQuery to a supported release."),
    "bootstrap": ("Info", "Bootstrap version information was detected.", "Review the version and update when necessary."),
    "httpserver": ("Low", "The Server header may reveal server software information.", "Review and minimise server version disclosure."),
}

HEADER_INTEL = {
    "content-security-policy": {"recommendation": "Define a suitable Content-Security-Policy for your application."},
    "x-frame-options / CSP frame-ancestors": {"recommendation": "Use X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors policy."},
    "x-content-type-options": {"recommendation": "Add X-Content-Type-Options: nosniff."},
    "strict-transport-security": {"recommendation": "Configure Strict-Transport-Security after confirming HTTPS works correctly."},
    "referrer-policy": {"recommendation": "Consider strict-origin-when-cross-origin."},
    "permissions-policy": {"recommendation": "Restrict browser features that your application does not need."},
}


# ============================================================
# PORT ANALYSIS
# ============================================================

def analyse_ports(nmap_result):
    """
    Open ports are observations, but services that should not normally be
    public (databases, Telnet, SMB, RDP, ...) keep their elevated rating.
    Ubiquitous services (SSH, SMTP, HTTP) are capped at Low.
    """
    findings = []
    versions = (nmap_result or {}).get("versions", [])
    open_ports = {str(i.get("port", "")) for i in versions}

    for item in versions:
        port = str(item.get("port", ""))
        protocol = item.get("protocol", "tcp")
        service = item.get("service", "unknown")
        version = item.get("version_text") or item.get("version") or ""

        key = SERVICE_TO_INTEL_KEY.get(service.lower())
        matched_by = "Nmap service detection" if key else "port number"
        if not key and port in PORT_INTEL:
            key = port
        intel = PORT_INTEL.get(key) if key else None

        evidence = (f"Nmap reported {protocol}/{port} open; service={service}; "
                    f"version={version or 'not identified'}; matched by {matched_by}.")

        if intel:
            risk = intel["risk"]
            if key not in RESTRICTED_KEYS:
                risk = lower_risk(risk, "Low")
            if key == "80" and "443" in open_ports:
                risk = "Info"

            exposed = key in RESTRICTED_KEYS
            title = (f"Sensitive service exposed: {intel['name']} on {protocol.upper()} port {port}"
                     if exposed else
                     f"Open {protocol.upper()} port {port} - {intel['name']}")
            explanation = (
                intel["explanation"]
                + " This was observed by a port scan; whether the exposure is intentional "
                  "and whether the service is misconfigured has not been verified."
            )
            confidence = "High" if matched_by == "Nmap service detection" else "Medium"
            attack = intel["attack"]
            recommendation = intel["recommendation"]
        else:
            risk = "Info"
            title = f"Open {protocol.upper()} port {port} - {service}"
            explanation = ("An open port is an exposure observation, not proof of a vulnerability. "
                           "Review whether this service must be reachable from the public internet.")
            confidence = "High"
            attack = "The service may be targeted depending on its configuration and authentication."
            recommendation = ("Confirm business need, restrict source networks where possible, and "
                              "assess the service's configuration and patch level.")

        findings.append({
            "source": "Nmap", "type": "service_exposure", "title": title,
            "risk": risk, "confidence": confidence,
            "verification_status": "Observed - exposure not validated",
            "evidence": evidence, "explanation": explanation,
            "attack": attack, "recommendation": recommendation,
            "version": version, "cpe": ", ".join(item.get("cpes", []))
        })

    return findings


# ============================================================
# WHATWEB ANALYSIS
# ============================================================

def analyse_whatweb(output):
    """Report technology fingerprints as observations, never as vulnerabilities."""
    findings = []
    if not output or any(x in output.lower() for x in ("not installed", "could not be found", "could not retrieve usable results", "timed out")):
        return findings
    lower = output.lower()
    for technology in TECH_INTEL:
        if re.search(r"(?<![a-z0-9])" + re.escape(technology) + r"(?![a-z0-9])", lower):
            findings.append({
                "source": "WhatWeb", "type": "technology_observation",
                "title": f"Technology fingerprint: {technology.replace('-', ' ').title()}",
                "risk": "Info", "confidence": "Medium",
                "verification_status": "Observed - fingerprint only",
                "evidence": f"The WhatWeb output contains a fingerprint for {technology}.",
                "explanation": "Technology identification alone does not establish that the software is outdated or vulnerable.",
                "recommendation": "Verify the exact product and version against vendor advisories and the deployed asset inventory."
            })
    return findings


# ============================================================
# HTTP SECURITY HEADER ANALYSIS
# ============================================================

REDIRECT_CODES = {301, 302, 303, 307, 308}


def fetch_final_response(domain):
    """
    Follow redirects manually (max 6 hops), re-validating every hop against
    the public-IP rule, and return the final response (or None).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            for _ in range(6):
                parsed = urlparse(url)
                if (parsed.scheme not in ("http", "https")
                        or not parsed.hostname
                        or not resolve_public_ips(parsed.hostname)):
                    break
                response = requests.get(
                    url, timeout=HTTP_TIMEOUT, allow_redirects=False,
                    headers={"User-Agent": "WebRecon-Security-Scanner/1.0"},
                    stream=True)
                location = response.headers.get("Location")
                if response.status_code in REDIRECT_CODES and location:
                    response.close()
                    url = urljoin(url, location)
                    continue
                return response
        except requests.RequestException:
            continue
    return None


def analyse_http_headers(domain):
    """Inspect the FINAL response headers (after redirects)."""
    findings = []
    response = fetch_final_response(domain)
    if response is None:
        return findings
    try:
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = response.url.lower().startswith("https://")
        missing = []
        for header in ("content-security-policy", "x-content-type-options",
                       "referrer-policy", "permissions-policy"):
            if header not in headers:
                missing.append(header)
        if "x-frame-options" not in headers:
            csp = headers.get("content-security-policy", "").lower()
            if "frame-ancestors" not in csp:
                missing.append("x-frame-options / CSP frame-ancestors")
        if is_https and "strict-transport-security" not in headers:
            missing.append("strict-transport-security")

        for header in missing:
            findings.append({
                "source": "Headers", "type": "header_observation",
                "title": f"Security header not observed: {header}",
                "risk": "Low", "confidence": "High",
                "verification_status": "Observed",
                "evidence": f"Final response URL: {response.url}; status: {response.status_code}; header absent.",
                "explanation": "A missing security header may reduce browser-side defence in depth, but applicability depends on the application and deployment context.",
                "recommendation": HEADER_INTEL.get(header, {}).get("recommendation", "Review whether this header is appropriate for the application.")
            })

        for header in ("x-powered-by", "x-aspnet-version", "server"):
            if headers.get(header):
                findings.append({
                    "source": "Headers", "type": "information_disclosure",
                    "title": f"Technology disclosure header: {header}",
                    "risk": "Info", "confidence": "High",
                    "verification_status": "Observed",
                    "evidence": f"{header}: {headers[header][:200]}",
                    "explanation": "The response discloses technology information that may assist fingerprinting.",
                    "recommendation": "Remove unnecessary version details where operationally feasible."
                })
    finally:
        response.close()
    return findings


# ============================================================
# WHOIS ANALYSIS
# ============================================================

DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S",
    "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d",
)


def parse_date(value):
    """Parse a WHOIS date; uses python-dateutil when present, else a fallback."""
    value = (value or "").strip()
    if not value:
        return None
    if dateparser:
        try:
            return dateparser.parse(value, ignoretz=True)
        except (ValueError, OverflowError):
            pass
    cleaned = re.sub(r"\s*\(.*?\)\s*$", "", value)
    for fmt in DATE_FORMATS:
        try:
            parsed = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    return None


def analyse_whois(output, domain):
    findings = []

    if not output:
        return findings

    lower_output = output.lower()
    if "not installed" in lower_output or "could not be found" in lower_output:
        return findings

    expiry_patterns = [
        r"registry expiry date:\s*([^\n]+)",
        r"registrar registration expiration date:\s*([^\n]+)",
        r"expiration date:\s*([^\n]+)",
        r"expiry date:\s*([^\n]+)",
        r"paid-till:\s*([^\n]+)"
    ]

    expiry_value = None
    for pattern in expiry_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            expiry_value = match.group(1).strip()
            break

    if expiry_value:
        expiry_date = parse_date(expiry_value)

        if expiry_date is None:
            findings.append({
                "source": "WHOIS", "type": "domain_expiry_unparsed",
                "title": "WHOIS expiry date could not be parsed",
                "risk": "Info", "confidence": "Low",
                "verification_status": "Observed - not interpreted",
                "evidence": f"Raw expiry value: {expiry_value[:120]}",
                "explanation": "A WHOIS expiry date was present but its format was not recognised, so no expiry assessment was made.",
                "recommendation": "Check the domain's expiry date with the registrar."
            })
        else:
            days_left = (expiry_date - utcnow()).days

            if days_left < 0:
                risk, title = "Critical", "Domain Expired"
                recommendation = "Check the registrar and renew the domain immediately."
            elif days_left <= 7:
                risk, title = "Critical", f"Domain Expires in {days_left} Days"
                recommendation = "Renew the domain immediately."
            elif days_left <= 30:
                risk, title = "High", f"Domain Expires in {days_left} Days"
                recommendation = "Renew the domain soon."
            elif days_left <= 90:
                risk, title = "Low", f"Domain Expires in {days_left} Days"
                recommendation = "Plan the renewal and check auto-renewal settings."
            else:
                risk, title = "Info", f"Domain Valid - {days_left} Days Remaining"
                recommendation = "Ensure domain auto-renewal is enabled."

            findings.append({
                "source": "WHOIS", "type": "domain_expiry", "title": title,
                "risk": risk, "confidence": "High",
                "verification_status": "Observed - WHOIS record",
                "evidence": f"WHOIS expiry value: {expiry_value[:120]}",
                "explanation": f"{domain} has a reported expiry date of {expiry_date.date()}.",
                "recommendation": recommendation,
                "expiry_date": str(expiry_date.date()), "days_left": days_left
            })

    privacy_phrases = [
        "redacted for privacy", "data redacted", "data protected",
        "privacy service", "whois privacy", "registration private",
        "not disclosed", "masked for privacy"
    ]

    if any(phrase in lower_output for phrase in privacy_phrases):
        findings.append({
            "source": "WHOIS", "type": "whois_privacy",
            "title": "WHOIS Privacy Enabled", "risk": "Info",
            "explanation": "Registrant information appears to be protected or redacted.",
            "recommendation": "Continue using appropriate domain registration privacy protection."
        })
    else:
        registrant_email = re.search(
            r"(?im)^\s*(?:registrant|owner)\s+"
            r"(?:e-?mail|email address)\s*:\s*([^\s]+)", output)

        if registrant_email:
            email_value = registrant_email.group(1).strip()
            excluded = ("redacted", "privacy", "protected",
                        "not disclosed", "data unavailable")
            if not any(v in email_value.lower() for v in excluded):
                findings.append({
                    "source": "WHOIS", "type": "whois_exposure",
                    "title": "Registrant Email May Be Exposed", "risk": "Low",
                    "explanation": "An email address was found in the registrant contact field.",
                    "attack": "Phishing, spam and social engineering",
                    "recommendation": "Review whether the registrant contact information should be publicly visible."
                })

    return findings


# ============================================================
# DNS / SUBDOMAIN ANALYSIS
# ============================================================

def analyse_dns(output, domain):
    """Only report a successful AXFR, with evidence."""
    findings = []
    if not tool_installed("dig"):
        return findings
    try:
        ns_output = run_command(
            [find_tool("dig"), "+short", "NS", domain], timeout=15)
        nameservers = [x.rstrip(".") for x in ns_output.splitlines(
        ) if x.strip() and "not installed" not in x.lower()]
        for nameserver in nameservers[:10]:
            axfr = run_command(
                [find_tool("dig"), "AXFR", domain, f"@{nameserver}"], timeout=20)
            if "XFR size:" in axfr and "Transfer failed" not in axfr:
                findings.append({
                    "source": "DNS", "type": "zone_transfer",
                    "title": "DNS zone transfer succeeded", "risk": "High",
                    "confidence": "High", "verification_status": "Observed - AXFR response",
                    "evidence": f"AXFR against authoritative nameserver {nameserver} returned zone data.",
                    "explanation": "An authoritative DNS server returned zone-transfer data to this scanner.",
                    "recommendation": "Restrict AXFR to explicitly authorised secondary nameservers."
                })
    except Exception:
        pass
    return findings


def analyse_subdomains(subdomains, domain):
    """Discovered hostnames are informational; names do not prove exposed services."""
    findings = []
    for subdomain in sorted(set(subdomains or [])):
        if not subdomain.lower().endswith("." + domain.lower()):
            continue
        findings.append({
            "source": "Subdomains", "type": "subdomain_discovery",
            "title": f"Subdomain discovered: {subdomain}", "risk": "Info",
            "confidence": "Medium", "verification_status": "DNS-resolved; service not verified",
            "evidence": f"Hostname returned by configured DNS enumeration method: {subdomain}.",
            "explanation": "A discovered hostname does not by itself indicate an exposed administrative interface or vulnerability.",
            "recommendation": "Confirm ownership, purpose, whether it should be public, and whether any exposed service has appropriate access controls."
        })
    return findings


# ============================================================
# CVE GROUPING
# ============================================================

def group_cves(cve_list):
    """
    Group NVD candidates by the service that produced them.
    These are investigation leads, not confirmed vulnerabilities, so they do
    not influence the overall risk rating.
    """
    groups = {}

    for cve in cve_list or []:
        cid = cve.get("id")
        if not cid:
            continue
        try:
            score = float(cve["score"]) if cve.get(
                "score") is not None else None
        except (TypeError, ValueError):
            score = None

        key = (cve.get("service") or "unknown", cve.get("cpe", ""))
        group = groups.setdefault(
            key, {"service": key[0], "cpe": key[1], "cves": []})
        if any(existing["id"] == cid for existing in group["cves"]):
            continue
        group["cves"].append({
            "id": cid,
            "score": score,
            "severity": cvss_label(score, cve.get("severity") or "Unknown"),
            "desc": (cve.get("desc") or "No description available.")[:400],
            "url": cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cid}",
        })

    result = []
    for group in groups.values():
        group["cves"].sort(key=lambda c: (
            c["score"] is None, -(c["score"] or 0), c["id"]))
        scores = [c["score"] for c in group["cves"] if c["score"] is not None]
        group["max_score"] = max(scores) if scores else None
        group["max_severity"] = cvss_label(group["max_score"])
        group["count"] = len(group["cves"])
        result.append(group)

    result.sort(key=lambda g: (g["max_score"] is None,
                -(g["max_score"] or 0), g["service"]))
    return result


# ============================================================
# OVERALL INTELLIGENCE
# ============================================================

def run_intelligence(domain, nmap_result, whatweb_output, whois_output,
                     dns_output, subdomains, cve_list, scan_status=None,
                     subdomain_meta=None):
    findings = []
    findings.extend(analyse_ports(nmap_result))
    findings.extend(analyse_whatweb(whatweb_output))
    findings.extend(analyse_http_headers(domain))
    findings.extend(analyse_whois(whois_output, domain))
    findings.extend(analyse_dns(dns_output, domain))
    findings.extend(analyse_subdomains(subdomains, domain))

    if subdomain_meta and subdomain_meta.get("wildcard"):
        findings.append({
            "source": "Subdomains", "type": "wildcard_dns",
            "title": "Wildcard DNS detected", "risk": "Info",
            "confidence": "High", "verification_status": "Observed",
            "evidence": ("Random non-existent labels resolved to: "
                         + ", ".join(subdomain_meta.get("wildcard_ips", []))),
            "explanation": "The zone answers for names that do not exist. Brute-force results that match the wildcard address were discarded.",
            "recommendation": "Confirm the wildcard record is intentional; it can hide stale or abandoned hostnames."
        })

    for item in findings:
        item.setdefault("confidence", "Medium")
        item.setdefault("verification_status", "Observed - review evidence")
        item.setdefault("evidence", item.get(
            "explanation", "No structured evidence supplied."))

    findings.sort(key=lambda f: (
        RISK_ORDER.index(f.get("risk")) if f.get(
            "risk") in RISK_ORDER else len(RISK_ORDER),
        f.get("source", ""), f.get("title", "")))

    status = scan_status or {"complete": True,
                             "message": "Scan coverage not recorded."}
    complete = bool(status.get("complete", True))

    highest = next((level for level in RISK_ORDER
                    if any(x.get("risk") == level for x in findings)), None)
    if complete:
        risk_label = highest or "Low"
    else:
        # Never hide real findings behind "Incomplete".
        risk_label = highest if highest in (
            "Critical", "High", "Medium", "Low") else "Incomplete"

    counts = {x: 0 for x in RISK_ORDER}
    for item in findings:
        level = item.get("risk", "Info")
        if level in counts:
            counts[level] += 1

    cve_groups = group_cves(cve_list)

    return {
        "findings": findings,
        "risk_label": risk_label,
        "severity_counts": counts,
        "total_findings": len(findings),
        "actionable_count": len(findings) - counts["Info"],
        "cve_groups": cve_groups,
        "cve_candidate_count": sum(g["count"] for g in cve_groups),
        "scan_status": status,
    }


# ============================================================
# REPORT GENERATION
# ============================================================

RISK_COLORS = {
    "Critical": "#E74C3C", "High": "#E67E22", "Medium": "#F39C12",
    "Low": "#27AE60", "Info": "#3498DB"
}


def esc(value):
    return html.escape(str(value if value is not None else ""))


def save_txt(scan, filename, intel):
    path = REPORTS_DIR / filename
    status = intel.get("scan_status", {})

    with open(path, "w", encoding="utf-8") as file:
        file.write(f"WEBRECON SECURITY REPORT - {scan.domain}\n")
        file.write("=" * 60 + "\n\n")
        file.write(f"IP: {scan.ip}\n")
        file.write(f"Profile: {scan.profile}\n")
        file.write(f"Risk Level: {intel['risk_label']}\n")
        file.write(
            f"Findings: {intel['total_findings']} "
            f"({intel.get('actionable_count', 0)} above Info)\n")
        file.write(f"Scan complete: {status.get('complete')}\n")
        file.write(f"Scan note: {status.get('message', '')}\n")
        for warning in status.get("warnings", []):
            file.write(f"Warning: {warning}\n")
        file.write(f"Time: {scan.ran_at}\n\n")

        file.write("FINDINGS\n" + "-" * 40 + "\n")
        for finding in intel["findings"]:
            file.write(f"\n[{finding['risk']}] {finding['title']}\n")
            file.write(f"Source: {finding['source']}\n")
            file.write(
                f"Confidence: {finding.get('confidence', 'Not assessed')}\n")
            file.write(
                f"Verification: {finding.get('verification_status', 'Not assessed')}\n")
            file.write(
                f"Evidence: {finding.get('evidence', 'Not supplied')}\n")
            file.write(f"Explanation: {finding.get('explanation', '')}\n")
            if finding.get("attack"):
                file.write(f"Attack: {finding['attack']}\n")
            file.write(
                f"Recommendation: {finding.get('recommendation', '')}\n")

        file.write("\nPOTENTIAL CVE CANDIDATES BY SERVICE (unverified)\n")
        file.write("-" * 40 + "\n")
        if not intel.get("cve_groups"):
            file.write("None.\n")
        for group in intel.get("cve_groups", []):
            file.write(
                f"\n{group['service']}  [{group['count']} candidates, "
                f"highest CVSS {group['max_score'] if group['max_score'] is not None else 'n/a'}]\n")
            for cve in group["cves"]:
                score = cve["score"] if cve["score"] is not None else "n/a"
                file.write(
                    f"  {cve['id']}  CVSS {score} ({cve['severity']})  {cve['url']}\n")

        file.write("\nRAW SCAN DATA\n" + "-" * 40 + "\n")
        file.write(f"\nDNS\n{scan.dns or ''}\n")
        file.write(f"\nNMAP\n{scan.nmap or ''}\n")
        file.write(f"\nWHATWEB\n{scan.whatweb or ''}\n")
        file.write(f"\nWHOIS\n{scan.whois or ''}\n")
        file.write(f"\nSUBDOMAINS\n{scan.subdomains or 'None'}\n")
        file.write(f"\nCVE DATA\n{scan.cves or '[]'}\n")

    return filename


REPORT_CSS = """
body { font-family: Arial, sans-serif; margin: 40px; background: #0f1117; color: #ccc; }
h1 { color: #fff; }
h2 { color: #3B9EE8; border-bottom: 1px solid #333; padding-bottom: 8px; margin-top: 32px; }
.muted { color: #888; font-size: 13px; }
.risk-label { display: inline-block; padding: 8px 20px; font-size: 1.4rem; font-weight: bold; border-radius: 6px; color: #fff; }
.notice { background: #2a2110; border: 1px solid #6b5316; color: #e8c766; padding: 12px 16px; border-radius: 6px; margin: 16px 0; font-size: 14px; }
.finding { background: #161b22; border-radius: 6px; margin: 12px 0; overflow: hidden; }
.finding-header { padding: 12px 16px; display: flex; align-items: center; gap: 10px; background: #1a2130; flex-wrap: wrap; }
.badge { padding: 3px 8px; border-radius: 4px; color: #fff; font-size: 12px; font-weight: bold; }
.source-tag { margin-left: auto; font-size: 11px; color: #aaa; }
.finding-table, .cve-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.finding-table td, .cve-table td, .cve-table th { padding: 10px 16px; border-bottom: 1px solid #222; vertical-align: top; overflow-wrap: anywhere; text-align: left; }
.finding-table td:first-child { width: 120px; color: #aaa; }
.cve-table th { color: #aaa; font-weight: normal; font-size: 12px; }
.cve-table a { color: #3B9EE8; }
.sev-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 10px; margin: 16px 0; }
.sev-card { text-align: center; padding: 12px; border-radius: 6px; background: #161b22; }
.sev-card .num { font-size: 1.8rem; font-weight: bold; }
details { background: #161b22; border-radius: 6px; margin: 12px 0; }
details > summary { cursor: pointer; padding: 12px 16px; font-weight: bold; color: #ddd; list-style-position: inside; }
details > div { padding: 0 8px 8px 8px; }
pre { background: #161b22; padding: 12px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; border-radius: 4px; }
@media (max-width: 600px) { body { margin: 15px; } }
"""


def finding_html(finding):
    risk = finding.get("risk", "Info")
    color = RISK_COLORS.get(risk, "#888")

    rows = [("Explanation", finding.get("explanation"))]
    if finding.get("attack"):
        rows.append(("Attack types", finding.get("attack")))
    rows.append(("Evidence", finding.get("evidence")))
    rows.append(("Confidence / Status",
                 f"{finding.get('confidence', '')} / {finding.get('verification_status', '')}"))
    if finding.get("cpe"):
        rows.append(("CPE", finding.get("cpe")))
    rows.append(("Fix", finding.get("recommendation")))

    body = "".join(
        f"<tr><td><b>{esc(label)}</b></td><td>{esc(value)}</td></tr>"
        for label, value in rows)

    return (
        '<div class="finding">'
        f'<div class="finding-header" style="border-left:4px solid {color}">'
        f'<span class="badge" style="background:{color}">{esc(risk)}</span>'
        f'<b>{esc(finding.get("title"))}</b>'
        f'<span class="source-tag">{esc(finding.get("source"))}</span>'
        '</div>'
        f'<table class="finding-table">{body}</table>'
        '</div>'
    )


def cve_groups_html(groups):
    if not groups:
        return '<p class="muted">No CVE candidates were returned by NVD for the detected, versioned CPEs.</p>'

    parts = []
    for group in groups:
        severity = group.get("max_severity") or "Unknown"
        color = RISK_COLORS.get(severity, "#888")
        top = group["max_score"] if group.get(
            "max_score") is not None else "n/a"

        rows = ""
        for cve in group["cves"]:
            score = cve["score"] if cve["score"] is not None else "n/a"
            rows += (
                "<tr>"
                f'<td><a href="{esc(cve["url"])}" target="_blank" rel="noopener noreferrer">{esc(cve["id"])}</a></td>'
                f"<td>{esc(score)}</td>"
                f"<td>{esc(cve['severity'])}</td>"
                f"<td>{esc(cve['desc'])}</td>"
                "</tr>"
            )

        parts.append(
            "<details>"
            f'<summary><span class="badge" style="background:{color}">{esc(severity)}</span> '
            f'{esc(group["service"])} &mdash; {group["count"]} candidate(s), highest CVSS {esc(top)}</summary>'
            "<div>"
            f'<p class="muted" style="padding:0 8px">CPE: {esc(group.get("cpe"))}</p>'
            '<table class="cve-table"><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Description</th></tr>'
            f"{rows}</table></div></details>"
        )
    return "".join(parts)


def save_html(scan, filename, intel):
    path = REPORTS_DIR / filename

    risk_label = intel["risk_label"]
    label_color = RISK_COLORS.get(risk_label, "#888")
    counts = intel["severity_counts"]
    status = intel.get("scan_status", {})

    actionable = [f for f in intel["findings"] if f.get("risk") != "Info"]
    informational = [f for f in intel["findings"] if f.get("risk") == "Info"]

    notice_html = ""
    notes = []
    if not status.get("complete", True):
        notes.append(status.get("message", "Scan coverage was incomplete."))
    notes.extend(status.get("warnings", []))
    if notes:
        notice_html = '<div class="notice">' + \
            "<br>".join(esc(n) for n in notes) + "</div>"

    actionable_html = "".join(finding_html(f) for f in actionable) or \
        '<p class="muted">No findings above Info severity.</p>'

    info_html = ""
    if informational:
        info_html = (
            "<details>"
            f"<summary>Informational findings ({len(informational)}) - click to expand</summary>"
            "<div>" + "".join(finding_html(f)
                              for f in informational) + "</div>"
            "</details>"
        )

    raw_sections = {
        "DNS": scan.dns, "Nmap": scan.nmap, "WhatWeb": scan.whatweb,
        "WHOIS": scan.whois, "Subdomains": scan.subdomains, "CVE Data": scan.cves
    }
    raw_html = "".join(
        f"<h3>{esc(name)}</h3><pre>{esc(value)}</pre>"
        for name, value in raw_sections.items())

    cards = "".join(
        f'<div class="sev-card"><div class="num" style="color:{RISK_COLORS[level]}">'
        f'{counts[level]}</div><div>{level}</div></div>'
        for level in RISK_ORDER)

    cve_total = intel.get("cve_candidate_count", 0)

    report = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f"<title>Security Report - {esc(scan.domain)}</title>"
        f"<style>{REPORT_CSS}</style></head><body>"
        f"<h1>Security Report - {esc(scan.domain)}</h1>"
        f'<p class="muted">IP: {esc(scan.ip)} | Profile: {esc(scan.profile)} | Scanned: {esc(scan.ran_at)}</p>'
        "<h2>Overall Risk</h2>"
        f'<div class="risk-label" style="background:{label_color}">{esc(risk_label)}</div>'
        f"<p>{intel['total_findings']} findings ({intel.get('actionable_count', 0)} above Info)</p>"
        f"{notice_html}"
        f'<div class="sev-grid">{cards}</div>'
        f"<h2>Findings that need attention ({len(actionable)})</h2>"
        f"{actionable_html}{info_html}"
        f"<h2>Potential CVE candidates by service ({cve_total})</h2>"
        '<p class="muted">These are NVD matches for the CPEs Nmap reported. They are unverified leads: '
        "installed package version, vendor backports, configuration and role have not been checked, "
        "so they do not affect the overall risk rating.</p>"
        f"{cve_groups_html(intel.get('cve_groups', []))}"
        f"<h2>Raw Scan Data</h2>{raw_html}"
        "</body></html>"
    )

    with open(path, "w", encoding="utf-8") as file:
        file.write(report)

    return filename


# ============================================================
# BACKGROUND SCAN JOBS
# ============================================================

MODULE_ORDER = ["dns", "whois", "whatweb", "subdomains",
                "nmap", "cves", "analysis", "reports"]

JOB_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


def run_scan_job(scan_id):
    """Runs one scan to completion inside its own app context."""
    with app.app_context():
        try:
            scan = db.session.get(Scan, scan_id)
            if scan is None:
                return

            domain, profile = scan.domain, scan.profile
            progress = {name: "pending" for name in MODULE_ORDER}

            def checkpoint(stage=None, **states):
                progress.update(states)
                scan.progress = json.dumps(progress)
                if stage:
                    scan.stage = stage
                db.session.commit()

            scan.status = "running"
            checkpoint("Resolving target", dns="running")

            public_ips = resolve_public_ips(domain)
            if not public_ips:
                raise RuntimeError(
                    "Target did not resolve exclusively to public IP addresses.")
            ip = public_ips[0]
            scan.ip = ip

            dns_output = get_dns(domain)

            checkpoint(
                "Running scan modules",
                dns="done", whois="running", whatweb="running",
                subdomains="running",
                nmap="skipped" if profile == "safe" else "running")

            defaults = {
                "whois": "WHOIS module failed.",
                "whatweb": "WhatWeb module failed.",
                "subdomains": ([], {"wildcard": False}),
                "nmap": {"xml": "", "normal": "Nmap module failed.",
                         "error": "Nmap module failed.", "returncode": None,
                         "skipped": False},
            }
            results, warnings = {}, []

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(run_whois, domain): "whois",
                    executor.submit(run_whatweb, domain): "whatweb",
                    executor.submit(get_subdomains, domain, profile): "subdomains",
                    executor.submit(run_nmap, ip, profile): "nmap",
                }
                pending = set(futures)
                while pending:
                    done, pending = wait(
                        pending, timeout=3, return_when=FIRST_COMPLETED)
                    changed = {}
                    for future in done:
                        name = futures[future]
                        try:
                            results[name] = future.result()
                            changed[name] = "done"
                            if name == "nmap" and results[name].get("skipped"):
                                changed[name] = "skipped"
                        except Exception as exc:
                            results[name] = defaults[name]
                            changed[name] = "failed"
                            warnings.append(
                                f"{name} module crashed: {exc.__class__.__name__}")
                    if changed:
                        checkpoint(**changed)

            whois_output = results["whois"]
            whatweb_output = results["whatweb"]
            subdomains, subdomain_meta = results["subdomains"]
            nmap_run = results["nmap"]

            nmap_xml = nmap_run.get("xml", "")
            nmap_display = nmap_run.get("normal", "")
            nmap_skipped = bool(nmap_run.get("skipped"))
            nmap_failed = (not nmap_skipped) and (
                not nmap_xml.strip() or nmap_run.get("returncode") != 0)

            nmap_result = parse_nmap(nmap_xml)
            if nmap_skipped:
                nmap_result = {
                    "count": 0, "ports": [], "services": [], "versions": [],
                    "risk": "Info",
                    "reason": "Nmap skipped because the safe profile was selected."}
            elif nmap_failed:
                nmap_result = {
                    "count": 0, "ports": [], "services": [], "versions": [],
                    "risk": "Info",
                    "reason": (nmap_run.get("error") or nmap_display
                               or "Nmap did not return valid scan results.")}
                warnings.append(
                    "Nmap did not complete successfully; port and CVE results may be incomplete.")
                progress["nmap"] = "failed"

            for label, output in (("WHOIS", whois_output), ("WhatWeb", whatweb_output)):
                if tool_missing(output):
                    warnings.append(
                        f"{label} is not installed; that check was skipped.")

            checkpoint("Looking up CVE candidates", cves="running")
            cve_info = get_cves(nmap_result["versions"])
            cve_list = cve_info["cves"]

            if cve_info["errors"]:
                warnings.append(
                    f"NVD lookup failed for {len(cve_info['errors'])} CPE(s); "
                    "CVE candidates may be incomplete.")
            if cve_info["truncated"]:
                warnings.append(
                    f"Only the first {MAX_CPE_LOOKUPS} CPEs were queried against NVD "
                    "(set NVD_API_KEY to raise the limit).")
            if cve_info["skipped_unversioned"]:
                warnings.append(
                    f"{cve_info['skipped_unversioned']} CPE(s) had no version and were not looked up.")

            checkpoint("Building intelligence",
                       cves="failed" if cve_info["errors"] else "done",
                       analysis="running")

            scan_complete = (not nmap_failed) and (not cve_info["errors"])
            if nmap_skipped:
                message = "Safe profile: active port scanning was intentionally skipped."
            elif nmap_failed:
                message = "Nmap did not complete successfully; findings may be incomplete."
            elif cve_info["errors"]:
                message = "Nmap completed, but the NVD lookup had errors."
            else:
                message = "Nmap completed. Other checks may still have individual limitations."

            status_info = {
                "complete": scan_complete,
                "nmap": "skipped" if nmap_skipped else ("failed" if nmap_failed else "completed"),
                "message": message,
                "warnings": warnings,
                "resolved_addresses": public_ips,
            }

            intelligence = run_intelligence(
                domain, nmap_result, whatweb_output, whois_output, dns_output,
                subdomains, cve_list, scan_status=status_info,
                subdomain_meta=subdomain_meta)
            intelligence["nmap_result"] = nmap_result

            checkpoint("Writing reports", analysis="done", reports="running")

            report_base = f"{domain}_{utcnow().strftime('%Y%m%d_%H%M%S_%f')}"

            scan.risk = intelligence["risk_label"]
            scan.port_count = nmap_result["count"]
            scan.services = ", ".join(nmap_result["services"])
            scan.dns = dns_output
            scan.whois = whois_output
            scan.nmap = nmap_display
            scan.whatweb = whatweb_output
            scan.cves = json.dumps(cve_list)
            scan.subdomains = "\n".join(subdomains)
            scan.intelligence = json.dumps(intelligence)
            scan.report_txt = report_base + ".txt"
            scan.report_html = report_base + ".html"
            db.session.commit()

            save_txt(scan, scan.report_txt, intelligence)
            save_html(scan, scan.report_html, intelligence)

            progress["reports"] = "done"
            scan.progress = json.dumps(progress)
            scan.status = "completed"
            scan.stage = "Completed"
            scan.finished_at = utcnow()
            db.session.commit()

        except Exception as exc:
            db.session.rollback()
            try:
                scan = db.session.get(Scan, scan_id)
                if scan:
                    scan.status = "failed"
                    scan.stage = "Failed"
                    scan.error = f"{exc.__class__.__name__}: {exc}"[:2000]
                    scan.finished_at = utcnow()
                    db.session.commit()
            except Exception:
                db.session.rollback()
        finally:
            db.session.remove()


def _job_entry(scan_id):
    with JOB_SLOTS:  # the scan stays "queued" until a slot frees up
        run_scan_job(scan_id)


def start_scan_job(scan_id):
    threading.Thread(target=_job_entry, args=(scan_id,),
                     daemon=True, name=f"scan-{scan_id}").start()


def active_scan_for(user_id):
    cutoff = utcnow() - timedelta(minutes=STALE_SCAN_MINUTES)
    return Scan.query.filter(
        Scan.user_id == user_id,
        Scan.status.in_(["queued", "running"]),
        Scan.ran_at > cutoff
    ).first()


def get_owned_scan(scan_id):
    user = get_user()
    if not user:
        abort(404)
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if not scan:
        abort(404)
    return scan


def safe_json(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def build_view_data(scan):
    """Rebuild the `data` dict that index.html expects from a stored scan."""
    intel = safe_json(scan.intelligence, {})
    cves = safe_json(scan.cves, [])
    subs = scan.subdomains.splitlines() if scan.subdomains else []
    result = intel.get("nmap_result") or {
        "count": scan.port_count or 0, "ports": [], "services": [],
        "versions": [], "risk": "Info", "reason": ""}
    intel.setdefault("cve_groups", group_cves(cves))
    return {"scan": scan, "result": result, "cves": cves,
            "subs": subs, "intel": intel}


STATUS_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scan - {{ scan.domain }}</title>
<style>
body { font-family: Arial, sans-serif; background: #0f1117; color: #ccc; margin: 40px auto; max-width: 640px; padding: 0 16px; }
h1 { color: #fff; font-size: 1.5rem; }
.muted { color: #888; font-size: 13px; }
.stage { font-size: 1.1rem; color: #3B9EE8; margin: 20px 0 12px; }
ul { list-style: none; padding: 0; }
li { background: #161b22; margin: 6px 0; padding: 10px 14px; border-radius: 6px; display: flex; justify-content: space-between; }
.pending { color: #777; } .running { color: #F39C12; } .done { color: #27AE60; }
.failed { color: #E74C3C; } .skipped { color: #888; }
.error { background: #2a1212; border: 1px solid #6b1c1c; color: #f0a0a0; padding: 12px 16px; border-radius: 6px; margin: 16px 0; white-space: pre-wrap; }
a { color: #3B9EE8; }
</style></head><body>
<h1>Scan: {{ scan.domain }}</h1>
<p class="muted">Profile: {{ scan.profile }} &middot; Started: {{ scan.ran_at }}</p>
<div class="stage" id="stage">{{ scan.stage or scan.status }}</div>
<ul id="modules"></ul>
{% if scan.status == 'failed' %}<div class="error">{{ scan.error }}</div>{% endif %}
<p><a href="{{ url_for('index') }}">Back to scanner</a></p>
<script>
var LABELS = {dns: "DNS", whois: "WHOIS", whatweb: "WhatWeb", subdomains: "Subdomains",
              nmap: "Nmap", cves: "CVE lookup", analysis: "Analysis", reports: "Reports"};
var ORDER = ["dns", "whois", "whatweb", "subdomains", "nmap", "cves", "analysis", "reports"];
var ACTIVE = {{ 'true' if scan.status in ('queued', 'running') else 'false' }};
function render(s) {
  document.getElementById("stage").textContent = s.stage || s.status;
  var list = document.getElementById("modules");
  list.innerHTML = "";
  ORDER.forEach(function (key) {
    var state = (s.progress && s.progress[key]) || "pending";
    var li = document.createElement("li");
    var name = document.createElement("span");
    name.textContent = LABELS[key];
    var st = document.createElement("span");
    st.textContent = state;
    st.className = state;
    li.appendChild(name); li.appendChild(st); list.appendChild(li);
  });
}
function poll() {
  fetch("{{ url_for('scan_status_api', scan_id=scan.id) }}", {credentials: "same-origin"})
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (s) {
      if (s) {
        render(s);
        if (s.status === "completed" || s.status === "failed") { location.reload(); return; }
      }
      setTimeout(poll, 2500);
    })
    .catch(function () { setTimeout(poll, 4000); });
}
render({stage: document.getElementById("stage").textContent, progress: {{ (scan.progress or '{}')|safe }}});
if (ACTIVE) { poll(); }
</script>
</body></html>"""


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Fill in both fields.", "danger")
            return redirect(url_for("register"))

        if len(username) > 80:
            flash("Username is too long.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("That username is already taken.", "danger")
            return redirect(url_for("register"))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created. Log in.", "success")
        return redirect(url_for("login"))

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session["uid"] = user.id
            return redirect(url_for("index"))

        flash("Wrong username or password.", "danger")

    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# SCAN ROUTES
# ============================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user = get_user()
    error = None

    if request.method == "POST":
        domain = request.form.get("domain", "").strip().lower()
        profile = request.form.get("profile", "safe").lower()

        if not valid_domain(domain):
            error = "Invalid domain."
        elif profile not in {"safe", "normal", "advanced"}:
            error = "Invalid scan profile."
        elif active_scan_for(user.id):
            error = "You already have a scan in progress. Wait for it to finish first."
        else:
            public_ips = resolve_public_ips(domain)
            if not public_ips:
                error = ("Target did not resolve exclusively to public IP addresses. "
                         "Private, loopback, link-local, reserved, or unresolved targets are blocked.")
            else:
                scan = Scan(
                    user_id=user.id, domain=domain, ip=public_ips[0],
                    profile=profile, status="queued", stage="Queued",
                    progress=json.dumps({m: "pending" for m in MODULE_ORDER}),
                    ran_at=utcnow())
                db.session.add(scan)
                db.session.commit()

                start_scan_job(scan.id)
                return redirect(url_for("scan_view", scan_id=scan.id))

    history = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.ran_at.desc()).limit(10).all()
    )

    return render_template(
        "index.html", data={}, error=error, user=user, history=history)


@app.route("/scan/<int:scan_id>")
@login_required
def scan_view(scan_id):
    scan = get_owned_scan(scan_id)
    status = scan.status or "completed"

    if status in ("queued", "running", "failed"):
        return render_template_string(STATUS_PAGE, scan=scan)

    user = get_user()
    history = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.ran_at.desc()).limit(10).all()
    )
    return render_template(
        "index.html", data=build_view_data(scan), error=None,
        user=user, history=history)


@app.route("/scan/<int:scan_id>/status")
@login_required
def scan_status_api(scan_id):
    scan = get_owned_scan(scan_id)
    status = scan.status or "completed"
    progress = safe_json(scan.progress, {})

    if status == "failed":
        progress = {k: ("failed" if v == "running" else v)
                    for k, v in progress.items()}

    return jsonify({
        "status": status,
        "stage": scan.stage or status,
        "progress": progress,
        "error": scan.error,
        "risk": scan.risk,
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()

    scans = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.ran_at.desc()).all()
    )

    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

    for scan in scans:
        if (scan.status or "completed") != "completed":
            continue
        risk = scan.risk or "Low"
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    return render_template(
        "dashboard.html", user=user, scans=scans, risk_counts=risk_counts)


# ============================================================
# REPORT ACCESS
# ============================================================

def get_owned_report(filename):
    # Prevent directory traversal.
    if not filename or Path(filename).name != filename:
        abort(404)

    user = get_user()
    if not user:
        abort(404)

    scan = Scan.query.filter(
        Scan.user_id == user.id,
        or_(Scan.report_txt == filename, Scan.report_html == filename)
    ).first()

    if not scan:
        abort(404)

    return scan


@app.route("/report/view/<filename>")
@login_required
def view_report(filename):
    get_owned_report(filename)
    return send_from_directory(str(REPORTS_DIR), filename)


@app.route("/report/download/<filename>")
@login_required
def download_report(filename):
    get_owned_report(filename)
    return send_from_directory(str(REPORTS_DIR), filename, as_attachment=True)


# ============================================================
# TOOL STATUS
# ============================================================

@app.route("/tools")
@login_required
def tools_status():
    return {"platform": platform.system(), "tools": tool_status()}


# ============================================================
# INITIALISE DATABASE
# ============================================================

def init_database():
    db.create_all()

    # Lightweight SQLite migration: add the job-tracking columns to old databases.
    existing = {c["name"] for c in sa_inspect(db.engine).get_columns("scans")}
    wanted = {
        "status": "VARCHAR(20)", "stage": "VARCHAR(120)",
        "progress": "TEXT", "error": "TEXT", "finished_at": "DATETIME",
    }
    with db.engine.begin() as connection:
        for name, ddl in wanted.items():
            if name not in existing:
                connection.execute(
                    text(f"ALTER TABLE scans ADD COLUMN {name} {ddl}"))
        connection.execute(
            text("UPDATE scans SET status = 'completed' WHERE status IS NULL"))

    # Jobs cannot survive a restart: mark anything unfinished as failed.
    Scan.query.filter(Scan.status.in_(["queued", "running"])).update(
        {"status": "failed", "stage": "Failed",
         "error": "Interrupted by an application restart.",
         "finished_at": utcnow()},
        synchronize_session=False)
    db.session.commit()


with app.app_context():
    init_database()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode, threaded=True)
