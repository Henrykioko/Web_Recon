
import os
import re
import json
import html
import shutil
import socket
import platform
import subprocess
import threading
import tempfile
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

import requests

from flask import (
    Flask, render_template, request, send_from_directory,
    redirect, url_for, session, flash, abort
)

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key-change-this"
)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{BASE_DIR / 'recon.db'}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "connect_args": {"check_same_thread": False}
}

db = SQLAlchemy(app)

IS_WINDOWS = platform.system().lower() == "windows"

TOOL_TIMEOUT = 180
NMAP_TIMEOUT = 600
GOBUSTER_TIMEOUT = 300
WHATWEB_TIMEOUT = 90

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = os.environ.get("NVD_API_KEY")

HTTP_TIMEOUT = 15


# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    joined = db.Column(db.DateTime, default=datetime.utcnow)

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

    ran_at = db.Column(db.DateTime, default=datetime.utcnow)


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
    """
    Find an installed executable.
    """

    return shutil.which(name)


def tool_installed(name):
    return find_tool(name) is not None


def build_command(command):
    """
    Prepare a command for Windows or Linux.

    Windows .CMD and .BAT files are launched through cmd.exe.
    """

    if not command:
        return command

    command = [str(part) for part in command]

    executable = command[0]

    if IS_WINDOWS and executable.lower().endswith((".cmd", ".bat")):

        return [
            "cmd.exe",
            "/d",
            "/c",
            subprocess.list2cmdline(command)
        ]

    return command


def run_command(command, timeout=TOOL_TIMEOUT):
    """
    Run external commands safely.
    """

    if not command:
        return "No command provided."

    command = [str(part) for part in command]

    executable = command[0]

    resolved = find_tool(executable)

    if resolved:
        command[0] = resolved

    elif not Path(executable).is_file():
        return (
            f"{executable} is not installed "
            "or is not available in PATH."
        )

    try:

        launch_command = build_command(command)

        result = subprocess.run(
            launch_command,
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
        name: {
            "installed": tool_installed(name),
            "path": find_tool(name)
        }
        for name in tools
    }


# ============================================================
# DOMAIN VALIDATION AND DNS
# ============================================================

def valid_domain(domain):

    if not domain:
        return False

    domain = domain.strip().lower()

    if len(domain) > 253:
        return False

    if domain.endswith("."):
        domain = domain[:-1]

    if domain in {"localhost", "internal"}:
        return False

    if any(
        part in domain.split(".")
        for part in ["local", "localhost", "internal"]
    ):
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    return bool(re.match(pattern, domain))


def resolve_ip(domain):

    try:

        results = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM
        )

        addresses = []

        for result in results:

            address = result[4][0]

            if address not in addresses:
                addresses.append(address)

        return addresses[0] if addresses else ""

    except socket.gaierror:
        return ""

    except Exception:
        return ""


def get_dns(domain):

    output = []

    if IS_WINDOWS:

        commands = [
            ["nslookup", domain]
        ]

    else:

        commands = []

        if tool_installed("dig"):

            commands.append([
                "dig", domain, "A", "+noall", "+answer"
            ])

        if tool_installed("nslookup"):

            commands.append([
                "nslookup", domain
            ])

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
            Path(
                r"C:\SecLists\Discovery\DNS"
                r"\subdomains-top1million-5000.txt"
            ),
            Path(
                r"C:\SecLists\Discovery\DNS"
                r"\subdomains-top1million-20000.txt"
            ),
            Path(
                r"C:\Tools\SecLists\Discovery\DNS"
                r"\subdomains-top1million-5000.txt"
            ),
            Path.home() / "SecLists" / "Discovery" / "DNS" /
            "subdomains-top1million-5000.txt"
        ])

    else:

        candidates.extend([
            Path(
                "/usr/share/seclists/Discovery/DNS/"
                "subdomains-top1million-5000.txt"
            ),
            Path(
                "/usr/share/seclists/Discovery/DNS/"
                "subdomains-top1million-20000.txt"
            ),
            Path(
                "/usr/share/seclists/Discovery/DNS/"
                "subdomains-top1million.txt"
            ),
            Path("/usr/share/wordlists/dnsmap.txt")
        ])

    existing = [
        path for path in candidates
        if path.is_file()
    ]

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

        return (
            "WhatWeb is not installed or "
            "is not available in PATH."
        )

    for scheme in ("https", "http"):

        url = f"{scheme}://{domain}"

        result = run_command(
            [
                whatweb_path,
                "--color=never",
                "-v",
                "-a",
                "3",
                "--no-errors",
                url
            ],
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

    return (
        "WhatWeb could not retrieve usable results "
        "from the target."
    )


# ============================================================
# WHOIS
# ============================================================

def run_whois(domain):

    whois_path = find_tool("whois")

    if not whois_path:

        return (
            "WHOIS is not installed or "
            "is not available in PATH."
        )

    return run_command(
        [whois_path, domain],
        timeout=30
    )


# ============================================================
# NMAP
# ============================================================

def parse_nmap(output):
    """
    Parse Nmap XML output.

    Preserves:
    - Open ports
    - Service names
    - Product names
    - Versions
    - Extra version information
    - CPE identifiers

    XML is used internally for parsing and CVE matching.
    It is not used as the report display output.
    """

    ports = []
    services = []
    versions = []

    if not output:

        return {
            "count": 0,
            "ports": [],
            "services": [],
            "versions": [],
            "risk": "Info",
            "reason": "No Nmap results were returned."
        }

    try:

        root = ET.fromstring(output)

        for port in root.findall(".//port"):

            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_number = port.get("portid", "")

            service_element = port.find("service")

            service = "unknown"
            version = ""
            cpes = []

            if service_element is not None:

                service = service_element.get(
                    "name",
                    "unknown"
                )

                product = service_element.get("product", "")
                version_number = service_element.get("version", "")
                extra = service_element.get("extrainfo", "")

                version = " ".join(
                    part for part in [
                        product,
                        version_number,
                        extra
                    ]
                    if part
                )

                for cpe_element in service_element.findall("cpe"):

                    if cpe_element.text:

                        cpes.append(
                            cpe_element.text.strip()
                        )

            ports.append(port_number)
            services.append(service)

            versions.append({
                "port": port_number,
                "service": service,
                "version": version,
                "cpes": cpes
            })

    except ET.ParseError:

        # Fallback for ordinary Nmap output.
        # This does not provide reliable CPE information.

        for line in output.splitlines():

            if "/tcp" not in line or "open" not in line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            port_number = parts[0].split("/")[0]

            service = (
                parts[2]
                if len(parts) > 2
                else "unknown"
            )

            version = (
                " ".join(parts[3:])
                if len(parts) > 3
                else ""
            )

            ports.append(port_number)
            services.append(service)

            versions.append({
                "port": port_number,
                "service": service,
                "version": version,
                "cpes": []
            })

    risky_ports = {
        "21", "23", "445", "1433", "3306",
        "3389", "5432", "6379", "27017"
    }

    if any(port in risky_ports for port in ports):

        risk = "High"
        reason = "Potentially sensitive services are exposed."

    elif ports:

        risk = "Medium"
        reason = "Open ports were detected."

    else:

        risk = "Low"
        reason = "No open ports were detected by this scan."

    return {
        "count": len(ports),
        "ports": ports,
        "services": list(set(services)),
        "versions": versions,
        "risk": risk,
        "reason": reason
    }


def run_nmap(domain, profile):
    """
    Run Nmap once and generate two output formats:

    1. Normal output (-oN): readable output for reports.
    2. XML output (-oX -): structured output for internal parsing.

    The function returns a dictionary so that the XML and
    normal output can be handled independently.

    XML is never saved as the displayed Nmap report.
    """

    result_data = {
        "xml": "",
        "normal": "",
        "error": "",
        "returncode": None,
        "skipped": False
    }

    nmap_path = find_tool("nmap")

    if not nmap_path:

        message = (
            "Nmap is not installed or "
            "is not available in PATH."
        )

        result_data["normal"] = message
        result_data["error"] = message

        return result_data

    if profile == "safe":

        result_data["normal"] = "Skipped (safe profile)."
        result_data["skipped"] = True

        return result_data

    if profile == "normal":
        port_range = "1-1000"

    elif profile == "advanced":
        port_range = "1-65535"

    else:

        message = "Invalid scan profile."

        result_data["normal"] = message
        result_data["error"] = message

        return result_data

    normal_output_path = None

    try:

        # Create a temporary file for normal Nmap output.
        # Close it before Nmap writes to it (important on Windows).

        file_descriptor, normal_output_path = tempfile.mkstemp(
            prefix="webrecon_nmap_",
            suffix=".txt"
        )

        os.close(file_descriptor)

        command = [
            nmap_path,
            "-sV",
            "-p",
            port_range,
            "--open",
            "-oN",
            normal_output_path,
            "-oX",
            "-",
            domain
        ]

        launch_command = build_command(command)

        process_result = subprocess.run(
            launch_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=NMAP_TIMEOUT,
            shell=False,
            env=os.environ.copy()
        )

        # XML is returned through standard output.
        result_data["xml"] = process_result.stdout or ""

        result_data["returncode"] = process_result.returncode

        # Normal output is read from the temporary file.
        if os.path.exists(normal_output_path):

            with open(
                normal_output_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:

                result_data["normal"] = file.read().strip()

        stderr_output = (
            process_result.stderr or ""
        ).strip()

        if stderr_output:

            result_data["error"] = stderr_output

            if result_data["normal"]:
                result_data["normal"] += (
                    "\n\nNmap messages:\n" + stderr_output
                )
            else:
                result_data["normal"] = stderr_output

        # Handle unsuccessful Nmap execution.

        if process_result.returncode != 0:

            message = (
                f"Nmap exited with code "
                f"{process_result.returncode}."
            )

            if result_data["error"]:
                result_data["error"] = (
                    message + "\n" + result_data["error"]
                )
            else:
                result_data["error"] = message

            if not result_data["normal"]:
                result_data["normal"] = message

        # Handle a scan that produced no normal output.

        if not result_data["normal"]:

            result_data["normal"] = (
                "Nmap completed but did not produce normal output."
            )

        return result_data

    except subprocess.TimeoutExpired as exc:

        partial_xml = exc.stdout or ""

        if isinstance(partial_xml, bytes):
            partial_xml = partial_xml.decode(
                "utf-8",
                errors="replace"
            )

        result_data["xml"] = partial_xml

        message = (
            f"Nmap scan timed out after "
            f"{NMAP_TIMEOUT} seconds."
        )

        result_data["error"] = message

        if normal_output_path and os.path.exists(normal_output_path):

            try:

                with open(
                    normal_output_path,
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as file:

                    result_data["normal"] = file.read().strip()

            except OSError:
                pass

        if result_data["normal"]:
            result_data["normal"] += "\n\n" + message
        else:
            result_data["normal"] = message

        return result_data

    except FileNotFoundError:

        message = "Nmap executable could not be found."

        result_data["normal"] = message
        result_data["error"] = message

        return result_data

    except Exception as exc:

        message = f"Error running Nmap: {exc}"

        result_data["normal"] = message
        result_data["error"] = message

        return result_data

    finally:

        # Always remove the temporary normal-output file.

        if normal_output_path and os.path.exists(normal_output_path):

            try:
                os.remove(normal_output_path)
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


def socket_scan(domain):

    def check(subdomain):

        host = f"{subdomain}.{domain}"

        try:

            socket.getaddrinfo(
                host,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )

            return host

        except socket.gaierror:
            return None

        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:

        results = executor.map(
            check,
            FALLBACK_SUBDOMAINS
        )

    return sorted(
        set(result for result in results if result)
    )


def gobuster_scan(domain, profile):

    gobuster_path = find_tool("gobuster")

    if not gobuster_path:
        return []

    wordlist = get_wordlist(profile)

    if not wordlist:
        return []

    command = [
        gobuster_path,
        "dns",
        "-d",
        domain,
        "-w",
        wordlist,
        "-t",
        "30",
        "--timeout",
        "5s",
        "-q",
        "--no-color"
    ]

    output = run_command(
        command,
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

        line = line.strip()

        match = re.search(
            r"(?:Found:\s*)?([a-zA-Z0-9.-]+\." +
            re.escape(domain) + r")",
            line,
            re.IGNORECASE
        )

        if match:
            found.append(match.group(1).lower())

    return sorted(set(found))


def get_subdomains(domain, profile):

    results = []

    if tool_installed("gobuster") and get_wordlist(profile):

        results = gobuster_scan(domain, profile)

    if not results:
        results = socket_scan(domain)

    return sorted(set(results))


# ============================================================
# CVE LOOKUP
# ============================================================

cve_cache = {}
cve_lock = threading.Lock()


def legacy_cpe_to_23(cpe):
    """
    Convert a legacy Nmap CPE URI into CPE 2.3 format.
    """

    if not cpe:
        return None

    cpe = cpe.strip()

    if cpe.startswith("cpe:2.3:"):
        return cpe

    if not cpe.startswith("cpe:/"):
        return None

    parts = cpe[5:].split(":")

    if len(parts) < 3:
        return None

    while len(parts) < 11:
        parts.append("*")

    parts = parts[:11]

    return "cpe:2.3:" + ":".join(parts)


def extract_vulnerable_cpe_matches(node):
    """
    Recursively extract vulnerable CPE match entries
    from an NVD CVE configuration structure.
    """

    matches = []

    if isinstance(node, dict):

        cpe_match = node.get("cpeMatch", [])

        if isinstance(cpe_match, list):

            for item in cpe_match:

                if item.get("vulnerable") is True:
                    matches.append(item)

        for value in node.values():

            if isinstance(value, (dict, list)):
                matches.extend(
                    extract_vulnerable_cpe_matches(value)
                )

    elif isinstance(node, list):

        for item in node:

            matches.extend(
                extract_vulnerable_cpe_matches(item)
            )

    return matches


def fetch_cves_for_cpe(cpe23, service="unknown"):
    """
    Query NVD using a specific CPE.

    Does not use generic keyword searches.
    """

    if not cpe23:
        return []

    with cve_lock:

        if cpe23 in cve_cache:
            return cve_cache[cpe23]

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:

        response = requests.get(
            NVD_API_URL,
            params={
                "cpeName": cpe23,
                "resultsPerPage": 100
            },
            headers=headers,
            timeout=25
        )

        if response.status_code != 200:
            return []

        vulnerabilities = response.json().get(
            "vulnerabilities",
            []
        )

        found = []

        for item in vulnerabilities:

            cve = item.get("cve", {})

            cid = cve.get("id", "")

            if not cid:
                continue

            vulnerable_matches = extract_vulnerable_cpe_matches(
                cve.get("configurations", [])
            )

            if not vulnerable_matches:
                continue

            severity = "N/A"
            score = "N/A"

            metrics = cve.get("metrics", {})

            for key in (
                "cvssMetricV40",
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2"
            ):

                entries = metrics.get(key, [])

                if not entries:
                    continue

                data = entries[0].get("cvssData", {})

                severity = data.get(
                    "baseSeverity",
                    severity
                )

                score = data.get(
                    "baseScore",
                    score
                )

                if severity == "N/A" and score != "N/A":

                    try:
                        numeric_score = float(score)

                        if numeric_score >= 9:
                            severity = "CRITICAL"
                        elif numeric_score >= 7:
                            severity = "HIGH"
                        elif numeric_score >= 4:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"

                    except (TypeError, ValueError):
                        pass

                break

            description = next(
                (
                    desc.get("value", "")
                    for desc in cve.get("descriptions", [])
                    if desc.get("lang") == "en"
                ),
                "No description available."
            )

            found.append({
                "id": cid,
                "service": service,
                "cpe": cpe23,
                "severity": severity,
                "score": score,
                "desc": description[:300],
                "url": (
                    f"https://nvd.nist.gov/vuln/detail/{cid}"
                )
            })

        with cve_lock:
            cve_cache[cpe23] = found

        return found

    except requests.RequestException:
        return []

    except (ValueError, KeyError, TypeError):
        return []

    except Exception:
        return []


def get_cves(versions):
    """
    Collect CVEs from detected software CPEs.
    """

    if not versions:
        return []

    targets = {}

    for item in versions:

        service = item.get("service", "unknown")

        for raw_cpe in item.get("cpes", []):

            cpe23 = legacy_cpe_to_23(raw_cpe)

            if cpe23:
                targets[cpe23] = service

    if not targets:
        return []

    result = []

    with ThreadPoolExecutor(max_workers=3) as executor:

        futures = [
            executor.submit(
                fetch_cves_for_cpe,
                cpe,
                service
            )
            for cpe, service in targets.items()
        ]

        for future in futures:

            try:
                result.extend(future.result())
            except Exception:
                continue

    unique = {}

    for item in result:

        key = item.get("id")

        if key and key not in unique:
            unique[key] = item

    return list(unique.values())


# ============================================================
# SECURITY INTELLIGENCE
# ============================================================

PORT_INTEL = {
    "21": {
        "name": "FTP",
        "risk": "High",
        "explanation": "FTP may transmit credentials and data without encryption.",
        "attack": "Credential sniffing, brute force, anonymous access",
        "recommendation": "Disable FTP where possible and use SFTP or FTPS."
    },
    "22": {
        "name": "SSH",
        "risk": "Medium",
        "explanation": "Exposed SSH services may be targeted by automated login attacks.",
        "attack": "Brute force, password spraying",
        "recommendation": "Use SSH keys, disable password login where practical, and restrict access."
    },
    "23": {
        "name": "Telnet",
        "risk": "Critical",
        "explanation": "Telnet transmits credentials and commands without encryption.",
        "attack": "Credential interception, session hijacking",
        "recommendation": "Disable Telnet and use SSH."
    },
    "25": {
        "name": "SMTP",
        "risk": "Medium",
        "explanation": "An improperly configured SMTP server may be abused for spam or email spoofing.",
        "attack": "Open relay abuse, phishing",
        "recommendation": "Restrict relaying and configure SPF, DKIM and DMARC."
    },
    "80": {
        "name": "HTTP",
        "risk": "Low",
        "explanation": "HTTP traffic is not encrypted.",
        "attack": "Traffic interception, content injection",
        "recommendation": "Redirect HTTP traffic to HTTPS."
    },
    "443": {
        "name": "HTTPS",
        "risk": "Info",
        "explanation": "HTTPS is expected for public websites. TLS configuration should still be reviewed.",
        "attack": "Weak TLS configuration",
        "recommendation": "Use modern TLS versions and secure cipher suites."
    },
    "445": {
        "name": "SMB",
        "risk": "Critical",
        "explanation": "Publicly exposed SMB services can expose file-sharing infrastructure.",
        "attack": "Remote exploitation, credential theft",
        "recommendation": "Block public SMB access."
    },
    "1433": {
        "name": "MSSQL",
        "risk": "Critical",
        "explanation": "Direct database exposure increases the risk of unauthorised access.",
        "attack": "Brute force, data theft",
        "recommendation": "Restrict database access to trusted networks."
    },
    "3306": {
        "name": "MySQL",
        "risk": "Critical",
        "explanation": "Public database access can expose sensitive records.",
        "attack": "Brute force, data exfiltration",
        "recommendation": "Restrict MySQL to trusted interfaces."
    },
    "3389": {
        "name": "RDP",
        "risk": "Critical",
        "explanation": "Exposed Remote Desktop services are common targets for attackers.",
        "attack": "Brute force, remote exploitation",
        "recommendation": "Place RDP behind a VPN and enforce strong authentication."
    },
    "5432": {
        "name": "PostgreSQL",
        "risk": "Critical",
        "explanation": "Public database access can expose stored information.",
        "attack": "Brute force, data theft",
        "recommendation": "Restrict PostgreSQL to trusted networks."
    },
    "6379": {
        "name": "Redis",
        "risk": "Critical",
        "explanation": "An exposed Redis instance may allow unauthorised access to cached data.",
        "attack": "Unauthorised access, data theft",
        "recommendation": "Require authentication and restrict network access."
    },
    "8080": {
        "name": "HTTP Alternate",
        "risk": "Medium",
        "explanation": "Alternative HTTP ports may expose development or administrative services.",
        "attack": "Default credentials, information disclosure",
        "recommendation": "Identify the service and restrict access where necessary."
    },
    "27017": {
        "name": "MongoDB",
        "risk": "Critical",
        "explanation": "An exposed MongoDB service may allow unauthorised database access.",
        "attack": "Data theft, unauthorised database access",
        "recommendation": "Enable authentication and restrict network access."
    }
}


TECH_INTEL = {
    "wordpress": (
        "Medium",
        "WordPress installations should be kept updated.",
        "Update WordPress, themes and plugins."
    ),
    "drupal": (
        "Medium",
        "Outdated Drupal installations may contain known vulnerabilities.",
        "Update Drupal core and modules."
    ),
    "joomla": (
        "Medium",
        "Outdated Joomla installations may contain known vulnerabilities.",
        "Update Joomla and its extensions."
    ),
    "apache": (
        "Low",
        "Server version disclosure can help attackers identify software versions.",
        "Keep Apache updated and minimise version disclosure."
    ),
    "nginx": (
        "Low",
        "Server version disclosure can assist targeted reconnaissance.",
        "Keep Nginx updated and minimise version disclosure."
    ),
    "iis": (
        "Low",
        "IIS version disclosure may reveal server information.",
        "Keep IIS updated and review exposed headers."
    ),
    "php": (
        "Medium",
        "Outdated PHP versions may contain known security vulnerabilities.",
        "Use a supported PHP version."
    ),
    "jquery": (
        "Low",
        "Outdated jQuery versions may contain known vulnerabilities.",
        "Update jQuery to a supported release."
    ),
    "bootstrap": (
        "Info",
        "Bootstrap version information was detected.",
        "Review the version and update when necessary."
    ),
    "httpserver": (
        "Low",
        "The Server header may reveal server software information.",
        "Review and minimise server version disclosure."
    )
}


HEADER_INTEL = {
    "content-security-policy": {
        "explanation": "No Content-Security-Policy header was detected.",
        "attack": "May increase exposure to certain cross-site scripting attacks.",
        "recommendation": "Define a suitable Content-Security-Policy for your application."
    },
    "x-frame-options": {
        "explanation": "No X-Frame-Options header was detected.",
        "attack": "Clickjacking may be possible if framing is not otherwise restricted.",
        "recommendation": "Use X-Frame-Options: DENY or SAMEORIGIN, or an appropriate CSP frame-ancestors policy."
    },
    "x-content-type-options": {
        "explanation": "No X-Content-Type-Options header was detected.",
        "attack": "MIME type sniffing may create additional risk.",
        "recommendation": "Add X-Content-Type-Options: nosniff."
    },
    "strict-transport-security": {
        "explanation": "No HSTS header was detected.",
        "attack": "Users may be more exposed to protocol downgrade attacks.",
        "recommendation": "Configure Strict-Transport-Security after confirming HTTPS works correctly."
    },
    "referrer-policy": {
        "explanation": "No Referrer-Policy header was detected.",
        "attack": "Referrer information may disclose more URL data than intended.",
        "recommendation": "Consider strict-origin-when-cross-origin."
    },
    "permissions-policy": {
        "explanation": "No Permissions-Policy header was detected.",
        "attack": "Browser features may not be explicitly restricted.",
        "recommendation": "Restrict browser features that your application does not need."
    }
}


# ============================================================
# PORT ANALYSIS
# ============================================================

def analyse_ports(nmap_result):

    findings = []

    for item in nmap_result.get("versions", []):

        port = item["port"]
        service = item["service"]
        version = item["version"]

        intel = PORT_INTEL.get(port)

        if intel:

            explanation = intel["explanation"]

            if version:
                explanation += f" Detected version: {version}."

            findings.append({
                "source": "Nmap",
                "type": "open_port",
                "title": f"Port {port} Open — {intel['name']}",
                "risk": intel["risk"],
                "explanation": explanation,
                "attack": intel["attack"],
                "recommendation": intel["recommendation"],
                "version": version
            })

        else:

            findings.append({
                "source": "Nmap",
                "type": "open_port",
                "title": f"Port {port} Open ({service})",
                "risk": "Low",
                "explanation": f"Port {port} is open and running {service}.",
                "attack": "Service exploitation, information disclosure",
                "recommendation": "Confirm that the service is required and properly secured.",
                "version": version
            })

    return findings


# ============================================================
# WHATWEB ANALYSIS
# ============================================================

def analyse_whatweb(output):

    findings = []

    if not output:
        return findings

    lower_output = output.lower()

    if any(
        message in lower_output
        for message in (
            "not installed",
            "could not be found",
            "could not retrieve usable results"
        )
    ):
        return findings

    for technology, intel in TECH_INTEL.items():

        if technology not in lower_output:
            continue

        risk, explanation, recommendation = intel

        findings.append({
            "source": "WhatWeb",
            "type": "technology",
            "title": f"Detected: {technology.replace('-', ' ').title()}",
            "risk": risk,
            "explanation": explanation,
            "recommendation": recommendation
        })

    return findings


# ============================================================
# HTTP SECURITY HEADER ANALYSIS
# ============================================================

def analyse_http_headers(domain):
    """
    Retrieve real HTTP response headers.

    HTTPS is attempted first. HTTP is attempted only if HTTPS
    cannot be reached.

    HSTS is assessed only when the final response uses HTTPS.
    """

    findings = []

    response = None

    urls = [
        f"https://{domain}",
        f"http://{domain}"
    ]

    for url in urls:

        try:

            response = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                headers={
                    "User-Agent": "WebRecon-Security-Scanner/1.0"
                }
            )

            break

        except requests.RequestException:
            continue

    if response is None:
        return findings

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    is_https = response.url.lower().startswith("https://")

    for header, intel in HEADER_INTEL.items():

        if header == "strict-transport-security" and not is_https:
            continue

        if header not in headers:

            findings.append({
                "source": "Headers",
                "type": "missing_header",
                "title": (
                    f"Missing Security Header: "
                    f"{header.title()}"
                ),
                "risk": "Medium",
                "explanation": intel["explanation"],
                "attack": intel["attack"],
                "recommendation": intel["recommendation"]
            })

    for header in ("x-powered-by", "x-aspnet-version"):

        if header in headers:

            findings.append({
                "source": "Headers",
                "type": "information_disclosure",
                "title": f"Technology Disclosure: {header.title()}",
                "risk": "Low",
                "explanation": (
                    f"The response exposes the {header} header."
                ),
                "attack": "Technology fingerprinting",
                "recommendation": (
                    "Remove unnecessary technology and version disclosure headers."
                )
            })

    return findings


# ============================================================
# WHOIS ANALYSIS
# ============================================================

def analyse_whois(output, domain):

    findings = []

    if not output:
        return findings

    lower_output = output.lower()

    if (
        "not installed" in lower_output
        or "could not be found" in lower_output
    ):
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

        match = re.search(
            pattern,
            output,
            re.IGNORECASE
        )

        if match:

            expiry_value = match.group(1).strip()
            break

    if expiry_value:

        try:

            from dateutil import parser as dateparser

            expiry_date = dateparser.parse(
                expiry_value,
                ignoretz=True
            )

            days_left = (
                expiry_date - datetime.utcnow()
            ).days

            if days_left < 0:

                risk = "Critical"
                title = "Domain Expired"
                recommendation = (
                    "Check the registrar and renew the domain immediately."
                )

            elif days_left <= 7:

                risk = "Critical"
                title = f"Domain Expires in {days_left} Days"
                recommendation = "Renew the domain immediately."

            elif days_left <= 30:

                risk = "High"
                title = f"Domain Expires in {days_left} Days"
                recommendation = "Renew the domain soon."

            elif days_left <= 90:

                risk = "Low"
                title = f"Domain Expires in {days_left} Days"
                recommendation = (
                    "Plan the renewal and check auto-renewal settings."
                )

            else:

                risk = "Info"
                title = (
                    f"Domain Valid — {days_left} Days Remaining"
                )
                recommendation = (
                    "Ensure domain auto-renewal is enabled."
                )

            findings.append({
                "source": "WHOIS",
                "type": "domain_expiry",
                "title": title,
                "risk": risk,
                "explanation": (
                    f"{domain} has a reported expiry date "
                    f"of {expiry_date.date()}."
                ),
                "recommendation": recommendation,
                "expiry_date": str(expiry_date.date()),
                "days_left": days_left
            })

        except Exception:
            pass

    privacy_phrases = [
        "redacted for privacy",
        "data redacted",
        "data protected",
        "privacy service",
        "whois privacy",
        "registration private",
        "not disclosed",
        "masked for privacy"
    ]

    privacy_enabled = any(
        phrase in lower_output
        for phrase in privacy_phrases
    )

    if privacy_enabled:

        findings.append({
            "source": "WHOIS",
            "type": "whois_privacy",
            "title": "WHOIS Privacy Enabled",
            "risk": "Info",
            "explanation": (
                "Registrant information appears to be protected "
                "or redacted."
            ),
            "recommendation": (
                "Continue using appropriate domain registration privacy protection."
            )
        })

    else:

        registrant_email = re.search(
            r"(?im)^\s*(?:registrant|owner)\s+"
            r"(?:e-?mail|email address)\s*:\s*([^\s]+)",
            output
        )

        if registrant_email:

            email_value = registrant_email.group(1).strip()

            excluded_values = (
                "redacted",
                "privacy",
                "protected",
                "not disclosed",
                "data unavailable"
            )

            if not any(
                value in email_value.lower()
                for value in excluded_values
            ):

                findings.append({
                    "source": "WHOIS",
                    "type": "whois_exposure",
                    "title": "Registrant Email May Be Exposed",
                    "risk": "Low",
                    "explanation": (
                        "An email address was found in the "
                        "registrant contact field."
                    ),
                    "attack": "Phishing, spam and social engineering",
                    "recommendation": (
                        "Review whether the registrant contact "
                        "information should be publicly visible."
                    )
                })

    return findings


# ============================================================
# DNS ANALYSIS
# ============================================================

def analyse_dns(output, domain):

    findings = []

    if not output:
        return findings

    text = output.lower()

    if "wildcard" in text:

        findings.append({
            "source": "DNS",
            "type": "misconfiguration",
            "title": "Wildcard DNS Record Detected",
            "risk": "Medium",
            "explanation": (
                "Wildcard DNS information was detected in the DNS output."
            ),
            "attack": "Phishing using misleading subdomains",
            "recommendation": (
                "Review whether wildcard DNS records are required."
            )
        })

    if tool_installed("dig"):

        dig_path = find_tool("dig")

        axfr = run_command(
            [
                dig_path,
                "AXFR",
                domain,
                f"@{domain}"
            ],
            timeout=20
        )

        if (
            "Transfer failed" not in axfr
            and "connection timed out" not in axfr.lower()
            and "not installed" not in axfr.lower()
            and "timed out" not in axfr.lower()
            and "XFR size" in axfr
        ):

            findings.append({
                "source": "DNS",
                "type": "misconfiguration",
                "title": "DNS Zone Transfer May Be Enabled",
                "risk": "High",
                "explanation": (
                    "The DNS server appears to have returned "
                    "zone transfer data."
                ),
                "attack": "DNS information disclosure",
                "recommendation": (
                    "Restrict zone transfers to authorised "
                    "secondary nameservers."
                )
            })

    return findings


# ============================================================
# SUBDOMAIN ANALYSIS
# ============================================================

def analyse_subdomains(subdomains, domain):

    findings = []

    sensitive = {
        "admin": ("Administrative Subdomain Detected", "High"),
        "vpn": ("VPN Subdomain Detected", "High"),
        "dev": ("Development Subdomain Detected", "High"),
        "staging": ("Staging Subdomain Detected", "High"),
        "test": ("Test Subdomain Detected", "Medium"),
        "jenkins": ("Jenkins Subdomain Detected", "Critical"),
        "gitlab": ("GitLab Subdomain Detected", "High"),
        "git": ("Git Service Subdomain Detected", "High"),
        "jira": ("Jira Subdomain Detected", "Medium"),
        "confluence": ("Confluence Subdomain Detected", "Medium"),
        "ftp": ("FTP Subdomain Detected", "Medium"),
        "db": ("Database Subdomain Detected", "Critical"),
        "database": ("Database Subdomain Detected", "Critical")
    }

    flagged = set()

    for subdomain in subdomains:

        label = subdomain.split(".")[0].lower()

        for keyword, (title, risk) in sensitive.items():

            if keyword in label and keyword not in flagged:

                flagged.add(keyword)

                findings.append({
                    "source": "Subdomains",
                    "type": "sensitive_subdomain",
                    "title": f"{title}: {subdomain}",
                    "risk": risk,
                    "explanation": (
                        f"The subdomain {subdomain} was discovered. "
                        "Its purpose and access controls should be reviewed."
                    ),
                    "attack": (
                        "Targeted reconnaissance and unauthorised access"
                    ),
                    "recommendation": (
                        "Confirm that the subdomain is intended to be public. "
                        "Restrict access where appropriate."
                    )
                })

    return findings


# ============================================================
# CVE FINDINGS
# ============================================================

def cve_findings(cve_list):

    findings = []
    seen = set()

    for cve in cve_list:

        cid = cve.get("id", "")

        if not cid or cid in seen:
            continue

        seen.add(cid)

        try:
            score = float(cve.get("score", 0) or 0)
        except (ValueError, TypeError):
            score = 0

        if score >= 9:
            risk = "Critical"

        elif score >= 7:
            risk = "High"

        elif score >= 4:
            risk = "Medium"

        else:
            continue

        findings.append({
            "source": "CVE",
            "type": "cve",
            "title": (
                f"{risk} CVE: {cid} "
                f"({cve.get('service', '')})"
            ),
            "risk": risk,
            "explanation": cve.get(
                "desc",
                "No description available."
            ),
            "attack": f"CVSS score: {score}",
            "recommendation": (
                f"Review the affected software and vendor advisory: "
                f"{cve.get('url', '')}"
            ),
            "cpe": cve.get("cpe", "")
        })

    return findings


# ============================================================
# OVERALL INTELLIGENCE
# ============================================================

def run_intelligence(
    domain,
    nmap_result,
    whatweb_output,
    whois_output,
    dns_output,
    subdomains,
    cve_list
):

    findings = []

    findings.extend(
        analyse_ports(nmap_result)
    )

    findings.extend(
        analyse_whatweb(whatweb_output)
    )

    findings.extend(
        analyse_http_headers(domain)
    )

    findings.extend(
        analyse_whois(whois_output, domain)
    )

    findings.extend(
        analyse_dns(dns_output, domain)
    )

    findings.extend(
        analyse_subdomains(subdomains, domain)
    )

    findings.extend(
        cve_findings(cve_list)
    )

    risk_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info"
    ]

    risk_label = "Low"

    for level in risk_order:

        if any(
            item.get("risk") == level
            for item in findings
        ):

            risk_label = level
            break

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    for item in findings:

        level = item.get("risk", "Info")

        if level in severity_counts:
            severity_counts[level] += 1

    return {
        "findings": findings,
        "risk_label": risk_label,
        "severity_counts": severity_counts,
        "total_findings": len(findings)
    }


# ============================================================
# REPORT GENERATION
# ============================================================

def save_txt(scan, filename, intel):

    path = REPORTS_DIR / filename

    with open(path, "w", encoding="utf-8") as file:

        file.write(
            f"WEBRECON SECURITY REPORT — {scan.domain}\n"
        )

        file.write("=" * 60 + "\n\n")

        file.write(f"IP: {scan.ip}\n")
        file.write(f"Profile: {scan.profile}\n")
        file.write(f"Risk Level: {intel['risk_label']}\n")
        file.write(f"Findings: {intel['total_findings']}\n")
        file.write(f"Time: {scan.ran_at}\n\n")

        file.write("FINDINGS\n")
        file.write("-" * 40 + "\n")

        for finding in intel["findings"]:

            file.write(
                f"\n[{finding['risk']}] {finding['title']}\n"
            )

            file.write(
                f"Source: {finding['source']}\n"
            )

            file.write(
                f"Explanation: {finding['explanation']}\n"
            )

            if finding.get("attack"):
                file.write(
                    f"Attack: {finding['attack']}\n"
                )

            file.write(
                f"Recommendation: {finding['recommendation']}\n"
            )

        file.write("\nRAW SCAN DATA\n")
        file.write("-" * 40 + "\n")

        file.write(
            f"\nDNS\n{scan.dns or ''}\n"
        )

        file.write(
            f"\nNMAP\n{scan.nmap or ''}\n"
        )

        file.write(
            f"\nWHATWEB\n{scan.whatweb or ''}\n"
        )

        file.write(
            f"\nWHOIS\n{scan.whois or ''}\n"
        )

        file.write(
            f"\nSUBDOMAINS\n{scan.subdomains or 'None'}\n"
        )

        file.write(
            f"\nCVE DATA\n{scan.cves or '[]'}\n"
        )

    return filename


def save_html(scan, filename, intel):

    path = REPORTS_DIR / filename

    def esc(value):
        return html.escape(str(value or ""))

    risk_colors = {
        "Critical": "#E74C3C",
        "High": "#E67E22",
        "Medium": "#F39C12",
        "Low": "#27AE60",
        "Info": "#3498DB"
    }

    risk_label = intel["risk_label"]

    label_color = risk_colors.get(
        risk_label,
        "#888"
    )

    findings_html = ""

    for finding in intel["findings"]:

        risk = finding.get("risk", "Info")

        color = risk_colors.get(
            risk,
            "#888"
        )

        attack_row = ""

        if finding.get("attack"):

            attack_row = (
                "<tr><td><b>Attack types</b></td>"
                f"<td>{esc(finding.get('attack'))}</td></tr>"
            )

        cpe_row = ""

        if finding.get("cpe"):

            cpe_row = (
                "<tr><td><b>CPE</b></td>"
                f"<td>{esc(finding.get('cpe'))}</td></tr>"
            )

        findings_html += f"""
        <div class="finding">

            <div class="finding-header"
                 style="border-left:4px solid {color}">

                <span class="badge"
                      style="background:{color}">
                    {esc(risk)}
                </span>

                <b>{esc(finding.get('title'))}</b>

                <span class="source-tag">
                    {esc(finding.get('source'))}
                </span>

            </div>

            <table class="finding-table">

                <tr>
                    <td><b>Explanation</b></td>
                    <td>{esc(finding.get('explanation'))}</td>
                </tr>

                {attack_row}

                {cpe_row}

                <tr>
                    <td><b>Fix</b></td>
                    <td>{esc(finding.get('recommendation'))}</td>
                </tr>

            </table>

        </div>
        """

    counts = intel["severity_counts"]

    raw_sections = {
        "DNS": scan.dns,
        "Nmap": scan.nmap,
        "WhatWeb": scan.whatweb,
        "WHOIS": scan.whois,
        "Subdomains": scan.subdomains,
        "CVE Data": scan.cves
    }

    raw_html = ""

    for name, value in raw_sections.items():

        raw_html += f"""
        <h3>{esc(name)}</h3>
        <pre>{esc(value)}</pre>
        """

    report = f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Security Report — {esc(scan.domain)}</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #0f1117;
    color: #ccc;
}}

h1 {{
    color: #fff;
}}

h2 {{
    color: #3B9EE8;
    border-bottom: 1px solid #333;
    padding-bottom: 8px;
}}

.risk-label {{
    display: inline-block;
    padding: 8px 20px;
    font-size: 1.4rem;
    font-weight: bold;
    border-radius: 6px;
    color: #fff;
    background: {label_color};
}}

.finding {{
    background: #161b22;
    border-radius: 6px;
    margin: 12px 0;
    overflow: hidden;
}}

.finding-header {{
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    background: #1a2130;
    flex-wrap: wrap;
}}

.badge {{
    padding: 3px 8px;
    border-radius: 4px;
    color: #fff;
    font-size: 12px;
    font-weight: bold;
}}

.source-tag {{
    margin-left: auto;
    font-size: 11px;
    color: #aaa;
}}

.finding-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

.finding-table td {{
    padding: 10px 16px;
    border-bottom: 1px solid #222;
    vertical-align: top;
    overflow-wrap: anywhere;
}}

.finding-table td:first-child {{
    width: 120px;
    color: #aaa;
}}

.sev-grid {{
    display: grid;
    grid-template-columns: repeat(
        auto-fit,
        minmax(100px, 1fr)
    );
    gap: 10px;
    margin: 16px 0;
}}

.sev-card {{
    text-align: center;
    padding: 12px;
    border-radius: 6px;
    background: #161b22;
}}

.sev-card .num {{
    font-size: 1.8rem;
    font-weight: bold;
}}

pre {{
    background: #161b22;
    padding: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-size: 12px;
    border-radius: 4px;
}}

@media(max-width: 600px) {{
    body {{
        margin: 15px;
    }}
}}

</style>

</head>

<body>

<h1>Security Report — {esc(scan.domain)}</h1>

<p>
IP: {esc(scan.ip)} |
Profile: {esc(scan.profile)} |
Scanned: {esc(scan.ran_at)}
</p>

<h2>Overall Risk</h2>

<div class="risk-label">
    {esc(risk_label)}
</div>

<p>{intel['total_findings']} findings</p>

<div class="sev-grid">

    <div class="sev-card">
        <div class="num" style="color:#E74C3C">
            {counts['Critical']}
        </div>
        <div>Critical</div>
    </div>

    <div class="sev-card">
        <div class="num" style="color:#E67E22">
            {counts['High']}
        </div>
        <div>High</div>
    </div>

    <div class="sev-card">
        <div class="num" style="color:#F39C12">
            {counts['Medium']}
        </div>
        <div>Medium</div>
    </div>

    <div class="sev-card">
        <div class="num" style="color:#27AE60">
            {counts['Low']}
        </div>
        <div>Low</div>
    </div>

    <div class="sev-card">
        <div class="num" style="color:#3498DB">
            {counts['Info']}
        </div>
        <div>Info</div>
    </div>

</div>

<h2>Findings ({intel['total_findings']})</h2>

{findings_html}

<h2>Raw Scan Data</h2>

{raw_html}

</body>
</html>
"""

    with open(path, "w", encoding="utf-8") as file:
        file.write(report)

    return filename


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        if not username or not password:

            flash(
                "Fill in both fields.",
                "danger"
            )

            return redirect(url_for("register"))

        if len(username) > 80:

            flash(
                "Username is too long.",
                "danger"
            )

            return redirect(url_for("register"))

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )

            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():

            flash(
                "That username is already taken.",
                "danger"
            )

            return redirect(url_for("register"))

        user = User(username=username)

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash(
            "Account created. Log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template(
        "auth.html",
        mode="register"
    )


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        user = User.query.filter_by(
            username=username
        ).first()

        if user and user.check_password(password):

            session.clear()

            session["uid"] = user.id

            return redirect(url_for("index"))

        flash(
            "Wrong username or password.",
            "danger"
        )

    return render_template(
        "auth.html",
        mode="login"
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# MAIN SCAN ROUTE
# ============================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    user = get_user()

    data = {}
    error = None

    if request.method == "POST":

        domain = request.form.get(
            "domain",
            ""
        ).strip().lower()

        profile = request.form.get(
            "profile",
            "safe"
        ).lower()

        if not valid_domain(domain):

            error = "Invalid domain."

        elif profile not in {
            "safe",
            "normal",
            "advanced"
        }:

            error = "Invalid scan profile."

        else:

            ip = resolve_ip(domain)

            dns_output = get_dns(domain)

            # Run independent scan modules concurrently.

            with ThreadPoolExecutor(max_workers=4) as executor:

                whois_future = executor.submit(
                    run_whois,
                    domain
                )

                whatweb_future = executor.submit(
                    run_whatweb,
                    domain
                )

                subdomains_future = executor.submit(
                    get_subdomains,
                    domain,
                    profile
                )

                nmap_future = executor.submit(
                    run_nmap,
                    domain,
                    profile
                )

                whois_output = whois_future.result()

                whatweb_output = whatweb_future.result()

                subdomains = subdomains_future.result()

                # Nmap now returns both XML and normal output.

                nmap_run = nmap_future.result()

            # XML is used internally for parsing and CVE detection.

            nmap_xml = nmap_run["xml"]

            # Normal Nmap output is used in reports and database.

            nmap_display = nmap_run["normal"]

            nmap_result = parse_nmap(nmap_xml)

            # Determine whether Nmap failed.

            nmap_failed = (
                not nmap_xml.strip()
                or nmap_run.get("returncode") != 0
                or bool(nmap_run.get("error"))
            )

            if nmap_failed:

                nmap_result = {
                    "count": 0,
                    "ports": [],
                    "services": [],
                    "versions": [],
                    "risk": "Info",
                    "reason": (
                        nmap_run.get("error")
                        or nmap_display
                        or "Nmap did not return valid scan results."
                    )
                }

            # Safe profile intentionally skips Nmap.

            if nmap_run.get("skipped"):

                nmap_result = {
                    "count": 0,
                    "ports": [],
                    "services": [],
                    "versions": [],
                    "risk": "Info",
                    "reason": "Nmap skipped because the safe profile was selected."
                }

            # Use detected software CPEs, not generic service names.

            cve_list = get_cves(
                nmap_result["versions"]
            )

            intelligence = run_intelligence(
                domain,
                nmap_result,
                whatweb_output,
                whois_output,
                dns_output,
                subdomains,
                cve_list
            )

            now = datetime.utcnow()

            report_base = (
                f"{domain}_"
                f"{now.strftime('%Y%m%d_%H%M%S_%f')}"
            )

            scan = Scan(
                user_id=user.id,
                domain=domain,
                ip=ip,
                profile=profile,
                risk=intelligence["risk_label"],
                port_count=nmap_result["count"],
                services=", ".join(
                    nmap_result["services"]
                ),
                dns=dns_output,
                whois=whois_output,

                # IMPORTANT:
                # Save normal output, not XML.

                nmap=nmap_display,

                whatweb=whatweb_output,
                cves=json.dumps(cve_list),
                subdomains="\n".join(subdomains),
                intelligence=json.dumps(intelligence),
                report_txt=report_base + ".txt",
                report_html=report_base + ".html",
                ran_at=now
            )

            db.session.add(scan)
            db.session.commit()

            save_txt(
                scan,
                scan.report_txt,
                intelligence
            )

            save_html(
                scan,
                scan.report_html,
                intelligence
            )

            data = {
                "scan": scan,
                "result": nmap_result,
                "cves": cve_list,
                "subs": subdomains,
                "intel": intelligence
            }

    history = (
        Scan.query
        .filter_by(user_id=user.id)
        .order_by(Scan.ran_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "index.html",
        data=data,
        error=error,
        user=user,
        history=history
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = get_user()

    scans = (
        Scan.query
        .filter_by(user_id=user.id)
        .order_by(Scan.ran_at.desc())
        .all()
    )

    risk_counts = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    for scan in scans:

        risk = scan.risk or "Low"

        risk_counts[risk] = (
            risk_counts.get(risk, 0) + 1
        )

    return render_template(
        "dashboard.html",
        user=user,
        scans=scans,
        risk_counts=risk_counts
    )


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
        or_(
            Scan.report_txt == filename,
            Scan.report_html == filename
        )
    ).first()

    if not scan:
        abort(404)

    return scan


@app.route("/report/view/<filename>")
@login_required
def view_report(filename):

    get_owned_report(filename)

    return send_from_directory(
        str(REPORTS_DIR),
        filename
    )


@app.route("/report/download/<filename>")
@login_required
def download_report(filename):

    get_owned_report(filename)

    return send_from_directory(
        str(REPORTS_DIR),
        filename,
        as_attachment=True
    )


# ============================================================
# TOOL STATUS
# ============================================================

@app.route("/tools")
@login_required
def tools_status():

    return {
        "platform": platform.system(),
        "tools": tool_status()
    }


# ============================================================
# INITIALISE DATABASE
# ============================================================

with app.app_context():
    db.create_all()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    debug_mode = (
        os.environ.get("FLASK_DEBUG", "1") == "1"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=debug_mode
    )
