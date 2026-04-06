import os
from flask import Flask, render_template, request, send_from_directory
import subprocess
import re
from datetime import datetime

app = Flask(__name__)

# -----------------------------
# Report folder (single folder)
# -----------------------------
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# -----------------------------
# Utility: Run system commands
# -----------------------------
def run(cmd):
    try:
        result = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except FileNotFoundError:
        return "Required tool not installed or not in PATH."

# -----------------------------
# Target validation
# -----------------------------
def validate_domain(domain):
    pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain)

# -----------------------------
# Extract IP from nslookup
# -----------------------------
def extract_ip(dns_output):
    lines = dns_output.splitlines()
    for i, line in enumerate(lines):
        if "Non-authoritative answer" in line:
            # The real IP is usually 2 lines below
            for next_line in lines[i+1:]:
                if "Address:" in next_line and "#53" not in next_line:
                    return next_line.split()[-1]
    return ""

# -----------------------------
# Analyze Nmap output (summary)
# -----------------------------
def analyze_nmap(nmap_output):
    ports = []
    services = []

    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            ports.append(parts[0])
            services.append(parts[2])

    risk = "Low"
    reason = "Only common public services detected."

    sensitive_ports = ["22", "3306", "3389"]
    for p in ports:
        if any(p.startswith(sp) for sp in sensitive_ports):
            risk = "Medium"
            reason = "Sensitive service ports detected."

    return {
        "open_ports": len(ports),
        "services": ", ".join(set(services)) if services else "None",
        "risk": risk,
        "reason": reason
    }

# -----------------------------
# Report Generators
# -----------------------------
def generate_txt_report(data, filename):
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w") as f:
        f.write("WEB RECON REPORT\n")
        f.write("=" * 40 + "\n\n")
        f.write(f"Target: {data['domain']}\n")
        f.write(f"IP Address: {data['ip']}\n\n")
        f.write("DNS DETAILS\n")
        f.write(data['dns'] + "\n\n")
        f.write("OPEN PORTS\n")
        f.write(data['nmap'] + "\n\n")
        f.write("WEB TECHNOLOGIES\n")
        f.write(data['whatweb'] + "\n\n")
        f.write("CONCLUSION\n")
        f.write("No critical exposure detected.\n")

    return filename

def generate_html_report(data, filename):
    path = os.path.join(REPORT_DIR, filename)

    html = f"""
    <h1>Web Recon Report</h1>
    <h3>{data['domain']}</h3>

    <h4>DNS</h4>
    <pre>{data['dns']}</pre>

    <h4>Nmap</h4>
    <pre>{data['nmap']}</pre>

    <h4>WhatWeb</h4>
    <pre>{data['whatweb']}</pre>
    """

    with open(path, "w") as f:
        f.write(html)

    return filename

# -----------------------------
# Routes
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    data = {}

    if request.method == "POST":
        domain = request.form["domain"].strip()
        profile = request.form.get("profile", "safe")

        if not validate_domain(domain):
            data["error"] = "Invalid domain format."
            return render_template("index.html", data=data)

        # DNS
        dns = run(["nslookup", domain])
        ip = extract_ip(dns)

        # WHOIS
        whois = run(["whois", ip]) if ip else "No IP found."

        # WHATWEB
        whatweb = run(["whatweb", "-v", domain])

        # NMAP based on profile
        nmap = "Skipped (Safe profile)"
        if profile == "normal":
            nmap = run(["nmap", "-sV", "-p", "--min-rate",  "5000", ip]) if ip else "No IP found."
        elif profile == "advanced":
            nmap = run(["nmap", "-p-", "-sV", "--min-rate", "5000", ip]) if ip else "No IP found."

        # Summary
        summary = analyze_nmap(nmap) if "open" in nmap else None

        # Timestamp for unique filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{domain}_{timestamp}"

        txt_file = generate_txt_report(data={"domain": domain, "ip": ip, "dns": dns, "nmap": nmap, "whatweb": whatweb}, filename=base_name + ".txt")
        html_file = generate_html_report(data={"domain": domain, "dns": dns, "nmap": nmap, "whatweb": whatweb}, filename=base_name + ".html")

        data = {
            "domain": domain,
            "ip": ip,
            "dns": dns,
            "whois": whois,
            "whatweb": whatweb,
            "nmap": nmap,
            "summary": summary,
            "profile": profile,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "report_files": {
                "txt": txt_file,
                "html": html_file
            }
        }

    # Past scans
    past_scans = sorted([f for f in os.listdir(REPORT_DIR) if f.endswith(".html")], reverse=True)
    data["past_scans"] = [
        {
            "name": f.replace(".html", ""),
            "html": f"/report/view/{f}",
            "txt": f"/report/download/{f.replace('.html', '.txt')}"
        }
        for f in past_scans
    ]

    return render_template("index.html", data=data)

# -----------------------------
# Serve Reports
# -----------------------------
@app.route("/report/view/<filename>")
def view_report(filename):
    return send_from_directory(REPORT_DIR, filename)

@app.route("/report/download/<filename>")
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)

# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
