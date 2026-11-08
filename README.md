# WebRecon

**A Flask-based web reconnaissance and security assessment tool.**

WebRecon automates the collection of security information about websites and network infrastructure using commonly used reconnaissance and security assessment tools. It brings multiple scanning utilities together in a single web interface and generates reports to help identify potential security weaknesses.

## Features

- **Nmap Scanning:** Discover open ports, running services and service versions.
- **WhatWeb Scanning:** Identify web technologies, frameworks, servers and content management systems.
- **WHOIS Lookup:** Retrieve domain registration and ownership information.
- **Gobuster Scanning:** Discover directories and files exposed by web servers.
- **Vulnerability Intelligence:** Integrate with the National Vulnerability Database (NVD) to retrieve relevant CVE information.
- **Scan Profiles:** Choose between Safe, Normal and Advanced scanning profiles.
- **Automated Reporting:** Generate and access scan reports in TXT and HTML formats.
- **User Authentication:** Register and log in to access the application.
- **Scan Management:** Store and manage scan information using SQLite.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite, Flask-SQLAlchemy |
| Frontend | HTML, CSS, JavaScript |
| HTTP Requests | Requests |
| Port and Service Scanning | Nmap |
| Web Technology Detection | WhatWeb |
| Domain Information | WHOIS |
| Directory Enumeration | Gobuster |
| Vulnerability Intelligence | NVD API |

## Project Structure

```text
Web_Recon1/
│
├── app.py
├── requirements.txt
├── recon.db
├── .gitignore
│
├── install_windows.ps1
├── install_linux.sh
│
├── Templates/
│   └── ...
│
├── static/
│   └── ...
│
└── reports/
```

## Requirements

- Python 3.10 or later
- Git
- Internet connection
- Nmap
- WhatWeb
- WHOIS
- Gobuster

The installation scripts automate the installation and setup of the required dependencies and external reconnaissance tools where supported.

## Installation

### Windows

**1. Clone the repository**

```powershell
git clone https://github.com/Henrykioko/Web_Recon.git
cd Web_Recon
```

**2. Run the installation script**

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Then:

```powershell
.\install_windows.ps1
```

**3. Activate the virtual environment**

If the installer creates a `venv` directory:

```powershell
.\venv\Scripts\Activate.ps1
```

**4. Start the application**

```powershell
python app.py
```

### Linux

**1. Clone the repository**

```bash
git clone https://github.com/Henrykioko/Web_Recon.git
cd Web_Recon
```

**2. Make the installation script executable**

```bash
chmod +x install_linux.sh
```

**3. Run the installer**

```bash
./install_linux.sh
```

**4. Activate the virtual environment**

If the installer creates a `venv` directory:

```bash
source venv/bin/activate
```

**5. Start the application**

```bash
python app.py
```

### Manual Python Dependency Installation

If you prefer to install Python dependencies manually:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Nmap, WhatWeb, WHOIS and Gobuster are external system tools. They cannot be installed through `pip` or `requirements.txt`; use the appropriate installation script or install them separately.

## Configuration

WebRecon can use the NVD API to retrieve vulnerability information.

An NVD API key can be configured through an environment variable:

```text
NVD_API_KEY=your_api_key
```

The application also uses a Flask secret key for session security. Configure a strong, unique secret key through the environment rather than using a development value in production.

Do not commit API keys, passwords, secret keys or other sensitive configuration to GitHub.

## Usage

1. Start the WebRecon application.
2. Open the application in your browser using the local address configured by Flask.
3. Register an account or log in.
4. Enter the target domain or IP address.
5. Select the desired scan profile.
6. Start the reconnaissance scan.
7. Review discovered ports, services, technologies and other findings.
8. Generate or access the resulting scan reports.

## Scan Profiles

WebRecon provides three scanning profiles:

| Profile | Description |
|---|---|
| Safe | Intended for less intrusive reconnaissance. |
| Normal | Performs a broader security assessment. |
| Advanced | Enables more extensive scanning and enumeration. |

The actual checks performed depend on the selected profile and the available external tools.

## Reports

Scan results are stored in the application's reports directory.

Supported report formats:

- TXT
- HTML

Reports may contain sensitive infrastructure information. Protect them appropriately and avoid publishing them publicly.

## Security and Responsible Use

WebRecon is intended for authorized security testing, educational purposes and defensive security assessments.

**Only scan systems you own or have explicit permission to assess.**

- Obtain authorization before scanning third-party infrastructure.
- Respect the scope and restrictions of penetration testing agreements.
- Avoid disruptive scans against production systems.
- Protect collected information and generated reports.
- Do not use the tool for unauthorized access or malicious activity.

## Limitations

- Scan results depend on the availability and configuration of external tools.
- Some vulnerability information may require further verification.
- Network restrictions, firewalls and rate limits can affect scan results.
- Automated findings should be manually validated before being treated as confirmed vulnerabilities.

## Contributing

Contributions, bug reports and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test your changes.
5. Submit a pull request.
