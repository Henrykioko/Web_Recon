#!/usr/bin/env bash

# WebRecon Linux Setup Installer
# Supported: Debian, Ubuntu and Kali Linux
#
# Run:
# chmod +x scripts/install_linux.sh
# ./scripts/install_linux.sh

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

echo "===================================="
echo "       WEBRECON LINUX SETUP"
echo "===================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python 3 is not installed."
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] This installer currently supports apt-based Linux distributions."
    exit 1
fi

echo
echo "[1/5] Updating package repositories..."

sudo apt-get update

echo
echo "[2/5] Installing system dependencies and scanning tools..."

sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    nmap \
    whatweb \
    whois \
    gobuster \
    ruby \
    ruby-dev \
    git \
    curl \
    ca-certificates

echo
echo "[3/5] Creating Python virtual environment..."

if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
fi

echo
echo "[4/5] Installing Python dependencies..."

.venv/bin/python -m pip install --upgrade pip setuptools wheel

.venv/bin/python -m pip install -r requirements.txt

echo
echo "[5/5] Verifying external tools..."

MISSING=0

for TOOL in nmap whatweb whois gobuster; do

    if command -v "$TOOL" >/dev/null 2>&1; then
        echo "[OK] $TOOL: $(command -v "$TOOL")"
    else
        echo "[MISSING] $TOOL"
        MISSING=1
    fi

done

echo
echo "===================================="

if [[ "$MISSING" -eq 0 ]]; then
    echo "WEBRECON SETUP COMPLETED SUCCESSFULLY"
else
    echo "SETUP COMPLETED WITH MISSING TOOLS"
fi

echo "===================================="

echo
echo "Activate the virtual environment:"
echo "source .venv/bin/activate"

echo
echo "Verify the installation:"
echo "python scripts/check_setup.py"

echo
echo "Start WebRecon:"
echo "python app.py"

if [[ "$MISSING" -ne 0 ]]; then
    exit 1
fi