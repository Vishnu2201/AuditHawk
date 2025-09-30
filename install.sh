#!/usr/bin/env bash
# install.sh - installer for AuditHawk
# Usage: ./install.sh

set -e

echo "[*] Setting up AuditHawk environment..."

# Check python3
if ! command -v python3 >/dev/null; then
  echo "[-] python3 not found. Install Python 3.10+ first."
  exit 1
fi

# Create venv
if [ ! -d ".venv" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
echo "[*] Installing Python requirements..."
pip install -r requirements.txt

# Optional: Install Playwright browsers for screenshots
if [ "$1" == "--with-playwright" ]; then
  echo "[*] Installing Playwright browsers..."
  python -m playwright install
fi

echo "[+] AuditHawk installation complete!"
echo "Activate with: source .venv/bin/activate"
echo "Run with: python3 AuditHawk.py --help"
