#!/usr/bin/env bash
# install.sh - installer for AuditHawk
# Usage: ./install.sh [--with-playwright]

set -e

echo "[*] Setting up AuditHawk environment..."

# Check python3
if ! command -v python3 >/dev/null; then
  echo "[-] python3 not found. Install Python 3.10+ or newer first."
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

# Install Python requirements
echo "[*] Installing Python requirements..."
pip install -r requirements.txt

# Check if Playwright was requested
if [ "$1" == "--with-playwright" ]; then
  echo "[*] Installing Playwright browsers..."

  # --- Check & install system dependencies (Debian/Ubuntu) ---
  if command -v apt-get >/dev/null; then
    echo "[*] Checking system dependencies for Playwright..."

    declare -A LIBS
    LIBS=(
      ["libicudata.so.66"]="libicu66"
      ["libicui18n.so.66"]="libicu66"
      ["libicuuc.so.66"]="libicu66"
      ["libjpeg.so.8"]="libjpeg8"
      ["libwebp.so.6"]="libwebp6"
      ["libffi.so.7"]="libffi7"
    )

    for so in "${!LIBS[@]}"; do
      if ldconfig -p | grep -q "$so"; then
        echo "  [OK] $so already present"
      else
        echo "  [MISSING] $so → installing ${LIBS[$so]}"
        sudo apt-get update
        sudo apt-get install -y "${LIBS[$so]}" || echo "  [WARN] Could not install ${LIBS[$so]} (may be newer version available)"
      fi
    done
  else
    echo "[!] apt-get not found. Skipping system dependency checks. Please install Playwright dependencies manually."
  fi

  # Install browsers
  python -m playwright install
fi

echo "[+] AuditHawk installation complete!"
echo "Activate with: source .venv/bin/activate"
echo "Run with: python3 AuditHawk.py --help"
