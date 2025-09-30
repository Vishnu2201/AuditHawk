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

# If requested, install Playwright browsers and try to install system libs (Debian/Ubuntu)
if [ "$1" == "--with-playwright" ]; then
  echo "[*] Installing Playwright browsers..."

  # prefer running playwright install inside venv to ensure correct binaries
  # Check and attempt to install system deps (Debian/Ubuntu)
  if command -v apt-get >/dev/null; then
    echo "[*] Checking common Playwright system libraries (apt)..."

    declare -A LIBS
    LIBS=(
      ["libicudata.so.66"]="libicu66"
      ["libicui18n.so.66"]="libicu66"
      ["libicuuc.so.66"]="libicu66"
      ["libjpeg.so.8"]="libjpeg8"
      ["libwebp.so.6"]="libwebp6"
      ["libffi.so.7"]="libffi7"
    )

    MISSING_PACKAGES=()

    for so in "${!LIBS[@]}"; do
      if ldconfig -p | grep -q "$so"; then
        echo "  [OK] $so"
      else
        echo "  [MISSING] $so -> will try to install ${LIBS[$so]}"
        MISSING_PACKAGES+=("${LIBS[$so]}")
      fi
    done

    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
      echo "[*] Installing missing packages: ${MISSING_PACKAGES[*]} (requires sudo)"
      sudo apt-get update
      sudo apt-get install -y "${MISSING_PACKAGES[@]}" || echo "[WARN] Some packages may not be available for this distribution; please install equivalents manually."
    fi
  else
    echo "[!] apt-get not found; skipping automatic system dependency install. Please ensure Playwright dependencies are available on your OS."
  fi

  # Install Playwright browsers using the venv python
  python -m playwright install
fi

echo "[+] AuditHawk installation complete!"
echo "Activate with: source .venv/bin/activate"
echo "Run with: python3 AuditHawk.py --help"
