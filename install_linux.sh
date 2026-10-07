#!/usr/bin/env bash
set -e

echo "==============================================================================="
echo " 🛡️  SENTINELAI - LINUX & macOS AUTOMATED INSTALLATION & SETUP"
echo "==============================================================================="
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found."
    echo "Please install Python 3.10+: sudo apt install -y python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VER=$(python3 --version)
echo "[*] Detected Python environment: $PYTHON_VER"

# Directory paths
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
VENV_DIR="$DIR/.venv"

# Create virtual environment if not present
if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR" || {
        echo "[ERROR] Failed to create virtual environment."
        echo "On Debian/Ubuntu/Kali, run: sudo apt install -y python3-venv python3-pip"
        exit 1
    }
    echo "[+] Virtual environment created successfully."
else
    echo "[+] Existing virtual environment detected in $VENV_DIR."
fi

# Upgrade pip & install dependencies
echo "[*] Installing Python packages from requirements.txt..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip --quiet
"$VENV_DIR/bin/python" -m pip install -r "$DIR/requirements.txt"
echo "[+] Requirements installed successfully."

# Install SentinelAI package in editable mode
echo "[*] Registering SentinelAI commands into virtual environment..."
"$VENV_DIR/bin/python" -m pip install -e "$DIR" --quiet
echo "[+] Console commands 'sentinelai' and 'sentinel' successfully registered!"

# Ensure scripts have execute permissions
chmod +x "$DIR/sentinel.sh" 2>/dev/null || true
chmod +x "$DIR/install_linux.sh" 2>/dev/null || true

# Check for ~/.local/bin in PATH and create symlink for global convenience
USER_BIN="$HOME/.local/bin"
if [ -d "$USER_BIN" ]; then
    ln -sf "$DIR/sentinel.sh" "$USER_BIN/sentinelai"
    ln -sf "$DIR/sentinel.sh" "$USER_BIN/sentinel"
    echo "[+] Symlinks created in $USER_BIN (sentinelai, sentinel)"
fi

echo ""
echo "==============================================================================="
echo " ✔ SENTINELAI SETUP COMPLETE!"
echo "==============================================================================="
echo ""
echo " How to run SentinelAI:"
echo "   ./sentinel.sh             (Opens Interactive Numbered Console)"
echo "   sentinelai scan <URL>     (Full Automated Vulnerability Scan)"
echo "   sentinelai copilot        (AI Security Copilot Chat)"
echo "   sentinelai tools          (Curated Security Tools Arsenal)"
echo ""
