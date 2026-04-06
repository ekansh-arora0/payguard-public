#!/bin/bash
# PayGuard Simple Installer - macOS and Linux

echo "=========================================="
echo "  Welcome to PayGuard Setup"
echo "  Protecting you from scams"
echo "=========================================="
echo ""

OS="$(uname -s)"
echo "Detected: $OS"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "Python is not installed."
    echo "Please install Python from python.org"
    exit 1
fi

echo "Python found!"
echo ""
echo "Installing PayGuard..."
echo ""

if [[ "$OS" == "Linux" ]]; then
    echo "Installing mss for Linux screen capture..."
    pip3 install --user pystray Pillow mss 2>/dev/null || pip3 install pystray Pillow mss 2>/dev/null || true
else
    pip3 install --user pystray Pillow 2>/dev/null || pip3 install pystray Pillow 2>/dev/null || true
fi

INSTALL_DIR="$HOME/.payguard"
mkdir -p "$INSTALL_DIR"

echo "Downloading PayGuard..."
curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$INSTALL_DIR/payguard.py"

cat > "$HOME/run_payguard.sh" << 'EOF'
#!/bin/bash
cd "$HOME/.payguard"
python3 payguard.py
EOF
chmod +x "$HOME/run_payguard.sh"

echo ""
echo "PayGuard installed!"
echo ""
echo "Starting PayGuard now..."
echo ""
echo "You should see a shield icon in your menu bar or system tray."
echo ""

cd "$INSTALL_DIR"
python3 payguard.py &

echo ""
echo "PayGuard is now running!"
