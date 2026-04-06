#!/bin/bash
# PayGuard Simple Installer - One Command for All Platforms

echo "=========================================="
echo "  Welcome to PayGuard Setup"
echo "  Protecting you from scams"
echo "=========================================="
echo ""

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    PLATFORM="mac"
elif [ "$OS" = "Linux" ]; then
    PLATFORM="linux"
elif [[ "$OS" == "MINGW"* ]] || [[ "$OS" == "MSYS"* ]]; then
    PLATFORM="windows"
else
    PLATFORM="unknown"
fi

echo "Detected: $PLATFORM"
echo ""

if ! command -v python3 &>/dev/null; then
    echo "Python is not installed."
    echo ""
    if [ "$PLATFORM" = "mac" ]; then
        echo "On Mac, please:"
        echo "1. Open the App Store"
        echo "2. Search for Xcode"
        echo "3. Install Xcode (free)"
        echo "4. Then run: ruby -e \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)\""
        echo "5. Then run: brew install python3"
    elif [ "$PLATFORM" = "linux" ]; then
        echo "Please run in terminal:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install python3"
    fi
    echo ""
    echo "Once Python is installed, run this script again."
    exit 1
fi

echo "Python found!"
echo ""

echo "Installing PayGuard..."
echo ""

pip3 install --user pystray Pillow mss 2>/dev/null || pip3 install pystray Pillow mss 2>/dev/null || true

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
echo "Click it to turn protection ON or OFF."
echo ""

cd "$INSTALL_DIR"
python3 payguard.py &

echo ""
echo "PayGuard is now running!"
