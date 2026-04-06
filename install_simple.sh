#!/bin/bash
# PayGuard Simple Installer - One Command for All Platforms
# Designed for seniors - simple questions, big buttons

echo "=========================================="
echo "  Welcome to PayGuard Setup"
echo "  Protecting you from scams"
echo "=========================================="
echo ""

# Detect platform
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

# Step 1: Check/install Python
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

# Step 2: Install required packages
echo "Installing PayGuard..."
echo ""

pip3 install --user pystray Pillow mss pyperclip 2>/dev/null || pip3 install pystray Pillow mss pyperclip 2>/dev/null || true

# Step 3: Create the app directory
INSTALL_DIR="$HOME/.payguard"
mkdir -p "$INSTALL_DIR"

# Download the cross-platform app directly
echo "Downloading PayGuard..."
curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$INSTALL_DIR/payguard_crossplatform.py"

# Step 4: Create launcher
cat > "$HOME/run_payguard.sh" << 'EOF'
#!/bin/bash
cd "$HOME/.payguard"
python3 payguard_crossplatform.py
EOF
chmod +x "$HOME/run_payguard.sh"

echo "PayGuard installed!"
echo ""

# Step 5: Start the app
echo "Starting PayGuard now..."
echo ""
echo "You should see a shield icon in your menu bar."
echo "Click it to turn protection ON or OFF."
echo ""

# Run the app
cd "$INSTALL_DIR"
python3 payguard_crossplatform.py &

echo ""
echo "PayGuard is now running!"
echo "A shield icon should appear in your system tray."
