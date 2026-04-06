#!/bin/bash
# PayGuard Installer

echo "Installing PayGuard..."

# Install ALL Python packages
pip3 install --user pystray Pillow mss pyperclip 2>/dev/null || pip3 install pystray Pillow mss pyperclip 2>/dev/null || true

# Linux: install scrot
if [[ "$(uname -s)" == "Linux" ]]; then
    echo "Installing screenshot tools..."
    sudo apt-get update -qq
    sudo apt-get install -y scrot 2>/dev/null || sudo dnf install -y scrot 2>/dev/null || true
fi

# macOS: create app bundle for Spotlight search
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "Creating PayGuard app..."
    mkdir -p "/Applications/PayGuard.app/Contents/MacOS"
    mkdir -p "/Applications/PayGuard.app/Contents/Resources"
    
    cat > "/Applications/PayGuard.app/Contents/MacOS/PayGuard" << 'EOF'
#!/bin/bash
cd "$HOME/.payguard"
python3 payguard.py
EOF
    chmod +x "/Applications/PayGuard.app/Contents/MacOS/PayGuard"
    
    cat > "/Applications/PayGuard.app/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>PayGuard</string>
    <key>CFBundleName</key>
    <string>PayGuard</string>
    <key>CFBundleDisplayName</key>
    <string>PayGuard</string>
    <key>CFBundleIdentifier</key>
    <string>com.payguard.app</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF
fi

mkdir -p "$HOME/.payguard"

curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$HOME/.payguard/payguard.py"

echo "Starting PayGuard..."
cd "$HOME/.payguard"
python3 payguard.py &
echo "Done!"
