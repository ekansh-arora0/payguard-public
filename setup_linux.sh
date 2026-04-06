#!/bin/bash
# PayGuard Linux Auto-Launcher
# Creates .desktop file for app launcher and autostart

set -e

echo "PayGuard Setting Up..."

# Install system dependencies for notifications and voice
if command -v apt-get &>/dev/null; then
    echo "Installing system dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq libnotify-bin espeak 2>/dev/null || true
fi

# Check if already installed
if [ -f "$HOME/.payguard/installed" ]; then
    echo "PayGuard already set up"
    exit 0
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --user pystray mss pyperclip plyer Pillow requests httpx xgboost numpy scikit-learn joblib 2>/dev/null || true

# Copy payguard_unified.py to AppData
mkdir -p "$HOME/.payguard"
cp "$(dirname "$0")/payguard_crossplatform.py" "$HOME/.payguard/"

# Create .desktop file for searchability
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/payguard.desktop" << EOF
[Desktop Entry]
Type=Application
Name=PayGuard
Comment=Phishing Protection
Exec=python3 $HOME/.payguard/payguard_unified.py
Icon=security-high
Terminal=false
Categories=Security;
EOF

# Add to autostart (works on most distros - GNOME, KDE, XFCE, etc.)
mkdir -p "$HOME/.config/autostart"
cat > "$HOME/.config/autostart/payguard.desktop" << EOF
[Desktop Entry]
Type=Application
Name=PayGuard
Comment=Phishing Protection
Exec=python3 $HOME/.payguard/payguard_unified.py
Icon=security-high
Terminal=false
Categories=Security;
X-GNOME-Autostart-enabled=true
EOF

# Mark as installed
touch "$HOME/.payguard/installed"

echo "✅ PayGuard installed"
echo "   Search 'PayGuard' with Super key to find it"
echo "   It will start automatically when you log in"

# Start PayGuard
python3 "$HOME/.payguard/payguard_unified.py" &
