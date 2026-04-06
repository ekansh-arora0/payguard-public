#!/bin/bash
# PayGuard Installer - installs ALL dependencies

echo "Installing PayGuard..."

# Install ALL Python packages that might be needed
pip3 install --user pystray Pillow mss pyperclip 2>/dev/null || pip3 install pystray Pillow mss pyperclip 2>/dev/null || true

# Install screenshot tools for Linux
if [[ "$(uname -s)" == "Linux" ]]; then
    echo "Installing screenshot tools..."
    sudo apt-get update -qq
    sudo apt-get install -y scrot gnome-screenshot 2>/dev/null || sudo dnf install -y scrot 2>/dev/null || true
fi

mkdir -p "$HOME/.payguard"

curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$HOME/.payguard/payguard.py"

echo "Starting PayGuard..."
cd "$HOME/.payguard"
python3 payguard.py &
echo "Done! Shield icon should appear."
