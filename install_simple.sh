#!/bin/bash
# PayGuard Installer

echo "Installing PayGuard..."

# Install required packages
pip3 install --user pystray Pillow mss 2>/dev/null || pip3 install pystray Pillow mss 2>/dev/null || true

# Linux: install scrot if not present
if [[ "$(uname -s)" == "Linux" ]] && ! command -v scrot &>/dev/null; then
    echo "Installing scrot..."
    sudo apt-get install -y scrot 2>/dev/null || sudo dnf install -y scrot 2>/dev/null || true
fi

mkdir -p "$HOME/.payguard"

curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$HOME/.payguard/payguard.py"

echo "Starting PayGuard..."
cd "$HOME/.payguard"
python3 payguard.py &
echo "Done! Shield icon should appear."
