#!/bin/bash
# PayGuard Installer

echo "Installing PayGuard..."

pip3 install --user pystray Pillow mss 2>/dev/null || pip3 install pystray Pillow mss 2>/dev/null || true

mkdir -p "$HOME/.payguard"

curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_crossplatform.py -o "$HOME/.payguard/payguard.py"

echo "Starting PayGuard..."
cd "$HOME/.payguard"
python3 payguard.py &
echo "Done! Shield icon should appear."
