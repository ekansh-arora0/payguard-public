#!/bin/bash
# PayGuard One-Liner Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard/main/install.sh | bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🛡️  PayGuard Installer${NC}"
echo ""

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}❌ Python 3 not found. Install with: brew install python${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓ Python $PYTHON_VERSION detected"

# Clone repo
INSTALL_DIR="$HOME/.payguard"
if [ -d "$INSTALL_DIR/payguard" ]; then
    echo "📦 Updating existing installation..."
    cd "$INSTALL_DIR/payguard" && git pull origin main 2>/dev/null || true
else
    echo "📥 Downloading PayGuard..."
    mkdir -p "$INSTALL_DIR"
    git clone --depth 1 https://github.com/ekansh-arora0/payguard.git "$INSTALL_DIR/payguard"
fi

cd "$INSTALL_DIR/payguard"

# Install dependencies
echo "📥 Installing dependencies..."
pip3 install --user -q rumps httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null

# Verify
echo "🔍 Verifying..."
python3 -c "
import sys; sys.path.insert(0, '.')
from payguard.detector import PayGuard
from payguard.page_analyzer import classify_page
from payguard.js_analyzer import classify_js
print('✓ All modules loaded')
" || {
    echo -e "${RED}❌ Import failed${NC}"
    exit 1
}

# Create aliases
if ! grep -q "payguard" "$HOME/.zshrc" 2>/dev/null; then
    echo '' >> "$HOME/.zshrc"
    echo '# PayGuard' >> "$HOME/.zshrc"
    echo 'alias payguard="python3 $HOME/.payguard/payguard/payguard/detector.py"' >> "$HOME/.zshrc"
fi

echo ""
echo -e "${GREEN}✅ PayGuard installed!${NC}"
echo ""
echo "Start now:"
echo "  python3 $HOME/.payguard/payguard/payguard/detector.py"
echo ""
echo "Or open a new terminal and run:"
echo "  payguard"
echo ""
echo "🛡️  Look for the shield icon in your menu bar"
