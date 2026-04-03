#!/bin/bash
set -e

echo "🛡️  PayGuard Installer"
echo ""

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 not found."
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  Fedora: sudo dnf install python3 python3-pip"
    exit 1
fi

echo "✓ Python $(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')") detected"

# Detect OS
OS="$(uname -s)"
echo "📱 Detected: $OS"

# Clone the repo
INSTALL_DIR="$HOME/.payguard"
if [ -d "$INSTALL_DIR" ]; then
    echo "📦 Updating existing installation..."
    cd "$INSTALL_DIR" && git pull origin main 2>/dev/null || true
else
    echo "📥 Downloading PayGuard..."
    git clone --depth 1 https://github.com/ekansh-arora0/payguard-public.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# Install dependencies (skip rumps on Linux - it's macOS-only)
echo "📥 Installing dependencies..."
if [ "$OS" = "Darwin" ]; then
    pip3 install --user -q rumps httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || true
else
    pip3 install --user -q httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || true
fi

# Verify
echo "🔍 Verifying..."
cd "$INSTALL_DIR"
python3 -c "
import sys; sys.path.insert(0, '.')
from payguard_unified import PayGuard
from page_analyzer import classify_page
from js_analyzer import classify_js
print('✓ All modules loaded')
" || {
    echo "❌ Module import failed"
    exit 1
}

echo ""
echo "✅ PayGuard installed to $INSTALL_DIR"
echo ""

if [ "$OS" = "Darwin" ]; then
    echo "Start with:"
    echo "  cd $INSTALL_DIR && python3 payguard_unified.py"
    echo ""
    echo "🛡️  Look for the shield icon in your menu bar"
else
    echo "📋 Linux: Run the detection engine directly:"
    echo "  cd $INSTALL_DIR && python3 payguard_unified.py"
    echo ""
    echo "Or use the API:"
    echo "  cd $INSTALL_DIR/backend && PAYGUARD_ALLOW_DEMO_KEY=true uvicorn server:app --host 0.0.0.0 --port 8002"
fi
