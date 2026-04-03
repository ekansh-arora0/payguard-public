#!/bin/bash
set -e

echo ""
echo "  🛡️  PayGuard - AI Phishing Detection"
echo "  Installing..."
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "  ❌ Python 3 not found"
    echo "  Install it first: sudo apt install python3 python3-pip"
    exit 1
fi

echo "  ✓ Python found"

# Create install directory
DIR="$HOME/.payguard"
mkdir -p "$DIR/models"
cd "$DIR"

# Download files directly (no git needed)
echo "  📥 Downloading..."
FILES=(
    "payguard_unified.py"
    "page_analyzer.py" 
    "js_analyzer.py"
    "models/url_xgboost_v2.model"
    "models/js_xgboost_v1.model"
)

BASE="https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main"

for f in "${FILES[@]}"; do
    curl -sSL "$BASE/$f" -o "$DIR/$f" 2>/dev/null || {
        echo "  ⚠️  Failed to download $f"
    }
done

# Install dependencies
echo "  📦 Installing packages..."
pip3 install --user -q httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || true
pip3 install --user -q rumps 2>/dev/null || true  # macOS only, fails silently on Linux

# Verify
echo "  🔍 Checking..."
cd "$DIR"
python3 -c "from payguard_unified import PayGuard; print('  ✓ Ready')" 2>/dev/null || {
    echo "  ❌ Something went wrong"
    exit 1
}

echo ""
echo "  ✅ Done!"
echo ""
echo "  To start: cd ~/.payguard && python3 payguard_unified.py"
echo ""
