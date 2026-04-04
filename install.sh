#!/bin/bash

echo ""
echo "  🛡️  PayGuard - AI Phishing Detection"
echo ""

# Make sure pip exists
python3 -m pip --version >/dev/null 2>&1 || {
    echo "  ❌ pip not found. Install it first:"
    echo "     Ubuntu/Debian: sudo apt install python3-pip"
    echo "     Fedora: sudo dnf install python3-pip"
    echo "     macOS: brew install python"
    exit 1
}

DIR="$HOME/.payguard"
mkdir -p "$DIR/models"
cd "$DIR"

echo "  📥 Downloading files..."
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_unified.py" -o "$DIR/payguard_unified.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/page_analyzer.py" -o "$DIR/page_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/js_analyzer.py" -o "$DIR/js_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/url_xgboost_v2.model" -o "$DIR/models/url_xgboost_v2.model"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/js_xgboost_v1.model" -o "$DIR/models/js_xgboost_v1.model"

echo "  📦 Installing packages..."
python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib 2>&1 | tail -3

# Verify
echo ""
echo "  🔍 Checking..."
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    echo "  Run: cd ~/.payguard && python3 payguard_unified.py"
else
    echo "  ⚠️  Import failed. Try:"
    echo "     cd ~/.payguard"
    echo "     python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib"
    echo "     python3 payguard_unified.py"
fi
