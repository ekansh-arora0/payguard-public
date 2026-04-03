#!/bin/bash

echo ""
echo "  🛡️  PayGuard - AI Phishing Detection"
echo ""

DIR="$HOME/.payguard"
mkdir -p "$DIR/models"
cd "$DIR"

echo "  📥 Downloading files..."
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_unified.py" -o "$DIR/payguard_unified.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/page_analyzer.py" -o "$DIR/page_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/js_analyzer.py" -o "$DIR/js_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/url_xgboost_v2.model" -o "$DIR/models/url_xgboost_v2.model"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/js_xgboost_v1.model" -o "$DIR/models/js_xgboost_v1.model"

echo "  📦 Installing packages (this takes a minute)..."
pip3 install httpx xgboost numpy scikit-learn Pillow requests joblib 2>&1 | grep -v "WARNING\|already satisfied" || true

# Check if it works
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo ""
    echo "  ✅ Installed!"
    echo ""
    echo "  Run: cd ~/.payguard && python3 payguard_unified.py"
else
    echo ""
    echo "  ⚠️  Packages installed but import failed."
    echo "  Try: cd ~/.payguard && python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib"
    echo "  Then: python3 payguard_unified.py"
fi
