#!/bin/bash

echo "  🛡️  PayGuard - AI Phishing Detection"
echo ""

DIR="$HOME/.payguard"
mkdir -p "$DIR/models"
cd "$DIR"

echo "  1/3 Downloading files..."
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/payguard_unified.py" -o "$DIR/payguard_unified.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/page_analyzer.py" -o "$DIR/page_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/js_analyzer.py" -o "$DIR/js_analyzer.py"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/url_xgboost_v2.model" -o "$DIR/models/url_xgboost_v2.model"
curl -sSL "https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/models/js_xgboost_v1.model" -o "$DIR/models/js_xgboost_v1.model"
echo "  ✓ Done"

echo "  2/3 Installing packages..."
# Try each method until one works
if python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib --break-system-packages 2>&1; then
    echo "  ✓ Done"
elif python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib --user 2>&1; then
    echo "  ✓ Done"
elif sudo python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib 2>&1; then
    echo "  ✓ Done"
else
    echo "  ❌ pip install failed."
    echo "  Install pip first: sudo apt install python3-pip"
    exit 1
fi

echo ""
echo "  3/3 Checking..."
cd "$DIR"
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    echo "  Run: cd ~/.payguard && python3 payguard_unified.py"
else
    echo "  ❌ Import failed. Run manually:"
    echo "     cd ~/.payguard"
    echo "     python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib --break-system-packages"
    echo "     python3 payguard_unified.py"
fi
