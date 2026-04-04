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
python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install httpx xgboost numpy scikit-learn Pillow requests joblib
echo "  ✓ Done"

echo ""
echo "  3/3 Checking..."
cd "$DIR"
if "$DIR/venv/bin/python" -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    echo "  Run: cd ~/.payguard && source venv/bin/activate && python3 payguard_unified.py"
else
    echo "  ❌ Failed. Run these commands manually:"
    echo "     cd ~/.payguard"
    echo "     source venv/bin/activate"
    echo "     pip install httpx xgboost numpy scikit-learn Pillow requests joblib"
    echo "     python3 payguard_unified.py"
fi
