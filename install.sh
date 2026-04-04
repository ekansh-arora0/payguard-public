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
# Create a virtual environment - works everywhere, no permission issues
python3 -m venv "$DIR/venv" 2>/dev/null || {
    echo "  ❌ venv not available. Install: sudo apt install python3-venv"
    exit 1
}
source "$DIR/venv/bin/activate"
pip install httpx xgboost numpy scikit-learn Pillow requests joblib
echo "  ✓ Done"

echo "  3/3 Checking..."
cd "$DIR"
source "$DIR/venv/bin/activate"
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    echo "  Run: cd ~/.payguard && source venv/bin/activate && python3 payguard_unified.py"
else
    echo "  ❌ Failed. Contact support."
    exit 1
fi
