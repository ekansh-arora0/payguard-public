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
# Try venv first (cleanest, works everywhere)
if python3 -m venv "$DIR/venv" 2>/dev/null; then
    source "$DIR/venv/bin/activate"
    pip install -q httpx xgboost numpy scikit-learn Pillow requests joblib
    echo "  ✓ Done (venv)"
# Try --break-system-packages (Ubuntu 24.04+)
elif python3 -m pip install --break-system-packages -q httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null; then
    echo "  ✓ Done (system)"
# Try --user (older systems)
elif python3 -m pip install --user -q httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null; then
    echo "  ✓ Done (user)"
else
    echo "  ❌ pip install failed. Try:"
    echo "     sudo apt install python3-pip python3-venv"
    echo "     Then run this script again"
    exit 1
fi

echo ""
echo "  3/3 Checking..."
cd "$DIR"
if [ -d "$DIR/venv" ]; then
    source "$DIR/venv/bin/activate"
fi
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    if [ -d "$DIR/venv" ]; then
        echo "  Run: cd ~/.payguard && source venv/bin/activate && python3 payguard_unified.py"
    else
        echo "  Run: cd ~/.payguard && python3 payguard_unified.py"
    fi
else
    echo "  ❌ Import failed. Run:"
    echo "     cd ~/.payguard"
    echo "     python3 -m pip install httpx xgboost numpy scikit-learn Pillow requests joblib"
    echo "     python3 payguard_unified.py"
fi
