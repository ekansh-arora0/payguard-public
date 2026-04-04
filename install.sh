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
# Try all possible pip commands
PIP_CMD=""
for cmd in "python3 -m pip" "pip3" "pip"; do
    if command -v $cmd >/dev/null 2>&1; then
        PIP_CMD="$cmd"
        break
    fi
done

if [ -z "$PIP_CMD" ]; then
    echo "  ❌ pip not found. Install: sudo apt install python3-pip"
    exit 1
fi

# Install with all possible flags for compatibility
$PIP_CMD install --break-system-packages httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || \
$PIP_CMD install --user httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || \
$PIP_CMD install httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null || \
sudo $PIP_CMD install httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null

echo "  ✓ Done"

echo "  3/3 Checking..."
cd "$DIR"
if python3 -c "from payguard_unified import PayGuard" 2>/dev/null; then
    echo "  ✅ Ready!"
    echo ""
    echo "  Run: cd ~/.payguard && python3 payguard_unified.py"
else
    echo "  ⚠️  Try this:"
    echo "     cd ~/.payguard"
    echo "     python3 -m pip install --break-system-packages httpx xgboost numpy scikit-learn Pillow requests joblib"
    echo "     python3 payguard_unified.py"
fi
