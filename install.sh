#!/bin/bash
set -e
echo "🛡️  PayGuard Installer"
echo ""
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 not found. Install with: brew install python"
    exit 1
fi
echo "✓ Python $(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')") detected"
echo "📥 Installing dependencies..."
pip3 install --user -q rumps httpx xgboost numpy scikit-learn Pillow requests joblib 2>/dev/null
echo "🔍 Verifying..."
python3 -c "
import sys; sys.path.insert(0, '.')
from payguard_unified import PayGuard
from page_analyzer import classify_page
from js_analyzer import classify_js
print('✓ All modules loaded')
" || { echo "❌ Import failed"; exit 1; }
echo ""
echo "✅ PayGuard installed!"
echo ""
echo "Start with:"
echo "  python3 payguard_unified.py"
echo ""
echo "🛡️  Look for the shield icon in your menu bar"
