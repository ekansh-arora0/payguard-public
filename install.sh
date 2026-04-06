#!/bin/bash
# PayGuard One-Liner Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ekansh-arora0/payguard-public/main/install.sh | bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🛡️  PayGuard Installer${NC}"
echo ""

# Detect OS
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    PLATFORM="macOS"
elif [ "$OS" = "Linux" ]; then
    PLATFORM="Linux"
elif [ "$OS" = "MINGW"* ] || [ "$OS" = "MSYS"* ]; then
    PLATFORM="Windows"
else
    PLATFORM="Unknown"
fi
echo "📍 Platform: $PLATFORM"

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}❌ Python 3 not found.${NC}"
    if [ "$PLATFORM" = "macOS" ]; then
        echo "   Install with: brew install python"
    elif [ "$PLATFORM" = "Linux" ]; then
        echo "   Install with: sudo apt-get install python3 (Debian/Ubuntu)"
        echo "   Or: sudo dnf install python3 (Fedora)"
    fi
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓ Python $PYTHON_VERSION detected"

# Clone repo (from public repo - uses GitHub CLI or disables git prompt)
INSTALL_DIR="$HOME/.payguard"
if [ -d "$INSTALL_DIR/payguard" ]; then
    echo "📦 Updating existing installation..."
    cd "$INSTALL_DIR/payguard" && GIT_TERMINAL_PROMPT=0 git pull origin main 2>/dev/null || true
else
    echo "📥 Downloading PayGuard..."
    mkdir -p "$INSTALL_DIR"
    
    # Try GitHub CLI first (no auth), then git with prompt disabled, then curl fallback
    if command -v gh &>/dev/null; then
        gh repo clone ekansh-arora0/payguard-public "$INSTALL_DIR/payguard" 2>/dev/null || {
            echo "   gh clone failed, trying git..."
            GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/ekansh-arora0/payguard-public.git "$INSTALL_DIR/payguard" 2>/dev/null || {
                echo "   git clone failed, using curl download..."
                curl -fsSL https://github.com/ekansh-arora0/payguard-public/archive/refs/heads/main.zip -o /tmp/payguard.zip
                unzip -q /tmp/payguard.zip -d "$INSTALL_DIR"
                mv "$INSTALL_DIR/payguard-public-main" "$INSTALL_DIR/payguard"
                rm /tmp/payguard.zip
            }
        }
    else
        GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/ekansh-arora0/payguard-public.git "$INSTALL_DIR/payguard" 2>/dev/null || {
            echo "   git clone failed, using curl download..."
            curl -fsSL https://github.com/ekansh-arora0/payguard-public/archive/refs/heads/main.zip -o /tmp/payguard.zip
            unzip -q /tmp/payguard.zip -d "$INSTALL_DIR"
            mv "$INSTALL_DIR/payguard-public-main" "$INSTALL_DIR/payguard"
            rm /tmp/payguard.zip
        }
    fi
fi

cd "$INSTALL_DIR/payguard"

# Install dependencies
echo "📥 Installing dependencies..."

# Core dependencies (all platforms)
PIP_PACKAGES="httpx xgboost numpy scikit-learn Pillow requests joblib"

# Platform-specific
if [ "$PLATFORM" = "macOS" ]; then
    PIP_PACKAGES="$PIP_PACKAGES rumps"
    echo "   Installing: $PIP_PACKAGES (including menu bar)"
elif [ "$PLATFORM" = "Linux" ]; then
    PIP_PACKAGES="$PIP_PACKAGES pystray"
    echo "   Installing: $PIP_PACKAGES (Linux system tray)"
    echo "   Note: Menu bar not available on Linux (rumps is macOS-only)"
elif [ "$PLATFORM" = "Windows" ]; then
    PIP_PACKAGES="$PIP_PACKAGES win10toast pystray"
    echo "   Installing: $PIP_PACKAGES (system tray + notifications)"
fi

pip3 install --user -q $PIP_PACKAGES 2>/dev/null || pip3 install $PIP_PACKAGES 2>/dev/null || true

# Verify
echo "🔍 Verifying..."
python3 -c "
import sys
sys.path.insert(0, '.')
# Test main module
from payguard_unified import PayGuard
print('✓ Core modules loaded')
" || {
    echo -e "${RED}❌ Import failed${NC}"
    exit 1
}

# Create launcher script
echo "📝 Creating launcher..."
LAUNCHER="$HOME/.payguard/payguard.sh"
cat > "$LAUNCHER" << 'LAUNCHER_EOF'
#!/bin/bash
cd "$HOME/.payguard/payguard"
python3 payguard_unified.py "$@"
LAUNCHER_EOF
chmod +x "$LAUNCHER"

# Create alias
SHELL_RC="$HOME/.zshrc"
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if ! grep -q "payguard.sh" "$SHELL_RC" 2>/dev/null; then
    echo '' >> "$SHELL_RC"
    echo '# PayGuard' >> "$SHELL_RC"
    echo 'alias payguard="$HOME/.payguard/payguard.sh"' >> "$SHELL_RC"
fi

echo ""
echo -e "${GREEN}✅ PayGuard installed!${NC}"
echo ""
echo "Start now:"
echo "  python3 $HOME/.payguard/payguard/payguard_unified.py"
echo ""
echo "Or open a new terminal and run:"
echo "  payguard"
echo ""

if [ "$PLATFORM" = "macOS" ]; then
    echo "🛡️  Look for the shield icon in your menu bar"
elif [ "$PLATFORM" = "Linux" ]; then
    echo "🛡️  Runs as CLI tool (menu bar not available on Linux)"
elif [ "$PLATFORM" = "Windows" ]; then
    echo "🛡️  Runs in system tray"
fi