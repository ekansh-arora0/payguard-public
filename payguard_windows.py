#!/usr/bin/env python3
"""
PayGuard Windows - System Tray App
Uses the same detection engine as the macOS unified app.
"""

import os
import sys
import time
import threading
import logging
import platform
import re
from io import BytesIO
from pathlib import Path

# Setup logging
LOG_DIR = os.path.expanduser("~/AppData/Local/PayGuard/Logs") if platform.system() == "Windows" else os.path.expanduser("~/Library/Logs/PayGuard")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s',
    handlers=[logging.FileHandler(f"{LOG_DIR}/payguard.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Imports
try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False
    logger.error("pip install pystray Pillow")

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from payguard.detector import PayGuard
    from payguard.page_analyzer import classify_page
    from payguard.js_analyzer import classify_js
    HAS_DETECTION = True
except ImportError:
    HAS_DETECTION = False
    logger.error("Detection engine not found")


def create_icon():
    """Create shield icon"""
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield shape
    draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], fill=(16, 185, 129))
    draw.polygon([(32, 14), (50, 24), (50, 38), (32, 52), (14, 38), (14, 24)], fill=(255, 255, 255))
    return img


def create_alert_icon():
    """Create alert shield icon (red)"""
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], fill=(239, 68, 68))
    draw.polygon([(32, 14), (50, 24), (50, 38), (32, 52), (14, 38), (14, 24)], fill=(255, 255, 255))
    return img


def show_notification(title, message, critical=False):
    """Show Windows toast notification"""
    try:
        if platform.system() == "Windows":
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(title, message, duration=10, threaded=True)
        else:
            os.system(f'notify-send "{title}" "{message}" 2>/dev/null || true')
    except Exception:
        print(f"\n{'='*40}\n🚨 {title}\n{message}\n{'='*40}")


class PayGuardWindows:
    def __init__(self):
        self.enabled = True
        self.threats_blocked = 0
        self.scans_completed = 0
        self.scanning = False
        self.guard = None
        self.icon = None

        if HAS_DETECTION:
            self.guard = PayGuard()

    def get_clipboard(self):
        """Get clipboard text"""
        try:
            if platform.system() == "Windows":
                import win32clipboard
                win32clipboard.OpenClipboard()
                data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                return data
            else:
                import subprocess
                return subprocess.check_output(["pbpaste"], text=True)
        except Exception:
            return ""

    def scan_clipboard(self):
        """Scan clipboard for threats"""
        text = self.get_clipboard()
        if not text or len(text.strip()) < 5:
            show_notification("PayGuard", "Clipboard is empty")
            return

        self.scans_completed += 1

        # Check for URLs
        urls = re.findall(r'https?://[^\s\'"<>)}\]]+', text)
        threat_found = False

        if self.guard and urls:
            for url in urls[:3]:
                result = self.guard._run_url_analysis(url)
                findings = result.get('findings', [])
                if findings and self.guard._passes_alert_gate(findings):
                    self.threats_blocked += 1
                    threat_found = True
                    lines = [f"[{f[2]}%] {f[1][:50]}" for f in findings[:3]]
                    show_notification("🚨 THREAT DETECTED", "\n".join(lines), critical=True)
                    break

        # Check text content
        if not threat_found and self.guard:
            behavioral = self.guard._analyze_page_behavior(text)
            if behavioral and behavioral[2] >= 70:
                self.threats_blocked += 1
                threat_found = True
                show_notification("🚨 SCAM DETECTED", f"{behavioral[1]}", critical=True)

        if not threat_found:
            show_notification("PayGuard", "Clipboard scan complete - no threats")

    def scan_url(self, url):
        """Scan a single URL"""
        if not self.guard:
            return
        result = self.guard._run_url_analysis(url)
        findings = result.get('findings', [])
        if findings and self.guard._passes_alert_gate(findings):
            self.threats_blocked += 1
            lines = [f"[{f[2]}%] {f[1][:50]}" for f in findings[:3]]
            show_notification("🚨 PHISHING DETECTED", "\n".join(lines), critical=True)

    def toggle_monitoring(self):
        """Toggle monitoring on/off"""
        self.enabled = not self.enabled
        if self.icon:
            self.icon.icon = create_icon() if self.enabled else Image.new('RGBA', (64, 64), (128, 128, 128, 255))

    def build_menu(self):
        """Build system tray menu"""
        return pystray.Menu(
            pystray.MenuItem(
                lambda item: f"🟢 Protection ON" if self.enabled else "🔴 Protection OFF",
                self.toggle_monitoring,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("📋 Scan Clipboard", lambda: threading.Thread(target=self.scan_clipboard, daemon=True).start()),
            pystray.MenuItem(lambda item: f"Threats blocked: {self.threats_blocked}", None, enabled=False),
            pystray.MenuItem(lambda item: f"Scans completed: {self.scans_completed}", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.quit),
        )

    def quit(self):
        """Quit the app"""
        if self.icon:
            self.icon.stop()

    def run(self):
        """Start the system tray app"""
        if not HAS_TRAY:
            logger.error("pystray not installed: pip install pystray Pillow")
            return

        if not HAS_DETECTION:
            logger.error("Detection engine not found")
            return

        logger.info("PayGuard starting...")
        print("\n🛡️  PayGuard is running in your system tray")
        print("   Right-click the shield icon to access controls\n")

        self.icon = pystray.Icon(
            "PayGuard",
            create_icon(),
            "PayGuard - Phishing Protection",
            menu=self.build_menu(),
        )
        self.icon.run()


def main():
    app = PayGuardWindows()
    app.run()


if __name__ == "__main__":
    main()
