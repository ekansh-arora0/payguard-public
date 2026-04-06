#!/usr/bin/env python3
"""
PayGuard - Simple Cross-Platform Phishing & Scam Detection
Works on Windows, macOS, and Linux
Only scans screen for visual scam indicators
"""

import os
import sys
import time
import threading
import platform
import logging
import subprocess
import io
from PIL import Image, ImageDraw

SYSTEM = platform.system()

LOG_DIR = os.path.expanduser("~/Library/Logs/PayGuard")
if SYSTEM == "Windows":
    LOG_DIR = os.path.expanduser("~/AppData/Local/PayGuard/Logs")
elif SYSTEM == "Linux":
    LOG_DIR = os.path.expanduser("~/.local/share/payguard/logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/payguard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

try:
    import pystray
    HAS_PYSTRAY = True
except ImportError:
    logger.error("pystray not installed. Run: pip install pystray Pillow")
    sys.exit(1)

try:
    import mss
    HAS_MSS = True
except ImportError:
    HAS_MSS = False
    logger.warning("mss not available")

try:
    import tkinter as tk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    logger.warning("tkinter not available for dialogs")


class PayGuardApp:
    def __init__(self):
        self.protection_enabled = True
        self.scans_performed = 0
        self.threats_detected = 0
        self.monitoring_active = False
        self.monitor_thread = None
        self.last_alert_time = 0
        self.alert_cooldown = 10
        
        logger.info("PayGuard initialized")
    
    def start_monitoring(self):
        if self.monitoring_active:
            return
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Monitoring started")
    
    def stop_monitoring(self):
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Monitoring stopped")
    
    def _monitor_loop(self):
        while self.monitoring_active:
            try:
                if self.protection_enabled:
                    self.scan_screen()
                time.sleep(3)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)
    
    def capture_screen(self):
        # macOS: use screencapture
        if SYSTEM == "Darwin":
            try:
                result = subprocess.run(
                    ["screencapture", "-x", "/tmp/payguard_screen.png"],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    with open("/tmp/payguard_screen.png", "rb") as f:
                        return f.read()
            except Exception as e:
                logger.error(f"screencapture failed: {e}")
        
        # Windows/Linux: try mss
        if HAS_MSS:
            try:
                with mss.mss() as sct:
                    sct_img = sct.grab(sct.monitors[1])
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    return buf.getvalue()
            except Exception as e:
                logger.error(f"mss capture failed: {e}")
        
        return None
    
    def analyze_screen(self, image_data):
        if not image_data:
            return {"is_scam": False}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return {"is_scam": False}
            
            total = sum(count for count, _ in colors)
            
            red_count = sum(c for c, (r, g, b) in colors if r > 180 and g < 80 and b < 80)
            orange_count = sum(c for c, (r, g, b) in colors if r > 200 and g > 100 and g < 220 and b < 100)
            
            red_ratio = red_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                return {"is_scam": True, "confidence": 75, "reason": "Red warning screen detected"}
            if orange_ratio > 0.15:
                return {"is_scam": True, "confidence": 60, "reason": "Orange warning screen detected"}
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
        
        return {"is_scam": False}
    
    def scan_screen(self):
        image_data = self.capture_screen()
        if not image_data:
            return
        
        result = self.analyze_screen(image_data)
        self.scans_performed += 1
        
        if result.get("is_scam"):
            self.threats_detected += 1
            now = time.time()
            if now - self.last_alert_time > self.alert_cooldown:
                self.last_alert_time = now
                self.show_alert(result.get("reason", "Scam detected!"))
                logger.warning(f"THREAT: {result.get('reason')}")
    
    def show_alert(self, message):
        if not HAS_TKINTER:
            logger.warning(f"ALERT: {message}")
            return
        
        def show_dialog():
            root = tk.Tk()
            root.withdraw()
            
            dialog = tk.Toplevel(root)
            dialog.title("PayGuard Alert")
            dialog.geometry("450x180")
            dialog.configure(bg="#ffcccc")
            
            warn_label = tk.Label(
                dialog, 
                text="WARNING: SCAM DETECTED!",
                font=("Arial", 16, "bold"),
                fg="red",
                bg="#ffcccc"
            )
            warn_label.pack(pady=15)
            
            msg_label = tk.Label(
                dialog,
                text=message,
                font=("Arial", 12),
                bg="#ffcccc",
                wraplength=400
            )
            msg_label.pack(pady=10)
            
            ok_btn = tk.Button(
                dialog,
                text="I UNDERSTAND - CLOSE WEBSITE",
                font=("Arial", 12, "bold"),
                bg="red",
                fg="white",
                command=dialog.destroy
            )
            ok_btn.pack(pady=20)
            
            dialog.lift()
            dialog.attributes('-topmost', True)
            dialog.mainloop()
        
        threading.Thread(target=show_dialog, daemon=True).start()


def load_icon():
    """Load shield icon - try multiple sources"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    icon_paths = [
        os.path.join(script_dir, "icon.png"),
        os.path.join(script_dir, "..", "extension", "icons", "icon128.png"),
        os.path.join(script_dir, "extension", "icons", "icon128.png"),
    ]
    
    for path in icon_paths:
        if os.path.exists(path):
            try:
                img = Image.open(path)
                return img.convert("RGBA")
            except:
                pass
    
    return create_icon_fallback()


def create_icon_fallback():
    """Create a simple shield icon"""
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    draw.polygon([(32, 4), (60, 16), (60, 40), (32, 60), (4, 40), (4, 16)], 
                 fill=(0, 150, 0, 255), outline=(255, 255, 255, 255), width=2)
    draw.polygon([(32, 4), (60, 16), (60, 40), (32, 60), (4, 40), (4, 16)], 
                 fill=(0, 180, 0, 255))
    
    return img


def create_icon(green=True):
    """Create tray icon - green or red shield"""
    return create_icon_fallback()


def create_menu(app):
    from pystray import MenuItem as Item
    
    def toggle_protection(icon, item):
        app.protection_enabled = not app.protection_enabled
        if app.protection_enabled:
            app.start_monitoring()
            icon.image = create_icon(green=True)
        else:
            app.stop_monitoring()
            icon.image = create_icon(green=False)
    
    def scan_now(icon, item):
        app.scan_screen()
    
    def quit_click(icon, item):
        app.stop_monitoring()
        icon.stop()
    
    status = "ON" if app.protection_enabled else "OFF"
    
    return (
        Item(f"Status: {status}", lambda icon, item: None),
        Item("Toggle ON/OFF", toggle_protection),
        Item("Scan Now", scan_now),
        Item("Quit", quit_click),
    )


def main():
    logger.info(f"PayGuard starting on {SYSTEM}...")
    
    app = PayGuardApp()
    app.start_monitoring()
    
    icon_image = create_icon(green=True)
    icon = pystray.Icon(
        "payguard",
        icon_image,
        "PayGuard",
        create_menu(app)
    )
    
    logger.info("PayGuard ready!")
    try:
        icon.run()
    except KeyboardInterrupt:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
