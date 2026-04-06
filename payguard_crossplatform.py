#!/usr/bin/env python3
"""
PayGuard - Cross-Platform Phishing & Scam Detection
"""

import os
import sys
import time
import threading
import platform
import logging
import subprocess
import io
from PIL import Image

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

LOG_DIR = os.path.expanduser("~/payguard_logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/payguard.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

try:
    import pystray
except ImportError:
    logger.error("pystray not installed. Run: pip install pystray Pillow")
    sys.exit(1)

try:
    import tkinter as tk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False


class PayGuardApp:
    def __init__(self):
        self.enabled = True
        self.scans_performed = 0
        self.threats_detected = 0
        self.running = True
        self.last_alert_time = 0
        self.alert_cooldown = 30
        
        logger.info("=== PayGuard started ===")
        self._start_scan_loop()
    
    def capture_screen(self):
        if IS_MAC:
            return self._capture_screen_mac()
        elif IS_LINUX:
            return self._capture_screen_linux()
        elif IS_WINDOWS:
            return self._capture_screen_windows()
        return None
    
    def _capture_screen_mac(self):
        try:
            import Quartz
            image = Quartz.CGWindowListCreateImage(
                Quartz.CGRectInfinite,
                Quartz.kCGWindowListOptionOnScreenOnly,
                Quartz.kCGNullWindowID,
                Quartz.kCGWindowImageDefault
            )
            if image is None:
                return self._capture_screen_subprocess()
            
            width = Quartz.CGImageGetWidth(image)
            height = Quartz.CGImageGetHeight(image)
            bytesperrow = Quartz.CGImageGetBytesPerRow(image)
            pixeldata = Quartz.CGDataProviderCopyData(Quartz.CGImageGetDataProvider(image))
            
            return Image.frombytes('RGBA', (width, height), pixeldata, 'raw', 'BGRA', bytesperrow, 1)
        except:
            return self._capture_screen_subprocess()
    
    def _capture_screen_subprocess(self):
        try:
            subprocess.run(["screencapture", "-x", "/tmp/pg_screen.png"], 
                          capture_output=True, timeout=10)
            if os.path.exists("/tmp/pg_screen.png"):
                img = Image.open("/tmp/pg_screen.png")
                img.load()
                os.remove("/tmp/pg_screen.png")
                return img
        except:
            pass
        return None
    
    def _capture_screen_linux(self):
        try:
            import mss
            with mss.mss() as sct:
                screenshot = sct.grab(sct.monitors[1])
                return Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
        except:
            pass
        return None
    
    def _capture_screen_windows(self):
        try:
            import mss
            with mss.mss() as sct:
                screenshot = sct.grab(sct.monitors[1])
                return Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
        except:
            pass
        return None
    
    def analyze_screen(self, image_data):
        if not image_data:
            return None
        
        try:
            img = image_data
            if isinstance(img, bytes):
                img = Image.open(io.BytesIO(img))
            
            img.thumbnail((200, 200))
            colors = img.convert("RGB").getcolors(maxcolors=50000)
            
            if not colors:
                return None
            
            total = sum(count for count, _ in colors)
            
            red_count = sum(c for c, (r, g, b) in colors if r > 200 and g < 60 and b < 60)
            orange_count = sum(c for c, (r, g, b) in colors if r > 220 and g > 100 and g < 180 and b < 80)
            
            red_ratio = red_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.20:
                return "Red warning screen detected!"
            if orange_ratio > 0.25:
                return "Orange warning screen - be careful!"
            
        except:
            pass
        
        return None
    
    def _start_scan_loop(self):
        def loop():
            while self.running:
                try:
                    if self.enabled:
                        img = self.capture_screen()
                        if img:
                            threat = self.analyze_screen(img)
                            if threat:
                                now = time.time()
                                if now - self.last_alert_time > self.alert_cooldown:
                                    self.last_alert_time = now
                                    self.threats_detected += 1
                                    self._show_alert(threat)
                                    logger.warning(f"THREAT: {threat}")
                        self.scans_performed += 1
                except Exception as e:
                    logger.error(f"Scan error: {e}")
                time.sleep(3)
        
        threading.Thread(target=loop, daemon=True).start()
        logger.info("Scanning every 3 seconds")
    
    def _show_alert(self, message):
        if not HAS_TKINTER:
            logger.warning(f"ALERT: {message}")
            return
        
        try:
            def show_dialog():
                root = tk.Tk()
                root.withdraw()
                
                dialog = tk.Toplevel(root)
                dialog.title("PayGuard Alert")
                dialog.geometry("450x180")
                dialog.configure(bg="#ffcccc")
                
                tk.Label(dialog, text="WARNING: SCAM DETECTED!",
                        font=("Arial", 16, "bold"), fg="red", bg="#ffcccc").pack(pady=15)
                tk.Label(dialog, text=message,
                        font=("Arial", 12), bg="#ffcccc", wraplength=400).pack(pady=10)
                tk.Button(dialog, text="I UNDERSTAND - CLOSE WEBSITE",
                         font=("Arial", 12, "bold"), bg="red", fg="white",
                         command=dialog.destroy).pack(pady=20)
                
                dialog.lift()
                dialog.attributes('-topmost', True)
                dialog.mainloop()
            
            threading.Thread(target=show_dialog, daemon=True).start()
        except:
            pass


def create_icon(enabled=True):
    """Create proper shield icon - green when on, black when off"""
    from PIL import ImageDraw
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Shield shape - green when on, black when off
    if enabled:
        draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], fill=(16, 185, 129))
        draw.polygon([(32, 14), (50, 24), (50, 38), (32, 52), (14, 38), (14, 24)], fill=(255, 255, 255))
    else:
        draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], fill=(0, 0, 0))
    return img


def create_menu(app):
    from pystray import MenuItem as Item
    
    def toggle(icon, item):
        app.enabled = not app.enabled
        icon.image = create_icon(enabled=app.enabled)
        logger.info(f"Protection {'ON' if app.enabled else 'OFF'}")
    
    def quit_click(icon, item):
        app.running = False
        icon.stop()
    
    status = "ON" if app.enabled else "OFF"
    
    return (
        Item(f"Status: {status}", lambda icon, item: None),
        Item("Toggle ON/OFF", toggle),
        Item("Quit", quit_click),
    )


def main():
    logger.info(f"PayGuard running on {platform.system()}")
    
    app = PayGuardApp()
    
    icon = pystray.Icon(
        "payguard",
        create_icon(enabled=app.enabled),
        "PayGuard",
        create_menu(app)
    )
    
    logger.info("Shield icon ready!")
    try:
        icon.run()
    except:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
