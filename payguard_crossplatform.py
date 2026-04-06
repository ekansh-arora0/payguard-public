#!/usr/bin/env python3
"""
PayGuard - Simple Phishing & Scam Detection
Works on macOS and Linux
Always scanning - no clicking needed
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

SYSTEM = platform.system()

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
        self.scans_performed = 0
        self.threats_detected = 0
        self.screen_capture_works = False
        self.running = True
        
        logger.info("=== PayGuard started ===")
        self._test_screen_capture()
        
        # Always start scanning
        self._start_scan_loop()
    
    def _test_screen_capture(self):
        """Test if screen capture works"""
        try:
            # macOS
            if SYSTEM == "Darwin":
                subprocess.run(["screencapture", "-x", "/tmp/pg_screen.png"], 
                              capture_output=True, timeout=10)
                if os.path.exists("/tmp/pg_screen.png") and os.path.getsize("/tmp/pg_screen.png") > 0:
                    self.screen_capture_works = True
                    logger.info("Screen capture: OK")
                    return
            
            # Linux - try mss
            try:
                import mss
                with mss.mss() as sct:
                    sct.grab(sct.monitors[1])
                self.screen_capture_works = True
                logger.info("Screen capture: OK (mss)")
                return
            except:
                pass
            
            # Linux - scrot
            try:
                subprocess.run(["scrot", "/tmp/pg_screen.png"], capture_output=True, timeout=10)
                if os.path.exists("/tmp/pg_screen.png"):
                    self.screen_capture_works = True
                    logger.info("Screen capture: OK (scrot)")
                    return
            except:
                pass
                
        except Exception as e:
            logger.info(f"Screen capture test: {e}")
        
        logger.warning("Screen capture NOT available")
    
    def _capture(self):
        if not self.screen_capture_works:
            return None
        
        try:
            if SYSTEM == "Darwin":
                subprocess.run(["screencapture", "-x", "/tmp/pg_screen.png"], 
                              capture_output=True, timeout=10)
                if os.path.exists("/tmp/pg_screen.png"):
                    with open("/tmp/pg_screen.png", "rb") as f:
                        return f.read()
            else:
                try:
                    import mss
                    with mss.mss() as sct:
                        sct_img = sct.grab(sct.monitors[1])
                        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                        buf = io.BytesIO()
                        img.save(buf, format='PNG')
                        return buf.getvalue()
                except:
                    pass
                
                try:
                    subprocess.run(["scrot", "/tmp/pg_screen.png"], capture_output=True, timeout=10)
                    if os.path.exists("/tmp/pg_screen.png"):
                        with open("/tmp/pg_screen.png", "rb") as f:
                            return f.read()
                except:
                    pass
        except:
            pass
        
        return None
    
    def _analyze(self, image_data):
        if not image_data:
            return None
        
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return None
            
            total = sum(count for count, _ in colors)
            
            red_count = sum(c for c, (r, g, b) in colors if r > 180 and g < 80 and b < 80)
            orange_count = sum(c for c, (r, g, b) in colors if r > 200 and g > 100 and g < 220 and b < 100)
            
            red_ratio = red_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                return "Red warning screen detected"
            if orange_ratio > 0.15:
                return "Orange warning screen detected"
            
        except:
            pass
        
        return None
    
    def _start_scan_loop(self):
        """Background scan loop"""
        def loop():
            while self.running:
                try:
                    img_data = self._capture()
                    if img_data:
                        threat = self._analyze(img_data)
                        if threat:
                            self.threats_detected += 1
                            self._show_alert(threat)
                            logger.warning(f"THREAT: {threat}")
                    self.scans_performed += 1
                except Exception as e:
                    logger.error(f"Scan error: {e}")
                time.sleep(3)
        
        threading.Thread(target=loop, daemon=True).start()
        logger.info("Scanning started")
    
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


def create_icon():
    """Green shield icon"""
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    draw.polygon([(32, 4), (60, 16), (60, 40), (32, 60), (4, 40), (4, 16)], 
                 fill=(0, 180, 0, 255), outline=(255, 255, 255, 255), width=2)
    return img


def create_menu(app):
    from pystray import MenuItem as Item
    
    def quit_click(icon, item):
        app.running = False
        icon.stop()
    
    scan_status = f"Scans: {app.scans_performed}, Threats: {app.threats_detected}"
    
    return (
        Item("PayGuard - Always Scanning", lambda icon, item: None),
        Item(scan_status, lambda icon, item: None),
        Item("Quit", quit_click),
    )


def main():
    logger.info(f"PayGuard running on {SYSTEM}")
    
    app = PayGuardApp()
    
    icon = pystray.Icon("payguard", create_icon(), "PayGuard", create_menu(app))
    
    logger.info("Shield icon ready!")
    try:
        icon.run()
    except:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
