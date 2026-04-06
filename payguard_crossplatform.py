#!/usr/bin/env python3
"""
PayGuard - Cross-Platform Phishing & Scam Detection
Based on payguard_unified.py - simplified for cross-platform use
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
        self.scans_performed = 0
        self.threats_detected = 0
        self.running = True
        self.enabled = True
        
        logger.info("=== PayGuard started ===")
        
        # Start scanning
        self._start_scan_loop()
    
    def capture_screen(self):
        """Capture screen - cross-platform (from unified)"""
        
        if IS_MAC:
            return self._capture_screen_mac()
        elif IS_LINUX:
            return self._capture_screen_linux()
        elif IS_WINDOWS:
            return self._capture_screen_windows()
        
        return None
    
    def _capture_screen_mac(self):
        """Capture screen on macOS using Quartz"""
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
            
            img = Image.frombytes('RGBA', (width, height), pixeldata, 'raw', 'BGRA', bytesperrow, 1)
            return img
            
        except ImportError:
            return self._capture_screen_subprocess()
        except Exception as e:
            logger.error(f"macOS capture error: {e}")
            return self._capture_screen_subprocess()
    
    def _capture_screen_subprocess(self):
        """Fallback: macOS screencapture"""
        try:
            tmp_path = "/tmp/pg_screen.png"
            result = subprocess.run(
                ["screencapture", "-x", tmp_path],
                capture_output=True, timeout=10
            )
            if result.returncode != 0 or not os.path.exists(tmp_path):
                return None
            
            img = Image.open(tmp_path)
            img.load()
            os.remove(tmp_path)
            return img
        except Exception as e:
            logger.error(f"screencapture error: {e}")
            return None
    
    def _capture_screen_linux(self):
        """Capture screen on Linux using mss or scrot"""
        # Try mss first
        try:
            import mss
            
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                return img
        except ImportError:
            logger.warning("mss not installed - install with: pip install mss")
        except Exception as e:
            logger.debug(f"mss error: {e}")
        
        # Fallback to scrot
        try:
            tmp_path = "/tmp/pg_screen.png"
            subprocess.run(["scrot", tmp_path], capture_output=True, timeout=10)
            if os.path.exists(tmp_path):
                img = Image.open(tmp_path)
                img.load()
                os.remove(tmp_path)
                return img
        except Exception as e:
            logger.debug(f"scrot error: {e}")
        
        # Fallback to gnome-screenshot
        try:
            tmp_path = "/tmp/pg_screen.png"
            subprocess.run(["gnome-screenshot", "-f", tmp_path], capture_output=True, timeout=10)
            if os.path.exists(tmp_path):
                img = Image.open(tmp_path)
                img.load()
                os.remove(tmp_path)
                return img
        except Exception as e:
            logger.debug(f"gnome-screenshot error: {e}")
        
        logger.error("Linux capture failed - no working method found")
        return None
    
    def _capture_screen_windows(self):
        """Capture screen on Windows using mss"""
        try:
            import mss
            
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                return img
        except ImportError:
            logger.error("mss not installed - install with: pip install mss")
        except Exception as e:
            logger.error(f"Windows capture error: {e}")
        
        return None
    
    def analyze_screen(self, image_data):
        """Analyze screen for scam indicators (from unified logic)"""
        if not image_data:
            return None
        
        try:
            if isinstance(image_data, bytes):
                img = Image.open(io.BytesIO(image_data))
            else:
                img = image_data
            
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return None
            
            total = sum(count for count, _ in colors)
            
            # Red = danger (scam warnings, virus alerts)
            red_count = sum(c for c, (r, g, b) in colors if r > 180 and g < 80 and b < 80)
            # Orange = warning
            orange_count = sum(c for c, (r, g, b) in colors if r > 200 and g > 100 and g < 220 and b < 100)
            
            red_ratio = red_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                return "Red warning screen detected - possible scam!"
            if orange_ratio > 0.15:
                return "Orange warning screen - be careful!"
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
        
        return None
    
    def _start_scan_loop(self):
        """Background scan loop"""
        def loop():
            while self.running:
                try:
                    if self.enabled:
                        img = self.capture_screen()
                        if img:
                            threat = self.analyze_screen(img)
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
    
    status = f"Scans: {app.scans_performed}, Threats: {app.threats_detected}"
    
    return (
        Item("PayGuard - Active", lambda icon, item: None),
        Item(status, lambda icon, item: None),
        Item("Quit", quit_click),
    )


def main():
    logger.info(f"PayGuard running on {platform.system()}")
    
    app = PayGuardApp()
    
    icon = pystray.Icon("payguard", create_icon(), "PayGuard", create_menu(app))
    
    logger.info("Shield icon ready!")
    try:
        icon.run()
    except:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
