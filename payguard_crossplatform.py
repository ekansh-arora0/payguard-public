#!/usr/bin/env python3
"""
PayGuard - Cross-Platform Phishing & Scam Detection
Works on Windows, macOS, and Linux
"""

import os
import sys
import time
import threading
import base64
import platform
import logging
import subprocess
import requests
import io

from PIL import Image, ImageDraw, ImageFont

# Setup logging
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

# Configuration
BACKEND_URL = "http://127.0.0.1:8002"
API_KEY = "demo_key"
CACHE_TTL = 300  # 5 minutes

# Check for PIL
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL not available - image features disabled")

# Cross-platform tray icon using pystray
try:
    import pystray
    HAS_PYTRAY = True
except ImportError:
    HAS_PYTRAY = False
    logger.warning("pystray not available")

# Cross-platform clipboard
try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False
    logger.warning("pyperclip not available - clipboard scanning disabled")

# Cross-platform screen capture (mss is best - works everywhere)
try:
    import mss
    import mss.tools
    HAS_MSS = True
except ImportError:
    HAS_MSS = False
    logger.warning("mss not available - trying fallback screen capture")

# Cross-platform notifications
try:
    from plyer import notification
    HAS_PLYER = True
except ImportError:
    HAS_PLYER = False
    logger.warning("plyer not available - using platform-specific notification fallback")

# Cross-platform TTS for voice alerts
try:
    from gtts import gTTS
    HAS_GTTS = True
except ImportError:
    HAS_GTTS = False
    logger.warning("gTTS not available for voice alerts")

# Cross-platform dialog popups
try:
    import tkinter as tk
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False
    logger.warning("tkinter not available for dialogs")


class PayGuardApp:
    def __init__(self):
        self.url_cache = {}
        self.cache_ttl = CACHE_TTL
        self.last_checked_url = None
        self.scans_performed = 0
        self.threats_detected = 0
        self.backend_online = False
        self.request_session = None
        self.protection_enabled = True  # Simple ON/OFF
        self.monitoring_active = False
        self.monitor_thread = None
        self.voice_alerts = True  # Voice alert option
        self._check_backend()
        
        # Auto-start on launch if enabled
        if self.protection_enabled:
            self.start_monitoring()
        
        # Setup auto-start
        self.setup_auto_start()
        
        # Safe domains whitelist
        self.safe_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
            'reddit.com', 'amazon.com', 'netflix.com', 'icloud.com',
            'linkedin.com', 'instagram.com', 'yahoo.com', 'bing.com',
            '.edu', '.gov', '.mil',  # Trusted TLDs
            'wikipedia.org', 'mozilla.org', 'w3.org',
            'openai.com', 'anthropic.com', 'deepmind.com',
            'localhost', '127.0.0.1', '0.0.0.0',
        ]
        
        logger.info("PayGuard initialized")
    
    def setup_auto_start(self):
        """Setup auto-start on system boot"""
        try:
            system = platform.system()
            script_path = os.path.abspath(__file__)
            
            if system == "Darwin":
                plist_path = os.path.expanduser("~/Library/LaunchAgents/com.payguard.menubar.plist")
                plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.payguard.menubar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
                
                if not os.path.exists(plist_path):
                    with open(plist_path, 'w') as f:
                        f.write(plist_content)
                    logger.info(f"Auto-start configured: {plist_path}")
                    
            elif system == "Windows":
                import winreg
                exe_path = sys.executable
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(key, "PayGuard", 0, winreg.REG_SZ, f'"{exe_path}" "{script_path}"')
                    winreg.CloseKey(key)
                    logger.info("Auto-start configured for Windows")
                except Exception as e:
                    logger.warning(f"Could not configure Windows auto-start: {e}")
            else:
                # Linux: systemd user service
                xdg_dir = os.path.expanduser("~/.config/autostart")
                desktop_file = os.path.join(xdg_dir, "payguard.desktop")
                
                if not os.path.exists(desktop_file):
                    try:
                        os.makedirs(xdg_dir, exist_ok=True)
                        desktop_content = f'''[Desktop Entry]
Type=Application
Name=PayGuard
Comment=PayGuard Phishing & Scam Detection
Exec=python3 {script_path}
Icon=security-high
Terminal=false
Categories=Security;Utility;
'''
                        with open(desktop_file, 'w') as f:
                            f.write(desktop_content)
                        logger.info(f"Auto-start configured for Linux: {desktop_file}")
                    except Exception as e:
                        logger.warning(f"Could not configure Linux auto-start: {e}")
        except Exception as e:
            logger.warning(f"Auto-start setup failed: {e}")
    
    def start_monitoring(self):
        """Start background monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        logger.info("Monitoring stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop - checks clipboard periodically"""
        while self.monitoring_active:
            try:
                if self.protection_enabled:
                    self.scan_clipboard()
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)
    
    def play_alert(self):
        """Play loud alert sound for danger - cross-platform"""
        if not self.voice_alerts:
            return
        
        message = "Danger! Threat detected. Close the website now."
        
        try:
            system = platform.system()
            if system == "Darwin":
                subprocess.Popen(["say", message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Windows":
                try:
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONSTOP)
                except ImportError:
                    pass
                try:
                    import win32com.client
                    speaker = win32com.client.Dispatch("SAPI.SpVoice")
                    speaker.Speak(message)
                except ImportError:
                    pass
            else:
                # Linux - try espeak or festival
                try:
                    subprocess.Popen(["espeak", message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    try:
                        subprocess.Popen(["festival", "--tts"], stdin=subprocess.PIPE, 
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).communicate(input=message.encode())
                    except FileNotFoundError:
                        pass
        except Exception as e:
            logger.warning(f"Voice alert failed: {e}")
    
    def _check_backend(self):
        """Check if backend is running"""
        try:
            r = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
            self.backend_online = r.status_code == 200
        except:
            self.backend_online = False
        logger.info(f"Backend online: {self.backend_online}")
    
    def _capture_screen(self):
        """Capture screenshot - cross-platform using mss"""
        try:
            # Try mss first (works on Windows, Linux, macOS)
            if HAS_MSS:
                with mss.mss() as sct:
                    sct_img = sct.grab(sct.monitors[1])
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    return buf.getvalue()
            
            # Fallback: platform-specific capture
            system = platform.system()
            if system == "Darwin":
                result = subprocess.run(
                    ["screencapture", "-x", "/tmp/payguard_screen.png"],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    with open("/tmp/payguard_screen.png", "rb") as f:
                        return f.read()
            elif system == "Windows":
                try:
                    import pyautogui
                    img = pyautogui.screenshot()
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    return buf.getvalue()
                except ImportError:
                    logger.warning("pyautogui not installed")
            else:
                # Linux fallback
                try:
                    import pyscreenshot
                    img = pyscreenshot.grab()
                    buf = io.BytesIO()
                    img.save(buf, format='PNG')
                    return buf.getvalue()
                except ImportError:
                    logger.warning("pyscreenshot not installed")
        except Exception as e:
            logger.error(f"Capture failed: {e}")
        return None
    
    def _scan_with_backend(self, image_data):
        """Send image to backend for AI/scam detection"""
        if not self.backend_online:
            return None
        
        try:
            payload = {
                "url": "screen://menubar",
                "content": base64.b64encode(image_data).decode(),
                "metadata": {"source": "menubar"}
            }
            r = requests.post(
                f"{BACKEND_URL}/api/media-risk/bytes",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=60
            )
            
            if r.status_code == 200:
                data = r.json()
                
                # Check AI-generated images
                image_fake_prob = data.get("image_fake_prob", 0)
                if image_fake_prob and image_fake_prob >= 30:
                    return {
                        "is_scam": True,
                        "confidence": int(image_fake_prob),
                        "reason": f"AI-generated image detected ({int(image_fake_prob)}%)"
                    }
                
                # Check scam alerts
                scam = data.get("scam_alert", {})
                if scam.get("is_scam"):
                    return {
                        "is_scam": True,
                        "confidence": scam.get("confidence", 80),
                        "reason": scam.get("senior_message", "Threat detected")
                    }
                
                # Check visual cues
                reasons = data.get("reasons", [])
                for reason in reasons:
                    if "visual scam" in reason.lower() or "red" in reason.lower():
                        return {
                            "is_scam": True,
                            "confidence": 75,
                            "reason": reason
                        }
                
            return {"is_scam": False}
        except Exception as e:
            logger.error(f"Backend error: {e}")
        return None
    
    def _local_detect(self, image_data):
        """Local scam detection based on colors"""
        if not HAS_PIL or not image_data:
            return {"is_scam": False, "confidence": 0}
        
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((400, 400))
            colors = img.convert("RGB").getcolors(maxcolors=100000)
            
            if not colors:
                return {"is_scam": False, "confidence": 0}
            
            total = sum(count for count, _ in colors)
            
            # Count danger colors
            red_count = sum(c for c, (r, g, b) in colors if r > 180 and g < 80 and b < 80)
            blue_count = sum(c for c, (r, g, b) in colors if b > 150 and r < 100 and g < 150)
            orange_count = sum(c for c, (r, g, b) in colors if r > 200 and g > 100 and g < 220 and b < 100)
            
            red_ratio = red_count / total if total > 0 else 0
            blue_ratio = blue_count / total if total > 0 else 0
            orange_ratio = orange_count / total if total > 0 else 0
            
            if red_ratio > 0.15:
                return {"is_scam": True, "confidence": 75, "reason": "Red warning screen detected"}
            if blue_ratio > 0.20:
                return {"is_scam": True, "confidence": 65, "reason": "Blue tech support scam detected"}
            if orange_ratio > 0.15:
                return {"is_scam": True, "confidence": 60, "reason": "Warning color detected"}
            
        except Exception as e:
            logger.error(f"Local detection error: {e}")
        
        return {"is_scam": False, "confidence": 0}
    
    def scan_screen(self):
        """Perform screen scan"""
        logger.info("Screen scan started")
        
        image_data = self._capture_screen()
        if not image_data:
            logger.warning("No image captured")
            return {"is_scam": False, "message": "Failed to capture screen"}
        
        logger.info(f"Captured {len(image_data)} bytes")
        
        # Try backend first
        result = self._scan_with_backend(image_data)
        
        # Fallback to local detection
        if not result or not result.get("is_scam"):
            local_result = self._local_detect(image_data)
            if local_result.get("is_scam"):
                result = local_result
        
        self.scans_performed += 1
        
        if result and result.get("is_scam"):
            self.threats_detected += 1
            logger.warning(f"THREAT DETECTED: {result.get('reason')}")
            return result
        
        logger.info("Screen scan: safe")
        return {"is_scam": False, "message": "No threats detected"}
    
    def scan_clipboard(self):
        """Scan clipboard text/URLs for scams - LIVE MONITORING"""
        try:
            # Get clipboard content - cross-platform
            if platform.system() == "Darwin":
                text = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=3).stdout
            elif HAS_PYPERCLIP:
                text = pyperclip.paste()
            else:
                logger.warning("Clipboard access not available - no pyperclip")
                return {"is_scam": False, "message": "Clipboard not available"}
            
            if not text:
                return {"is_scam": False, "message": "Empty clipboard"}
            
            # Check if it's a URL
            import re
            url_match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', text.strip())
            
            if url_match and self.backend_online:
                # LIVE URL CHECK - Check URL against backend
                url = url_match.group(0)
                
                # Don't re-check same URL
                if url == self.last_checked_url:
                    return {"is_scam": False, "message": "Already checked"}
                
                try:
                    r = requests.post(
                        f"{BACKEND_URL}/api/v1/risk",
                        json={"url": url},
                        headers={"X-API-Key": API_KEY},
                        timeout=5
                    )
                    if r.status_code == 200:
                        result = r.json()
                        risk_level = result.get("risk_level", "low")
                        
                        if risk_level in ["high", "critical"]:
                            self.last_checked_url = url
                            self.threats_detected += 1
                            self.scans_performed += 1
                            self.play_alert()  # Voice alert!
                            logger.warning(f"DANGEROUS URL: {url} - {risk_level}")
                            return {
                                "is_scam": True,
                                "confidence": 90,
                                "reason": f"DANGEROUS! {result.get('risk_factors', ['Unknown threat'])[0]}"
                            }
                        elif risk_level == "medium":
                            self.last_checked_url = url
                            self.scans_performed += 1
                            logger.warning(f"SUSPICIOUS URL: {url}")
                            return {
                                "is_scam": False,
                                "confidence": 50,
                                "reason": "Caution: Suspicious website"
                            }
                except Exception as e:
                    logger.error(f"URL check failed: {e}")
            
            # Simple scam keyword detection
            scam_keywords = [
                "call now", "1-800", "urgent", "immediately",
                "your account", "suspended", "verify", "password",
                "bitcoin", "gift card", "western union", "winner",
                "congratulations", "prize", "claim now", "act now"
            ]
            
            text_lower = text.lower()
            matches = [kw for kw in scam_keywords if kw in text_lower]
            
            if matches:
                self.threats_detected += 1
                self.scans_performed += 1
                self.play_alert()  # Voice alert!
                logger.warning(f"Clipboard scam detected: {matches}")
                return {
                    "is_scam": True,
                    "confidence": 80,
                    "reason": f"SCAM! {matches[0].upper()} - Don't fall for it!"
                }
            
            self.scans_performed += 1
            return {"is_scam": False, "message": "✅ Safe"}
             
        except Exception as e:
            logger.error(f"Clipboard scan error: {e}")
            return {"is_scam": False, "message": str(e)}


def create_icon(green=True):
    """Create tray icon image - green for ON, red for OFF"""
    size = (64, 64)
    color = (40, 167, 69) if green else (220, 53, 69)  # Green or Red
    img = Image.new('RGB', size, color)
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    draw.polygon([(32, 8), (56, 20), (56, 40), (32, 58), (8, 40), (8, 20)], 
                 outline='white', width=3)
    draw.line([(32, 18), (32, 40)], fill='white', width=3)
    draw.line([(22, 28), (32, 38), (42, 28)], fill='white', width=2)
    
    return img  # Return Image object, not bytes


def create_menu(app):
    """Create simplified system tray menu - one button ON/OFF"""
    from pystray import MenuItem as Item
    
    def toggle_protection(icon, item):
        app.protection_enabled = not app.protection_enabled
        if app.protection_enabled:
            app.start_monitoring()
            icon.image = create_icon(green=True)
            show_notification("Protection ON", "PayGuard is now protecting you!")
        else:
            app.stop_monitoring()
            icon.image = create_icon(green=False)
            show_notification("Protection OFF", "PayGuard is paused")
    
    def scan_now(icon, item):
        result = app.scan_clipboard()
        if result.get("is_scam"):
            show_notification("🚨 DANGER!", result.get("reason", "Threat detected!"))
            app.play_alert()
        else:
            show_notification("✅ Safe", "No threats detected")
    
    def status_click(icon, item):
        app._check_backend()
        
        # What's currently happening
        status = "🟢 ON" if app.protection_enabled else "🔴 OFF"
        scanning = "✅ YES - scanning every 5 seconds" if app.monitoring_active else "❌ NO"
        
        msg = f"""Status: {status}

🔍 Auto-Scanning: {scanning}

📊 Stats:
• Scans done: {app.scans_performed}
• Threats blocked: {app.threats_detected}

🌐 Backend: {'Online' if app.backend_online else 'Offline'}

What's protected:
• Clipboard URLs
• Copied scam text
• Phishing websites"""
        
        show_notification("📊 PayGuard Status", msg)
    
    def quit_click(icon, item):
        app.stop_monitoring()
        icon.stop()
    
    # Show current status in menu
    status_text = "🟢 ON" if app.protection_enabled else "🔴 OFF"
    
    menu = (
        Item(f"Status: {status_text}", lambda icon, item: None),
        Item("🛡️ Toggle ON/OFF", toggle_protection),
        Item("🔍 Scan Now", scan_now),
        Item("📊 Status", status_click),
        Item("❌ Quit", quit_click),
    )
    return menu


def show_notification(title, message):
    """Show dialog popup - senior-friendly, works cross-platform"""
    try:
        simple_title = title
        simple_message = message
        
        if "DANGER" in message.upper() or "THREAT" in message.upper() or "SCAM" in message.upper():
            simple_title = "WARNING"
            simple_message = "Scam detected! Close the website now!"
        elif "SAFE" in message.upper():
            simple_title = "Safe"
            simple_message = "No threats detected"
        elif "ON" in message.upper():
            simple_title = "Protection ON"
            simple_message = "PayGuard is protecting you"
        elif "OFF" in message.upper():
            simple_title = "Protection OFF"
            simple_message = "PayGuard is paused"
        
        # Use tkinter for dialog popup (works everywhere)
        if HAS_TKINTER:
            def show_dialog():
                root = tk.Tk()
                root.withdraw()
                
                if "WARNING" in simple_title or "SCAM" in simple_message.upper():
                    # Critical alert - show big warning dialog
                    dialog = tk.Toplevel(root)
                    dialog.title("PayGuard Alert")
                    dialog.geometry("450x200")
                    dialog.configure(bg="#ffcccc")
                    
                    # Warning label
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
                        text=simple_message,
                        font=("Arial", 12),
                        bg="#ffcccc",
                        wraplength=400
                    )
                    msg_label.pack(pady=10)
                    
                    ok_btn = tk.Button(
                        dialog,
                        text="I UNDERSTAND - CLOSE WEBSITE",
                        font=("Arial", 14, "bold"),
                        bg="red",
                        fg="white",
                        command=dialog.destroy
                    )
                    ok_btn.pack(pady=20)
                    
                    # Make it pop to front
                    dialog.lift()
                    dialog.attributes('-topmost', True)
                    dialog.mainloop()
                else:
                    # Normal notification - simple dialog
                    dialog = tk.Toplevel(root)
                    dialog.title("PayGuard")
                    dialog.geometry("350x150")
                    dialog.configure(bg="white")
                    
                    label = tk.Label(
                        dialog,
                        text=simple_message,
                        font=("Arial", 12),
                        bg="white",
                        wraplength=300
                    )
                    label.pack(pady=30, padx=20)
                    
                    ok_btn = tk.Button(
                        dialog,
                        text="OK",
                        font=("Arial", 12),
                        command=dialog.destroy
                    )
                    ok_btn.pack(pady=10)
                    
                    dialog.lift()
                    dialog.attributes('-topmost', True)
                    dialog.mainloop()
            
            # Run in thread to not block
            threading.Thread(target=show_dialog, daemon=True).start()
            return
        
        # Fallback: platform-specific
        system = platform.system()
        if system == "Darwin":
            subprocess.Popen([
                "osascript", "-e",
                f'display dialog "{simple_message}" with title "{simple_title}" buttons {{"OK"}} default button "OK" with icon stop'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Windows":
            try:
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(simple_title, simple_message, duration=10, threaded=True)
            except ImportError:
                subprocess.Popen([
                    "powershell", "-Command",
                    f'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show("{simple_message}", "{simple_title}", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Linux - use tkinter or zenity
            try:
                subprocess.Popen(["zenity", "--warning", "--text=" + simple_message, "--title=" + simple_title], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                logger.warning("No dialog available on Linux - install zenity")
    except Exception as e:
        logger.error(f"Dialog error: {e}")


def main():
    """Main entry point"""
    logger.info(f"PayGuard starting on {SYSTEM}...")
    
    # Check critical dependencies
    if not HAS_PYTRAY:
        logger.error("pystray not installed. Run: pip install pystray Pillow")
        sys.exit(1)
    
    # Show available features
    logger.info(f"Features: PIL={HAS_PIL}, pystray={HAS_PYTRAY}, pyperclip={HAS_PYPERCLIP}, mss={HAS_MSS}, tkinter={HAS_TKINTER}")
    
    # Create app
    app = PayGuardApp()
    
    # Create icon (green if ON, red if OFF)
    icon_image = create_icon(green=app.protection_enabled)
    icon = pystray.Icon(
        "payguard",
        icon_image,
        "PayGuard",
        create_menu(app)
    )
    
    # Run
    logger.info("PayGuard ready!")
    try:
        icon.run()
    except KeyboardInterrupt:
        logger.info("PayGuard stopped")


if __name__ == "__main__":
    main()
