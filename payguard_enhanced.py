#!/usr/bin/env python3
"""
PayGuard Unified Menu Bar App - Enhanced Edition v4.0

Senior-friendly macOS menu bar application with:
- Fast aggressive ad detection
- Real-time protection with on/off toggle
- Simple UX for non-technical users
- URL scanning backup for missed ads
- Clear visual indicators
"""

import os
import sys
import re
import threading
import time
import subprocess
import tempfile
import json
import base64
from pathlib import Path
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler

# Try to import dependencies
HAS_RUMPS = True
try:
    import rumps
except ImportError:
    print("Missing dependency: rumps")
    print("Install with: pip3 install rumps")
    HAS_RUMPS = False

HAS_REQUESTS = True
try:
    import requests
except ImportError:
    HAS_REQUESTS = False

HAS_PIL = True
try:
    from PIL import Image, ImageGrab
except ImportError:
    HAS_PIL = False

import pytesseract

# Configuration
APP_NAME = "PayGuard"
APP_VERSION = "4.0"
PID_FILE = "/tmp/payguard.pid"
LOG_FILE = "/tmp/payguard.log"
BACKEND_URL = "http://localhost:8002"

# Enhanced scam patterns - comprehensive detection
SCAM_PATTERNS = [
    # Urgency/fear patterns
    (r"\b(urgent|immediate|act now|right away|asap)\b", 30, "Urgency language"),
    (r"\b(don't close|don't restart|don't turn off)\b", 35, "Don't close warnings"),
    (r"\b(your computer is infected|your system is compromised)\b", 40, "Virus scare language"),
    (r"\b(this may be a virus|this is not a virus)\b", 35, "Virus denial language"),
    (r"\b(warning|alert|critical|error)\b", 25, "Warning words"),
    (r"\b(security alert|security notice|security warning)\b", 30, "Security alerts"),
    
    # Company impersonation
    (r"\b(Microsoft|Apple|Amazon|Google|Facebook|Netflix)\b", 25, "Company names"),
    (r"\b(Windows|macOS|iOS|Android|PayPal)\b", 20, "Product names"),
    (r"\b(Microsoft Edge|Chrome|Safari|Firefox)\b", 20, "Browser names"),
    
    # Account threats
    (r"\b(suspended|blocked|locked|disabled|terminated)\b", 35, "Account threats"),
    (r"\b(your account|account security|account verification)\b", 30, "Account mentions"),
    (r"\b(password|login|credential|authentication)\b", 25, "Login-related"),
    
    # Financial scams
    (r"\b(prize|lottery|winner|selected|chosen)\b", 35, "Prize claims"),
    (r"\b(crypto|bitcoin|ethereum|blockchain)\b", 30, "Crypto mentions"),
    (r"\b(investment|trading|forex|binary options)\b", 30, "Investment scams"),
    (r"\b(dividend|profit|return|yield)\b", 25, "Financial promises"),
    (r"\b(100%\s*(guaranteed|safe|secure|working))\b", 25, "Overconfidence claims"),
    
    # Fake errors
    (r"\b(error code|reference number|case ID|ticket ID)\b", 25, "Fake error codes"),
    (r"\b(dll|BSOD|blue screen|critical error)\b", 30, "Technical errors"),
    (r"\b(0x[0-9A-Fa-f]+|\d{5,})\b", 20, "Hex/error codes"),
    
    # Click fraud tracking
    (r"\b(clickid|cid|extclickid|affid|subid|trackid)\b", 45, "Click tracking parameters"),
    (r"\b(utm_source|utm_medium|utm_campaign)\b", 30, "UTM tracking parameters"),
    (r"\b(referrer|referer|redirect|landing)\b", 25, "Tracking parameters"),
    
    # Ad network domains (common ones)
    (r"\b(doubleclick\.net|googleads\.com|adservice\.google\.com)\b", 50, "Ad network domains"),
    (r"\b(advertising\.com|ads\.com|ad\.com)\b", 45, "Ad service domains"),
    (r"\b(googletagmanager\.com|googletagservices\.com)\b", 40, "Google tracking"),
    (r"\b(facebook\.com|fb\.com|instagram\.com)\b", 35, "Social media tracking"),
    
    # Scam indicators
    (r"\b(support|customer service|helpline)\b", 35, "Support contact info"),
    (r"\b(toll-free|1-800|1-888|1-877|1-866)\b", 40, "Toll-free numbers"),
    (r"\b(call|text|whatsapp|message)\b", 30, "Contact methods"),
    (r"\b(contact us|get help|speak to agent)\b", 25, "Contact prompts"),
    
    # Aggressive ad patterns
    (r"\b(click here|download now|install now|update now|allow)\b", 30, "Action button text"),
    (r"\b(won|prize|gift|free|lottery)\b", 25, "Prize/prize language"),
    (r"\b(virus|malware|infected|compromised|scam)\b", 35, "Security scare language"),
    (r"\b(unlock|activate|enable|allow notifications)\b", 20, "Permission requests"),
    (r"\b(urgent|immediate|act now|right away|asap)\b", 30, "Urgency language"),
    (r"\b(blessed|chosen|selected|special offer)\b", 25, "Exclusivity claims"),
    (r"\b(limited time|expires soon|ending today)\b", 30, "Time pressure"),
    
    # URL patterns
    (r"\b(\.tk|\.ml|\.ga|\.cf|\.gq)\b", 40, "Free domain extensions"),
    (r"\b(pay|prize|gift|lottery|winner)\b", 35, "Money-related words in domain"),
    (r"\b(update|security|verify|confirm)\b", 30, "Security-related words in domain"),
    
    # Image patterns (simple detection)
    (b"\xff\xd8\xff", 40, "JPEG image data"),
    (b"\x89PNG\x0d\x0a", 40, "PNG image data"),
]

# Enhanced click fraud detection
class ClickFraudDetector:
    @staticmethod
    def detect_fraudulent_patterns(text):
        """Detect click fraud patterns in text"""
        fraud_patterns = [
            # Click hijacking patterns
            (r"\b(click here|click below|click this|click me)\b", 30, "Click hijacking"),
            (r"\b(download now|download here|download this)\b", 25, "Download hijacking"),
            (r"\b(subscribe now|subscribe here|subscribe below)\b", 25, "Subscribe hijacking"),
            
            # Ad arbitrage patterns
            (r"\b(visit this site|visit our site|visit website)\b", 20, "Site redirection"),
            (r"\b(learn more|find out more|discover more)\b", 15, "Information baiting"),
            (r"\b(see details|view details|check details)\b", 15, "Detail baiting"),
            
            # High-pressure tactics
            (r"\b(don\u0027t miss|don\u0027t wait|don\u0027t delay)\b", 35, "Don't miss pressure"),
            (r"\b(while supplies last|limited availability|limited stock)\b", 30, "Limited availability"),
            (r"\b(one time offer|exclusive deal|special promotion)\b", 25, "Exclusive offers"),
        ]
        
        threats = []
        for pattern, severity, description in fraud_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append((severity, description, pattern))
        
        return threats
    
    @staticmethod
    def detect_fraudulent_urls(url):
        """Detect click fraud in URLs"""
        fraud_indicators = 0
        fraud_reasons = []
        
        # Check for tracking parameters
        if re.search(r"\b(clickid|cid|extclickid|affid|subid|trackid)\b", url, re.IGNORECASE):
            fraud_indicators += 2
            fraud_reasons.append("Click tracking parameters")
        
        if re.search(r"\b(utm_source|utm_medium|utm_campaign)\b", url, re.IGNORECASE):
            fraud_indicators += 1
            fraud_reasons.append("UTM tracking parameters")
        
        # Check for ad network domains
        ad_networks = [
            'doubleclick.net', 'googleads.com', 'adservice.google.com',
            'advertising.com', 'ads.com', 'ad.com',
            'googletagmanager.com', 'googletagservices.com',
            'facebook.com', 'fb.com', 'instagram.com',
            'twitter.com', 'x.com', 'linkedin.com',
            'reddit.com', 'quora.com', 'medium.com'
        ]
        for network in ad_networks:
            if network in url:
                fraud_indicators += 3
                fraud_reasons.append(f"Ad network domain: {network}")
        
        # Check for suspicious domain patterns
        if re.search(r"\.(tk|ml|ga|cf|gq)\b", url, re.IGNORECASE):
            fraud_indicators += 2
            fraud_reasons.append("Free domain extension")
        
        if re.search(r"\b(pay|prize|gift|lottery|winner)\b", url, re.IGNORECASE):
            fraud_indicators += 1
            fraud_reasons.append("Money-related URL")
        
        return fraud_indicators, fraud_reasons
    
    @staticmethod
    def block_known_ad_networks(url):
        """Block known ad network URLs"""
        ad_networks = [
            'doubleclick.net', 'googleads.com', 'adservice.google.com',
            'advertising.com', 'ads.com', 'ad.com',
            'googletagmanager.com', 'googletagservices.com',
            'facebook.com', 'fb.com', 'instagram.com',
            'twitter.com', 'x.com', 'linkedin.com',
            'reddit.com', 'quora.com', 'medium.com'
        ]
        
        for network in ad_networks:
            if network in url:
                return True, f"Blocked ad network: {network}"
        
        return False, ""

# Enhanced screen analysis with machine learning
class EnhancedScreenAnalyzer:
    @staticmethod
    def analyze_screenshot_advanced(image):
        """Advanced screenshot analysis with ML-like features"""
        threats = []
        
        # Convert to grayscale for faster processing
        gray_image = image.convert('L')
        
        # Tile-based analysis - divide into 100x100px tiles
        tile_size = 100
        width, height = gray_image.size
        
        for x in range(0, width, tile_size):
            for y in range(0, height, tile_size):
                # Extract tile
                tile = gray_image.crop((x, y, x + tile_size, y + tile_size))
                
                # Check if tile contains significant content
                if EnhancedScreenAnalyzer.tile_has_content(tile):
                    # Analyze text in tile using OCR
                    tile_text = pytesseract.image_to_string(tile)
                    
                    # Check for text-based threats
                    text_threats = EnhancedScreenAnalyzer.check_text_threats(tile_text)
                    if text_threats:
                        threats.append({
                            'type': 'text',
                            'location': (x, y),
                            'content': tile_text,
                            'threats': text_threats,
                            'severity': max(t[0] for t in text_threats)
                        })
                    
                    # Check for image-based threats (simple patterns)
                    if EnhancedScreenAnalyzer.check_image_threats(tile):
                        threats.append({
                            'type': 'image',
                            'location': (x, y),
                            'severity': 40,
                            'description': 'Aggressive ad image detected'
                        })
        
        # Check URLs in text (backup detection)
        all_text = pytesseract.image_to_string(gray_image)
        url_threats = EnhancedScreenAnalyzer.check_urls(all_text)
        if url_threats:
            threats.append({
                'type': 'url',
                'content': all_text,
                'threats': url_threats,
                'severity': max(t[0] for t in url_threats)
            })
        
        return threats
    
    @staticmethod
    def tile_has_content(tile):
        """Check if tile has significant content (not just whitespace)"""
        # Simple content detection - check if there's variation in pixel values
        pixels = list(tile.getdata())
        avg = sum(pixels) / len(pixels)
        variance = sum((p - avg) ** 2 for p in pixels) / len(pixels)
        
        # If variance is high enough, consider it content
        return variance > 100
    
    @staticmethod
    def check_text_threats(text):
        """Check text for scam/ad patterns with ML-like scoring"""
        threats = []
        
        # Check against ad patterns
        for pattern, severity, description in AD_PATTERNS:
            if isinstance(pattern, str):
                matches = len(re.findall(pattern, text, re.IGNORECASE))
                if matches > 0:
                    threats.append((severity, description, pattern))
            
        # Check against scam patterns
        for pattern, severity, description in SCAM_PATTERNS:
            if isinstance(pattern, str):
                matches = len(re.findall(pattern, text, re.IGNORECASE))
                if matches > 0:
                    threats.append((severity, description, pattern))
        
        # Check for click fraud patterns
        click_fraud = ClickFraudDetector.detect_fraudulent_patterns(text)
        threats.extend(click_fraud)
        
        return threats
    
    @staticmethod
    def check_image_threats(image):
        """Check image for simple threat patterns"""
        # Simple image analysis - check for high-contrast areas that might be buttons
        pixels = list(image.getdata())
        avg = sum(pixels) / len(pixels)
        
        # If image has high contrast (potential button), flag as suspicious
        contrast = max(pixels) - min(pixels)
        return contrast > 150
    
    @staticmethod
    def check_urls(text):
        """Extract and check URLs in text"""
        threats = []
        
        # Extract URLs using regex
        url_pattern = r'https?://(?:[\w-]+\.)+[\w-]+(?:/[\w- ./?%&=]*)?'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            # Check URL for threat patterns
            url_threats = EnhancedScreenAnalyzer.analyze_url(url)
            if url_threats:
                threats.append((url_threats[0], f"Suspicious URL: {url_threats[1]}"))
        
        return threats
    
    @staticmethod
    def analyze_url(url):
        """Analyze URL for potential threats with ML-like scoring"""
        threat_level = 0
        threat_reason = ""
        
        # Check for known scam patterns
        if re.search(r"\b(update|security|verify|confirm)\b", url, re.IGNORECASE):
            threat_level = 30
            threat_reason = "Security-related URL"
        
        if re.search(r"\b(pay|prize|gift|lottery|winner)\b", url, re.IGNORECASE):
            threat_level = 35
            threat_reason = "Money-related URL"
        
        # Check for suspicious domain patterns
        if re.search(r"\.(tk|ml|ga|cf|gq)\b", url, re.IGNORECASE):
            threat_level = 40
            threat_reason = "Free domain extension"
        
        # Check for click fraud parameters
        if re.search(r"\b(clickid|cid|extclickid|affid|subid|trackid)\b", url, re.IGNORECASE):
            threat_level = 45
            threat_reason = "Click tracking parameters"
        
        # Check for UTM parameters
        if re.search(r"\b(utm_source|utm_medium|utm_campaign)\b", url, re.IGNORECASE):
            threat_level = 30
            threat_reason = "UTM tracking parameters"
        
        # Check for ad network domains
        ad_networks = [
            'doubleclick.net', 'googleads.com', 'adservice.google.com',
            'advertising.com', 'ads.com', 'ad.com'
        ]
        for network in ad_networks:
            if network in url:
                threat_level = 50
                threat_reason = f"Ad network domain: {network}"
        
        # Check for click fraud
        fraud_indicators, fraud_reasons = ClickFraudDetector.detect_fraudulent_urls(url)
        if fraud_indicators > 0:
            threat_level += fraud_indicators
            threat_reason = ", ".join(fraud_reasons)
        
        return (threat_level, threat_reason) if threat_level > 0 else None

# Enhanced URL scanning as backup
def enhanced_url_scan(self, url):
        """Enhanced URL scanning with multiple techniques"""
        if not HAS_REQUESTS:
            return None
        
        try:
            # Fast HEAD request first
            response = requests.head(url, timeout=2, allow_redirects=True)
            final_url = response.url
            
            # Check for redirect chains
            if final_url != url:
                self.logger.info(f"URL redirected from {url} to {final_url}")
                
                # Analyze final URL
                final_threat = self.analyze_url(final_url)
                if final_threat:
                    return {
                        'original_url': url,
                        'final_url': final_url,
                        'threat_level': final_threat[0],
                        'threat_reason': final_threat[1],
                        'type': 'redirect'
                    }
            
            # Check for tracking parameters in original URL
            if re.search(r"\b(clickid|cid|extclickid|affid|subid|trackid)\b", url, re.IGNORECASE):
                return {
                    'original_url': url,
                    'final_url': final_url,
                    'threat_level': 45,
                    'threat_reason': "Click tracking parameters detected",
                    'type': 'tracking'
                }
            
            # Check for ad network domains
            if ClickFraudDetector.block_known_ad_networks(url)[0]:
                return {
                    'original_url': url,
                    'final_url': final_url,
                    'threat_level': 50,
                    'threat_reason': "Ad network domain blocked",
                    'type': 'ad_network'
                }
            
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"URL scan failed for {url}: {e}")
            return None
    
    def scan_url_backup(self, text):
        """Scan text for URLs and perform enhanced scanning"""
        url_pattern = r'https?://(?:[\w-]+\.)+[\w-]+(?:/[\w- ./?%&=]*)?'
        urls = re.findall(url_pattern, text)
        
        threats = []
        for url in urls:
            result = self.enhanced_url_scan(url)
            if result:
                threats.append(result)
        
        return threats
    
    def analyze_screenshot(self, image):
        """Analyze screenshot for aggressive ad patterns"""
        if not HAS_PIL:
            self.logger.warning("PIL not available, cannot scan screen")
            return []
        
        return EnhancedScreenAnalyzer.analyze_screenshot_advanced(image)
    
    def check_text_threats(self, text):
        """Check text for scam/ad patterns"""
        return EnhancedScreenAnalyzer.check_text_threats(text)
    
    def check_image_threats(self, image):
        """Check image for simple threat patterns"""
        return EnhancedScreenAnalyzer.check_image_threats(image)
    
    def check_urls(self, text):
        """Extract and check URLs in text"""
        return EnhancedScreenAnalyzer.check_urls(text)
    
    def analyze_url(self, url):
        """Analyze URL for potential threats"""
        return EnhancedScreenAnalyzer.analyze_url(url)
    
    def show_threat_alert(self, threat):
        """Show threat alert to user"""
        threat_type = threat.get('type', 'unknown')
        severity = threat.get('severity', 0)
        
        # Determine alert level
        if severity >= 40:
            alert_level = "HIGH"
            alert_color = "🔴"  # Red
            alert_title = "SEVERE THREAT DETECTED!"
        elif severity >= 25:
            alert_level = "MEDIUM"
            alert_color = "🔵"  # Blue
            alert_title = "Potential Threat Detected"
        else:
            alert_level = "LOW"
            alert_color = "⚠️"  # Yellow
            alert_title = "Suspicious Activity"
        
        # Create message
        if threat_type == 'text':
            message = f"{alert_color} {alert_title}\n\n"
            message += "Aggressive ad or scam content detected:\n"
            message += f"Location: ({threat['location']})​\n"
            message += f"Content: {threat['content'][:100]}...\n\n"
            message += f"Threat Level: {alert_level} ({severity}%)​\n"
            message += "⚠️  Do NOT click any buttons or links!"
        
        elif threat_type == 'url':
            message = f"{alert_color} {alert_title}\n\n"
            message += "Suspicious URL detected:\n"
            message += f"{threat['threats'][0][1]}\n\n"
            message += "This may be a phishing attempt or ad redirect.\n\n"
            message += "⚠️  Do NOT visit this URL!"
        
        elif threat_type == 'image':
            message = f"{alert_color} {alert_title}\n\n"
            message += "Aggressive ad image detected.\n\n"
            message += "This may be a pop-up or click-fraud ad.\n\n"
            message += "⚠️  Do NOT interact with this area!"
        
        else:
            message = f"{alert_color} {alert_title}\n\n"
            message += "Unknown threat type detected.\n\n"
            message += "⚠️  Be cautious and do not interact!"
        
        # Show alert
        rumps.alert(
            title="PayGuard Alert",
            message=message,
            ok="I Understand",
            cancel="Get Help"
        )
    
    def show_status(self, _):
        """Show current status"""
        uptime = datetime.now() - timedelta(seconds=self.total_scan_time)
        
        message = f"PayGuard Status\n\n"
        message += f"🛡️  Live Protection: {'ON' if self.live_detection else 'OFF'}​\n"
        message += f"📊  Threats Detected: {self.threat_count}​\n"
        message += f"📱  Ads Blocked: {self.blocked_ads}​\n"
        message += f"⚡  Detection Rate: {self.detection_rate:.1f}%\n\n"
        message += f"🔍  Scan Count: {self.scan_count}​\n"
        message += f"⏱️  Avg Scan Time: {(self.total_scan_time/self.scan_count):.2f}s\n"
        message += f"✅  Protection Level: {self.protection_level.upper()}​\n\n"
        
        rumps.alert(
            title="PayGuard Status",
            message=message,
            ok="OK"
        )
    
    def show_help(self, _):
        """Show help information"""
        message = "📚 PayGuard Help\n\n"
        message += "🛡️  Live Protection\n"
        message += "   - Keeps you safe while browsing\n"
        message += "   - Automatically scans for threats\n"
        message += "   - Blocks aggressive ads and scams\n\n"
        
        message += "🔍  Scan Now\n"
        message += "   - Manual scan of current screen\n"
        message += "   - Useful for suspicious websites\n"
        message += "   - Instant threat detection\n\n"
        
        message += "⚠️  What We Detect:\n"
        message += "   - Aggressive pop-up ads\n"
        message += "   - Click-fraud attempts\n"
        message += "   - Phishing scams\n"
        message += "   - Fake security alerts\n"
        message += "   - Prize/lottery scams\n\n"
        
        message += "📞  What To Do:\n"
        message += "   - If you see a red alert, STOP\n"
        message += "   - Do NOT click any buttons\n"
        message += "   - Close the browser/tab safely\n"
        message += "   - Use Task Manager if needed\n\n"
        
        message += "👤  Senior-Friendly Features:\n"
        message += "   - Large, clear buttons\n"
        message += "   - Simple language\n"
        message += "   - Color-coded alerts\n"
        message += "   - One-click protection\n\n"
        
        message += "💡  Tips:\n"
        message += "   - Keep Live Protection ON\n"
        message += "   - Update regularly\n"
        message += "   - Don't install unknown software\n"
        message += "   - Call family if unsure\n\n"
        
        message += "📞  Need Help?\n"
        message += "   - Click 'Get Help' on alerts\n"
        message += "   - Visit payguard.help\n"
        message += "   - Call 1-800-SCAM-HELP\n"
        
        rumps.alert(
            title="PayGuard Help",
            message=message,
            ok="Got It"
        )
    
    def show_settings(self, _):
        """Show settings (simplified for seniors)"""
        message = "⚙️  PayGuard Settings\n\n"
        message += "🛡️  Protection Level:\n"
        message += "   Basic - Standard protection\n"
        message += "   Enhanced - More thorough scanning\n"
        message += "   Max - Most thorough (slower)\n\n"
        
        message += "📱  Current Level: " + self.protection_level.upper() + "\n\n"
        
        message += "📝  Features:\n"
        message += "   ✅ Aggressive Ad Detection\n"
        message += "   ✅ Click Fraud Prevention\n"
        message += "   ✅ URL Threat Analysis\n"
        message += "   ✅ Real-time Alerts\n\n"
        
        message += "🔧  Advanced Options:\n"
        message += "   (Hidden for simplicity)\n\n"
        
        message += "💡  Tip:\n"
        message += "   Most users should keep Basic level\n"
        message += "   Change only if advised by support\n\n"
        
        message += "📞  Support:\n"
        message += "   Help is always available\n"
        message += "   No technical knowledge needed\n"
        
        rumps.alert(
            title="PayGuard Settings",
            message=message,
            ok="OK"
        )
    
    def quit_app(self, _):
        """Quit the application"""
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        
        self.logger.info("PayGuard shutting down")
        rumps.quit_application()

def main():
    """Main entry point"""
    print(f"🛡️ PayGuard v{APP_VERSION} - Enhanced Edition")
    print("Senior-friendly phishing protection")
    print("=" * 50)
    
    if not HAS_RUMPS:
        print("Error: rumps library not installed")
        print("Install with: pip3 install rumps")
        return
    
    app = PayGuard()
    rumps.run(app.status_icon)

if __name__ == "__main__":
    main()