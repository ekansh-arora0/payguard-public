#!/usr/bin/env python3
"""
PayGuard Menu Bar App - Optimized Privacy-First Version

PRIVACY NOTICE: This version has been redesigned with privacy-first principles:
- NO continuous screen capture
- NO background clipboard monitoring  
- All scans require explicit user action (button click, menu selection, or keyboard shortcut)
- User data stays on device unless explicitly approved

Performance improvements, better error handling, and cleaner architecture
"""

import subprocess
import time
import threading
import os
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
from pathlib import Path
import json
from concurrent.futures import ThreadPoolExecutor
import queue
import weakref

try:
    from PIL import Image
    import io
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AlertType(Enum):
    """Types of alerts"""
    VISUAL_RED_ALERT = "visual_red_alert"
    VISUAL_WARNING = "visual_warning"
    CLIPBOARD_SCAM = "clipboard_scam"
    PHONE_SCAM = "phone_scam"
    VIRUS_WARNING = "virus_warning"
    PHISHING = "phishing"

@dataclass
class ScamPattern:
    """Scam detection pattern"""
    pattern: str
    weight: int
    name: str
    compiled_regex: re.Pattern = field(init=False)
    
    def __post_init__(self):
        self.compiled_regex = re.compile(self.pattern)

@dataclass
class DetectionResult:
    """Result of scam detection"""
    is_scam: bool
    confidence: float = 0.0
    alert_type: Optional[AlertType] = None
    patterns: List[str] = field(default_factory=list)
    message: str = ""
    advice: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

class PerformanceMonitor:
    """Monitor performance metrics"""
    
    def __init__(self, max_samples: int = 100):
        self.max_samples = max_samples
        self.screen_capture_times: List[float] = []
        self.analysis_times: List[float] = []
        self.clipboard_times: List[float] = []
        self._lock = threading.Lock()
    
    def record_screen_capture_time(self, duration: float):
        """Record screen capture duration"""
        with self._lock:
            self.screen_capture_times.append(duration)
            if len(self.screen_capture_times) > self.max_samples:
                self.screen_capture_times.pop(0)
    
    def record_analysis_time(self, duration: float):
        """Record analysis duration"""
        with self._lock:
            self.analysis_times.append(duration)
            if len(self.analysis_times) > self.max_samples:
                self.analysis_times.pop(0)
    
    def record_clipboard_time(self, duration: float):
        """Record clipboard check duration"""
        with self._lock:
            self.clipboard_times.append(duration)
            if len(self.clipboard_times) > self.max_samples:
                self.clipboard_times.pop(0)
    
    def get_stats(self) -> Dict[str, Dict[str, float]]:
        """Get performance statistics"""
        with self._lock:
            def calc_stats(times: List[float]) -> Dict[str, float]:
                if not times:
                    return {"avg": 0.0, "min": 0.0, "max": 0.0}
                return {
                    "avg": sum(times) / len(times),
                    "min": min(times),
                    "max": max(times)
                }
            
            return {
                "screen_capture": calc_stats(self.screen_capture_times),
                "analysis": calc_stats(self.analysis_times),
                "clipboard": calc_stats(self.clipboard_times)
            }

class ScamDetector:
    """Optimized scam detection engine"""
    
    # Pre-compiled patterns for better performance
    SCAM_PATTERNS = [
        ScamPattern(r'\b1-\d{3}-\d{3}-\d{4}\b', 30, 'phone_number'),
        ScamPattern(r'(?i)\b(urgent|immediate|act now|call now)\b', 25, 'urgency'),
        ScamPattern(r'(?i)\b(virus|infected|malware|trojan)\b', 30, 'virus_warning'),
        ScamPattern(r'(?i)\b(microsoft|apple|amazon|google).*(support|security|alert)\b', 25, 'fake_company'),
        ScamPattern(r'(?i)do not (close|restart|shut down)', 30, 'scare_tactic'),
        ScamPattern(r'(?i)\b(suspended|blocked|expired|compromised)\b', 20, 'account_threat'),
        ScamPattern(r'(?i)\b(verify|update|confirm).*(account|payment|card)\b', 20, 'phishing'),
        ScamPattern(r'(?i)\b(error code|reference id):\s*[a-z0-9-]+', 15, 'fake_error'),
    ]
    
    def __init__(self):
        self.patterns = self.SCAM_PATTERNS.copy()
        self._text_cache = weakref.WeakValueDictionary()
        self._cache_lock = threading.Lock()
    
    def analyze_text(self, text: str) -> DetectionResult:
        """Analyze text for scam patterns with caching"""
        if not text or len(text.strip()) < 10:
            return DetectionResult(is_scam=False)
        
        # Check cache first
        text_hash = hash(text)
        with self._cache_lock:
            if text_hash in self._text_cache:
                return self._text_cache[text_hash]
        
        score = 0
        detected_patterns = []
        
        # Use pre-compiled patterns
        for pattern in self.patterns:
            if pattern.compiled_regex.search(text):
                score += pattern.weight
                detected_patterns.append(pattern.name)
        
        # Calculate confidence with text length consideration
        text_length = len(text)
        pattern_density = len(detected_patterns) / max(text_length / 100, 1)
        confidence = min(score + (pattern_density * 10), 100)
        
        is_scam = score >= 40
        
        result = DetectionResult(
            is_scam=is_scam,
            confidence=confidence,
            patterns=detected_patterns,
            alert_type=self._determine_alert_type(detected_patterns),
            message=self._generate_message(detected_patterns, is_scam),
            advice=self._generate_advice(detected_patterns, is_scam),
            metadata={"score": score, "text_length": text_length}
        )
        
        # Cache result
        with self._cache_lock:
            self._text_cache[text_hash] = result
        
        return result
    
    def analyze_image_colors(self, image_data: bytes) -> DetectionResult:
        """Analyze image colors for scam indicators"""
        if not PIL_AVAILABLE:
            logger.warning("PIL not available for image analysis")
            return DetectionResult(is_scam=False)
        
        try:
            img = Image.open(io.BytesIO(image_data))
            
            # Optimize: resize large images for faster processing
            if img.size[0] > 1920 or img.size[1] > 1080:
                img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
            
            colors = img.getcolors(maxcolors=256*256*256)
            if not colors:
                return DetectionResult(is_scam=False)
            
            total_pixels = sum(count for count, color in colors)
            color_ratios = self._calculate_color_ratios(colors, total_pixels)
            
            return self._evaluate_color_threat(color_ratios)
            
        except Exception as e:
            logger.error(f"Image analysis error: {e}")
            return DetectionResult(is_scam=False)
    
    def _calculate_color_ratios(self, colors: List[Tuple], total_pixels: int) -> Dict[str, float]:
        """Calculate color ratios efficiently"""
        red_pixels = orange_pixels = yellow_pixels = 0
        
        for count, color in colors:
            if isinstance(color, tuple) and len(color) >= 3:
                r, g, b = color[:3]
                
                # Vectorized color detection
                if r > 180 and g < 100 and b < 100:
                    red_pixels += count
                elif r > 200 and 100 < g < 180 and b < 100:
                    orange_pixels += count
                elif r > 200 and g > 200 and b < 100:
                    yellow_pixels += count
        
        return {
            "red": red_pixels / total_pixels,
            "orange": orange_pixels / total_pixels,
            "yellow": yellow_pixels / total_pixels
        }
    
    def _evaluate_color_threat(self, color_ratios: Dict[str, float]) -> DetectionResult:
        """Evaluate threat level based on color ratios"""
        red_ratio = color_ratios["red"]
        orange_ratio = color_ratios["orange"]
        yellow_ratio = color_ratios["yellow"]
        
        if red_ratio > 0.25:
            return DetectionResult(
                is_scam=True,
                confidence=min(85 + (red_ratio * 15), 100),
                alert_type=AlertType.VISUAL_RED_ALERT,
                message='FAKE SECURITY ALERT DETECTED!',
                advice='This red warning screen is FAKE. Close it immediately!',
                metadata={"color_ratios": color_ratios}
            )
        elif orange_ratio > 0.15 or yellow_ratio > 0.15:
            return DetectionResult(
                is_scam=True,
                confidence=70,
                alert_type=AlertType.VISUAL_WARNING,
                message='Suspicious warning screen detected!',
                advice='Be careful - this looks like a fake warning.',
                metadata={"color_ratios": color_ratios}
            )
        
        return DetectionResult(is_scam=False, metadata={"color_ratios": color_ratios})
    
    def _determine_alert_type(self, patterns: List[str]) -> Optional[AlertType]:
        """Determine alert type based on detected patterns"""
        if 'phone_number' in patterns:
            return AlertType.PHONE_SCAM
        elif 'virus_warning' in patterns:
            return AlertType.VIRUS_WARNING
        elif 'phishing' in patterns:
            return AlertType.PHISHING
        return None
    
    def _generate_message(self, patterns: List[str], is_scam: bool) -> str:
        """Generate appropriate message based on patterns"""
        if not is_scam:
            return ""
        
        if 'phone_number' in patterns and 'virus_warning' in patterns:
            return "FAKE TECH SUPPORT SCAM DETECTED!"
        elif 'phishing' in patterns:
            return "PHISHING ATTEMPT DETECTED!"
        elif 'virus_warning' in patterns:
            return "FAKE VIRUS WARNING DETECTED!"
        else:
            return "SCAM CONTENT DETECTED!"
    
    def _generate_advice(self, patterns: List[str], is_scam: bool) -> str:
        """Generate appropriate advice based on patterns"""
        if not is_scam:
            return ""
        
        if 'phone_number' in patterns:
            return "NEVER call random phone numbers from pop-ups or alerts!"
        elif 'phishing' in patterns:
            return "Do not enter personal information on suspicious websites!"
        elif 'virus_warning' in patterns:
            return "This is a fake virus warning. Your computer is safe!"
        else:
            return "Close this window and do not follow any instructions!"

class NotificationManager:
    """Optimized notification system"""
    
    def __init__(self, cooldown_seconds: int = 10):
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time = 0
        self.notification_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notification")
        self._running = True
        self._start_worker()
    
    def _start_worker(self):
        """Start notification worker thread"""
        def worker():
            while self._running:
                try:
                    notification = self.notification_queue.get(timeout=1)
                    if notification:
                        self._send_notification_sync(**notification)
                        self.notification_queue.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Notification worker error: {e}")
        
        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()
    
    def notify_user(self, title: str, message: str, critical: bool = True) -> bool:
        """Queue notification for async delivery"""
        current_time = time.time()
        
        if critical and current_time - self.last_alert_time < self.cooldown_seconds:
            logger.info(f"Notification throttled: {title}")
            return False
        
        if critical:
            self.last_alert_time = current_time
        
        # Queue notification for async processing
        self.notification_queue.put({
            "title": title,
            "message": message,
            "critical": critical
        })
        
        return True
    
    def _send_notification_sync(self, title: str, message: str, critical: bool):
        """Send notification synchronously"""
        try:
            # Sanitize inputs
            clean_title = self._sanitize_text(title)
            clean_message = self._sanitize_text(message)
            
            if critical:
                self._send_critical_notification(clean_title, clean_message)
            else:
                self._send_normal_notification(clean_title, clean_message)
                
        except Exception as e:
            logger.error(f"Notification error: {e}")
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize text for shell commands"""
        return text.replace('\\', '\\\\').replace('"', '\\"')
    
    def _send_critical_notification(self, title: str, message: str):
        """Send critical notification with sound and dialog"""
        # Play alert sound
        subprocess.run(
            ["afplay", "/System/Library/Sounds/Sosumi.aiff"], 
            capture_output=True, 
            timeout=5
        )
        
        # Show notification
        cmd = f'display notification "{message}" with title "{title}" sound name "Hero"'
        subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=10)
        
        # Show dialog with timeout
        dialog_cmd = f'''display dialog "{message}\\n\\nThis is PayGuard protecting you from scams!" with title "{title}" buttons {{"OK", "More Info"}} default button "OK" with icon stop giving up after 30'''
        
        result = subprocess.run(
            ["osascript", "-e", dialog_cmd], 
            capture_output=True, 
            text=True, 
            timeout=35
        )
        
        if "More Info" in result.stdout:
            self._show_info_dialog()
    
    def _send_normal_notification(self, title: str, message: str):
        """Send normal notification"""
        cmd = f'display notification "{message}" with title "{title}"'
        subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=10)
    
    def _show_info_dialog(self):
        """Show information dialog about scams"""
        info_msg = """PayGuard detected suspicious content that looks like a scam. Common scam tactics include:

• Fake virus warnings
• Urgent security alerts  
• Requests to call phone numbers
• Fake company support messages

NEVER call random phone numbers or download software from pop-ups!"""
        
        info_cmd = f'display dialog "{info_msg}" with title "PayGuard - Scam Information" buttons {{"OK"}} default button "OK" with icon caution'
        subprocess.run(["osascript", "-e", info_cmd], capture_output=True, timeout=30)
    
    def shutdown(self):
        """Shutdown notification manager"""
        self._running = False
        self.executor.shutdown(wait=True)

class PayGuardMenuBarOptimized:
    """
    Optimized PayGuard Menu Bar Application - Privacy-First Design
    
    All monitoring capabilities require explicit user action.
    No background capture or clipboard snooping.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        defaults = self._default_config()
        if config:
            defaults.update(config)
        self.config = defaults
        self.running = True
        self.scam_count = 0
        self.last_clipboard_content = ""
        
        # Initialize components
        self.detector = ScamDetector()
        self.notification_manager = NotificationManager(
            cooldown_seconds=self.config["alert_cooldown"]
        )
        self.performance_monitor = PerformanceMonitor()
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Temporary file management
        self.temp_files: List[Path] = []
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            "alert_cooldown": 10,
            "screen_check_interval": 4,
            "clipboard_check_interval": 2,
            "status_update_interval": 30,
            "max_image_size": (1920, 1080),
            "enable_performance_monitoring": True,
            "log_level": "INFO"
        }
    
    @contextmanager
    def _temp_file_manager(self, suffix: str = ".tmp"):
        """Context manager for temporary files"""
        temp_path = None
        try:
            import tempfile
            fd, temp_path = tempfile.mkstemp(suffix=suffix)
            os.close(fd)
            temp_path = Path(temp_path)
            self.temp_files.append(temp_path)
            yield temp_path
        finally:
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                    if temp_path in self.temp_files:
                        self.temp_files.remove(temp_path)
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file {temp_path}: {e}")
    
    def capture_screen(self) -> Optional[bytes]:
        """
        Optimized screen capture - USER-INITIATED ONLY
        
        This method should only be called in response to explicit user action
        (button click, menu selection, or keyboard shortcut).
        
        Returns:
            bytes: Screen capture data, or None if capture failed
        """
        start_time = time.time()
        
        try:
            with self._temp_file_manager(".png") as temp_path:
                result = subprocess.run(
                    ["screencapture", "-x", "-C", str(temp_path)], 
                    capture_output=True, 
                    timeout=5
                )
                
                if result.returncode == 0 and temp_path.exists():
                    data = temp_path.read_bytes()
                    
                    # Record performance
                    if self.config["enable_performance_monitoring"]:
                        duration = time.time() - start_time
                        self.performance_monitor.record_screen_capture_time(duration)
                    
                    return data
                    
        except Exception as e:
            logger.error(f"Screen capture error: {e}")
        
        return None
    
    def analyze_screen(self, image_data: bytes) -> DetectionResult:
        """
        Analyze screen - USER-INITIATED ONLY
        
        This method analyzes screen content for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            image_data: Screen capture bytes from capture_screen()
            
        Returns:
            DetectionResult: Detection result with is_scam, confidence, etc.
        """
        start_time = time.time()
        
        try:
            result = self.detector.analyze_image_colors(image_data)
            
            # Record performance
            if self.config["enable_performance_monitoring"]:
                duration = time.time() - start_time
                self.performance_monitor.record_analysis_time(duration)
            
            return result
            
        except Exception as e:
            logger.error(f"Screen analysis error: {e}")
            return DetectionResult(is_scam=False)
    
    def analyze_text(self, text: str) -> DetectionResult:
        """
        Analyze text - USER-INITIATED ONLY
        
        This method analyzes provided text for potential scam indicators.
        Should only be called after user explicitly requests a scan.
        
        Args:
            text: Text content to analyze
            
        Returns:
            DetectionResult: Detection result
        """
        start_time = time.time()
        
        try:
            # Analyze text
            detection_result = self.detector.analyze_text(text)
            
            # Record performance
            if self.config["enable_performance_monitoring"]:
                duration = time.time() - start_time
                self.performance_monitor.record_clipboard_time(duration)
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Text analysis error: {e}")
            return DetectionResult(is_scam=False)
    
    def check_clipboard(self) -> DetectionResult:
        """
        Check clipboard for scam content - USER-INITIATED ONLY
        
        Reads the current clipboard text via pbpaste and analyzes it.
        Skips analysis if the content hasn't changed since last check.
        
        Returns:
            DetectionResult: Detection result
        """
        start_time = time.time()
        
        try:
            result = subprocess.run(
                ["pbpaste"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return DetectionResult(is_scam=False)
            
            content = result.stdout
            
            # Skip if content hasn't changed
            if content == self.last_clipboard_content:
                return DetectionResult(is_scam=False)
            
            self.last_clipboard_content = content
            
            # Analyze the clipboard text
            detection_result = self.detector.analyze_text(content)
            
            # Record performance
            if self.config["enable_performance_monitoring"]:
                duration = time.time() - start_time
                self.performance_monitor.record_clipboard_time(duration)
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Clipboard check error: {e}")
            return DetectionResult(is_scam=False)
    
    def scan_screen_now(self) -> DetectionResult:
        """
        User-initiated screen scan
        
        Call this method when user explicitly requests a screen scan
        (e.g., clicks "Scan Now" button or uses keyboard shortcut).
        
        Returns:
            DetectionResult: Detection result
        """
        logger.info("🔍 User-initiated screen scan...")
        image_data = self.capture_screen()
        if image_data:
            result = self.analyze_screen(image_data)
            self.handle_detection(result, "screen")
            return result
        return DetectionResult(is_scam=False, message="Failed to capture screen")
    
    def scan_text_now(self, text: str) -> DetectionResult:
        """
        User-initiated text scan
        
        Call this method when user explicitly requests a text scan
        (e.g., pastes text and clicks "Scan" button).
        
        Args:
            text: Text content to analyze
            
        Returns:
            DetectionResult: Detection result
        """
        logger.info("🔍 User-initiated text scan...")
        result = self.analyze_text(text)
        self.handle_detection(result, "text")
        return result
    
    def update_status(self):
        """Update status display"""
        try:
            status = f"🛡️ PayGuard Active - {self.scam_count} scams blocked"
            logger.info(f"Status: {status}")
            
            # Log performance stats if enabled
            if self.config["enable_performance_monitoring"]:
                stats = self.performance_monitor.get_stats()
                logger.debug(f"Performance stats: {stats}")
                
        except Exception as e:
            logger.error(f"Status update error: {e}")
    
    def handle_detection(self, result: DetectionResult, source: str):
        """Handle scam detection result"""
        if not result.is_scam:
            return
        
        with self._lock:
            self.scam_count += 1
        
        # Send notification
        success = self.notification_manager.notify_user(
            f"🚨 PayGuard {source.title()} Alert",
            result.message,
            critical=True
        )
        
        if success:
            logger.warning(f"SCAM #{self.scam_count} BLOCKED ({source}): {result.message}")
        else:
            logger.info(f"Notification throttled for {source} detection")
    
    def start(self):
        """
        Start PayGuard in user-initiated mode
        
        PayGuard now operates in a privacy-first mode where all scans
        require explicit user action. No background monitoring.
        """
        logger.info("🛡️ PAYGUARD MENU BAR - PRIVACY-FIRST MODE")
        logger.info("=" * 50)
        
        # Send startup notification
        self.notification_manager.notify_user(
            "🛡️ PayGuard Active",
            "PayGuard is ready. Use 'Scan Now' to check for scams.",
            critical=False
        )
        
        logger.info("✅ PayGuard is now running in privacy-first mode!")
        logger.info("")
        logger.info("🔒 PRIVACY FEATURES:")
        logger.info("   • NO continuous screen capture")
        logger.info("   • NO background clipboard monitoring")
        logger.info("   • All scans require YOUR explicit action")
        logger.info("")
        logger.info("📱 AVAILABLE COMMANDS:")
        logger.info("   • scan_screen_now() - Scan current screen")
        logger.info("   • scan_text_now(text) - Scan provided text")
        logger.info("")
        logger.info("Press Ctrl+C to stop PayGuard")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\n🛑 Stopping PayGuard...")
            self.shutdown()
    
    def shutdown(self):
        """Graceful shutdown"""
        self.running = False
        
        # Shutdown components
        self.notification_manager.shutdown()
        
        # Cleanup temp files
        for temp_file in self.temp_files[:]:
            try:
                if temp_file.exists():
                    temp_file.unlink()
                self.temp_files.remove(temp_file)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")
        
        # Final notification
        self.notification_manager.notify_user(
            "PayGuard Stopped",
            "Scam protection has been disabled.",
            critical=False
        )
        
        logger.info("✅ PayGuard stopped")

def main():
    """Main function with configuration support"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PayGuard Menu Bar Protection")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    config = None
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
    
    payguard = PayGuardMenuBarOptimized(config)
    payguard.start()

if __name__ == "__main__":
    main()