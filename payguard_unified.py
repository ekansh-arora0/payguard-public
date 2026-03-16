#!/usr/bin/env python3
"""
PayGuard Unified - Phishing, Scam, AI Image, Deepfake & Ad Detector
Menu bar app: ON/OFF toggle, auto-scans screen every ~3s, popup alerts on threats.
Integrates: color analysis, OCR scam patterns, AI image detection, email guardian,
            aggressive ads, URL reputation, risk engine, video/audio deepfake detection.
All detectors run IN PARALLEL via ThreadPoolExecutor for sub-second detection.

Supports: macOS, Windows, Linux
"""

import os
import sys
import re
import platform

IS_MAC = platform.system() == 'Darwin'
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

# Suppress HuggingFace tokenizer parallelism warning when forking threads
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
import time
import subprocess
import threading
import io
import hashlib
import logging
import difflib
import asyncio
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import rumps
except ImportError:
    print("Missing: pip3 install rumps")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("Missing: pip3 install Pillow")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= Detection Patterns =============

SCAM_PATTERNS = [
    (re.compile(r'\b1-\d{3}-\d{3}-\d{4}\b'), 'phone_number', 30),
    (re.compile(r'(?i)\b(urgent|immediate|act now|call now)\b'), 'urgency', 25),
    (re.compile(r'(?i)\b(virus|infected|malware|trojan)\b'), 'virus_warning', 35),
    (re.compile(r'(?i)\b(microsoft|apple|amazon|google).*(support|security|alert)\b'), 'fake_company', 25),
    (re.compile(r'(?i)do not (close|restart|shut down)'), 'scare_tactic', 30),
    (re.compile(r'(?i)\b(suspended|blocked|expired|compromised)\b'), 'account_threat', 20),
    (re.compile(r'(?i)\b(verify|update|confirm).*(account|payment|card)\b'), 'phishing', 25),
    (re.compile(r'(?i)\b(error code|reference id):\s*[a-z0-9-]+'), 'fake_error', 15),
    (re.compile(r'(?i)\b(prize|winner|lottery|congratulations)\b'), 'prize_scam', 30),
    (re.compile(r'(?i)\b(free gift|claim now|click here)\b'), 'click_fraud', 25),
]

URL_SCAM_PATTERNS = [
    'apple.com.verify', 'microsoft.security', 'google.account', 'amazon.payment',
    'paypal.verify', 'netflix.account', 'facebook.security', 'instagram.verify',
    'account.update', 'password.reset', 'login.verify', 'secure.login',
    'bank.security', 'verify.identity', 'confirm.payment',
]

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'zip', 'review', 'country', 'bid', 'lol',
    'link', 'kim', 'men', 'live', 'ru', 'biz', 'info', 'support',
    'security', 'account', 'verify', 'update', 'tk', 'ml', 'ga', 'cf', 'gq',
}

# Only genuinely shady affiliate/adware params — NOT standard analytics (utm_*, cid, etc.)
# utm_source/utm_medium/utm_campaign appear on virtually every news/newsletter URL and are
# Google Analytics standard params, not scam indicators.
TRACKING_PARAMS = ['clickid', 'affid', 'subid', 'trackid']

AD_NETWORK_DOMAINS = {
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'adnxs.com', 'adsrvr.org', 'outbrain.com', 'taboola.com',
    'revcontent.com', 'mgid.com', 'content.ad', 'zergnet.com',
    'adblade.com', 'adroll.com', 'criteo.com', 'media.net',
    'popads.net', 'popcash.net', 'propellerads.com', 'admaven.com',
    'clickadu.com', 'hilltopads.net', 'trafficjunky.com',
}

AD_TEXT_PATTERNS = [
    (re.compile(r'(?i)\b(download now|install now|update now)\b'), 'aggressive_download', 20),
    (re.compile(r'(?i)\b(your (computer|device|phone) (is|has been|may be))\b'), 'fake_device_warning', 30),
    (re.compile(r'(?i)\b(clean(er|up)|speed up|optimize|boost)\b.*\b(pc|mac|computer|phone)\b'), 'fake_optimizer', 25),
    (re.compile(r'(?i)\b(singles|dating|meet|hookup)\b.*\b(near you|in your area|tonight)\b'), 'dating_scam_ad', 20),
    (re.compile(r'(?i)\b(make \$|earn \$|\$\d+.*(per|a) (day|hour|week))\b'), 'money_scam_ad', 25),
    (re.compile(r'(?i)\b(doctors? hate|this one trick|they don.t want you)\b'), 'clickbait_ad', 15),
    (re.compile(r'(?i)\b(limited time|act fast|expires? (soon|today))\b'), 'urgency_ad', 15),
]

PROTECTED_BRANDS = [
    'microsoft', 'google', 'apple', 'amazon', 'paypal', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe',
    'outlook', 'office365', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'stripe', 'coinbase', 'binance', 'metamask', 'norton', 'mcafee',
]

HOMOGLYPH_MAP = {
    'vv': 'w', 'rn': 'm', 'cl': 'd', 'nn': 'm',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a',
    '5': 's', '8': 'b', '|': 'l', '!': 'i', 'v': 'u',
}

URL_SHORTENERS = {
    'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly',
    'goo.gl', 'bit.do', 'ow.ly', 'shorte.st', 'tiny.cc',
}


# ============= Backend Integration Classes (Lazy Loaded, Thread-Safe) =============

class URLReputationChecker:
    """Lazy wrapper for backend/url_reputation.py — thread-safe with lock"""

    _instance = None
    _service = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _load_service(self):
        """Lazy load the URL reputation service"""
        if self._service is not None:
            return True

        try:
            from backend.url_reputation import URLReputationService
            self._service = URLReputationService(
                enable_domain_age_check=True,
                enable_ssl_inspection=True
            )
            logger.info("URLReputationService loaded")

            # Try to populate feeds in background
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._service.update_cache())
                loop.close()
            except Exception as e:
                logger.debug(f"Feed update skipped: {e}")
            return True
        except Exception as e:
            logger.warning(f"Could not load URLReputationService: {e}")
            return False

    async def check_url_async(self, url: str) -> dict:
        """Async check URL against threat feeds"""
        if not self._load_service():
            return {"is_malicious": False, "error": "Service unavailable"}

        try:
            result = await self._service.check_url(url)
            return {
                "is_malicious": result.is_malicious,
                "threat_type": result.threat_type.value if result.threat_type else None,
                "sources": result.sources,
                "confidence": result.confidence,
                "domain_age_days": result.domain_age_days,
            }
        except Exception as e:
            logger.error(f"URL check error: {e}")
            return {"is_malicious": False, "error": str(e)}

    def check_url_sync(self, url: str) -> dict:
        """Sync wrapper for URL checking — thread-safe"""
        with self._lock:
            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(self.check_url_async(url))
                loop.close()
                return result
            except Exception as e:
                logger.error(f"URL sync check error: {e}")
                return {"is_malicious": False, "error": str(e)}


class RiskEngineChecker:
    """Lazy wrapper for backend/risk_engine.py.
    
    Thread safety analysis: All 6 core detection methods (_screen_text_alerts,
    _screen_visual_cues, _analyze_text_for_scam, _html_code_analysis,
    _content_signals, _has_suspicious_patterns) are confirmed thread-safe:
    they never mutate self.* state, only read immutable class constants and
    self.email_guardian (whose methods are also read-only). Therefore NO lock
    is needed for these methods — they can run fully in parallel.
    
    Only fast_validate_sync needs a lock because it creates asyncio event loops.
    """

    _instance = None
    _engine = None
    _init_lock = threading.Lock()  # Only for lazy init
    _async_lock = threading.Lock()  # Only for async->sync wrappers

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _load_engine(self):
        """Lazy load the risk scoring engine (thread-safe init)"""
        if self._engine is not None:
            return True

        with self._init_lock:
            if self._engine is not None:
                return True
            try:
                from unittest.mock import MagicMock
                from backend.risk_engine import RiskScoringEngine

                mock_db = MagicMock()
                self._engine = RiskScoringEngine(mock_db)
                logger.info("RiskScoringEngine loaded")
                return True
            except Exception as e:
                logger.warning(f"Could not load RiskScoringEngine: {e}")
                return False

    def analyze_text(self, text: str) -> dict:
        """Analyze text for risk using ML model"""
        if not self._load_engine():
            return {"risk_level": "unknown", "error": "Engine unavailable"}
        try:
            result = self._engine.analyze_text_risk(text)
            return {
                "risk_level": result.risk_level.value if hasattr(result, 'risk_level') else "unknown",
                "risk_score": result.risk_score if hasattr(result, 'risk_score') else 0,
                "factors": result.factors if hasattr(result, 'factors') else [],
            }
        except Exception as e:
            logger.error(f"Risk analysis error: {e}")
            return {"risk_level": "unknown", "error": str(e)}

    # --- Comprehensive backend detector delegates (ALL lock-free, thread-safe) ---

    def screen_text_alerts(self, image_bytes: bytes) -> dict:
        """Run _screen_text_alerts: enhanced OCR + 15+ scam pattern categories.
        Thread-safe: no mutable state accessed."""
        if not self._load_engine():
            return None
        try:
            return self._engine._screen_text_alerts(image_bytes, static=True)
        except Exception as e:
            logger.debug(f"screen_text_alerts error: {e}")
            return None

    def screen_visual_cues(self, image_bytes: bytes) -> dict:
        """Run _screen_visual_cues: HSV color analysis with 4x4 grid tiling.
        Thread-safe: pure function, no self.* access."""
        if not self._load_engine():
            return None
        try:
            return self._engine._screen_visual_cues(image_bytes)
        except Exception as e:
            logger.debug(f"screen_visual_cues error: {e}")
            return None

    def analyze_text_for_scam(self, text: str) -> dict:
        """Run _analyze_text_for_scam: crypto wallets, unicode obfuscation, combo rules.
        Thread-safe: no mutable state accessed."""
        if not self._load_engine():
            return None
        try:
            return self._engine._analyze_text_for_scam(text)
        except Exception as e:
            logger.debug(f"analyze_text_for_scam error: {e}")
            return None

    def html_code_analysis(self, url: str, html: str):
        """Run _html_code_analysis: 17-category phishing/clickjacking detection.
        Thread-safe: pure function, no self.* access."""
        if not self._load_engine():
            return False, ""
        try:
            return self._engine._html_code_analysis(url, html)
        except Exception as e:
            logger.debug(f"html_code_analysis error: {e}")
            return False, ""

    def content_signals(self, url: str, html: str):
        """Run _content_signals: cross-origin forms, external scripts, SRI, obfuscation.
        Thread-safe: pure function, no self.* access."""
        if not self._load_engine():
            return 0.0, [], []
        try:
            return self._engine._content_signals(url, html)
        except Exception as e:
            logger.debug(f"content_signals error: {e}")
            return 0.0, [], []

    def has_suspicious_patterns(self, url: str) -> bool:
        """Run _has_suspicious_patterns: 30+ regex patterns for phishing URLs.
        Thread-safe: reads only immutable class-level constant list."""
        if not self._load_engine():
            return False
        try:
            return self._engine._has_suspicious_patterns(url)
        except Exception as e:
            logger.debug(f"has_suspicious_patterns error: {e}")
            return False

    def fast_validate_sync(self, url: str) -> dict:
        """Run fast_validate: quick HTTP HEAD for security headers (async->sync).
        Needs lock: creates asyncio event loop."""
        if not self._load_engine():
            return None
        with self._async_lock:
            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(self._engine.fast_validate(url))
                loop.close()
                return result
            except Exception as e:
                logger.debug(f"fast_validate error: {e}")
                return None

    def calculate_risk_sync(self, url: str, html: str = None) -> dict:
        """Run the full ML pipeline via calculate_risk(url, content).
        This invokes: XGBoost URL model, HTML CNN / RF model, and BERT text model.
        Needs lock: creates asyncio event loop."""
        if not self._load_engine():
            return None
        with self._async_lock:
            try:
                loop = asyncio.new_event_loop()
                result = loop.run_until_complete(
                    self._engine.calculate_risk(url, html)
                )
                loop.close()
                return result
            except Exception as e:
                logger.debug(f"calculate_risk error: {e}")
                return None

    def predict_text_phishing_sync(self, text: str) -> dict:
        """Run BERT phishing detector directly on raw text (e.g. OCR output).
        Returns {'spam_prob': float, 'ham_prob': float} or None on failure.
        Thread-safe: BERT inference is read-only on self._engine.text_model."""
        if not self._load_engine():
            return None
        engine = self._engine
        if engine.text_model is None or engine.text_tokenizer is None:
            logger.debug("BERT model not loaded, skipping text phishing prediction")
            return None
        try:
            import re as _re
            import torch

            # Strip HTML tags if any
            clean = _re.sub(r"<[^>]+>", " ", text)
            clean = _re.sub(r"\s+", " ", clean).strip()
            if len(clean) < 20:
                return None
            enc = engine.text_tokenizer(
                clean,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors="pt",
            )
            with torch.no_grad():
                out = engine.text_model(**enc)
                prob = torch.softmax(out.logits, dim=1)[0]
                ham = float(prob[0].item())
                spam = float(prob[1].item()) if prob.shape[0] > 1 else (1.0 - ham)
            return {"spam_prob": spam, "ham_prob": ham}
        except Exception as e:
            logger.debug(f"BERT text prediction error: {e}")
            return None

    def predict_url_xgb_sync(self, url: str) -> float:
        """Run XGBoost URL classifier directly — fast, no network I/O.
        Returns phishing probability (0.0–1.0), or -1.0 on failure.
        This is the fast ML path; use calculate_risk_sync only for confirmed-suspicious URLs."""
        if not self._load_engine():
            return -1.0
        engine = self._engine
        if engine.ml_model is None:
            return -1.0
        try:
            import numpy as np
            feat = engine._url_features(url)
            x = np.array(feat).reshape(1, -1)
            try:
                import xgboost as xgb
                dm = xgb.DMatrix(x)
                proba = engine.ml_model.predict(dm)
                return float(proba[0])
            except Exception:
                pass
            # Fallback: sklearn-compatible predict_proba
            if hasattr(engine.ml_model, 'predict_proba'):
                p = engine.ml_model.predict_proba(x)[0]
                return float(p[1]) if len(p) > 1 else float(1.0 - p[0])
        except Exception as e:
            logger.debug(f"XGBoost URL prediction error: {e}")
        return -1.0


class DeepfakeVideoDetector:
    """Lazy wrapper for backend/video_deepfake_detector.py"""

    _instance = None
    _detector = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _load_detector(self):
        """Lazy load the video deepfake detector"""
        if self._detector is not None:
            return True

        try:
            from backend.video_deepfake_detector import VideoDeepfakeDetector
            self._detector = VideoDeepfakeDetector()
            logger.info("VideoDeepfakeDetector loaded")
            return True
        except Exception as e:
            logger.warning(f"Could not load VideoDeepfakeDetector: {e}")
            return False

    def check_video_file(self, video_path: str) -> dict:
        """Check a video file for deepfakes"""
        if not self._load_detector():
            return {"is_deepfake": None, "error": "Detector unavailable"}

        try:
            result = self._detector.check_video(video_path)
            return result
        except Exception as e:
            logger.error(f"Video deepfake check error: {e}")
            return {"is_deepfake": None, "error": str(e)}


class DeepfakeAudioDetector:
    """Lazy wrapper for backend/audio_deepfake_detector.py"""

    _instance = None
    _detector = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _load_detector(self):
        """Lazy load the audio deepfake detector"""
        if self._detector is not None:
            return True

        try:
            from backend.audio_deepfake_detector import AudioDeepfakeDetector
            self._detector = AudioDeepfakeDetector()
            logger.info("AudioDeepfakeDetector loaded")
            return True
        except Exception as e:
            logger.warning(f"Could not load AudioDeepfakeDetector: {e}")
            return False

    def check_audio_file(self, audio_path: str) -> dict:
        """Check an audio file for deepfakes"""
        if not self._load_detector():
            return {"is_deepfake": None, "error": "Detector unavailable"}

        try:
            result = self._detector.check_audio(audio_path)
            return result
        except Exception as e:
            logger.error(f"Audio deepfake check error: {e}")
            return {"is_deepfake": None, "error": str(e)}


# ============= Backend API Client =============

class PayGuardAPIClient:
    """Client for backend/server.py FastAPI - connects to local API"""

    _instance = None
    _base_url = "http://localhost:8000"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._client = None
        self._session = None

    def _get_client(self):
        """Lazy load httpx client"""
        if self._client is not None:
            return self._client

        try:
            import httpx
            self._client = httpx.Client(base_url=self._base_url, timeout=10.0)
            return self._client
        except Exception as e:
            logger.warning(f"Could not create API client: {e}")
            return None

    def is_server_available(self) -> bool:
        """Check if backend server is running"""
        try:
            client = self._get_client()
            if client is None:
                return False
            response = client.get("/health")
            return response.status_code == 200
        except Exception:
            return False

    def check_url_reputation(self, url: str) -> dict:
        """Check URL via backend API"""
        try:
            client = self._get_client()
            if client is None:
                return {"error": "API client unavailable"}

            response = client.post("/api/v1/check-url", json={"url": url})
            if response.status_code == 200:
                return response.json()
            return {"error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_text_risk(self, text: str) -> dict:
        """Analyze text risk via backend API"""
        try:
            client = self._get_client()
            if client is None:
                return {"error": "API client unavailable"}

            response = client.post("/api/v1/analyze-text", json={"text": text})
            if response.status_code == 200:
                return response.json()
            return {"error": f"API returned {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# ============= PayGuard App =============

class PayGuard:
    def __init__(self):
        self.enabled = True  # Start enabled so monitoring begins immediately on launch
        self.scanning = False
        self.threats_found = 0
        self.last_screen_hash = ""
        self.last_alert_time = 0
        self.alert_cooldown = 5  # Reduced from 10s to 5s so it feels more responsive during tests

        # Backend integrations (lazy loaded)
        self.url_reputation = URLReputationChecker()
        self.risk_engine = RiskEngineChecker()
        self.deepfake_video = DeepfakeVideoDetector()
        self.deepfake_audio = DeepfakeAudioDetector()
        self.api_client = PayGuardAPIClient()

        # Thread pool for parallel detection (reused across scans)
        self.executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="payguard")

        # Menu bar - rumps auto-adds Quit, don't add custom one
        self.app = rumps.App("PayGuard")
        self.toggle_item = rumps.MenuItem('OFF', callback=self.toggle)
        self.app.menu = [self.toggle_item]

        self.update_status()
        self.start_monitoring()  # Auto-start monitoring since enabled=True at launch

    def update_status(self):
        if self.enabled:
            self.toggle_item.title = 'ON'
            self.app.title = "\U0001f6e1\ufe0f"
        else:
            self.toggle_item.title = 'OFF'
            self.app.title = "\u26ab"

    def toggle(self, _):
        self.enabled = not self.enabled
        self.update_status()

        if self.enabled:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    # ============= Popup Dialog Alerts =============

    def notify(self, title, message, critical=False):
        """Show popup dialog alert with sound"""
        now = time.time()
        if now - self.last_alert_time < self.alert_cooldown:
            logger.info(f"Alert suppressed (cooldown): {title}")
            return
        self.last_alert_time = now

        # Plain-language dialog body — no percentages or technical jargon.
        # Technical detail stays in the log and notification banner only.
        _friendly = {
            'PHISHING DETECTED!':        "Be careful — this page may be trying to steal your information. Do not enter any passwords or personal details.",
            'SCAM DETECTED!':            "This looks like a scam. Do not call any phone numbers, click any links, or share personal information.",
            'HIGH RISK SITE DETECTED!':  "This website looks dangerous. Close it and stay safe.",
            'KNOWN THREAT Detected!':    "This is a known dangerous site. Close it immediately.",
            'Suspicious Site Detected!': "This site looks suspicious. Stay safe and do not share personal information.",
            'Phishing Email Detected!':  "This email may be trying to steal your information. Do not click any links or attachments.",
            'SMS Scam Detected!':        "This looks like a scam text message. Do not call back or reply.",
            'Suspicious URL Detected!':  "This link looks suspicious. Stay safe and do not enter personal information.",
            'PHISHING WEBSITE Detected!': "This website is designed to steal your information. Close it immediately.",
            'Insecure Website Detected!': "This website is not secure. Be careful sharing personal information.",
        }
        dialog_body = _friendly.get(title, "Stay safe online. Do not share personal information or click links you do not trust.")

        try:
            clean_title = title.replace('"', '\\"').replace('\n', ' ')
            clean_message = message.replace('"', '\\"').replace('\n', ' ')
            clean_body = dialog_body.replace('"', '\\"')

            if critical:
                # Play sound - cross-platform
                if IS_MAC:
                    subprocess.Popen(
                        ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                elif IS_WINDOWS:
                    try:
                        import winsound
                        winsound.MessageBeep(winsound.MB_ICONSTOP)
                    except Exception:
                        pass

                # Show notification - cross-platform
                if IS_MAC:
                    notif_cmd = f'display notification "{clean_message}" with title "{clean_title}" sound name "Hero"'
                    subprocess.run(["osascript", "-e", notif_cmd], capture_output=True, timeout=5)

                    dialog_cmd = (
                        f'display dialog "{clean_body}\\n\\n'
                        f'PayGuard is protecting you from threats!" '
                        f'with title "{clean_title}" '
                        f'buttons {{"OK", "More Info"}} default button "OK"with icon stop giving up after 30 '
                        f''
                    )
                    result = subprocess.run(
                        ["osascript", "-e", dialog_cmd],
                        capture_output=True, text=True, timeout=60
                    )

                    if "More Info" in (result.stdout or ""):
                        self._show_more_info()
                elif IS_WINDOWS:
                    try:
                        from win10toast import ToastNotifier
                        toaster = ToastNotifier()
                        toaster.show_toast(
                            clean_title,
                            clean_body + "\n\nPayGuard is protecting you!",
                            duration=15,
                            icon_path=None,
                            threaded=True
                        )
                    except ImportError:
                        logger.debug("win10toast not installed, using fallback")
                        subprocess.run([
                            "powershell", "-Command",
                            f'[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; '
                            f'$template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02; '
                            f'$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template); '
                            f'$xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("{clean_title}")) | Out-Null; '
                            f'$xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{clean_body}")) | Out-Null; '
                            f'$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); '
                            f'[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("PayGuard").Show($toast)'
                        ], capture_output=True, timeout=15)
                    except Exception as e:
                        logger.debug(f"Windows notification error: {e}")

                self.threats_found += 1
                logger.info(f"THREAT #{self.threats_found}: {title} - {message}")
            else:
                # Non-critical notification
                if IS_MAC:
                    cmd = f'display notification "{clean_message}" with title "{clean_title}"'
                    subprocess.run(["osascript", "-e", cmd], capture_output=True, timeout=5)
                elif IS_WINDOWS:
                    try:
                        from win10toast import ToastNotifier
                        toaster = ToastNotifier()
                        toaster.show_toast(clean_title, clean_message, duration=5, threaded=True)
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Notification error: {e}")

    def _show_more_info(self):
        """Show educational info dialog"""
        info_msg = (
            "PayGuard detected suspicious content that may be a scam or threat. "
            "Common tactics include:\\n\\n"
            "• Fake virus/security warnings\\n"
            "• Urgent alerts asking you to call a number\\n"
            "• Fake company support messages\\n"
            "• Phishing emails with lookalike domains\\n"
            "• AI-generated fake images\\n"
            "• Video/audio deepfakes\\n"
            "• Aggressive/deceptive ads\\n\\n"
            "NEVER call random phone numbers or download software from pop-ups!"
        )
        info_cmd = (
            f'display dialog "{info_msg}" '
            f'with title "PayGuard - Threat Information" '
            f'buttons {{"OK"}} default button "OK" with icon caution'
        )
        subprocess.run(["osascript", "-e", info_cmd], capture_output=True, timeout=60)

    # ============= Screen Capture =============

    # Pre-computed downscale sizes
    OCR_WIDTH = 960        # Width for OCR (smaller = faster pytesseract)
    AI_SIZE = (512, 512)   # Size for AI image FFT analysis
    VISUAL_WIDTH = 800     # Width for visual cues / color analysis

    def capture_screen(self):
        """Capture screen - cross-platform.
        
        Returns (raw_bytes, visual_bytes, img_full, img_ocr, img_ai) tuple:
          - raw_bytes: JPEG bytes for backend methods that take bytes
          - visual_bytes: JPEG bytes of downscaled image for visual analysis
          - img_full: PIL Image at full resolution
          - img_ocr: PIL Image downscaled for fast OCR
          - img_ai: PIL Image downscaled for fast AI/FFT analysis
        
        Quartz (macOS) is ~6x faster than subprocess screencapture (0.2s vs 1.4s).
        Downscaling happens once here, not in each detector.
        """
        if IS_MAC:
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

                img_full = Image.frombytes('RGBA', (width, height), pixeldata, 'raw', 'BGRA', bytesperrow, 1)

                return self._prepare_images(img_full)

            except ImportError:
                logger.debug("Quartz not available, falling back to screencapture")
                return self._capture_screen_subprocess()
            except Exception as e:
                logger.error(f"Quartz capture error: {e}")
                return self._capture_screen_subprocess()
        
        elif IS_WINDOWS:
            return self._capture_screen_windows()
        
        elif IS_LINUX:
            return self._capture_screen_linux()
        
        else:
            logger.error(f"Unsupported platform: {platform.system()}")
            return None

    def _capture_screen_windows(self):
        """Capture screen on Windows using mss + PIL"""
        try:
            import mss
            import mss.tools
            
            with mss.mss() as sct:
                monitor = sct.monitors[1]  # Primary monitor
                screenshot = sct.grab(monitor)
                
                # Convert to PIL Image (BGRA to RGB)
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                
                return self._prepare_images(img)
        except ImportError:
            logger.error("Windows capture requires 'pip install mss'")
            return None
        except Exception as e:
            logger.error(f"Windows capture error: {e}")
            return None

    def _capture_screen_linux(self):
        """Capture screen on Linux using mss or scrot"""
        # Try mss first (cross-platform)
        try:
            import mss
            
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                screenshot = sct.grab(monitor)
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                return self._prepare_images(img)
        except ImportError:
            pass
        
        # Fallback to scrot
        try:
            tmp_path = "/tmp/payguard_screen.png"
            subprocess.run(["scrot", tmp_path], capture_output=True, timeout=5)
            if os.path.exists(tmp_path):
                img = Image.open(tmp_path)
                img.load()
                os.remove(tmp_path)
                return self._prepare_images(img)
        except Exception as e:
            logger.error(f"Linux capture error: {e}")
        
        return None

    def _capture_screen_subprocess(self):
        """Fallback: capture screen using macOS screencapture subprocess."""
        try:
            tmp_path = "/tmp/payguard_screen.png"
            result = subprocess.run(
                ["screencapture", "-x", "-C", tmp_path],
                capture_output=True, timeout=5
            )
            if result.returncode != 0 or not os.path.exists(tmp_path):
                return None

            img_full = Image.open(tmp_path)
            img_full.load()  # Force load before removing file
            os.remove(tmp_path)

            return self._prepare_images(img_full)
        except Exception as e:
            logger.error(f"Subprocess capture error: {e}")
        return None

    def _prepare_images(self, img_full):
        """Pre-compute downscaled image variants from full-resolution capture.
        Called once per capture, avoids redundant resizing in each detector.
        Uses BILINEAR for speed (LANCZOS is 3-4x slower with marginal quality gain)."""
        w, h = img_full.size

        # Convert to RGB if needed (Quartz gives RGBA)
        if img_full.mode == 'RGBA':
            img_full = img_full.convert('RGB')

        # OCR version: 960px wide (proportional) — downscale from full resolution
        if w > self.OCR_WIDTH:
            ocr_h = int(h * self.OCR_WIDTH / w)
            img_ocr = img_full.resize((self.OCR_WIDTH, ocr_h), Image.Resampling.BILINEAR)
        else:
            img_ocr = img_full

        # AI and visual versions are derived from img_ocr (already downscaled to 960px)
        # rather than from full Retina resolution — saves 3 expensive resizes from ~3456px.
        ocr_w, ocr_h_actual = img_ocr.size

        # AI version: 512x512 (fixed for FFT consistency) — downscale from 960px
        img_ai = img_ocr.resize(self.AI_SIZE, Image.Resampling.BILINEAR)

        # Visual version: 800px wide for color analysis — but img_ocr is already 960px,
        # so only one more downscale step needed (960→800 is cheap).
        if ocr_w > self.VISUAL_WIDTH:
            vis_h = int(ocr_h_actual * self.VISUAL_WIDTH / ocr_w)
            img_visual = img_ocr.resize((self.VISUAL_WIDTH, vis_h), Image.Resampling.BILINEAR)
        else:
            img_visual = img_ocr

        # Convert visual image to JPEG bytes for backend visual cues method
        buf = io.BytesIO()
        img_visual.save(buf, format='JPEG', quality=70)
        visual_bytes = buf.getvalue()

        # Raw bytes: only needed if _screen_text_alerts is called (deferred check)
        # Use visual_bytes as raw_bytes to avoid extra JPEG encode
        raw_bytes = visual_bytes

        return raw_bytes, visual_bytes, img_full, img_ocr, img_ai

    # ============= Inline Detectors (fallbacks, also used in parallel) =============

    def analyze_screen_colors(self, img):
        """Analyze screen for suspicious colors (inline fallback)"""
        try:
            if img.size[0] * img.size[1] > 1000000:
                img = img.resize((800, 600), Image.Resampling.LANCZOS)

            colors = img.getcolors(maxcolors=256 * 256 * 256)
            if not colors:
                return 0, 0, 0

            total = sum(count for count, _ in colors)
            red = orange = yellow = 0

            for count, color in colors:
                if isinstance(color, tuple) and len(color) >= 3:
                    r, g, b = color[:3]
                    if r > 180 and g < 100 and b < 100:
                        red += count
                    elif r > 200 and 100 < g < 200 and b < 100:
                        orange += count
                    elif r > 200 and g > 200 and b < 100:
                        yellow += count

            return red / total, orange / total, yellow / total
        except Exception:
            return 0, 0, 0

    def check_text_scams(self, text):
        """Check text for scam patterns (inline)"""
        if not text or len(text) < 10:
            return [], 0

        threats = []
        score = 0

        for pattern, name, weight in SCAM_PATTERNS:
            if pattern.search(text):
                score += weight
                threats.append(name)

        return threats, score

    def check_url_scams(self, url):
        """Check URL for scam patterns (inline)"""
        url_lower = url.lower()
        threats = []

        for domain in URL_SCAM_PATTERNS:
            if domain in url_lower:
                threats.append(f"fake_{domain}")

        for param in TRACKING_PARAMS:
            if param in url_lower:
                threats.append("tracking")
                break

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
            if tld in SUSPICIOUS_TLDS:
                # Don't flag suspicious TLD if the domain is in the trusted list
                # or is a well-known high-reputation host (e.g. yandex.ru, vk.ru)
                is_trusted = False
                for apex in self._TRUSTED_URL_DOMAINS:
                    if domain == apex or domain.endswith('.' + apex):
                        is_trusted = True
                        break
                if not is_trusted:
                    threats.append(f"suspicious_tld_{tld}")

            for ad_domain in AD_NETWORK_DOMAINS:
                if ad_domain in domain:
                    threats.append(f"ad_network_{ad_domain}")
                    break
        except Exception:
            pass

        return threats

    def check_aggressive_ads(self, text):
        """Check for aggressive/deceptive advertising (inline)"""
        if not text or len(text) < 10:
            return [], 0

        threats = []
        score = 0

        for pattern, name, weight in AD_TEXT_PATTERNS:
            if pattern.search(text):
                score += weight
                threats.append(name)

        return threats, score

    def check_email_typosquatting(self, text):
        """Check for typosquatted email domains (inline)"""
        if not text:
            return []

        threats = []
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)

        for full_domain in emails:
            parts = full_domain.lower().split('.')
            if len(parts) < 2:
                continue

            tld = parts[-1]
            domain_body = '.'.join(parts[:-1])
            body_parts = re.split(r'[-_.]', domain_body)

            for brand in PROTECTED_BRANDS:
                normalized = domain_body
                for char in sorted(HOMOGLYPH_MAP.keys(), key=len, reverse=True):
                    normalized = normalized.replace(char, HOMOGLYPH_MAP[char])

                if normalized == brand and domain_body != brand:
                    threats.append(f"typosquat_{brand}")
                    break

                for part in body_parts:
                    norm_part = part
                    for char in sorted(HOMOGLYPH_MAP.keys(), key=len, reverse=True):
                        norm_part = norm_part.replace(char, HOMOGLYPH_MAP[char])

                    if norm_part == brand and part != brand:
                        threats.append(f"typosquat_{brand}")
                        break
                    elif brand in part and len(body_parts) > 1:
                        threats.append(f"suspicious_email_{brand}")
                        break
                    else:
                        sim = difflib.SequenceMatcher(None, part, brand).ratio()
                        if 0.85 <= sim < 1.0:
                            threats.append(f"lookalike_{brand}")
                            break

                if domain_body == brand and tld in SUSPICIOUS_TLDS:
                    threats.append(f"brand_suspicious_tld_{brand}")

        return threats

    def check_sms_scams(self, text):
        """Check for SMS/smishing patterns (inline)"""
        if not text:
            return []

        threats = []
        text_lower = text.lower()

        urls = re.findall(r'https?://[^\s]+', text)
        for url in urls:
            try:
                domain = urlparse(url).netloc.lower()
                for shortener in URL_SHORTENERS:
                    if domain == shortener or domain.endswith('.' + shortener):
                        threats.append('sms_url_shortener')
                        break
            except Exception:
                pass

        sms_patterns = {
            r'parcel.*waiting|delivery.*failed|shipping.*fee': 'package_scam',
            r'unpaid.*toll|highway.*bill|toll.*fine': 'toll_scam',
            r'refund.*available|tax.*rebate|claim.*refund': 'refund_scam',
            r'unauthorized.*login|locked.*account|verify.*identity': 'account_takeover',
            r'suspicious.*activity.*bank|card.*blocked': 'banking_scam',
        }

        for pattern, name in sms_patterns.items():
            if re.search(pattern, text_lower):
                threats.append(name)

        return threats

    def check_ai_image(self, img, img_full=None):
        """Spectral/frequency analysis for AI-generated image detection (inline).
        
        Args:
            img: Pre-downscaled image (512x512) for fast FFT analysis
            img_full: Optional full-res image for EXIF/XMP metadata checks
        """
        try:
            import numpy as np
            from scipy import fftpack
            from scipy.stats import entropy

            img_arr = np.array(img.convert('L'))
            if img_arr.shape[0] < 64 or img_arr.shape[1] < 64:
                return False, 0, []

            fft2 = fftpack.fft2(img_arr)
            fft_shift = fftpack.fftshift(fft2)
            magnitude = np.abs(fft_shift)
            log_magnitude = np.log1p(magnitude)

            h, w = log_magnitude.shape
            ch, cw = h // 2, w // 2

            low_freq = log_magnitude[ch - 10:ch + 10, cw - 10:cw + 10]
            high_freq = np.concatenate([
                log_magnitude[:20, :].flatten(),
                log_magnitude[-20:, :].flatten(),
                log_magnitude[:, :20].flatten(),
                log_magnitude[:, -20:].flatten(),
            ])

            low_mean = np.mean(low_freq)
            high_mean = np.mean(high_freq)
            ratio = high_mean / (low_mean + 1e-10)

            freq_variance = np.var(log_magnitude)
            freq_entropy = entropy(np.histogram(log_magnitude, bins=50)[0] + 1e-10)

            findings = []
            confidence = 0
            condition_count = 0

            # Require MULTIPLE conditions to fire - single conditions are not enough
            if ratio > 0.35:
                findings.append(f'high_freq_ratio_{ratio:.3f}')
                confidence = max(confidence, 35)
                condition_count += 1

            if freq_entropy < 4.5:
                findings.append(f'low_entropy_{freq_entropy:.2f}')
                confidence = max(confidence, 30)
                condition_count += 1

            if freq_variance > 1.5:
                findings.append(f'high_variance_{freq_variance:.2f}')
                confidence = max(confidence, 25)
                condition_count += 1

            center = log_magnitude[ch - 5:ch + 5, cw - 5:cw + 5]
            if np.std(center) < 0.1:
                findings.append('smooth_center')
                confidence = max(confidence, 20)
                condition_count += 1

            # EXIF/XMP metadata with AI keywords is VERY reliable - high confidence
            has_ai_metadata = False
            try:
                meta_img = img_full if img_full is not None else img
                exif = meta_img.getexif()
                if exif:
                    exif_str = ' '.join(str(v) for v in exif.values() if isinstance(v, (str, bytes)))
                    ai_keywords = ['dall-e', 'midjourney', 'stable diffusion', 'ai generated',
                                   'openai', 'firefly', 'gemini', 'synthetic']
                    for kw in ai_keywords:
                        if kw in exif_str.lower():
                            findings.append(f'exif_{kw}')
                            has_ai_metadata = True
            except Exception:
                pass

            try:
                meta_img = img_full if img_full is not None else img
                xmp = meta_img.getxmp()
                if xmp:
                    import json
                    xmp_str = json.dumps(xmp).lower()
                    ai_keywords = ['c2pa', 'contentauth', 'dall-e', 'midjourney',
                                   'stable diffusion', 'ai generated', 'openai']
                    for kw in ai_keywords:
                        if kw in xmp_str:
                            findings.append(f'xmp_{kw}')
                            has_ai_metadata = True
            except Exception:
                pass

            if has_ai_metadata:
                confidence = 90
                condition_count += 3  # Treat as multiple conditions

            # Require AT LEAST 2 spectral conditions OR AI metadata to fire
            # Single conditions are too common in normal images (false positives)
            is_ai = condition_count >= 2 and confidence >= 50

            return is_ai, confidence, findings

        except ImportError:
            logger.debug("numpy/scipy not available for AI image detection")
            return False, 0, []
        except Exception as e:
            logger.debug(f"AI image check error: {e}")
            return False, 0, []

    # ============= Backend Delegate Methods (unused standalone) =============

    def check_deepfake_video(self, video_path: str) -> dict:
        """Check video for deepfakes using backend detector"""
        return self.deepfake_video.check_video_file(video_path)

    def check_deepfake_audio(self, audio_path: str) -> dict:
        """Check audio for deepfakes using backend detector"""
        return self.deepfake_audio.check_audio_file(audio_path)

    def check_api_server(self) -> bool:
        """Check if backend API server is available"""
        return self.api_client.is_server_available()

    # ============= Parallel Detector Workers =============

    def _quick_ocr(self, img):
        """Fast OCR text extraction on pre-downscaled image.
        Uses Apple Vision framework (0.8s) with pytesseract fallback (1.3s)."""
        # Try Apple Vision framework first (faster, native macOS)
        try:
            import Vision
            from Foundation import NSData

            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=85)
            png_data = buf.getvalue()
            ns_data = NSData.dataWithBytes_length_(png_data, len(png_data))

            request = Vision.VNRecognizeTextRequest.alloc().init()
            request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)

            handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
            success, error = handler.performRequests_error_([request], None)

            if success:
                results = request.results()
                text_parts = []
                if results:
                    for obs in results:
                        cands = obs.topCandidates_(1)
                        if cands:
                            text_parts.append(cands[0].string())
                text = '\n'.join(text_parts)
                if text.strip():
                    return text
        except ImportError:
            pass  # Vision not installed, fall through to tesseract
        except Exception as e:
            logger.debug(f"Vision OCR error: {e}")

        # Fallback to pytesseract
        try:
            import pytesseract
            return pytesseract.image_to_string(img, config='--psm 6 -l eng')
        except Exception:
            return ""

    def _fetch_html(self, url):
        """Fetch HTML content from a URL with short timeout"""
        try:
            import httpx
            resp = httpx.get(url, timeout=0.5, follow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 PayGuard/1.0"})
            content_type = resp.headers.get('content-type', '')
            if resp.status_code == 200 and 'text/html' in content_type:
                return resp.text[:50000]  # Cap at 50KB to avoid slowdowns
        except Exception:
            pass
        return None

    # Top-level domains / hostnames that are trusted enough to skip NO_SECURITY
    # (they have CDN/load-balancers that strip security headers from HEAD responses)
    _HIGH_REP_HOSTS = {
        'google.com', 'youtube.com', 'apple.com', 'microsoft.com', 'github.com',
        'amazon.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'linkedin.com', 'reddit.com', 'wikipedia.org', 'stackoverflow.com',
        'cloudflare.com', 'netflix.com', 'dropbox.com', 'icloud.com',
        'live.com', 'office.com', 'outlook.com', 'yahoo.com',
    }

    def _is_high_reputation_host(self, url: str) -> bool:
        """Return True if URL hostname is a known high-rep domain (or subdomain thereof).
        Used to avoid firing NO_SECURITY on major sites that strip headers on HEAD."""
        try:
            host = urlparse(url).netloc.lower().lstrip('www.')
            for apex in self._HIGH_REP_HOSTS:
                if host == apex or host.endswith('.' + apex):
                    return True
        except Exception:
            pass
        return False

    def _run_visual_cues(self, image_bytes):
        """Worker: detect scam/alert overlay colors using smart concentration analysis.

        Key insight:
          - Scam popups/alerts = ISOLATED, UNIFORM vivid color block in 1-3 screen tiles
          - Normal colorful content (logos, photos, websites) = SCATTERED low-density color

        Two gates must BOTH pass to fire:
          1. Saturation gate: pixels must be >160/255 saturated (pure vivid color, not muted)
          2. Concentration gate: only 1-3 tiles have significant color, rest of screen is normal

        This eliminates false positives from YouTube thumbnails, red logos, orange UI elements.
        """
        try:
            import numpy as np

            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            hsv = img.convert('HSV')
            H, S, V = [np.array(ch, dtype=np.uint8) for ch in hsv.split()]
            h_px, w_px = H.shape

            # Gate 1: Require HIGH saturation — vivid scam-red/orange/yellow only
            # Excludes muted/pastel/washed-out versions (normal UI, photos, logos)
            SAT_MIN = 160  # 0-255; 160 ≈ 63% saturation — only vivid colors pass
            VAL_MIN = 60   # Ignore near-black pixels

            red_mask    = ((H < 16) | (H > 240)) & (S > SAT_MIN) & (V > VAL_MIN)
            orange_mask = ((H >= 16) & (H < 40))  & (S > SAT_MIN) & (V > VAL_MIN)
            yellow_mask = ((H >= 40) & (H < 60))  & (S > SAT_MIN) & (V > VAL_MIN)
            alert_mask  = red_mask | orange_mask | yellow_mask

            # Gate 2: Concentration check via 4×4 grid (16 tiles)
            grid = 4
            th, tw = h_px // grid, w_px // grid
            tile_ratios = []
            for gy in range(grid):
                for gx in range(grid):
                    y0 = gy * th
                    x0 = gx * tw
                    y1 = (gy + 1) * th if gy < grid - 1 else h_px
                    x1 = (gx + 1) * tw if gx < grid - 1 else w_px
                    area = (y1 - y0) * (x1 - x0)
                    if area <= 0:
                        continue
                    tile_ratios.append(float(alert_mask[y0:y1, x0:x1].sum()) / area)

            if not tile_ratios:
                return None

            tile_ratios.sort(reverse=True)
            tile_max = tile_ratios[0]

            # Count how many tiles have ≥20% alert color
            hot_tiles = sum(1 for r in tile_ratios if r >= 0.20)
            
            # Count tiles with ANY alert color (≥5%) - video/content detection
            tiles_with_any_alert = sum(1 for r in tile_ratios if r >= 0.05)

            # If many tiles have ANY alert color, it's likely video/content, not a scam popup
            # Scam popups are isolated to 1-2 tiles; videos spread across many
            if tiles_with_any_alert >= 5:
                logger.debug(f"Visual: {tiles_with_any_alert}/16 tiles have alert color - likely video/content, skipping")
                return None

            # VERY STRICT: Require 55%+ color in EXACTLY 1 tile for strong alerts
            # Videos may have isolated red but rarely at 55%+ in a single tile
            # This eliminates false positives from red UI elements, thumbnails, etc.
            if tile_max >= 0.55 and hot_tiles == 1:
                conf = min(85, 55 + int(tile_max * 50))
                return ('VISUAL', f"Alert overlay detected: hotspot={tile_max:.0%} in {hot_tiles}/16 tiles", conf)

            # Very rare: 50%+ in only 1 tile - very strong isolated signal
            if tile_max >= 0.50 and hot_tiles <= 1:
                return ('VISUAL', f"Possible alert region: hotspot={tile_max:.0%} in {hot_tiles}/16 tiles", 50)

            # Anything else = normal content, video, or scattered colors - ignore
            return None

        except Exception as e:
            logger.debug(f"Visual cues worker error: {e}")
            return None

    def _run_screen_text_alerts(self, image_bytes):
        """Worker: backend comprehensive OCR + scam detection (15+ pattern categories).
        
        NOTE: This is EXPENSIVE (~1.2s) because it does its own internal OCR.
        Only called as a secondary check when quick_ocr didn't find threats.
        For the primary scan path, we use _quick_ocr + _run_inline_text_checks
        + _run_text_scam_analysis which is faster since OCR is already done.
        
        Receives downscaled visual_bytes for faster internal OCR processing."""
        try:
            result = self.risk_engine.screen_text_alerts(image_bytes)
            if result and result.get('is_scam') and result.get('confidence', 0) >= 40:
                patterns = result.get('detected_patterns', [])
                conf = result.get('confidence', 50)
                return ('TEXT_SCAM', f"Scam detected: {', '.join(patterns[:4])}", conf)
        except Exception as e:
            logger.debug(f"Screen text alerts worker error: {e}")
        return None

    def _run_inline_text_checks(self, text):
        """Worker: inline text scam + ads (runs when backend screen_text_alerts unavailable)"""
        findings = []

        # Scam text patterns
        threats, score = self.check_text_scams(text)
        if score >= 40:
            findings.append(('TEXT_SCAM', f"Scam patterns: {', '.join(threats[:3])}", min(score, 95)))

        # Aggressive ad detection
        ad_threats, ad_score = self.check_aggressive_ads(text)
        if ad_score >= 30:
            findings.append(('ADS', f"Aggressive ads: {', '.join(ad_threats[:3])}", min(ad_score, 90)))

        # Email typosquatting
        email_threats = self.check_email_typosquatting(text)
        if email_threats:
            findings.append(('EMAIL', f"Phishing email: {', '.join(email_threats[:2])}", 75))

        # SMS scams
        sms_threats = self.check_sms_scams(text)
        if sms_threats:
            findings.append(('SMS', f"SMS scam: {', '.join(sms_threats[:2])}", 70))

        return findings

    # Domains that are ALWAYS trusted for URL pattern analysis — pattern-based checks
    # (has_suspicious_patterns, check_url_scams) are completely skipped for these hosts.
    # Only the reputation database (known-malicious override) still applies.
    # Includes: major consumer/tech, school LMS/SIS software, SSO/identity providers,
    # CDN/infrastructure, and common developer platforms.
    # Note: *.edu, *.gov, *.mil are ALSO trusted via TLD check in _run_url_analysis,
    # so individual school domains don't need to be listed here.
    _TRUSTED_URL_DOMAINS = {
        # Major consumer / tech
        'google.com', 'docs.google.com', 'drive.google.com', 'mail.google.com',
        'accounts.google.com', 'calendar.google.com', 'maps.google.com',
        'github.com', 'github.io', 'gitlab.com',
        'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'onedrive.live.com',
        'apple.com', 'icloud.com',
        'linkedin.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
        'instagram.com', 'reddit.com', 'wikipedia.org',
        'amazon.com', 'dropbox.com', 'slack.com', 'zoom.us',
        'netflix.com', 'spotify.com', 'stripe.com', 'paypal.com',
        'notion.so', 'figma.com', 'vercel.app', 'netlify.app',
        'stackoverflow.com', 'medium.com', 'substack.com',
        'discord.com', 'telegram.org', 'whatsapp.com',
        # Major Banking / Finance (US/Global)
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
        'capitalone.com', 'schwab.com', 'fidelity.com', 'vanguard.com',
        'americanexpress.com', 'amex.com', 'discover.com', 'usbank.com',
        'pnc.com', 'td.com', 'hsbc.com', 'barclays.com',
        # School / education LMS + SIS software
        # (covers /login/saml, /authenticate, /sso, /oauth paths on these platforms)
        'instructure.com',      # Canvas LMS
        'canvaslms.com',
        'follettsoftware.com',  # Follett school software (portalapi.follettsoftware.com)
        'powerschool.com',
        'blackboard.com',
        'schoology.com',
        'brightspace.com',      # D2L
        'd2l.com',
        'clever.com',
        'classlink.com',
        'sso.schooldude.com',
        'hacktj.org',           # HackTJ hackathon (was FP source)
        # SSO / identity providers — /login, /authenticate, /saml are their ENTIRE job
        'okta.com',
        'oktapreview.com',
        'auth0.com',
        'onelogin.com',
        'ping.com',
        'pingidentity.com',
        'shibboleth.net',
        'adfs.microsoft.com',
        'login.microsoftonline.com',
        # CDN / infrastructure — these appear in OCR from network tab / error pages
        'cloudflare.com',
        'cloudfront.net',
        'fastly.net',
        'akamaihd.net',
        'akamai.net',
        'cdn.jsdelivr.net',
        'unpkg.com',
        # Transcript / research tools (were FP sources)
        'youtubetotranscript.com',
        'rev.com',
        # Common developer platforms
        'heroku.com', 'railway.app', 'render.com', 'fly.io',
        'supabase.com', 'firebase.google.com',
    }

    # Browser / OS UI chrome lines that should be stripped before BERT sees the text.
    # These are OCR artifacts from Chrome's title bar, menu bar, tab strip, and address bar.
    _BROWSER_CHROME_STRIP_RE = re.compile(
        r'(?m)^(?:'
        r'\uf8ff.*$'                               # macOS Apple menu line
        r'|Chrome$'                                # bare "Chrome" window title
        r'|(?:File|Edit|View|History|Bookmarks|Tab|Window|Help|Profiles|'
        r'Insert|Format|Extensions|Tools)\s*$'    # single-word menu items
        r'|[•·]\s*[•·]\s*[•·].*$'                 # tab strip "• • •" pattern
        r'|→\s*\S+.*$'                             # address bar line (→ url)
        r')'
    )

    def _clean_ocr_for_bert(self, text: str) -> str:
        """Strip browser/OS UI chrome from OCR text before feeding to BERT.

        Removes: macOS menu bar, Chrome menus, tab strip markers, and the
        address bar line (which starts with → in Chrome OCR output).
        Stripping the address bar removes trusted-domain URLs that would
        otherwise confuse BERT's phishing training patterns.
        """
        return self._BROWSER_CHROME_STRIP_RE.sub('', text).strip()

    def _has_suspicious_url_in_text(self, text: str) -> bool:
        """Return True only if text contains a URL on a non-trusted domain.

        Trusted-domain URLs (google.com, github.com, etc.) do NOT count as
        structural phishing indicators — they appear in browser chrome routinely.
        """
        for m in re.finditer(r'https?://([^/\s]+)|([a-zA-Z0-9-]{3,}\.[a-zA-Z]{2,})/\S', text):
            host = (m.group(1) or m.group(2) or '').lower().lstrip('www.')
            trusted = False
            for apex in self._TRUSTED_URL_DOMAINS:
                if host == apex or host.endswith('.' + apex):
                    trusted = True
                    break
            if not trusted:
                return True
        return False

    def _run_bert_text_analysis(self, text):
        """Worker: BERT phishing detector on OCR text (primary ML text analysis).

        Two-gate approach to prevent false positives:
          Gate 1 (ML score): spam_prob >= 0.92 — high threshold because OCR text is noisy
                             and BERT was trained on clean email data, not screen grabs.
          Gate 2 (structure): cleaned text must contain a suspicious (non-trusted) URL,
                             a phone number with action verb, or an explicit credential
                             request keyword. Trusted-domain URLs (browser address bar,
                             Google Docs, GitHub) are excluded from gate 2 so that normal
                             Chrome browsing never triggers a false positive.

        Pre-processing: browser UI chrome (menu bar, tab strip, address bar) is stripped
        from the text before BERT sees it, removing the exact patterns that caused the
        'My AP Login - docs.google.com' false positive.
        """
        try:
            # Strip browser/OS UI chrome before BERT scoring
            cleaned = self._clean_ocr_for_bert(text)
            if not cleaned:
                return None

            result = self.risk_engine.predict_text_phishing_sync(cleaned)
            if result is None:
                return None  # BERT not loaded — regex fallback will handle it

            spam_prob = result.get('spam_prob', 0.0)
            logger.debug(f"BERT raw score: spam_prob={spam_prob:.3f}")
            if spam_prob < 0.94:
                return None

            # Structural context gate — require at least one hard indicator
            tl = cleaned.lower()
            has_suspicious_url = self._has_suspicious_url_in_text(cleaned)
            has_phone = bool(re.search(
                r'(?:call|dial|contact|support|help)[^0-9]{0,25}[\+\(]?\d[\d\s\-\(\)]{7,}',
                cleaned, re.I
            ))
            # Credential gate: ONLY truly phishing-specific phrases.
            # Do NOT include generic terms like 'password', 'credit card', 'account number',
            # 'routing number', 'pin number' — those appear on every legitimate login /
            # checkout page and are the primary source of false positives against login screens.
            has_credential_request = any(w in tl for w in [
                'social security', 'ssn', 'cvv', 'pin code',
                'verify your', 'confirm your identity', 'update your payment',
                'enter your card', 'billing information', 'unauthorized access',
                'suspicious activity', 'identity theft',
            ])

            gate2_reason = (
                'suspicious_url' if has_suspicious_url else
                'phone_number' if has_phone else
                'credential_phrase' if has_credential_request else
                None
            )
            if gate2_reason is None:
                logger.debug(
                    f"BERT: {spam_prob:.0%} spam_prob but no structural indicator — suppressed"
                )
                return None
            logger.debug(
                f"BERT gate2 passed via {gate2_reason} at {spam_prob:.0%}: "
                f"{cleaned[:150]!r}"
            )

            conf = int(spam_prob * 100)
            return ('BERT_PHISHING', f"BERT: phishing content detected ({conf}% confidence)", conf)
        except Exception as e:
            logger.debug(f"BERT text analysis worker error: {e}")
        return None

    def _run_text_scam_analysis(self, text):
        """Worker: backend enhanced text analysis (regex/rule fallback for when BERT isn't loaded).

        Context gate: requires ≥2 distinct non-trivial pattern categories before firing.
        Single-pattern matches (e.g. just 'urgency' from 'act now' in an ad) are suppressed.
        """
        try:
            result = self.risk_engine.analyze_text_for_scam(text)
            if not result or not result.get('is_scam'):
                return None
            if result.get('confidence', 0) < 80:
                return None

            patterns = result.get('detected_patterns', [])
            # Generic weak patterns that appear in normal content — not sufficient alone
            weak_only = {'urgency', 'brand_impersonation', 'unicode_obfuscation',
                         'custom_phrase', 'suspicious_tld', 'url_shortener'}
            strong = [p for p in patterns if p not in weak_only]
            if len(strong) < 2:
                logger.debug(
                    f"Text analysis: suppressed (only weak patterns: {patterns})"
                )
                return None

            conf = result.get('confidence', 60)
            return ('TEXT_ANALYSIS', f"Text threats: {', '.join(patterns[:4])}", conf)
        except Exception as e:
            logger.debug(f"Text scam analysis worker error: {e}")
        return None

    def _run_url_analysis(self, url):
        """Worker: URL pipeline — fast checks first, slow ML only on suspicious URLs.

        False-positive prevention (structural, not threshold-based):
          1. Trusted/allowlisted domains (*.edu, *.gov, school LMS, SSO providers, CDNs)
             bypass ALL pattern checks. Even /login /saml /authenticate paths on these
             hosts are benign by definition. Only the reputation DB (known-malicious
             override) still runs — a truly compromised trusted domain can still be caught.
          2. XGBoost ML score gates every pattern-based finding. Patterns alone
             (/login, /verify, tracking params) never fire a popup without ML confirmation.
             This eliminates false positives from normal browsing on sites that happen
             to have login pages or marketing UTM params in their URLs.
          3. HTML fetch only runs for high XGBoost scores (>= 0.75) or known-malicious.
        """
        findings = []

        # Ensure scheme for network requests
        fetch_url = url if url.startswith('http') else f"https://{url}"

        # Extract hostname (strip www.) for trusted-domain matching
        try:
            from urllib.parse import urlparse as _urlparse
            _host = _urlparse(fetch_url).netloc.lower()
            if _host.startswith('www.'):
                _host = _host[4:]
        except Exception:
            _host = ''

        # Trusted-host check: .edu/.gov/.mil TLDs are ALWAYS safe; known-good apex domains too.
        def _is_trusted_host(h):
            # Government / education / military TLDs — login and auth paths are expected
            _tld = h.rsplit('.', 1)[-1] if '.' in h else ''
            if _tld in ('edu', 'gov', 'mil'):
                return True
            # Apex allowlist match (subdomains also match via endswith)
            for apex in self._TRUSTED_URL_DOMAINS:
                if h == apex or h.endswith('.' + apex):
                    return True
            return False

        is_trusted = _is_trusted_host(_host)

        # 1. URL reputation (OpenPhish / PhishTank / URLhaus — always check, even trusted hosts)
        #    A truly compromised trusted domain should still be caught.
        is_known_malicious = False
        try:
            rep = self.url_reputation.check_url_sync(url)
            if rep.get('is_malicious'):
                is_known_malicious = True
                conf = int(rep.get('confidence', 0.8) * 100)
                threat = rep.get('threat_type', 'malicious')
                findings.append(('URL_REPUTATION', f"Known threat ({threat}): {url[:60]}", conf))
        except Exception:
            pass

        # Trusted domain + not in reputation DB → skip ALL pattern and ML checks.
        # School login pages, SSO providers, CDN URLs etc. are never scam indicators.
        if is_trusted and not is_known_malicious:
            return findings

        # 2. Fast XGBoost URL scoring (pure ML, no network I/O, ~1ms).
        #    Run BEFORE pattern checks so we can use it to gate pattern-based findings.
        xgb_prob = self.risk_engine.predict_url_xgb_sync(fetch_url)
        xgb_available = xgb_prob >= 0.0
        if xgb_available:
            if xgb_prob >= 0.85:
                conf = int(xgb_prob * 100)
                findings.append(('ML_HIGH_RISK', f"XGBoost: phishing URL ({conf}%): {url[:50]}", conf))
            elif xgb_prob >= 0.65:
                conf = int(xgb_prob * 100)
                findings.append(('ML_MEDIUM_RISK', f"XGBoost: suspicious URL ({conf}%): {url[:50]}", conf))

        # 3. Pattern-based checks — GATED on XGBoost confirmation.
        #    Patterns fire a finding only when ML also says suspicious (>= 0.50).
        #    If the XGBoost model is unavailable, fall back to patterns alone but
        #    only for non-trivial threats (not just tracking params or ad networks).
        # IMPORTANT: pass fetch_url (with scheme) so urlparse() correctly extracts
        # the netloc/TLD. Without a scheme, urlparse returns empty netloc → TLD = ''.
        url_threats = self.check_url_scams(fetch_url)
        has_pattern = False
        try:
            if self.risk_engine.has_suspicious_patterns(fetch_url):
                has_pattern = True
        except Exception:
            pass

        # Real threats = explicit phishing URL patterns (not tracking params or ad networks)
        real_threats = [t for t in url_threats
                        if not t.startswith('tracking') and not t.startswith('ad_network_')]

        # Split into STRONG and WEAK threat categories:
        #   STRONG: TLD-based signals (.top, .xyz, .tk etc.), fake domain patterns, URL shorteners.
        #           These are reliable standalone indicators — fire WITHOUT ML confirmation.
        #   WEAK:   Path-based patterns (/login, /verify, /auth).
        #           These appear on legitimate sites — KEEP the ML gate to prevent FPs.
        strong_threats = [t for t in real_threats
                          if t.startswith('suspicious_tld_') or t.startswith('fake_') or t == 'url_shortener']
        weak_threats = [t for t in real_threats if t not in strong_threats]

        # Strong threats: fire directly (no ML gate needed — TLD signals are reliable)
        if strong_threats:
            findings.append(('URL_PATTERN', f"Suspicious URL ({', '.join(strong_threats[:2])}): {url[:60]}", 70))

        # Weak threats and path patterns: still require ML confirmation to prevent FPs
        ml_confirms = (xgb_available and xgb_prob >= 0.50) or (not xgb_available)

        if ml_confirms and weak_threats:
            findings.append(('URL_PATTERN', f"Suspicious URL ({', '.join(weak_threats[:2])}): {url[:60]}", 60))

        if ml_confirms and has_pattern and not real_threats:
            findings.append(('URL_PATTERN', f"Phishing URL pattern: {url[:60]}", 75))

        # Fast-path: nothing suspicious at all → no HTML fetch
        if not (real_threats or has_pattern or is_known_malicious or (xgb_available and xgb_prob >= 0.65)):
            return findings

        # 4. Fetch HTML + rule-based HTML analysis — only for high ML scores or known-malicious.
        should_fetch = is_known_malicious or (xgb_available and xgb_prob >= 0.75)
        html = self._fetch_html(fetch_url) if should_fetch else None

        # 5. Rule-based HTML analysis (supplementary, runs only if HTML was fetched)
        if html:
            # 5a. HTML code analysis (17-category phishing/clickjacking detection)
            try:
                is_phishing, reason = self.risk_engine.html_code_analysis(fetch_url, html)
                if is_phishing:
                    findings.append(('HTML_PHISHING', f"Phishing HTML: {reason[:80]}", 80))
            except Exception:
                pass

            # 5b. Content signals (structural HTML analysis)
            try:
                delta, risks, safes = self.risk_engine.content_signals(fetch_url, html)
                if delta < -15 and risks:
                    findings.append(('HTML_SIGNALS', f"Risky HTML structure: {', '.join(risks[:3])}", 65))
            except Exception:
                pass

        # Note: calculate_risk_sync (full async ML pipeline with network I/O) is intentionally
        # not used here — it serializes all URL checks and makes scans take 5-30s.
        # XGBoost + HTML rule-checks above cover the same detection with <10ms latency.

        return findings

    # ============= Main Scan (SINGLE-PHASE FULLY PARALLEL) =============

    def _collect_findings(self, futures, all_findings, timeout=2.0):
        """Collect results from a dict of {future: name}, appending to all_findings"""
        try:
            for future in as_completed(futures, timeout=timeout):
                name = futures[future]
                try:
                    result = future.result(timeout=0.5)
                    if result is None:
                        continue

                    if name == 'ai_image':
                        is_ai, ai_conf, ai_findings = result
                        if is_ai:
                            all_findings.append((
                                'AI_IMAGE',
                                f"AI-generated image ({ai_conf}% conf): {', '.join(ai_findings[:3])}",
                                ai_conf
                            ))
                    elif name in ('inline_text',) or name.startswith('url:'):
                        if isinstance(result, list):
                            all_findings.extend(result)
                    elif isinstance(result, tuple) and len(result) == 3:
                        all_findings.append(result)
                except Exception as e:
                    logger.debug(f"Detector '{name}' error: {e}")
        except Exception as e:
            logger.debug(f"Futures timeout/error: {e}")

    def scan_screen(self):
        """Main scanning function - ALL detectors run FULLY PARALLEL.

        Architecture (post-optimization):
          - Screen capture: Quartz CGWindowListCreateImage (~0.3s vs 1.7s subprocess)
          - Image pre-downscaled ONCE at capture time (not per-detector)
          - OCR: Apple Vision framework on 1280px image (~0.8s vs 7s tesseract full-res)
          - AI FFT on 512x512 image (~0.03s vs 1.6s full-res)
          - Backend visual cues on 800px image (~0.3s, lock-free)
          - ALL backend methods run lock-free (confirmed thread-safe)
          - Two-phase: Phase 1 = OCR + visual + AI, Phase 2 = text/URL detectors
          - _screen_text_alerts SKIPPED (redundant OCR); inline + analyze_text_for_scam used instead
          - Target: ~1s Phase 1 (limited by OCR), ~0.1s Phase 2 (text analysis is fast)
        """
        if self.scanning:
            return
        self.scanning = True

        try:
            scan_start = time.time()

            # Capture screen with pre-downscaled variants
            capture_result = self.capture_screen()
            if not capture_result:
                return
            raw_bytes, visual_bytes, img_full, img_ocr, img_ai = capture_result

            # Dedup unchanged screens (hash the smaller visual bytes for speed)
            screen_hash = hashlib.md5(visual_bytes).hexdigest()
            if screen_hash == self.last_screen_hash:
                return
            self.last_screen_hash = screen_hash

            all_findings = []

            # ===== PHASE 1: OCR + visual + AI — ALL truly parallel (no locks) =====
            phase1 = {}
            # Visual color detector DISABLED - too many false positives on videos/UI
            # Real threats are caught by TEXT_SCAM (80%) and URL_PATTERN (85%)
            # phase1[self.executor.submit(self._run_visual_cues, visual_bytes)] = 'visual'
            # 2. AI image detection on 512x512 image (inline, ~0.03s)
            phase1[self.executor.submit(self.check_ai_image, img_ai, img_full)] = 'ai_image'
            # 3. OCR on 1280px image (Vision framework, ~0.8s — this is the bottleneck)
            ocr_future = self.executor.submit(self._quick_ocr, img_ocr)
            phase1[ocr_future] = 'ocr'
            # NOTE: _screen_text_alerts intentionally NOT run here — it does redundant
            # OCR internally (~1.2s). Instead, we use _quick_ocr text + inline checks
            # + _analyze_text_for_scam, which is faster and covers the same patterns.

            # Wait for phase 1 — all run in parallel, no serialization
            text = ""
            try:
                for future in as_completed(phase1, timeout=4.0):
                    name = phase1[future]
                    try:
                        result = future.result(timeout=0.5)
                        if result is None:
                            continue

                        if name == 'ocr':
                            text = result if isinstance(result, str) else ""
                        elif name == 'ai_image':
                            is_ai, ai_conf, ai_findings = result
                            if is_ai:
                                all_findings.append((
                                    'AI_IMAGE',
                                    f"AI-generated image ({ai_conf}% conf): {', '.join(ai_findings[:3])}",
                                    ai_conf
                                ))
                        elif isinstance(result, tuple) and len(result) == 3:
                            all_findings.append(result)
                    except Exception as e:
                        logger.debug(f"Phase 1 '{name}' error: {e}")
            except Exception as e:
                logger.debug(f"Phase 1 timeout: {e}")

            phase1_time = time.time() - scan_start

            # ===== PHASE 2: Text + URL detectors (dispatched after OCR) =====
            # Updated regex to catch domains even if https:// is hidden by the browser
            # We match full URLs or domain-like strings ending in typical TLDs
            domain_regex = r'\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s\'"<>)}\]]*)?\b'
            raw_urls = re.findall(domain_regex, text) if text else []

            # Filter out URLs that appear to be from browser address bar / chrome
            # These are the URLs the user is currently visiting, not phishing content
            cleaned_text = self._clean_ocr_for_bert(text) if text else ''
            chrome_urls = set(raw_urls) - set(re.findall(domain_regex, cleaned_text)) if cleaned_text else set()
            raw_urls = [u for u in raw_urls if u not in chrome_urls]

            # Filter out false positives — file paths, code files, image files etc.
            # that the domain regex can match (e.g. "tescregex.py", "applescript.py")
            _code_exts = {
                '.py', '.js', '.ts', '.rb', '.go', '.rs', '.c', '.cpp', '.h',
                '.java', '.kt', '.swift', '.sh', '.bash', '.zsh', '.ps1',
                '.yml', '.yaml', '.toml', '.cfg', '.ini', '.conf',
                '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico',
                '.exe', '.dll', '.so', '.dylib',
                '.pdf', '.docx', '.xlsx', '.pptx', '.zip', '.tar', '.gz',
                '.mp4', '.mp3', '.mov', '.avi',
            }
            # Real TLDs are >=2 chars but exclude obvious non-TLD word endings
            _valid_tlds = {
                'com', 'net', 'org', 'io', 'co', 'gov', 'edu', 'mil',
                'app', 'dev', 'ai', 'cloud', 'tech', 'info', 'biz', 'me',
                'us', 'uk', 'ca', 'au', 'de', 'fr', 'nl', 'jp', 'cn',
                'ru', 'br', 'in', 'mx', 'es', 'it', 'pl', 'se', 'ch',
                'tv', 'fm', 'cc', 'ly', 'gl', 'gg', 'vc', 'to',
                'top', 'xyz', 'site', 'online', 'store', 'shop', 'live',
                'click', 'link', 'page', 'web', 'digital', 'media',
                'finance', 'bank', 'secure', 'login', 'account',
                'html', 'php',  # Allow actual web page extensions
            }
            urls = []
            for u in raw_urls:
                u_lower = u.lower()
                # Strip scheme for analysis
                stripped = u_lower.replace('https://', '').replace('http://', '')
                # Must be a reasonable length
                if len(stripped) < 5:
                    continue
                # Extract TLD (last part after final dot before any slash)
                domain_part = stripped.split('/')[0]
                parts = domain_part.split('.')
                if len(parts) < 2:
                    continue
                tld = parts[-1].lower()
                # Reject if TLD is a code/binary/media file extension
                if f'.{tld}' in _code_exts:
                    continue
                # For non-http URLs, require the TLD to be a known web TLD
                if not u.startswith('http') and tld not in _valid_tlds:
                    continue
                urls.append(u)
                
            urls = list(dict.fromkeys(urls))[:5]  # deduplicate, cap at 5

            phase2 = {}
            if text and len(text) >= 10:
                # BERT disabled — too many false positives. TEXT_SCAM catches all real threats.
                # phase2[self.executor.submit(self._run_bert_text_analysis, text)] = 'bert_text'
                # 5b. Backend regex text scam analysis (catches all real phishing at 100%)
                phase2[self.executor.submit(self._run_text_scam_analysis, text)] = 'text_analysis'
                # Inline text checks (scam patterns, ads, email, SMS) — kept disabled to avoid false positives
                # phase2[self.executor.submit(self._run_inline_text_checks, text)] = 'inline_text'

            # 7. URL analysis (parallel per URL)
            for url in urls:
                phase2[self.executor.submit(self._run_url_analysis, url)] = f'url:{url[:50]}'

            if phase2:
                self._collect_findings(phase2, all_findings, timeout=1.5)

            scan_duration = time.time() - scan_start

            # ===== AGGREGATE AND ALERT =====
            if all_findings:
                # Deduplicate by category (keep highest confidence per category)
                best_per_category = {}
                for cat, desc, conf in all_findings:
                    if cat not in best_per_category or conf > best_per_category[cat][2]:
                        best_per_category[cat] = (cat, desc, conf)

                deduped = sorted(best_per_category.values(), key=lambda x: x[2], reverse=True)

                top = deduped[0]
                max_confidence = top[2]

                # Minimum confidence gate — suppress low-confidence speculative findings.
                # URL_PATTERN at 60% from a single pattern match (e.g. /login on a school
                # site that somehow slipped past the trusted-domain check) should not fire
                # a popup. Real threats from TEXT_SCAM, ML_HIGH_RISK, URL_REPUTATION etc.
                # all produce >= 75%, so this gate has no effect on legitimate detections.
                if max_confidence < 65:
                    logger.debug(
                        f"Scan complete in {scan_duration:.2f}s — {len(deduped)} low-confidence "
                        f"findings suppressed (max={max_confidence}% < 65% gate)"
                    )
                    return

                # Title from highest-confidence finding
                category_titles = {
                    'VISUAL': 'Fake Warning Colors Detected!',
                    'TEXT_SCAM': 'SCAM DETECTED!',
                    'TEXT_ANALYSIS': 'SCAM DETECTED!',
                    'BERT_PHISHING': 'PHISHING DETECTED!',
                    'ML_HIGH_RISK': 'HIGH RISK SITE DETECTED!',
                    'ML_MEDIUM_RISK': 'Suspicious Site Detected!',
                    'AI_IMAGE': 'AI-Generated Image Detected!',
                    'ADS': 'Deceptive Advertising Detected!',
                    'EMAIL': 'Phishing Email Detected!',
                    'SMS': 'SMS Scam Detected!',
                    'URL_PATTERN': 'Suspicious URL Detected!',
                    'URL_REPUTATION': 'KNOWN THREAT Detected!',
                    'HTML_PHISHING': 'PHISHING WEBSITE Detected!',
                    'HTML_SIGNALS': 'Suspicious Website Detected!',
                    'NO_SECURITY': 'Insecure Website Detected!',
                }
                title = category_titles.get(top[0], 'THREAT DETECTED!')

                # Build comprehensive message with all findings
                lines = []
                for cat, desc, conf in deduped[:6]:  # Show top 6 findings
                    lines.append(f"[{conf}%] {desc}")

                message = ' | '.join(lines)
                if len(deduped) > 6:
                    message += f" | +{len(deduped) - 6} more issues"

                logger.info(f"Scan complete in {scan_duration:.2f}s (phase1={phase1_time:.2f}s) - {len(deduped)} threats found")
                self.notify(title, message, critical=(max_confidence >= 30))
            else:
                logger.info(f"Scan complete in {scan_duration:.2f}s (phase1={phase1_time:.2f}s) - clean")

        except Exception as e:
            logger.error(f"Scan error: {e}")
        finally:
            self.scanning = False

    # ============= Monitor Loop =============

    def monitor_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                if self.enabled:
                    self.scan_screen()
                time.sleep(1.5)  # Reduced from 3s to 1.5s for faster responsiveness
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)

    def start_monitoring(self):
        t = threading.Thread(target=self.monitor_loop, daemon=True)
        t.start()
        logger.info("Monitoring started")

    def stop_monitoring(self):
        logger.info("Monitoring stopped")


if __name__ == "__main__":
    app = PayGuard()
    app.app.run()
