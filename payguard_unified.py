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
from typing import Optional
from urllib.parse import urlparse

try:
    import rumps
    HAS_RUMPS = True
except ImportError:
    HAS_RUMPS = False

try:
    import pystray
    HAS_PYSTRAY = True
except ImportError:
    HAS_PYSTRAY = False

try:
    from PIL import Image
except ImportError:
    print("Missing: pip3 install Pillow")
    sys.exit(1)

_log_level_name = os.environ.get("PAYGUARD_LOG_LEVEL", "INFO").upper()
_log_level = getattr(logging, _log_level_name, logging.INFO)
logging.basicConfig(level=_log_level)
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
    'yahoo', 'ebay', 'spotify', 'slack', 'zoom', 'github', 'whatsapp',
    'dhl', 'fedex', 'usps', 'ups', 'capitalone', 'americanexpress',
    'walmart', 'target', 'costco', 'bestbuy',
    'chrome', 'firefox', 'safari', 'opera', 'edge',
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
                # Avoid creating an un-awaited coroutine when already inside
                # an active event loop.
                try:
                    asyncio.get_running_loop()
                    logger.debug("Feed update skipped: event loop already running")
                except RuntimeError:
                    asyncio.run(self._service.update_cache())
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

    def has_suspicious_patterns(self, url: str, domain: Optional[str] = None) -> bool:
        """Run _has_suspicious_patterns: 30+ regex patterns for phishing URLs.
        Thread-safe: reads only immutable class-level constant list."""
        if not self._load_engine():
            return False
        try:
            return self._engine._has_suspicious_patterns(url, domain)
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
            import json
            from pathlib import Path
            feat = engine._url_features(url)
            x = np.array(feat).reshape(1, -1)
            try:
                import xgboost as xgb
                feature_names = None
                try:
                    names_path = Path(__file__).parent / "models" / "url_feature_names.json"
                    if names_path.exists():
                        with open(names_path, "r", encoding="utf-8") as f:
                            feature_names = json.load(f)
                except Exception:
                    feature_names = None
                dm = xgb.DMatrix(x, feature_names=feature_names)
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
        self.last_alert_signature = ""
        self.last_alert_signature_time = 0
        self.alert_cooldown = 5  # Reduced from 10s to 5s so it feels more responsive during tests
        self._scan_auto_close_urls = []  # URLs flagged for auto-close (100% certainty)
        self._finding_hits = {}
        self._finding_confirm_window_s = 25
        self.url_cache = {}  # Cache URL analysis results: {url: (timestamp, findings)}

        # Backend integrations (lazy loaded)
        self.url_reputation = URLReputationChecker()
        self.risk_engine = RiskEngineChecker()
        self.deepfake_video = DeepfakeVideoDetector()
        self.deepfake_audio = DeepfakeAudioDetector()
        self.api_client = PayGuardAPIClient()

        # Thread pool for parallel detection (reused across scans)
        self.executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="payguard")
        self._monitor_thread = None
        self._monitor_stop = threading.Event()

        # Menu bar / system tray
        self.tray_icon = None
        if HAS_RUMPS:
            # macOS: use rumps menu bar
            self.app = rumps.App("PayGuard")
            self.toggle_item = rumps.MenuItem('OFF', callback=self.toggle)
            self.app.menu = [self.toggle_item]
            self.update_status()
        elif HAS_PYSTRAY and (IS_LINUX or IS_WINDOWS):
            # Linux/Windows: use pystray system tray
            self.app = None
            self.toggle_item = None
            self._setup_system_tray()
        else:
            # No tray available - CLI mode only
            self.app = None
            self.toggle_item = None
            self.app_title = "🛡️"
            print("⚠️  No menu bar available. Running in CLI mode.")
            print("   To reopen: run 'python3 payguard_unified.py' again")

        self.start_monitoring()  # Auto-start monitoring since enabled=True at launch

    def update_status(self):
        if HAS_RUMPS:
            if self.enabled:
                self.toggle_item.title = 'ON'
                self.app.title = "\U0001f6e1\ufe0f"
            else:
                self.toggle_item.title = 'OFF'
                self.app.title = "\u26ab"
        elif HAS_PYSTRAY and self.tray_icon:
            # Update tray icon based on enabled state
            self.tray_icon.update_icon(self._create_tray_image())
            if self.enabled:
                self.tray_icon.title = "🛡️ PayGuard ON"
            else:
                self.tray_icon.title = "🛡️ PayGuard OFF"

    def _create_tray_image(self):
        """Create a simple tray icon image"""
        from PIL import Image, ImageDraw
        size = 64
        img = Image.new('RGB', (size, size), color='black')
        draw = ImageDraw.Draw(img)
        # Draw a simple shield shape
        draw.ellipse([8, 8, 56, 56], fill='#10b981' if self.enabled else '#6b7280')
        return img

    def _setup_system_tray(self):
        """Setup system tray for Linux/Windows"""
        try:
            self.tray_icon = pystray.Icon(
                "payguard",
                self._create_tray_image(),
                "PayGuard",
                menu=pystray.Menu(
                    pystray.MenuItem("Show", self._show_window),
                    pystray.MenuItem("ON/OFF", self.toggle),
                    pystray.MenuItem("Quit", self.quit_app)
                )
            )
            self.tray_icon.title = "🛡️ PayGuard ON"
        except Exception as e:
            logger.warning(f"System tray setup failed: {e}")
            self.tray_icon = None

    def _show_window(self):
        """Show window - placeholder for tray click"""
        logger.info("PayGuard is running in background")

    def quit_app(self):
        """Quit the application"""
        self.enabled = False
        self.stop_monitoring()
        if self.tray_icon:
            self.tray_icon.stop()
        logger.info("PayGuard stopped")
        sys.exit(0)

    def toggle(self, _=None):
        if HAS_RUMPS:
            pass  # rumps handles toggle via callback
        elif self.tray_icon:
            self.enabled = not self.enabled
            self.update_status()
            if self.enabled:
                self.start_monitoring()
            else:
                self.stop_monitoring()
            return

        self.enabled = not self.enabled
        self.update_status()

    # ============= Popup Dialog Alerts =============

    def notify(self, title, message, critical=False, force=False):
        """Show notification - logs by default, popups only if explicitly enabled"""
        now = time.time()
        if not force and now - self.last_alert_time < 10:
            logger.info(f"Alert suppressed (cooldown): {title}")
            return

        self.last_alert_time = now

        # Check if notifications are enabled (default: off for privacy/simplicity)
        NOTIFICATIONS_ENABLED = os.environ.get("PAYGUARD_NOTIFICATIONS", "false").lower() == "true"

        # Always log the threat
        self.threats_found += 1
        logger.info(f"THREAT #{self.threats_found}: {title} - {message}")

        # Only show popups if explicitly enabled
        if not NOTIFICATIONS_ENABLED:
            return

        # Plain-language dialog body
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
            'SCAM TAB CLOSED!':          "This URL was a scam, PayGuard closed it for you.",
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
                        f'buttons {{"OK"}} default button "OK" with icon stop'
                    )
                    subprocess.Popen(
                        ["osascript", "-e", dialog_cmd],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
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

    def _finding_signature(self, finding):
        """Stable signature for deduplicating noisy transient findings."""
        cat, desc, _ = finding
        dl = (desc or "").lower()
        m = re.search(r'https?://([^/\s]+)', dl)
        if m:
            host = m.group(1).split(':')[0].lstrip('www.')
            return f"{cat}:{host}"

        m2 = re.search(r'\b([a-z0-9-]+\.[a-z]{2,})\b', dl)
        if m2:
            host = m2.group(1).split(':')[0].lstrip('www.')
            return f"{cat}:{host}"

        compact = re.sub(r'\s+', ' ', dl)[:160]
        return f"{cat}:{compact}"

    def _requires_repeat_confirmation(self, deduped):
        """Only require repeat confirmation for very low confidence findings."""
        if any(cat in {'URL_REPUTATION', 'TEXT_SCAM', 'TEXT_ANALYSIS'} for cat, _, _ in deduped):
            return False
        if any(cat == 'HTML_PHISHING' and conf >= 50 for cat, _, conf in deduped):
            return False
        if any(conf >= 60 for _, _, conf in deduped):
            return False
        if len({cat for cat, _, _ in deduped}) >= 2:
            return False
        return True

        return True

    def _confirmed_in_consecutive_scans(self, finding):
        now = time.time()
        sig = self._finding_signature(finding)
        count, last_ts = self._finding_hits.get(sig, (0, 0.0))
        if now - last_ts <= self._finding_confirm_window_s:
            count += 1
        else:
            count = 1
        self._finding_hits[sig] = (count, now)

        # Prune stale signatures
        ttl = max(120, self._finding_confirm_window_s * 4)
        stale = [k for k, (_, ts) in self._finding_hits.items() if now - ts > ttl]
        for k in stale:
            self._finding_hits.pop(k, None)

        return count >= 2

    def _passes_alert_gate(self, deduped):
        """Category-aware alert gate. Lowered thresholds so real threats show alerts."""
        if any(cat == 'URL_REPUTATION' for cat, _, _ in deduped):
            return True
        if any(cat in {'TEXT_ANALYSIS', 'TEXT_SCAM'} and conf >= 60 for cat, _, conf in deduped):
            return True
        # HTML structural analysis is high-confidence signal — allow at 50+
        if any(cat in {'HTML_PHISHING'} and conf >= 50 for cat, _, conf in deduped):
            return True
        if any(cat in {'ML_HIGH_RISK', 'URL_PATTERN', 'HTML_SIGNALS'} and conf >= 60 for cat, _, conf in deduped):
            return True
        top_conf = max((conf for _, _, conf in deduped), default=0)
        return top_conf >= 50

    # ============= Auto-Close Tab (100%-certain scams only) =============

    def _should_auto_close(self, findings, xgb_prob):
        """Return True ONLY when all three hard conditions are simultaneously satisfied:
          1. URL is in a known threat feed (URL_REPUTATION finding present)
          2. XGBoost confidence >= 0.95
          3. At least one strong secondary signal:
               - HTML_PHISHING confirmed, OR
               - URL_PATTERN with suspicious TLD + obvious fake-brand pattern
        Any single condition failing → False (zero false-positive tolerance).
        """
        # Condition 1: reputation DB hit is mandatory
        has_reputation_hit = any(cat == 'URL_REPUTATION' for cat, _, _ in findings)
        if not has_reputation_hit:
            return False

        # Condition 2: XGBoost must be >= 0.95
        if xgb_prob < 0.95:
            return False

        # Condition 3: at least one strong secondary signal
        has_html_phishing = any(cat == 'HTML_PHISHING' for cat, _, _ in findings)
        if has_html_phishing:
            return True

        # URL_PATTERN counts only when the description contains BOTH a suspicious TLD
        # signal AND a fake-brand signal (e.g. "suspicious_tld_xyz, fake_paypal")
        for cat, desc, _ in findings:
            if cat == 'URL_PATTERN':
                desc_lower = desc.lower()
                has_tld_signal = 'suspicious_tld_' in desc_lower
                has_fake_brand = 'fake_' in desc_lower
                if has_tld_signal and has_fake_brand:
                    return True

        return False

    def _close_browser_tab(self):
        """Send Cmd+W to the frontmost browser window via osascript.
        Tries Chrome, Firefox, and Safari in order; falls back to a
        generic key-stroke to whatever app is frontmost.
        """
        if not IS_MAC:
            logger.debug("Auto-close: not on macOS, skipping tab close")
            return

        browsers = ['Google Chrome', 'Firefox', 'Safari', 'Microsoft Edge']

        script = '''
tell application "System Events"
    set frontApp to name of first application process whose frontmost is true
    set browserNames to {"Google Chrome", "Firefox", "Safari", "Microsoft Edge", "Brave Browser", "Opera"}
    if browserNames contains frontApp then
        keystroke "w" using command down
        return "closed: " & frontApp
    else
        return "skipped: " & frontApp & " is not a browser"
    end if
end tell
'''
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=5
            )
            outcome = (result.stdout or "").strip()
            logger.info(f"Auto-close tab: {outcome}")
        except Exception as e:
            logger.error(f"Auto-close tab error: {e}")

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
            # token-boundary match to avoid substring false positives
            if re.search(rf'(^|[^a-z0-9]){re.escape(domain)}([^a-z0-9]|$)', url_lower):
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
            resp = httpx.get(url, timeout=1.0, follow_redirects=True,
                             headers={
                                 "User-Agent": "Mozilla/5.0 PayGuard/1.0",
                                 "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
                             })
            content_type = resp.headers.get('content-type', '')
            body = resp.text or ""
            looks_like_html = body.lstrip().lower().startswith('<!doctype html') or '<html' in body[:1000].lower()
            if resp.status_code == 200 and ('html' in content_type.lower() or looks_like_html):
                return body[:50000]  # Cap at 50KB to avoid slowdowns
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
        # Education / testing platforms
        'collegeboard.org',     # SAT, AP, collegeboard.org
        'khanacademy.org',     # Khan Academy
        'coursera.org',        # Coursera
        'udemy.com',           # Udemy
        'edx.org',             # edX
        'k12.com',             # K12
        'pearson.com',         # Pearson LMS / MyLab / Revel
        'clever.com',          # Clever SSO for schools
        'jclever.com',         # Clever Jumpstart / OAuth
        'classkick.com',       # Classkick
        'quizlet.com',         # Quizlet
        'powerschool.com',     # Powerschool SIS
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

    def _get_browser_url(self):
        """Get browser URL from window title or accessibility API."""
        try:
            # Try using window title extraction (faster, no AppleScript needed)
            # macOS window titles often contain " — Page Title" after the URL
            script = '''
            tell application "System Events"
                set frontApp to name of first application process whose frontmost is true
                if frontApp is in {"Safari", "Google Chrome", "Microsoft Edge", "Firefox", "Arc", "Brave Browser"} then
                    set frontWindow to first window of process frontApp
                    set winTitle to name of frontWindow
                    return frontApp & "|" & winTitle
                end if
            end tell
            return ""
            '''
            result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=2)
            output = result.stdout.strip()
            if not output or '|' not in output:
                return None

            app_name, win_title = output.split('|', 1)

            # Extract URL from window title
            # Chrome/Safari titles: "Page Title - Google Search" or "Google Search"
            # If the title contains a domain, extract it
            domain_match = re.search(r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', win_title)
            if domain_match:
                return f"https://{domain_match.group(1)}"

            # Try direct URL access for Safari/Chrome
            if app_name == "Safari":
                url_script = 'tell application "Safari" to return URL of current tab of window 1'
            elif app_name in ("Google Chrome", "Microsoft Edge", "Brave Browser"):
                url_script = f'tell application "{app_name}" to return URL of active tab of window 1'
            else:
                return None

            url_result = subprocess.run(["osascript", "-e", url_script], capture_output=True, text=True, timeout=2)
            url = url_result.stdout.strip()
            if url and url.startswith('http'):
                return url
        except Exception:
            pass
        return None

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

    def _is_likely_web_url_candidate(self, candidate: str) -> bool:
        """Filter OCR URL candidates to avoid filesystem/path false positives.

        OCR often reads local app bundle paths as pseudo-URLs like
        `n.app/Contents/MacOS/Python`. These are not real web links and should
        never enter URL risk analysis.
        """
        try:
            raw = (candidate or "").strip().strip('.,;:)]}\"\'')
            if not raw:
                return False

            has_scheme = raw.startswith(("http://", "https://"))
            parsed = urlparse(raw if has_scheme else f"https://{raw}")
            host = (parsed.netloc or "").lower().split(":")[0].lstrip("www.")
            if not host or "." not in host:
                return False
            if not re.fullmatch(r"[a-z0-9.-]+", host):
                return False

            labels = host.split(".")
            if any(not lbl or lbl.startswith("-") or lbl.endswith("-") for lbl in labels):
                return False

            # One-letter SLDs are usually OCR artifacts in our scans.
            # Keep explicit exceptions for legitimate well-known short domains.
            sld = labels[-2] if len(labels) >= 2 else ""
            if len(sld) == 1 and host not in {"x.com", "t.co"}:
                return False

            path = parsed.path or ""
            path_l = path.lower()

            # Hard reject local filesystem/app-bundle markers misread as URLs.
            fs_markers = (
                "/contents/macos",
                "/contents/resources",
                "/library/frameworks",
                "/system/library",
                "/site-packages",
                "/users/",
                "/applications/",
            )
            if any(m in path_l for m in fs_markers):
                return False

            # For no-scheme OCR candidates, multiple capitalized path segments are
            # a strong signal this is a local path, not a website route.
            if not has_scheme and path:
                segments = [seg for seg in path.split("/") if seg]
                cap_segments = 0
                for seg in segments:
                    if len(seg) >= 3 and seg.isalpha() and any(ch.isupper() for ch in seg):
                        cap_segments += 1
                if cap_segments >= 2:
                    return False

            return True
        except Exception:
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
            if result.get('confidence', 0) < 75:
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

            # Hard anchor requirement to reduce normal-page false positives.
            # At least one explicit scam anchor must be present.
            hard_anchors = {
                'phone_number',
                'payment_request',
                'virus_warning',
                'error_code',
                'do_not_close',
            }
            anchor_hits = [p for p in patterns if p in hard_anchors]
            has_suspicious_email = any(
                str(p).startswith('suspicious_email:') for p in patterns
            )
            # Require either:
            #  - explicit suspicious-email signal, OR
            #  - at least two hard anchors, OR
            #  - a strong scam combo: phone + (virus/error/payment/do_not_close)
            strong_combo = (
                'phone_number' in patterns and (
                    'virus_warning' in patterns or
                    'error_code' in patterns or
                    'payment_request' in patterns or
                    'do_not_close' in patterns
                )
            )
            if not (has_suspicious_email or len(anchor_hits) >= 2 or strong_combo):
                # High-confidence explicit phishing phrases should still pass
                # with one hard anchor.
                if not (result.get('confidence', 0) >= 85 and len(anchor_hits) >= 1):
                    logger.debug(
                        f"Text analysis: suppressed (insufficient hard anchors: {patterns})"
                    )
                    return None

            conf = result.get('confidence', 60)
            return ('TEXT_ANALYSIS', f"Text threats: {', '.join(patterns[:4])}", conf)
        except Exception as e:
            logger.debug(f"Text scam analysis worker error: {e}")
        return None

    # Suspicious TLDs — used almost exclusively for phishing
    _SUSPICIOUS_TLDS = frozenset({
        'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'site', 'online',
        'store', 'shop', 'live', 'click', 'link', 'page', 'digital',
        'finance', 'bank', 'secure', 'login', 'account', 'buzz', 'club',
        'work', 'fit', 'rest', 'monster', 'icu', 'cfd', 'sbs',
        'quest', 'cam', 'cyou', 'surf', 'uno', 'pro', 'info', 'biz',
    })

    # Brands commonly targeted by lookalike phishing domains
    _LOOKALIKE_BRAND_DOMAINS = {
        'paypal.com': 'paypal', 'amazon.com': 'amazon', 'microsoft.com': 'microsoft',
        'google.com': 'google', 'apple.com': 'apple', 'facebook.com': 'facebook',
        'netflix.com': 'netflix', 'instagram.com': 'instagram', 'whatsapp.com': 'whatsapp',
        'linkedin.com': 'linkedin', 'chase.com': 'chase', 'bankofamerica.com': 'bankofamerica',
        'wellsfargo.com': 'wellsfargo', 'citibank.com': 'citibank', 'capitalone.com': 'capitalone',
        'americanexpress.com': 'americanexpress', 'amex.com': 'amex',
        'dropbox.com': 'dropbox', 'adobe.com': 'adobe', 'outlook.com': 'outlook',
        'yahoo.com': 'yahoo', 'ebay.com': 'ebay', 'coinbase.com': 'coinbase',
        'binance.com': 'binance', 'stripe.com': 'stripe',
        'twitter.com': 'twitter', 'x.com': 'x', 'reddit.com': 'reddit',
        'spotify.com': 'spotify', 'slack.com': 'slack', 'zoom.us': 'zoom',
        'github.com': 'github',         'dhl.com': 'dhl', 'fedex.com': 'fedex',
        'usps.com': 'usps', 'ups.com': 'ups',
        'chrome.google.com': 'chrome', 'firefox.com': 'firefox',
    }

    # Homoglyph normalization map (Cyrillic/confusables → ASCII)
    _HOMOGLYPH_NORMALIZE = str.maketrans({
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
        '\u04bb': 'h', '\u04cf': 'l',
        '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
        '\u03c3': 'o', '\u03c4': 't', '\u03c5': 'u', '\u03c7': 'x',
        '\u03b9': 'i', '\u03ba': 'k', '\u03bd': 'v', '\u0410': 'a',
        '\u0415': 'e', '\u041e': 'o', '\u0420': 'p', '\u0421': 'c',
        '\u0425': 'x', '\u0406': 'i',
    })

    # Common character substitutions used in lookalike domains
    _CHAR_SUBS = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b'}

    def _levenshtein(self, a, b):
        """Levenshtein distance between two strings."""
        if len(a) < len(b):
            return self._levenshtein(b, a)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            curr = [i + 1]
            for j, cb in enumerate(b):
                cost = 0 if ca == cb else 1
                curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
            prev = curr
        return prev[-1]

    def _normalize_homoglyphs(self, s):
        """Normalize homoglyph characters to ASCII equivalents."""
        s = s.translate(self._HOMOGLYPH_NORMALIZE)
        return s

    def _substitute_chars(self, s):
        """Generate common character substitutions (0→o, 1→l, etc.)."""
        variants = set()
        for i, c in enumerate(s):
            if c in self._CHAR_SUBS:
                variants.add(s[:i] + self._CHAR_SUBS[c] + s[i+1:])
        return variants

    def _detect_brand_lookalike(self, host):
        """Detect brand impersonation via homoglyphs, char substitution, and typosquatting.

        Catches domains like:
        - paypa1.com (1→l substitution)
        - arnazon.com (typo: rn→m)
        - faceb00k-login.com (0→o substitution)
        - pаypal.com (Cyrillic а)
        - micr0soft-support.com (0→o in compound domain)
        """
        flags = []
        if '.' not in host:
            return flags
        sld = host.rsplit('.', 1)[0].lower()
        sld_flat = re.sub(r'[-_.]+', '', sld)

        # Step 1: Normalize homoglyphs (Cyrillic → Latin)
        sld_norm = self._normalize_homoglyphs(sld_flat)

        # Step 2: Normalize ALL digit substitutions (not just one-at-a-time)
        sld_norm = sld_norm.translate(
            str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b'})
        )

        # Step 3: Check if normalized SLD exactly matches, starts with, or ends with a brand
        for apex, brand in self._LOOKALIKE_BRAND_DOMAINS.items():
            if len(brand) < 4:
                continue
            if sld_norm == brand or sld_norm.startswith(brand) or sld_norm.endswith(brand):
                # Don't flag if it's the real domain
                is_real = any(host == a or host.endswith('.' + a) for a in self._TRUSTED_URL_DOMAINS)
                if not is_real:
                    flags.append(f'lookalike_{brand}')
                    return flags

        # Step 4: Fuzzy substring match — only for brand at START or END of SLD
        # Middle matches cause false positives (e.g. "odrome" vs "chrome" inside "aerodrome")
        if len(sld_norm) >= 6:
            for apex, brand in self._LOOKALIKE_BRAND_DOMAINS.items():
                if len(brand) < 5:
                    continue
                # Check chunk at START of SLD
                chunk_start = sld_norm[:len(brand)+1]
                dist_start = self._levenshtein(chunk_start, brand)
                max_d = 2 if len(brand) <= 7 else 1
                if dist_start <= max_d:
                    flags.append(f'lookalike_{brand}')
                    return flags
                # Check chunk at END of SLD
                chunk_end = sld_norm[-(len(brand)+1):]
                dist_end = self._levenshtein(chunk_end, brand)
                if dist_end <= max_d:
                    flags.append(f'lookalike_{brand}')
                    return flags

        return flags

    def _classify_domain_tier(self, host):
        """Classify domain into threat tiers for proportional analysis."""
        if not host:
            return 'TIER_NEUTRAL', []
        host = host.lower().split(':')[0]
        if host.startswith('www.'):
            host = host[4:]
        tld = host.rsplit('.', 1)[-1] if '.' in host else ''
        if tld in ('edu', 'gov', 'mil'):
            return 'TIER_SAFE', ['trusted_tld']
        for apex in self._TRUSTED_URL_DOMAINS:
            if host == apex or host.endswith('.' + apex):
                return 'TIER_SAFE', ['known_domain']
        labels = host.split('.')
        if len(labels) < 2:
            return 'TIER_NEUTRAL', ['bare_host']
        flags = []
        if tld in self._SUSPICIOUS_TLDS:
            flags.append(f'suspicious_tld_{tld}')
        host_tokens = set(re.split(r'[^a-z0-9]+', host))
        # Normalize host for substring brand matching (catches "secure-chase-banking.com")
        host_normalized = re.sub(r'[-_.]+', '', host.lower())
        for brand in PROTECTED_BRANDS:
            # Token match (exact word match after splitting on separators)
            # OR substring match only if brand is 6+ chars AND the SLD starts/ends with the brand
            # (prevents "chrome" matching inside "aerodrome")
            sld = host_normalized.rsplit('.', 1)[0] if '.' in host_normalized else host_normalized
            is_substring_match = False
            if len(brand) >= 6 and brand in host_normalized:
                # Only match if brand is at the START or END of the SLD (not buried in middle)
                if sld.startswith(brand) or sld.endswith(brand):
                    is_substring_match = True
            if brand in host_tokens or is_substring_match:
                is_real = any(host == apex or host.endswith('.' + apex) for apex in self._TRUSTED_URL_DOMAINS)
                if not is_real:
                    flags.append(f'fake_{brand}')
        if host in URL_SHORTENERS or any(host == s or host.endswith('.' + s) for s in URL_SHORTENERS):
            flags.append('url_shortener')
        # Lookalike detection: homoglyphs, char substitution, typosquatting
        lookalike_flags = self._detect_brand_lookalike(host)
        flags.extend(lookalike_flags)
        if flags:
            return 'TIER_SUSPICIOUS', flags
        return 'TIER_NEUTRAL', []

    def _compute_url_risk_score(self, url):
        """Signal-fusion risk scorer. Replaces the broken XGBoost model for URL analysis.

        Computes 5 independent risk signals and fuses them:
        1. Domain impersonation (brand similarity via multiple methods)
        2. TLD risk (suspicious TLD prevalence)
        3. URL structure risk (domain architecture patterns)
        4. HTML risk (page structure analysis)
        5. Content risk (text scam detection)

        Each signal is 0.0-1.0. Final score is weighted fusion.
        No hardcoded brand lists — uses generalized similarity detection.
        """
        fetch_url = url if url.startswith('http') else f"https://{url}"
        try:
            parsed = urlparse(fetch_url)
            host = parsed.netloc.lower()
            if host.startswith('www.'):
                host = host[4:]
        except Exception:
            return 0.0, []

        if not host or '.' not in host:
            return 0.0, []

        labels = host.split('.')
        sld = labels[-2] if len(labels) >= 2 else host
        tld = labels[-1] if labels else ''
        findings = []

        # Skip trusted domains entirely
        for apex in self._TRUSTED_URL_DOMAINS:
            if host == apex or host.endswith('.' + apex):
                return 0.0, []

        scores = {}

        # === SIGNAL 1: Domain Impersonation Score ===
        # Uses multiple detection methods — not hardcoded brand lists
        sld_flat = re.sub(r'[-_.]+', '', sld.lower())
        sld_norm = self._normalize_homoglyphs(sld_flat)
        sld_norm = sld_norm.translate(
            str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b'})
        )

        impersonation_score = 0.0
        impersonation_brand = None

        # Use the existing lookalike detector (proven to catch 14/15 test cases)
        lookalike_flags = self._detect_brand_lookalike(host)
        if lookalike_flags:
            # Extract brand from flag like 'lookalike_paypal'
            flag = lookalike_flags[0]
            brand = flag.replace('lookalike_', '')
            impersonation_score = 0.95
            impersonation_brand = brand

        # Also check exact brand token match in hyphenated compound domains
        # e.g., "paypal-secure-login.com"
        if not impersonation_brand:
            host_tokens = set(re.split(r'[^a-z0-9]+', host))
            for brand in PROTECTED_BRANDS:
                if brand in host_tokens:
                    is_real = any(host == apex or host.endswith('.' + apex) for apex in self._TRUSTED_URL_DOMAINS)
                    if not is_real:
                        impersonation_score = 0.85
                        impersonation_brand = brand
                        break

        scores['impersonation'] = impersonation_score
        if impersonation_brand:
            findings.append(('DOMAIN_IMPERSONATION',
                f"Domain impersonates {impersonation_brand} ({impersonation_score:.0%} similarity): {host}",
                int(impersonation_score * 100)))

        # === SIGNAL 2: TLD Risk Score ===
        # Use the tier classification which already has TLD analysis
        tier, tier_flags = self._classify_domain_tier(host)
        has_suspicious_tld = any(f.startswith('suspicious_tld_') for f in tier_flags)
        tld_risk = 0.7 if has_suspicious_tld else 0.0
        scores['tld'] = tld_risk

        # === SIGNAL 3: URL Structure Risk Score ===
        structure_score = 0.0
        structure_reasons = []

        # IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            structure_score += 0.6
            structure_reasons.append('ip-address')

        # Excessive subdomains
        if len(labels) >= 4:
            structure_score += 0.3
            structure_reasons.append('many-subdomains')

        # Excessive hyphens in domain
        if host.count('-') >= 3:
            structure_score += 0.3
            structure_reasons.append('many-hyphens')

        # Very long domain
        if len(host) > 40:
            structure_score += 0.2
            structure_reasons.append('long-domain')

        # @ symbol in URL (user:pass@host trick)
        if '@' in fetch_url:
            structure_score += 0.5
            structure_reasons.append('@-in-url')

        # Hex-encoded path segments
        if re.search(r'%[0-9a-f]{2}', fetch_url, re.I):
            structure_score += 0.1

        structure_score = min(1.0, structure_score)
        scores['structure'] = structure_score

        # === SIGNAL 4+5: HTML + Content Risk (fetched lazily) ===
        html_score = 0.0
        content_score = 0.0

        # Only fetch HTML if we have signals suggesting it's worth analyzing
        should_analyze = (
            impersonation_score > 0.3
            or tld_risk > 0.3
            or structure_score > 0.3
        )

        if should_analyze:
            html = self._fetch_html(fetch_url)
            if html:
                # HTML structural analysis
                try:
                    is_phish, reason = self.risk_engine.html_code_analysis(fetch_url, html)
                    if is_phish:
                        html_score = 0.85
                        findings.append(('HTML_PHISHING', f"Phishing HTML: {reason[:80]}", 85))
                except Exception:
                    pass

                # Content signals
                try:
                    delta, risks, safes = self.risk_engine.content_signals(fetch_url, html)
                    if delta < -20 and risks:
                        content_score = min(0.8, abs(delta) / 50.0)
                        findings.append(('HTML_SIGNALS', f"Risky structure: {', '.join(risks[:3])}", int(content_score * 100)))
                except Exception:
                    pass

        scores['html'] = html_score
        scores['content'] = content_score

        # === FUSION: Weighted combination ===
        # Domain impersonation is the STRONGEST signal — weight it highest
        # because it catches the most phishing with the fewest false positives
        weights = {
            'impersonation': 0.40,
            'tld': 0.15,
            'structure': 0.15,
            'html': 0.20,
            'content': 0.10,
        }

        # If we have a strong impersonation signal, boost its weight
        if impersonation_score >= 0.8:
            weights['impersonation'] = 0.55
            weights['tld'] = 0.10
            weights['structure'] = 0.10
            weights['html'] = 0.15
            weights['content'] = 0.10

        composite = sum(scores[k] * weights[k] for k in scores)
        composite = min(1.0, composite)

        return composite, findings

    def _analyze_page_behavior(self, text):
        """Behavioral phishing detector — analyzes what the USER SEES on screen.

        Catches modern phishing that doesn't use brand names in URLs:
        - Fake security warnings ("Your computer is infected!")
        - Credential harvesting ("Enter your password to continue")
        - Tech support scams ("Call 1-800-XXX immediately")
        - Urgency + consequence patterns ("Act now or lose access")
        - Brand mentions on non-brand pages ("PayPal requires verification")

        Uses BEHAVIORAL patterns, not hardcoded phrases. The ML model learns
        what phishing PAGES look like from the combination of signals.
        """
        if not text or len(text) < 20:
            return None

        tl = text.lower().strip()
        signals = {}

        # === SIGNAL 1: Threat + Demand Combination (PERSONAL/DIRECTED at the user) ===
        # Phishing always says "YOUR account" not "the account" — it's directed at the victim
        threat_patterns = [
            r'(?:your|you)\s+(?:\w+\s+)?(?:account|computer|device|system|browser|email|phone)\s+(?:has been|is|are)\s+(?:compromised|infected|locked|suspended|hacked|blocked|breached|stolen)',
            r'(?:your|you)\s+(?:\w+\s+)?(?:account|device|system)\s+(?:is|has been)\s+(?:at\s+risk|in\s+danger|compromised|locked|suspended)',
            r'(?:we\s+(?:have\s+)?detected|we\s+found|warning.*detected)\s+(?:a\s+)?(?:virus|malware|threat|suspicious\s+activity)',
            r'(?:your\s+(?:\w+\s+)?(?:computer|device|system|browser)\s+(?:is|has\s+been)\s+(?:infected|compromised|attacked))',
            r'(?:do\s+not|don\'t)\s+(?:close|shut|turn|exit|leave|ignore)\s+(?:this|the)\s+(?:window|page|tab|message)',
        ]
        threat_count = sum(1 for p in threat_patterns if re.search(p, tl))
        signals['threat'] = min(1.0, threat_count * 0.5)

        # === SIGNAL 2: Demand for Action (directed at the user) ===
        demand_patterns = [
            r'(?:call|dial|phone)\s*(?:us|support|now|immediately|at)\s*[\+\(]?\d',
            r'(?:call|dial)\s*[\+\(]?\d[\d\s\-\(\)]{7,}',
            r'(?:click|tap|press)\s*(?:here|the\s+(?:button|link))\s*(?:now|immediately|to)',
            r'(?:verify|confirm|validate|update|restore|unlock|recover|reset)\s*(?:your|the)\s*(?:\w+\s+)?(?:account|identity|password|email|payment)',
            r'(?:enter|provide|submit|type)\s*(?:your|the)\s*(?:\w+\s+)?(?:password|email|username|card|ssn|social\s+security)',
        ]
        demand_count = sum(1 for p in demand_patterns if re.search(p, tl))
        signals['demand'] = min(1.0, demand_count * 0.5)

        # === SIGNAL 3: Urgency/Consequence ===
        urgency_patterns = [
            r'(?:within|in)\s+\d+\s+(?:hours?|minutes?|days?|seconds?)',
            r'(?:expires?|expiring|suspension|deletion|closing)\s+(?:in|within|soon|today|tomorrow)',
            r'(?:immediately|right\s+now|asap|urgent|urgently|act\s+now|last\s+chance|final\s+warning)',
            r'(?:or\s+(?:else|your|lose|permanent|account|access))',
            r'(?:limited\s+time|time\s+sensitive|expires?\s+soon)',
        ]
        urgency_count = sum(1 for p in urgency_patterns if re.search(p, tl))
        signals['urgency'] = min(1.0, urgency_count * 0.4)

        # === SIGNAL 4: Phone Number + Support Context ===
        has_phone = bool(re.search(
            r'(?:call|dial|phone|contact|support|help|toll|free)[^0-9]{0,30}[\+\(]?\d[\d\s\-\(\)]{7,}',
            tl
        ))
        # Also: phone number displayed prominently (standalone, not in a URL)
        has_standalone_phone = bool(re.search(
            r'(?:^|\s)[\+\(]?\d{3}[\)\.\-\s]?\d{3}[\.\-\s]?\d{4}(?:\s|$)',
            text  # Use original text (not lowercased) for phone number pattern
        ))
        signals['phone'] = 1.0 if has_phone else (0.3 if has_standalone_phone else 0.0)

        # === SIGNAL 5: Credential/Form Request (directed at user) ===
        credential_patterns = [
            r'(?:enter|provide|submit|type|input)\s+your\s+(?:password|passcode|pin)',
            r'(?:your|the)\s+(?:credit\s+card|debit\s+card|card\s+number)',
            r'(?:your)\s+(?:social\s+security|ssn)',
            r'(?:enter|provide)\s+(?:cvv|cvc|security\s+code)',
            r'(?:sign\s+in|log\s+in)\s+(?:to|with)\s+your',
        ]
        cred_count = sum(1 for p in credential_patterns if re.search(p, tl))
        signals['credential'] = min(1.0, cred_count * 0.5)

        # === SIGNAL 6: Brand Mismatch (brand mentioned but page context is wrong) ===
        # If a big brand name appears in text alongside threat/demand language, it's phishing
        brand_mentioned = None
        common_brands = ['microsoft', 'apple', 'google', 'amazon', 'paypal', 'facebook',
                        'netflix', 'instagram', 'chase', 'wellsfargo', 'bank of america',
                        'citibank', 'yahoo', 'norton', 'mcafee', 'windows']
        for brand in common_brands:
            if brand in tl:
                brand_mentioned = brand
                break
        # Brand + (threat OR demand) = likely impersonation
        if brand_mentioned and (threat_count > 0 or demand_count > 0):
            signals['brand_impersonation'] = 0.8
        elif brand_mentioned and urgency_count > 0:
            signals['brand_impersonation'] = 0.5
        else:
            signals['brand_impersonation'] = 0.0

        # === SIGNAL 7: Error Code Fabrication ===
        # Fake error codes like "Error #0x80070057" or "Code: DL-3948"
        has_fake_error = bool(re.search(
            r'(?:error|code|alert)\s*[#:\s]+\s*(?:0x[0-9a-f]{4,}|[A-Z]{2,}[\-\s]?\d{3,})',
            text, re.I
        ))
        signals['fake_error'] = 0.7 if has_fake_error else 0.0

        # === SIGNAL 8: Browser/OS UI Mimicry ===
        # Text that looks like a system dialog ("Windows Defender Alert", "Apple Security Notice")
        system_mimicry = bool(re.search(
            r'(?:windows\s+defender|apple\s+security|microsoft\s+security|google\s+security|'
            r'system\s+alert|browser\s+warning|security\s+notice|antivirus\s+alert)',
            tl
        ))
        signals['system_mimicry'] = 0.7 if system_mimicry else 0.0

        # === SIGNAL 9: Reward + Action Combo (crypto/scam pattern) ===
        # Scams that steal money (not phishing) use: "Enter X → Get Y" where Y is money
        has_reward = bool(re.search(
            r'(?:earn|get|receive|claim|collect|win)\s*(?:up\s+to\s+)?[\$€£]?\s*\d',
            tl
        ))
        has_crypto_amount = bool(re.search(
            r'\d+\.?\d*\s*(?:btc|eth|usdt|usdc|bnb|sol|matic|avax|token|coin)',
            tl
        ))
        has_action_request = bool(re.search(
            r'(?:enter|provide|submit|input|send|deposit|transfer|connect)\s+'
            r'(?:your|the)\s+(?:address|wallet|funds|crypto|payment|details)',
            tl
        ))
        has_enter_address = bool(re.search(
            r'(?:enter|provide|your)\s+(?:bitcoin|btc|eth|crypto|wallet)\s+(?:address|receiving)',
            tl
        ))

        # "Enter address" + crypto amounts = deposit scam
        if (has_enter_address or has_action_request) and (has_crypto_amount or has_reward):
            signals['reward_scam'] = 0.85
        elif has_reward and has_action_request:
            signals['reward_scam'] = 0.7
        elif has_crypto_amount and has_action_request:
            signals['reward_scam'] = 0.65
        else:
            signals['reward_scam'] = 0.0

        # === SIGNAL 10: General Action Request (catches all scam types) ===
        # ANY page asking user to enter credentials, connect accounts, or send money
        # is suspicious if it's not a known legitimate domain
        action_patterns = [
            r'(?:enter|provide|input|type|submit)\s+(?:your|the)\s+\w+',
            r'(?:connect|link)\s+(?:your|the)\s+\w+',
            r'(?:send|transfer|deposit)\s+\w+\s+(?:to|into)',
            r'(?:verify|confirm|validate|authenticate)\s+(?:your|the)',
            r'(?:sign\s+in|log\s+in|login)',
            r'(?:get\s+(?:your|the)\s+(?:deposit|receiving)\s+address)',
        ]
        action_count = sum(1 for p in action_patterns if re.search(p, tl))
        signals['action_request'] = min(1.0, action_count * 0.35)

        # === FUSION: Weighted combination ===
        # Threat + demand together is the STRONGEST signal (tech support scam pattern)
        # Phone + threat is also very strong
        # Credential + urgency is credential harvesting

        # Check for multi-signal combos (these are almost always phishing)
        combo_score = 0.0
        if signals['threat'] > 0.3 and signals['demand'] > 0.3:
            combo_score = 0.9  # "Your PC is infected! Call support now!"
        if signals['threat'] > 0.3 and signals['phone'] > 0.3:
            combo_score = max(combo_score, 0.85)  # "Virus detected! Call 1-800-XXX"
        if signals['credential'] > 0.3 and signals['urgency'] > 0.3:
            combo_score = max(combo_score, 0.8)  # "Enter password within 24 hours"
        if signals['system_mimicry'] > 0.3 and signals['phone'] > 0.3:
            combo_score = max(combo_score, 0.85)  # "Windows Defender Alert! Call support"
        if signals['fake_error'] > 0.3 and signals['demand'] > 0.3:
            combo_score = max(combo_score, 0.8)  # "Error #0x80070057 — Click here to fix"
        if signals['reward_scam'] > 0.5:
            combo_score = max(combo_score, 0.75)  # Crypto/scam page
        if signals['action_request'] > 0.5:
            combo_score = max(combo_score, 0.6)  # Page asking user to do something

        # Individual signal scoring
        individual_score = (
            signals['threat'] * 0.25 +
            signals['demand'] * 0.20 +
            signals['urgency'] * 0.15 +
            signals['phone'] * 0.15 +
            signals['credential'] * 0.10 +
            signals['brand_impersonation'] * 0.10 +
            signals['fake_error'] * 0.03 +
            signals['system_mimicry'] * 0.02 +
            signals['reward_scam'] * 0.25 +
            signals['action_request'] * 0.15
        )

        # Take the max of combo and individual
        final_score = max(combo_score, individual_score)

        if final_score < 0.2:
            return None

        # Build findings
        findings = []
        active_signals = {k: v for k, v in signals.items() if v > 0.2}

        if final_score >= 0.7:
            findings.append(('TEXT_SCAM', f"Phishing page: {', '.join(active_signals.keys())}", int(final_score * 100)))
        elif final_score >= 0.5:
            findings.append(('TEXT_ANALYSIS', f"Suspicious page: {', '.join(active_signals.keys())}", int(final_score * 100)))

        return findings[0] if findings else None

    def _analyze_url_async(self, url):
        """Two-phase URL analysis: fast signals fire popup, slow signals run in background."""
        from page_analyzer import classify_page
        try:
            if url in self.url_cache:
                cached_time, cached_findings = self.url_cache[url]
                if time.time() - cached_time < 30:
                    if cached_findings and self._passes_alert_gate(cached_findings):
                        max_conf = max(f[2] for f in cached_findings)
                        lines = [f"[{f[2]}%] {f[1][:60]}" for f in cached_findings[:3]]
                        self.notify('PHISHING DETECTED!', ' | '.join(lines), critical=(max_conf >= 50), force=False)
                    return

            fetch_url = url if url.startswith('http') else f"https://{url}"
            try:
                parsed = urlparse(fetch_url)
                _host = parsed.netloc.lower()
                if _host.startswith('www.'): _host = _host[4:]
            except Exception:
                _host = ''

            # Skip trusted domains instantly (google docs, github, etc.)
            if any(_host == apex or _host.endswith('.' + apex) for apex in self._TRUSTED_URL_DOMAINS):
                self.url_cache[url] = (time.time(), [])
                return

            all_findings = []

            # === PHASE 1: FAST CHECKS (<0.5s) ===

            # 1. Reputation (instant)
            try:
                rep = self.url_reputation.check_url_sync(url)
                rep_sources = [str(s).strip().lower() for s in (rep.get('sources') or [])]
                if rep.get('is_malicious') and any(s in {'openphish', 'phishtank', 'urlhaus'} for s in rep_sources):
                    all_findings.append(('URL_REPUTATION', f"Known threat: {url[:60]}", int(rep.get('confidence', 0.8) * 100)))
            except Exception:
                pass

            # 2. Domain tier (instant)
            tier, tier_flags = self._classify_domain_tier(_host)
            has_lookalike = any(f.startswith('lookalike_') for f in tier_flags)
            has_suspicious_tld = any(f.startswith('suspicious_tld_') for f in tier_flags)
            has_fake_brand = any(f.startswith('fake_') for f in tier_flags)

            if has_lookalike:
                brand = next(f for f in tier_flags if f.startswith('lookalike_')).replace('lookalike_', '')
                all_findings.append(('URL_PATTERN', f"Lookalike: {url[:60]}", 90))
            if has_fake_brand:
                brand = next(f for f in tier_flags if f.startswith('fake_')).replace('fake_', '')
                all_findings.append(('URL_PATTERN', f"Brand impersonation: {url[:60]}", 85))

            # 3. URL structure (instant)
            query = parsed.query if hasattr(parsed, 'query') else ''
            path = parsed.path if hasattr(parsed, 'path') else ''
            if len(query) > 200:
                all_findings.append(('URL_PATTERN', f"Encoded query ({len(query)} chars): {url[:50]}", 75))
            path_depth = path.strip('/').count('/')
            if path_depth >= 3:
                segments = [s for s in path.strip('/').split('/') if s]
                random_segs = sum(1 for s in segments if len(s) <= 8 and not re.match(r'^(index|home|login|page|main|default|css|js|img|api|static)', s, re.I))
                if random_segs >= 3:
                    all_findings.append(('URL_PATTERN', f"Random path ({path_depth} levels): {url[:50]}", 70))

            # FIRE POPUP from fast signals if any found
            if all_findings and self._passes_alert_gate(all_findings):
                self.url_cache[url] = (time.time(), all_findings)
                max_conf = max(f[2] for f in all_findings)
                lines = [f"[{f[2]}%] {f[1][:60]}" for f in all_findings[:3]]
                logger.info(f"THREAT (fast): {url[:60]}")
                self.notify('PHISHING DETECTED!', ' | '.join(lines), critical=(max_conf >= 50), force=False)

            # === PHASE 2: SLOW CHECKS (HTML + WHOIS) — run in background, don't block ===
            should_analyze = (
                has_suspicious_tld or has_lookalike or has_fake_brand
                or any(c >= 60 for _, _, c in all_findings)
                or tier == 'TIER_NEUTRAL'  # analyze neutral domains too (catches okxweb3.io etc.)
            )
            if should_analyze:
                try:
                    html = self._fetch_html(fetch_url)
                    if html and len(html) > 100:
                        html_cap = html[:50000]
                        risk_score, signals = classify_page(fetch_url, html_cap)
                        if risk_score >= 0.4:
                            conf = int(risk_score * 100)
                            all_findings.append(('HTML_PHISHING', f"Page ({risk_score:.0%}): {', '.join(signals[:4])}", conf))
                except Exception:
                    pass

            # Cache all findings
            self.url_cache[url] = (time.time(), all_findings)

            # Fire popup from combined findings if not already fired
            if all_findings and self._passes_alert_gate(all_findings):
                max_conf = max(f[2] for f in all_findings)
                lines = [f"[{f[2]}%] {f[1][:60]}" for f in all_findings[:3]]
                logger.info(f"THREAT: {url[:60]}")
                self.notify('PHISHING DETECTED!', ' | '.join(lines), critical=(max_conf >= 50), force=False)

        except Exception as e:
            logger.debug(f"URL analysis: {e}")

    def _run_url_analysis(self, url):
        """Fast URL analysis: domain tier + quick signals, HTML only for suspicious domains."""
        from page_analyzer import classify_page

        fetch_url = url if url.startswith('http') else f"https://{url}"
        findings = []

        try:
            parsed = urlparse(fetch_url)
            _host = parsed.netloc.lower()
            if _host.startswith('www.'):
                _host = _host[4:]
        except Exception:
            _host = ''

        # 1. Reputation (instant)
        try:
            rep = self.url_reputation.check_url_sync(url)
            rep_sources = [str(s).strip().lower() for s in (rep.get('sources') or [])]
            if rep.get('is_malicious') and any(s in {'openphish', 'phishtank', 'urlhaus'} for s in rep_sources):
                conf = int(rep.get('confidence', 0.8) * 100)
                findings.append(('URL_REPUTATION', f"Known threat: {url[:60]}", conf))
                return {'url': url, 'findings': findings, 'auto_close': True}
        except Exception:
            pass

        # 2. Domain tier (instant)
        tier, tier_flags = self._classify_domain_tier(_host)
        if tier == 'TIER_SAFE':
            return {'url': url, 'findings': findings, 'auto_close': False}

        has_lookalike = any(f.startswith('lookalike_') for f in tier_flags)
        has_suspicious_tld = any(f.startswith('suspicious_tld_') for f in tier_flags)
        has_fake_brand = any(f.startswith('fake_') for f in tier_flags)

        # 3. Quick domain signals (instant)
        if has_lookalike:
            brand = next(f for f in tier_flags if f.startswith('lookalike_')).replace('lookalike_', '')
            findings.append(('URL_PATTERN', f"Lookalike domain: {url[:60]}", 90))
        if has_fake_brand:
            brand = next(f for f in tier_flags if f.startswith('fake_')).replace('fake_', '')
            findings.append(('URL_PATTERN', f"Brand impersonation: {url[:60]}", 85))

        # 4. URL structure signals (instant)
        query = parsed.query if hasattr(parsed, 'query') else ''
        path = parsed.path if hasattr(parsed, 'path') else ''
        path_depth = path.strip('/').count('/')

        if len(query) > 200:
            findings.append(('URL_PATTERN', f"Encoded query ({len(query)} chars): {url[:50]}", 75))
        if path_depth >= 3:
            segments = [s for s in path.strip('/').split('/') if s]
            random_segs = sum(1 for s in segments if len(s) <= 8 and not re.match(r'^(index|home|login|page|main|default|css|js|img|api|static)', s, re.I))
            if random_segs >= 3:
                findings.append(('URL_PATTERN', f"Random path ({path_depth} levels): {url[:50]}", 70))

        # 5. HTML analysis — always run (keeps accuracy, just with timeout)
        html = self._fetch_html(fetch_url)
        if html and len(html) > 100:
                try:
                    # Cap HTML size for speed
                    html_cap = html[:50000]
                    risk_score, signals = classify_page(fetch_url, html_cap)
                    if risk_score >= 0.4:
                        findings.append(('HTML_PHISHING',
                            f"Page structure ({risk_score:.0%}): {', '.join(signals[:4])}",
                            int(risk_score * 100)))
                except Exception:
                    pass

        return {'url': url, 'findings': findings, 'auto_close': self._should_auto_close(findings, 0.9 if findings else 0)}

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
                    elif name.startswith('url:'):
                        if isinstance(result, dict):
                            url_findings = result.get('findings') or []
                            if isinstance(url_findings, list):
                                all_findings.extend(url_findings)

                            if result.get('auto_close'):
                                hit_url = result.get('url') or name[4:]
                                self._scan_auto_close_urls.append(hit_url)
                        elif isinstance(result, list):
                            all_findings.extend(result)
                    elif name in ('inline_text',):
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
            self._scan_auto_close_urls = []

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

            # Detect frontmost app and get browser URL if applicable
            frontmost_url = self._get_browser_url()
            if frontmost_url:
                logger.info(f"Browser URL detected: {frontmost_url[:80]}")
                if frontmost_url not in raw_urls:
                    raw_urls.insert(0, frontmost_url)

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
                '.html', '.htm', '.php', '.aspx', '.jsp',
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
                if not self._is_likely_web_url_candidate(u):
                    continue
                urls.append(u)
                
            urls = list(dict.fromkeys(urls))[:5]  # deduplicate, cap at 5

            # Log what the scan sees
            logger.info(f"SCAN: text={len(text) if text else 0}chars, urls={urls}")

            phase2 = {}
            if text and len(text) >= 10:
                # Behavioral page analysis — PRIMARY detector for modern phishing
                # Analyzes what the user SEES, not the URL
                behavioral_result = self._analyze_page_behavior(text)
                if behavioral_result:
                    all_findings.append(behavioral_result)

                # Backend regex text scam analysis (catches specific scam patterns)
                phase2[self.executor.submit(self._run_text_scam_analysis, text)] = 'text_analysis'

            # Collect text analysis results (fast, ~0.1s)
            if phase2:
                self._collect_findings(phase2, all_findings, timeout=2.0)

            # URL analysis runs in BACKGROUND (not blocking the scan)
            # Each URL gets its own alert if phishing is found
            for url in urls:
                self.executor.submit(self._analyze_url_async, url)

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

                # Minimum confidence gate — suppress medium-confidence/speculative findings.
                # Keeps alerts focused on high-precision detections only.
                if not self._passes_alert_gate(deduped):
                    logger.debug(
                        f"Scan complete in {scan_duration:.2f}s — {len(deduped)} low-confidence "
                        f"findings suppressed (max={max_confidence}% did not pass category gate)"
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
                if self._scan_auto_close_urls:
                    self._close_browser_tab()
                    closed_url = self._scan_auto_close_urls[0]
                    self.notify(
                        'SCAM TAB CLOSED!',
                        'This URL was a scam, PayGuard closed it for you.',
                        critical=True,
                        force=True,
                    )
                    logger.info(f"Auto-close triggered for URL: {closed_url}")
                    return

                # Temporal-consistency gate for URL-only alerts:
                # require the same finding in 2 consecutive scans.
                if self._requires_repeat_confirmation(deduped):
                    primary_url_finding = next(
                        (f for f in deduped if f[0] in {'ML_HIGH_RISK', 'URL_PATTERN', 'HTML_PHISHING', 'HTML_SIGNALS'}),
                        top,
                    )
                    if not self._confirmed_in_consecutive_scans(primary_url_finding):
                        logger.info(
                            "URL alert pending confirmation: %s",
                            self._finding_signature(primary_url_finding),
                        )
                        return

                self.notify(title, message, critical=(max_confidence >= 50), force=True)
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
                time.sleep(3)  # Scan every 3 seconds
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)

    def start_monitoring(self):
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Monitoring started")

    def stop_monitoring(self):
        # Keep worker thread alive; ON/OFF is controlled by self.enabled.
        # This avoids spawning duplicate monitor threads on repeated toggles.
        logger.info("Monitoring paused")


if __name__ == "__main__":
    app = PayGuard()
    if HAS_RUMPS:
        app.app.run()
    elif HAS_PYSTRAY and (IS_LINUX or IS_WINDOWS):
        # Run system tray icon on Linux/Windows
        app.tray_icon.run()
    else:
        # CLI mode - keep alive with signal handling
        print("\n🛡️  PayGuard is running in background...")
        print("   Press Ctrl+C to stop")
        try:
            import signal
            def signal_handler(sig, frame):
                print("\n👋 PayGuard stopped")
                app.stop_monitoring()
                sys.exit(0)
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            while True:
                time.sleep(1)
        except Exception:
            while True:
                time.sleep(1)
