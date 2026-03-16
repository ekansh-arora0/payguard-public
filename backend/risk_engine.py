import asyncio
import importlib
import logging
import re
import socket
import ssl
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import numpy as np

from .email_guardian import EmailGuardian
from .models import Merchant, PaymentGateway, RiskLevel, RiskScore

# Shim numpy._core -> numpy.core for pickle compat (numpy 2.x pickles on 1.x runtime)
if not hasattr(np, "_core"):
    np._core = np.core  # type: ignore[attr-defined]
    sys.modules["numpy._core"] = np.core  # type: ignore[assignment]
    for _sub in ("multiarray", "numeric", "_multiarray_umath", "umath", "_internal"):
        _src = f"numpy.core.{_sub}"
        _dst = f"numpy._core.{_sub}"
        if _dst not in sys.modules:
            try:
                sys.modules[_dst] = importlib.import_module(_src)
            except ImportError:
                pass
from pathlib import Path
from pathlib import Path as _Path

import httpx
import joblib

try:
    import torch as _torch
    from transformers import AutoModelForSequenceClassification as _AutoModel
    from transformers import AutoTokenizer
except Exception:
    _torch = None
    _AutoModel = None
    AutoTokenizer = None
try:
    import xgboost as _xgb
except Exception:
    _xgb = None

logger = logging.getLogger(__name__)


class RiskScoringEngine:
    """
    Rule-based risk scoring engine.
    This can be replaced with ML model later by implementing the same interface.
    """

    # Known safe payment gateways
    SAFE_GATEWAYS = [
        "stripe.com",
        "paypal.com",
        "square.com",
        "authorize.net",
        "checkout.com",
        "adyen.com",
        "braintreepayments.com",
    ]

    # Trusted domains — well-known legitimate sites that should not be flagged
    # as high risk. Apex domains; subdomains are matched automatically.
    TRUSTED_DOMAINS = {
        # Major retailers / e-commerce
        "amazon.com",
        "amazon.co.uk",
        "amazon.de",
        "amazon.co.jp",
        "amazon.ca",
        "amazon.fr",
        "amazon.it",
        "amazon.es",
        "amazon.com.au",
        "amazon.in",
        "amazon.com.br",
        "ebay.com",
        "walmart.com",
        "target.com",
        "bestbuy.com",
        "costco.com",
        "etsy.com",
        "shopify.com",
        "aliexpress.com",
        "wayfair.com",
        "homedepot.com",
        "lowes.com",
        "macys.com",
        "nordstrom.com",
        "newegg.com",
        "overstock.com",
        # Major tech / platforms
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "apple.com",
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "outlook.com",
        "live.com",
        "github.com",
        "gitlab.com",
        "stackoverflow.com",
        "linkedin.com",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "youtube.com",
        "reddit.com",
        "wikipedia.org",
        "netflix.com",
        "spotify.com",
        "zoom.us",
        "slack.com",
        "dropbox.com",
        "salesforce.com",
        "adobe.com",
        "oracle.com",
        "ibm.com",
        "aws.amazon.com",
        "cloud.google.com",
        "azure.microsoft.com",
        # Payment / banking
        "paypal.com",
        "stripe.com",
        "square.com",
        "venmo.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "capitalone.com",
        "americanexpress.com",
        "visa.com",
        "mastercard.com",
        "discover.com",
        # Other major brands
        "nytimes.com",
        "bbc.com",
        "bbc.co.uk",
        "cnn.com",
        "washingtonpost.com",
        "reuters.com",
        "bloomberg.com",
    }

    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        # Account-related scams
        r"verify-?account",
        r"secure-?login",
        r"update-?payment",
        r"confirm-?identity",
        r"account-?verify",
        r"login-?verify",
        r"password-?reset",
        r"security-?alert",
        # Urgency tactics
        r"urgent",
        r"suspended",
        r"limited",
        r"expir(ed|ing)",
        r"terminate[ds]?",
        r"action-?required",
        r"immediate-?attention",
        # Crypto scams
        r"wallet-?connect",
        r"metamask-?verify",
        r"crypto-?gift",
        r"double-?your-?bitcoin",
        r"airdrop-?claim",
        # IP addresses (often malicious)
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        # Tech support scams
        r"microsoft-?support",
        r"apple-?support",
        r"windows-?alert",
        r"virus-?detected",
        r"call-?\d+",
        # Prize/lottery scams
        r"you-?won",
        r"congratulations",
        r"prize-?claim",
        r"winner",
        r"lottery",
        # Common scam paths
        r"/login",
        r"/signin",
        r"/verify",
        r"/account",
        r"/secure",
        r"/update",
        r"/confirm",
        r"/auth",
    ]
    # External reputation cache
    openphish_urls: set = set()
    openphish_last_fetch: Optional[datetime] = None

    def __init__(self, db):
        self.db = db
        self.email_guardian = EmailGuardian()
        self.ml_model = None
        self.ml_scaler = None
        self.html_model = None
        self.html_scaler = None
        try:
            mp_dir = Path(__file__).parent.parent / "models"
            json_path = mp_dir / "best_excel_xgb.json"
            ubj_path = mp_dir / "best_excel_xgb.ubj"
            scaler_path = mp_dir / "best_excel_xgb_scaler.pkl"
            if _xgb is not None and (json_path.exists() or ubj_path.exists()):
                try:
                    booster = _xgb.Booster()
                    booster.load_model(
                        str(json_path if json_path.exists() else ubj_path)
                    )
                    self.ml_model = booster
                    if scaler_path.exists():
                        self.ml_scaler = joblib.load(scaler_path)
                    else:
                        self.ml_scaler = None
                    self.shap_explainer = None
                except Exception:
                    self.ml_model = None
                    self.ml_scaler = None
                    self.shap_explainer = None
            else:
                p = mp_dir / "best_excel_xgb.pkl"
                obj = joblib.load(p)
                model = obj.get("model")
                scaler = obj.get("scaler")
                self.ml_model = model
                self.ml_scaler = scaler
                try:
                    import shap

                    self.shap_explainer = shap.TreeExplainer(self.ml_model)
                except Exception:
                    self.shap_explainer = None
                try:
                    if _xgb is not None:
                        booster = None
                        if hasattr(model, "get_booster"):
                            booster = model.get_booster()
                        elif isinstance(model, _xgb.Booster):
                            booster = model
                        if booster is not None:
                            out_json = mp_dir / "best_excel_xgb.json"
                            try:
                                booster.save_model(str(out_json))
                            except Exception:
                                pass
                            try:
                                if scaler is not None:
                                    joblib.dump(scaler, scaler_path)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            self.ml_model = None
            self.ml_scaler = None
            self.shap_explainer = None
        try:
            mdir = Path(__file__).parent.parent / "models"
            hp_cur = mdir / "best_html_rf_current.pkl"
            hp_old = mdir / "best_html_rf.pkl"
            hobj = None
            if hp_cur.exists():
                hobj = joblib.load(hp_cur)
            elif hp_old.exists():
                hobj = joblib.load(hp_old)
            if hobj is not None:
                if isinstance(hobj, dict):
                    self.html_model = hobj.get("model") or hobj.get("rf_model")
                    self.html_scaler = hobj.get("scaler")
                else:
                    self.html_model = hobj
                    self.html_scaler = None
                try:
                    joblib.dump(
                        {"model": self.html_model, "scaler": self.html_scaler}, hp_cur
                    )
                except Exception:
                    pass
            else:
                self.html_model = None
                self.html_scaler = None
        except Exception:
            self.html_model = None
            self.html_scaler = None
        self.html_cnn = None
        self.html_cnn_seq_len = 4096
        try:
            import torch

            hp2 = Path(__file__).parent / "models" / "best_html_cnn.pt"
            if not hp2.exists():
                hp2 = Path(__file__).parent.parent / "models" / "best_html_cnn.pt"
            if hp2.exists():
                try:
                    self.html_cnn = torch.jit.load(str(hp2))
                except Exception:
                    self.html_cnn = torch.load(str(hp2), map_location="cpu")
                if hasattr(self.html_cnn, "eval"):
                    self.html_cnn.eval()
        except Exception:
            self.html_cnn = None
        self.image_model = None
        self.image_processor = None
        self.image_device = "cpu"
        self.local_image_model = None
        self.local_image_device = "cpu"
        self.dire_home = _Path(__file__).parent.parent / "DIRE"
        self.dire_model_path = None
        self.text_model = None
        self.text_tokenizer = None
        self._dire_busy = False

        # Try to get DIRE paths from environment if available
        try:
            import os as _os

            dh = _os.environ.get("DIRE_HOME")
            dm = _os.environ.get("DIRE_MODEL_PATH")
            if dh:
                self.dire_home = _Path(dh)
            if dm:
                self.dire_model_path = _Path(dm)

            # If no env var for model, look for the one mentioned in demo.py default
            if not self.dire_model_path:
                default_model = (
                    self.dire_home / "data/exp/lsun_adm/ckpt/model_epoch_latest.pth"
                )
                if default_model.exists():
                    self.dire_model_path = default_model

            logger.debug(f"DIRE Home: {self.dire_home}")
            logger.debug(f"DIRE Model: {self.dire_model_path}")
        except Exception:
            pass

        try:
            tp = _Path(__file__).parent.parent / "bert_phishing_detector"
            if _AutoModel is not None and AutoTokenizer is not None and tp.exists():
                self.text_tokenizer = AutoTokenizer.from_pretrained(str(tp))
                self.text_model = _AutoModel.from_pretrained(str(tp))
                if hasattr(self.text_model, "eval"):
                    self.text_model.eval()
        except Exception:
            self.text_model = None
            self.text_tokenizer = None

    async def calculate_risk(
        self, url: str, content: Optional[str] = None
    ) -> RiskScore:
        """
        Main method to calculate risk score for a URL.
        Replace this with ML model prediction later.
        """
        domain = self._extract_domain(url)
        if self.ml_model and self.ml_scaler is not None:
            risk_factors = []
            safety_indicators = []
            trust_score = 50.0  # Initialize before any conditional usage
            ssl_valid = self._check_ssl(domain)
            if not ssl_valid:
                try:
                    ssl_valid = await self._check_ssl_http(domain)
                except Exception:
                    pass
            hsts_flag = False
            sec_hdrs = 0
            try:
                fv = await self.fast_validate(url)
                sec_hdrs = int(fv.get("security_headers_count", 0))
                if sec_hdrs >= 3:
                    safety_indicators.append("Strong security headers")
                hsts_flag = bool(fv.get("hsts", False))
            except Exception:
                pass
            domain_age_days = await self._check_domain_age(domain)
            detected_gateways = self._detect_payment_gateways(url, domain)
            has_payment_gateway = len(detected_gateways) > 0
            if ssl_valid:
                safety_indicators.append("Valid SSL certificate")
            else:
                risk_factors.append("No valid SSL certificate")
            if domain_age_days:
                if domain_age_days > 365:
                    safety_indicators.append(
                        f"Domain registered for {domain_age_days // 365} years"
                    )
                elif domain_age_days < 90:
                    risk_factors.append(
                        "Recently registered domain (less than 3 months)"
                    )
            if has_payment_gateway:
                safety_indicators.append(
                    f"Uses trusted payment gateway: {detected_gateways[0].value}"
                )
            tls_ok, cn_match, san_match = self._check_tls_details(domain)
            hsts = await self._check_hsts(domain)
            if not ssl_valid:
                if not tls_ok:
                    # if HTTPS HEAD succeeds, do not penalize handshake detail failure
                    if not await self._check_ssl_http(domain):
                        risk_factors.append("TLS handshake failed")
                # only flag CN/SAN mismatch when certificate details were read
                if tls_ok and not (cn_match or san_match):
                    risk_factors.append("TLS CN/SAN does not include domain")
            else:
                safety_indicators.append("TLS certificate matches domain")
                trust_score = min(100, trust_score + 3)
            if hsts or hsts_flag:
                safety_indicators.append("HSTS enabled")
            if self._has_suspicious_patterns(url, domain):
                risk_factors.append("URL contains suspicious patterns")
            merchant = await self._get_merchant_reputation(domain)
            merchant_reputation = None
            if merchant:
                merchant_reputation = merchant.get("reputation_score", 50.0)
                fraud_rate = merchant.get("fraud_reports", 0) / max(
                    merchant.get("total_reports", 1), 1
                )
                if merchant.get("verified"):
                    safety_indicators.append("Verified merchant")
                if fraud_rate > 0.3:
                    risk_factors.append("High fraud report rate")
            # apply conservative trust boosts for strong fundamentals (ML path)
            if ssl_valid:
                trust_score = min(100, trust_score + 10)
                safety_indicators.append("Valid SSL certificate")
            if domain_age_days:
                if domain_age_days > 365:
                    trust_score = min(100, trust_score + 10)
                elif domain_age_days < 90:
                    risk_factors.append(
                        "Recently registered domain (less than 3 months)"
                    )
                    trust_score = max(0, trust_score - 15)
            if has_payment_gateway:
                trust_score = min(100, trust_score + 10)
            is_blacklisted = await self._is_blacklisted(domain, url)
            if is_blacklisted:
                risk_factors.append("Domain flagged in fraud database")
            feats = self._url_features(url)
            x = self.ml_scaler.transform(feats) if self.ml_scaler is not None else feats
            proba = None
            try:
                if _xgb is not None and isinstance(self.ml_model, _xgb.Booster):
                    dm = _xgb.DMatrix(x)
                    yp = self.ml_model.predict(dm)
                    p1 = float(yp[0]) if hasattr(yp, "__len__") else float(yp)
                    p1 = max(0.0, min(1.0, p1))
                    proba = [1.0 - p1, p1]
                else:
                    proba = self.ml_model.predict_proba(x)[0]
            except Exception:
                proba = [0.5, 0.5]
            trust_score = max(0, min(100, float(proba[0]) * 100.0))
            if sec_hdrs >= 3:
                trust_score = min(100, trust_score + 10)
            if hsts or hsts_flag:
                trust_score = min(100, trust_score + 5)
            # Skip "Low confidence prediction" - not useful for users
            # stabilize known-good baselines even when HTML is missing
            try:
                reputable_base = (
                    ssl_valid
                    and (domain_age_days or 0) >= 365
                    and (sec_hdrs >= 2 or hsts or hsts_flag)
                    and not await self._is_blacklisted(domain, url)
                )
                if reputable_base:
                    trust_score = max(trust_score, 60.0)
            except Exception:
                pass
            if self.shap_explainer is not None:
                try:
                    sv = self.shap_explainer.shap_values(x)
                    if isinstance(sv, list):
                        vals = sv[0][0]
                    else:
                        vals = sv[0]
                    names = [
                        "url_length",
                        "dots",
                        "slashes",
                        "hyphens",
                        "underscores",
                        "qmarks",
                        "equals",
                        "amps",
                        "has_login",
                        "has_secure",
                        "has_account",
                        "has_verify",
                    ]
                    idx_sorted = np.argsort(np.abs(vals))[::-1]
                    for i in idx_sorted[:3]:
                        v = float(vals[i])
                        if v > 0:
                            safety_indicators.append(f"{names[i]} positive")
                        else:
                            risk_factors.append(f"{names[i]} negative")
                except Exception:
                    pass
            htrust_val = None
            text_spam_val = None
            phish_flag = False
            has_phish_pattern = False
            if content is not None and self.html_cnn is not None:
                try:
                    import numpy as _np
                    import torch

                    s = content[: self.html_cnn_seq_len]
                    arr = _np.frombuffer(s.encode("utf-8", "ignore"), dtype=_np.uint8)
                    if arr.size < self.html_cnn_seq_len:
                        pad = _np.zeros(
                            self.html_cnn_seq_len - arr.size, dtype=_np.uint8
                        )
                        arr = _np.concatenate([arr, pad])
                    else:
                        arr = arr[: self.html_cnn_seq_len]
                    arr = arr.copy()
                    x = torch.from_numpy(arr).long().unsqueeze(0)
                    with torch.no_grad():
                        y = self.html_cnn(x)
                        if hasattr(y, "shape") and y.shape[-1] == 2:
                            p = torch.softmax(y, dim=1)[0, 0].item()
                        else:
                            p = torch.sigmoid(y.view(-1)[0]).item()
                    htrust = max(0, min(100, float(p) * 100.0))
                    htrust_val = htrust
                    # If HTML model is confident about phishing (htrust < 40), trust it more
                    # Otherwise blend normally
                    if htrust < 40:
                        # Strong phishing signal from HTML - weight it heavily
                        trust_score = 0.3 * trust_score + 0.7 * htrust
                        risk_factors.append("Suspicious HTML structure detected")
                    else:
                        trust_score = 0.6 * trust_score + 0.4 * htrust
                except Exception:
                    pass
            elif content is not None and self.html_model is not None:
                try:
                    hfeats = self._html_features(content)
                    xh = (
                        hfeats
                        if self.html_scaler is None
                        else self.html_scaler.transform(hfeats)
                    )
                    hproba = self.html_model.predict_proba(xh)[0]
                    htrust = max(0, min(100, float(hproba[0]) * 100.0))
                    htrust_val = htrust
                    # Use ML model output directly - no keyword injection
                    trust_score = 0.6 * trust_score + 0.4 * htrust
                except Exception:
                    pass
            # Add support for text-based scam analysis in full risk pipeline
            if content is not None:
                try:
                    scam_res = self._analyze_text_for_scam(content)
                    if scam_res.get("is_scam"):
                        scam_conf = scam_res.get("confidence", 0)
                        # Heavy penalty for text-based scam indicators
                        penalty = (scam_conf / 100.0) * 60.0
                        trust_score = max(0.0, trust_score - penalty)
                        risk_factors.append(f"Scam content detected ({scam_conf}% confidence)")
                        if scam_conf >= 90:
                            phish_flag = True
                except Exception:
                    pass

            # trust floor for reputable sites (reduce false positives)
            try:
                if content is not None:
                    # already have sec_hdrs/hsts_flag above
                    reputable = (
                        ssl_valid
                        and ((domain_age_days or 0) >= 365)
                        and (sec_hdrs >= 2 or hsts or hsts_flag)
                    )
                    if reputable and not is_blacklisted:
                        trust_score = max(trust_score, 65.0)
            except Exception:
                pass
            if (
                content is not None
                and self.text_model is not None
                and self.text_tokenizer is not None
            ):
                try:
                    import re as _re

                    txt = _re.sub(r"<[^>]+>", " ", content)
                    txt = _re.sub(r"\s+", " ", txt).strip()
                    if len(txt) >= 80:
                        enc = self.text_tokenizer(
                            txt,
                            truncation=True,
                            padding=True,
                            max_length=512,
                            return_tensors="pt",
                        )
                        with _torch.no_grad():
                            out = self.text_model(**enc)
                            lg = out.logits
                            prob = _torch.softmax(lg, dim=1)[0]
                            ham = float(prob[0].item())
                            spam = (
                                float(prob[1].item())
                                if prob.shape[0] > 1
                                else (1.0 - ham)
                            )
                        text_spam_val = spam
                        cl = content.lower()
                        # Smart phishing pattern detection - check for actual phishing phrases, not just keywords
                        # This catches real phishing attempts while avoiding false positives on legitimate sites
                        urgency_words = [
                            "immediately",
                            "urgent",
                            "within 24 hours",
                            "act now",
                            "right away",
                            "suspend",
                            "terminate",
                            "lock",
                            "close your account",
                        ]
                        threat_words = [
                            "account suspended",
                            "account locked",
                            "account closed",
                            "verify your",
                            "confirm your",
                            "update your",
                            "payment",
                            "expired",
                            "unauthorized",
                        ]
                        action_words = [
                            "click here",
                            "click below",
                            "log in",
                            "sign in",
                            "login now",
                        ]

                        # Count actual phishing patterns (phrases, not single words)
                        urgency_count = sum(1 for w in urgency_words if w in cl)
                        threat_count = sum(1 for w in threat_words if w in cl)
                        action_count = sum(1 for w in action_words if w in cl)

                        # Real phishing has: urgency + threat + action (classic social engineering)
                        # Or: high spam score + threat + action
                        has_phish_pattern = (
                            urgency_count >= 1
                            and threat_count >= 1
                            and action_count >= 1
                        ) or (spam >= 0.9 and threat_count >= 1 and action_count >= 1)

                        if has_phish_pattern and spam >= 0.8:
                            alpha = 0.8
                            if abs(proba[0] - 0.5) < 0.1:
                                alpha = 0.9
                            text_trust = max(0, min(100, ham * 100.0))
                            trust_score = alpha * trust_score + (1 - alpha) * text_trust
                        elif ham >= 0.95 and not has_phish_pattern:
                            text_trust = max(0, min(100, ham * 100.0))
                            trust_score = 0.8 * trust_score + 0.2 * text_trust
                except Exception:
                    pass

            # Let ML models handle detection - trust their outputs
            # The HTML code analysis provides additional real-phishing detection
            if content is not None:
                try:
                    cs_delta, cs_risk, cs_safe = self._content_signals(url, content)
                    trust_score = max(0, min(100, trust_score + cs_delta))
                    risk_factors.extend(cs_risk)
                    safety_indicators.extend(cs_safe)
                except Exception:
                    pass

            # Smart HTML code analysis - check actual code structure
            if content is not None:
                try:
                    is_phishing, reason = self._html_code_analysis(url, content)
                    if is_phishing:
                        risk_factors.append(reason)
                        trust_score = max(0, min(100, trust_score - 25))
                except Exception:
                    pass
            # Trusted domain boost — override ML false positives for well-known sites
            if self._is_trusted_domain(domain) and not is_blacklisted:
                trust_score = max(trust_score, 75.0)
                if "Trusted domain" not in " ".join(safety_indicators):
                    safety_indicators.append("Trusted well-known domain")
            if trust_score >= 65:
                risk_level = RiskLevel.LOW
            elif trust_score >= 40:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.HIGH
            if (
                risk_level != RiskLevel.HIGH
                and (not ssl_valid)
                and self._has_suspicious_patterns(url, domain)
                and trust_score < 65
            ):
                risk_level = RiskLevel.HIGH
            # reduce false positives for long-registered domains with good headers when not blacklisted
            try:
                if (
                    (not is_blacklisted)
                    and domain_age_days
                    and domain_age_days >= 1825
                    and sec_hdrs >= 2
                    and risk_level == RiskLevel.HIGH
                ):
                    risk_level = RiskLevel.MEDIUM
                    safety_indicators.append(
                        "Long-registered domain with security headers"
                    )
            except Exception:
                pass
            education_message = self._generate_education_message(
                risk_level, risk_factors, safety_indicators
            )
            return RiskScore(
                url=url,
                domain=domain,
                risk_level=risk_level,
                trust_score=round(trust_score, 1),
                risk_factors=risk_factors,
                safety_indicators=safety_indicators,
                ssl_valid=ssl_valid,
                domain_age_days=domain_age_days,
                has_payment_gateway=has_payment_gateway,
                detected_gateways=detected_gateways,
                merchant_reputation=merchant_reputation,
                education_message=education_message,
            )
        else:
            trust_score = 50.0
            risk_factors = []
            safety_indicators = []
            ssl_valid = self._check_ssl(domain)
            if not ssl_valid:
                try:
                    ssl_valid = await self._check_ssl_http(domain)
                except Exception:
                    pass
            hsts_flag = False
            sec_hdrs = 0
            try:
                fv = await self.fast_validate(url)
                sec_hdrs = int(fv.get("security_headers_count", 0))
                if sec_hdrs >= 3:
                    trust_score += 10
                    safety_indicators.append("Strong security headers")
                hsts_flag = bool(fv.get("hsts", False))
            except Exception:
                pass
            if ssl_valid:
                trust_score += 15
                safety_indicators.append("Valid SSL certificate")
            else:
                trust_score -= 10
                risk_factors.append("No valid SSL certificate")
            domain_age_days = await self._check_domain_age(domain)
            if domain_age_days:
                if domain_age_days > 365:
                    trust_score += 15
                    safety_indicators.append(
                        f"Domain registered for {domain_age_days // 365} years"
                    )
                elif domain_age_days < 90:
                    trust_score -= 15
                    risk_factors.append(
                        "Recently registered domain (less than 3 months)"
                    )
            detected_gateways = self._detect_payment_gateways(url, domain)
            has_payment_gateway = len(detected_gateways) > 0
            if has_payment_gateway:
                trust_score += 10
                safety_indicators.append(
                    f"Uses trusted payment gateway: {detected_gateways[0].value}"
                )
            tls_ok, cn_match, san_match = self._check_tls_details(domain)
            hsts = await self._check_hsts(domain)
            if not ssl_valid:
                if not tls_ok:
                    if not await self._check_ssl_http(domain):
                        trust_score -= 5 if (hsts or hsts_flag) else 20
                        risk_factors.append("TLS handshake failed")
                if tls_ok and not (cn_match or san_match):
                    trust_score -= 5 if (hsts or hsts_flag) else 15
                    risk_factors.append("TLS CN/SAN does not include domain")
            else:
                trust_score += 3
                safety_indicators.append("TLS certificate matches domain")
            if hsts or hsts_flag:
                trust_score += 5
                safety_indicators.append("HSTS enabled")
            if self._has_suspicious_patterns(url, domain):
                trust_score -= 25
                risk_factors.append("URL contains suspicious patterns")
            merchant = await self._get_merchant_reputation(domain)
            merchant_reputation = None
            if merchant:
                merchant_reputation = merchant.get("reputation_score", 50.0)
                fraud_rate = merchant.get("fraud_reports", 0) / max(
                    merchant.get("total_reports", 1), 1
                )
                if fraud_rate > 0.3:
                    trust_score -= 20
                    risk_factors.append("High fraud report rate")
                elif merchant.get("verified"):
                    trust_score += 10
                    safety_indicators.append("Verified merchant")
            if await self._is_blacklisted(domain, url):
                trust_score -= 30
                risk_factors.append("Domain flagged in fraud database")
            trust_score = max(0, min(100, trust_score))
            # Trusted domain boost (heuristic path)
            is_blacklisted_h = await self._is_blacklisted(domain, url)
            if self._is_trusted_domain(domain) and not is_blacklisted_h:
                trust_score = max(trust_score, 75.0)
                if "Trusted domain" not in " ".join(safety_indicators):
                    safety_indicators.append("Trusted well-known domain")
            # rely on combined signals; no fixed trust floor
            if trust_score >= 65:
                risk_level = RiskLevel.LOW
            elif trust_score >= 40:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.HIGH
            if (
                (not ssl_valid)
                and (not self._has_suspicious_patterns(url, domain))
                and trust_score >= 40
            ):
                if risk_level == RiskLevel.HIGH:
                    risk_level = RiskLevel.MEDIUM
            if (
                risk_level != RiskLevel.HIGH
                and (not ssl_valid)
                and self._has_suspicious_patterns(url, domain)
                and trust_score < 65
            ):
                risk_level = RiskLevel.HIGH
            education_message = self._generate_education_message(
                risk_level, risk_factors, safety_indicators
            )
            return RiskScore(
                url=url,
                domain=domain,
                risk_level=risk_level,
                trust_score=round(trust_score, 1),
                risk_factors=risk_factors,
                safety_indicators=safety_indicators,
                ssl_valid=ssl_valid,
                domain_age_days=domain_age_days,
                has_payment_gateway=has_payment_gateway,
                detected_gateways=detected_gateways,
                merchant_reputation=merchant_reputation,
                education_message=education_message,
            )

    async def calculate_media_risk(self, url: str):
        domain = self._extract_domain(url)
        import os as _os

        _raw_safe = _os.environ.get("PAYGUARD_SAFE_DOMAINS", "")
        _safe_env = set([d.strip().lower() for d in _raw_safe.split(",") if d.strip()])
        SAFE_DOMAINS = _safe_env or {
            "google.com",
            "www.google.com",
            "wikipedia.org",
            "www.wikipedia.org",
            "youtube.com",
            "www.youtube.com",
        }
        _ai_thr_default = float(_os.environ.get("PAYGUARD_AI_THRESHOLD_DEFAULT", "0.7"))
        _ai_thr_safe = float(_os.environ.get("PAYGUARD_AI_THRESHOLD_SAFE", "0.9"))
        _url_tokens_safe = int(_os.environ.get("PAYGUARD_URL_TOKEN_HITS_SAFE", "3"))
        _url_tokens_default = int(
            _os.environ.get("PAYGUARD_URL_TOKEN_HITS_DEFAULT", "2")
        )
        reasons = []
        image_prob = None
        video_prob = None
        html = None
        scam_alert_data = None
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = None
                if url.lower().startswith("http"):
                    resp = await client.get(
                        url,
                        headers={"User-Agent": "PayGuard/1.0"},
                        follow_redirects=True,
                    )
                    resp.raise_for_status()
                    b = resp.content
                    ct = resp.headers.get("Content-Type", "")
                    if "image/" in ct and len(b) <= 10 * 1024 * 1024:
                        p = self._predict_image_fake_bytes(b)
                        if p is not None:
                            image_prob = float(p)
                            if image_prob >= (
                                _ai_thr_safe
                                if domain.lower() in SAFE_DOMAINS
                                else _ai_thr_default
                            ):
                                reasons.append("Images appear AI-generated")
                    if image_prob is None and resp is not None:
                        html = resp.text[:300000]
                else:
                    try:
                        from pathlib import Path as _P

                        pth = _P(url)
                        if pth.exists() and pth.is_file():
                            html = pth.read_text(errors="ignore")[:300000]
                    except Exception:
                        html = None
                    import re as _re

                    urls = []
                    html = html or ""
                    urls.extend(
                        _re.findall(
                            r'<img[^>]+src=["\']([^"\']+)["\']', html, flags=_re.I
                        )
                    )
                    urls.extend(
                        _re.findall(
                            r'<img[^>]+data-src=["\']([^"\']+)["\']', html, flags=_re.I
                        )
                    )
                    meta = _re.findall(
                        r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
                        html,
                        flags=_re.I,
                    )
                    urls.extend(meta)
                    links = _re.findall(
                        r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']',
                        html,
                        flags=_re.I,
                    )
                    urls.extend(links)
                    srcsets = _re.findall(
                        r'srcset=["\']([^"\']+)["\']', html, flags=_re.I
                    )
                    for s in srcsets:
                        first = s.split(",")[0].strip().split(" ")[0]
                        if first:
                            urls.append(first)
                    styles = _re.findall(r"url\(([^)]+)\)", html, flags=_re.I)
                    urls.extend([u.strip("\"'") for u in styles])
                    data_imgs = _re.findall(
                        r'src=["\']data:image/[^;]+;base64,([^"\']+)["\']',
                        html,
                        flags=_re.I,
                    )
                    img_urls = []
                    seen = set()
                    for u in urls:
                        iu = urljoin(url, u)
                        if iu not in seen:
                            seen.add(iu)
                            img_urls.append(iu)
                    img_urls = img_urls[:10]
                    probs = []
                    import base64 as _b64

                    for enc in data_imgs[:3]:
                        try:
                            bb = _b64.b64decode(enc)
                            p = self._predict_image_fake_bytes(bb)
                            if p is not None:
                                probs.append(float(p))
                        except Exception:
                            pass
                    if url.lower().startswith("http"):
                        for iu in img_urls:
                            try:
                                r = await client.get(
                                    iu,
                                    headers={"User-Agent": "PayGuard/1.0"},
                                    follow_redirects=True,
                                )
                                b2 = r.content
                                if len(b2) > 10 * 1024 * 1024:
                                    continue
                                if "image/" not in r.headers.get("Content-Type", ""):
                                    continue
                                p = self._predict_image_fake_bytes(b2)
                                if p is not None:
                                    probs.append(float(p))
                            except Exception:
                                pass
                    if probs:
                        image_prob = float(np.mean(probs))
                        if image_prob >= (
                            _ai_thr_safe
                            if domain.lower() in SAFE_DOMAINS
                            else _ai_thr_default
                        ):
                            reasons.append("Images appear AI-generated")
                if image_prob is None:
                    try:
                        from playwright.async_api import async_playwright

                        async with async_playwright() as pw:
                            browser = await pw.chromium.launch()
                            context = await browser.new_context()
                            page = await context.new_page()
                            await page.goto(url, wait_until="networkidle")
                            await page.wait_for_timeout(800)
                            found = await page.evaluate(
                                """
                                () => {
                                    const urls = new Set();
                                    const imgs = Array.from(document.querySelectorAll('img'));
                                    for (const im of imgs) {
                                        if (im.src) urls.add(im.src);
                                        const ss = im.srcset || '';
                                        if (ss) {
                                            const first = ss.split(',')[0].trim().split(' ')[0];
                                            if (first) urls.add(first);
                                        }
                                    }
                                    const all = Array.from(document.querySelectorAll('*'));
                                    for (const el of all) {
                                        const bg = getComputedStyle(el).backgroundImage;
                                        if (bg && bg.startsWith('url(')) {
                                            const u = bg.slice(4, -1).replace(/"/g,'');
                                            if (u) urls.add(u);
                                        }
                                    }
                                    return Array.from(urls).slice(0, 10);
                                }
                            """
                            )
                            await browser.close()
                            if found:
                                probs2 = []
                                for u in found:
                                    try:
                                        iu = urljoin(url, u)
                                        r = await client.get(
                                            iu,
                                            headers={"User-Agent": "PayGuard/1.0"},
                                            follow_redirects=True,
                                        )
                                        if "image/" not in r.headers.get(
                                            "Content-Type", ""
                                        ):
                                            continue
                                        bb = r.content
                                        if len(bb) > 10 * 1024 * 1024:
                                            continue
                                        p = self._predict_image_fake_bytes(bb)
                                        if p is not None:
                                            probs2.append(float(p))
                                    except Exception:
                                        pass
                                if probs2:
                                    image_prob = float(np.mean(probs2))
                                    if image_prob >= (
                                        _ai_thr_safe
                                        if domain.lower() in SAFE_DOMAINS
                                        else _ai_thr_default
                                    ):
                                        reasons.append("Images appear AI-generated")
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            if html:
                import html as _html
                import re as _re

                safe = _re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
                safe = _re.sub(r"(?is)<style.*?>.*?</style>", " ", safe)
                text_only = _re.sub(r"(?s)<[^>]+>", " ", safe)
                text_only = _html.unescape(text_only)
                scam_result = self._analyze_text_for_scam(text_only)
                # Require red/orange/yellow style tokens AND scam keywords for URL-based scam alerts
                hl = (html or "").lower()
                tokens = [
                    "background:red",
                    "background-color:red",
                    "color:red",
                    "#ff0000",
                    "#f00",
                    "orange",
                    "#ffa500",
                    "#ff9900",
                    "rgb(255,0,0)",
                    "rgb(255,165,0)",
                    "#cc0000",
                    "#ffff00",
                    "yellow",
                    "background:yellow",
                    "background-color:yellow",
                ]
                token_hits = sum(1 for t in tokens if t in hl)
                if scam_result.get("is_scam") and token_hits >= (
                    _url_tokens_safe
                    if domain.lower() in SAFE_DOMAINS
                    else _url_tokens_default
                ):
                    from .models import ScamAlert

                    scam_alert_data = ScamAlert(
                        is_scam=True,
                        confidence=scam_result["confidence"],
                        detected_patterns=scam_result["detected_patterns"],
                        senior_message=scam_result["senior_message"],
                        action_advice=scam_result["action_advice"],
                    )
                    reasons.append(
                        f"Scam detected (confidence: {scam_result['confidence']}%)"
                    )
                else:
                    patterns = set(scam_result.get("detected_patterns") or [])
                    key_hits = bool(
                        patterns.intersection(
                            {
                                "virus_warning",
                                "scare_tactics",
                                "action_demand",
                                "payment_request",
                                "phone_number",
                                "error_code",
                                "do_not_close",
                                "phishing_attempt",
                                "sensitive_input_request",
                            }
                        )
                    ) or any(p.startswith("suspicious_email:") for p in patterns)
                    if (key_hits and token_hits >= 2) or any(
                        p.startswith("suspicious_email:") for p in patterns
                    ):
                        from .models import ScamAlert

                        conf = max(75, scam_result.get("confidence") or 0)
                        msg = (
                            scam_result.get("senior_message")
                            or "STOP! This is a FAKE warning. Your computer is SAFE."
                        )
                        adv = (
                            scam_result.get("action_advice")
                            or "Close this window immediately. Do NOT call or pay."
                        )
                        scam_alert_data = ScamAlert(
                            is_scam=True,
                            confidence=conf,
                            detected_patterns=list(patterns),
                            senior_message=msg,
                            action_advice=adv,
                        )
                        reasons.append(f"Scam detected (confidence: {conf}%)")
        except Exception:
            pass
        vals = []
        wts = []
        if image_prob is not None:
            vals.append(image_prob * 100.0)
            wts.append(1.0)
        if video_prob is not None:
            vals.append(video_prob * 100.0)
            wts.append(1.0)
        if not vals:
            vals.append(0.0)
            wts.append(1.0)
        media_score = float(np.average(vals, weights=wts))
        media_score = max(0.0, min(100.0, media_score))
        try:
            merchant = await self._get_merchant_reputation(domain)
            if merchant:
                rep = merchant.get("reputation_score", 50.0)
                verified = bool(merchant.get("verified"))
                fraud_reports = int(merchant.get("fraud_reports", 0))
                if (verified or rep >= 70.0) and fraud_reports < 2:
                    if image_prob is None or image_prob < 0.95:
                        media_score = min(media_score, 30.0)
                        reasons.append("Verified merchant")
        except Exception:
            pass
        if media_score >= 70:
            color = RiskLevel.HIGH
        elif media_score >= 40:
            color = RiskLevel.MEDIUM
        else:
            color = RiskLevel.LOW
        if scam_alert_data is not None:
            color = RiskLevel.HIGH
        from .models import MediaRisk

        return MediaRisk(
            url=url,
            domain=domain,
            media_score=round(media_score, 1),
            media_color=color,
            reasons=reasons[:3],
            image_fake_prob=(image_prob * 100.0 if image_prob is not None else None),
            video_fake_prob=(video_prob * 100.0 if video_prob is not None else None),
            scam_alert=scam_alert_data,
        )

    async def capture_screen_bytes(self) -> Optional[bytes]:
        try:
            import os as _os
            import subprocess
            import tempfile

            fd, fp = tempfile.mkstemp(suffix=".png", prefix="payguard_screen_")
            _os.close(fd)
            try:
                subprocess.run(["screencapture", "-x", fp], check=True)
                if _os.path.exists(fp):
                    with open(fp, "rb") as fh:
                        return fh.read()
                return None
            finally:
                if _os.path.exists(fp):
                    _os.unlink(fp)
        except Exception:
            return None

    def _screen_text_alerts(self, b: bytes, static: bool = False) -> dict:
        """
        Enhanced scam detection with confidence scoring and senior-friendly messaging.
        Returns structured scam alert data instead of simple list.
        """
        result = {
            "is_scam": False,
            "confidence": 0.0,
            "detected_patterns": [],
            "senior_message": "",
            "action_advice": "",
        }

        try:
            import io
            import re as _re

            from PIL import Image

            img = Image.open(io.BytesIO(b)).convert("RGB")

            def _preprocess(im):
                try:
                    from PIL import ImageEnhance, ImageFilter

                    w, h = im.size
                    if max(w, h) > 1600:
                        s = 1600.0 / float(max(w, h))
                        im = im.resize((int(w * s), int(h * s)))
                    im = ImageEnhance.Contrast(im).enhance(1.5)
                    im = ImageEnhance.Brightness(im).enhance(1.1)
                    im = im.filter(ImageFilter.SHARPEN)
                    return im
                except Exception:
                    return im

            def _ocr_all(im, is_static=False):
                try:
                    import shutil as _sh

                    import pytesseract

                    cmd = _sh.which("tesseract") or "/opt/homebrew/bin/tesseract"
                    if cmd:
                        pytesseract.pytesseract.tesseract_cmd = cmd
                    texts = []
                    base = _preprocess(im)
                    # 1. Target colorful alert regions (fast)
                    hsv = base.convert("HSV")
                    import numpy as _np

                    H, S, V = [_np.array(ch, dtype=_np.uint8) for ch in hsv.split()]
                    h_px, w_px = H.shape
                    red_mask = ((H < 16) | (H > 240)) & (S > 128) & (V > 32)
                    orange_mask = ((H >= 16) & (H < 40)) & (S > 128) & (V > 32)
                    yellow_mask = ((H >= 40) & (H < 60)) & (S > 128) & (V > 32)
                    grid = 3
                    th = h_px // grid
                    tw = w_px // grid
                    rois = []
                    for gy in range(grid):
                        for gx in range(grid):
                            y0 = gy * th
                            x0 = gx * tw
                            y1 = (gy + 1) * th if gy < grid - 1 else h_px
                            x1 = (gx + 1) * tw if gx < grid - 1 else w_px
                            area = (y1 - y0) * (x1 - x0)
                            if area <= 0:
                                continue
                            r = float(red_mask[y0:y1, x0:x1].sum()) / float(area)
                            o = float(orange_mask[y0:y1, x0:x1].sum()) / float(area)
                            yel = float(yellow_mask[y0:y1, x0:x1].sum()) / float(area)
                            if (r + o + yel) >= 0.15:
                                rois.append((x0, y0, x1, y1))

                    for x0, y0, x1, y1 in rois:
                        try:
                            crop = base.crop((x0, y0, x1, y1))
                            t = pytesseract.image_to_string(crop, config="--psm 6")
                            if t.strip():
                                texts.append(t)
                        except Exception:
                            pass

                    # 2. If no alerts OR if static, do full screen OCR
                    if not texts or is_static:
                        try:
                            full_t = pytesseract.image_to_string(base, config="--psm 3")
                            if full_t.strip():
                                texts.append(full_t)
                        except Exception:
                            pass

                    return "\n".join(texts).strip()
                except Exception:
                    return ""

            text = _ocr_all(img, is_static=static)
            if text:
                text_sample = text[:50].replace("\n", " ")
                logger.debug(f"OCR Text Sample: {text_sample}...")
            if not text:
                return result

            tl = text.lower()
            tl_norm = _re.sub(r"[^a-z0-9\s]", " ", tl)
            tl_norm = _re.sub(r"\s+", " ", tl_norm).strip()

            # --- Legitimate UI Whitelist ---
            safe_ui_phrases = [
                "software update",
                "system preferences",
                "system settings",
                "touch id",
                "apple id",
                "icloud",
                "app store",
                "google chrome",
                "microsoft edge",
                "safari",
                "finder",
                "calculator",
                "calendar",
                "system report",
                "about this mac",
                "windows update",
                "task manager",
                "software is up to date",
                "checking for updates",
                "install now",
                "security preferences",
                "privacy settings",
                "network settings",
                "cancel",
                "done",
                "ok",
                "next",
                "back",
                "skip",
            ]
            is_safe_ui = any(p in tl for p in safe_ui_phrases)

            # Expanded pattern categories
            virus_words = [
                "virus",
                "malware",
                "spyware",
                "adware",
                "trojan",
                "worm",
                "keylogger",
                "ransomware",
                "infection",
                "infected",
                "threat",
            ]

            scare_phrases = [
                "your computer has a virus",
                "your pc is infected",
                "your mac is infected",
                "device is infected",
                "critical alert",
                "security alert",
                "security warning",
                "threats found",
                "system is heavily damaged",
                "browser has been locked",
                "your computer is blocked",
                "your pc is blocked",
                "your mac is blocked",
                "system error",
                "critical error",
                "fatal error",
                "your system is at risk",
                "severe damage",
                "hard drive failure",
                "data breach detected",
                "hacked",
                "account suspended",
                "account locked",
                "unauthorized login",
                "suspicious activity",
                "computer is infected",
                "pc is infected",
                "mac is infected",
                "system infected",
                "infected with a virus",
                "virus detected",
                "threat detected",
                "spyware detected",
            ]

            action_phrases = [
                "call support",
                "call microsoft",
                "call apple",
                "call customer support",
                "toll free",
                "do not close",
                "contact support",
                "contact us",
                "immediate action required",
                "click allow",
                "click ok",
                "download antivirus",
                "install antivirus",
                "update required",
                "pay a fine",
                "verify your computer",
                "run a scan now",
                "renew your subscription",
                "click here to fix",
                "update now",
                "activate now",
                "confirm your identity",
                "verify account",
                "sign in to",
                "log in to verify",
                "claim your prize",
                "claim reward",
                "call now",
                "speak with a technician",
            ]

            payment_phrases = [
                "pay now",
                "payment required",
                "enter credit card",
                "gift card",
                "bitcoin",
                "cryptocurrency",
                "wire transfer",
                "send money",
                "pay a fee",
                "subscription fee",
                "renewal fee",
                "activation fee",
            ]

            urgency_indicators = [
                "expires in",
                "limited time",
                "act now",
                "within 24 hours",
                "immediately",
                "urgent",
                "time sensitive",
                "before it",
                "will be deleted",
                "will expire",
                "last chance",
                "final warning",
            ]

            brands = [
                "microsoft",
                "apple",
                "windows",
                "macos",
                "google",
                "norton",
                "mcafee",
                "totalav",
                "avg",
                "avast",
                "kaspersky",
                "bitdefender",
                " Malwarebytes ",
                "amazon",
                "paypal",
                "facebook",
                "instagram",
                "twitter",
                "x.com",
                "tiktok",
                "snapchat",
                "linkedin",
                "netflix",
                "hulu",
                "disney",
                "spotify",
                "bank",
                "chase",
                "wellsfargo",
                "bankofamerica",
                "citi",
                "usbank",
                "capitalone",
                "binance",
                "coinbase",
                "kraken",
                "metamask",
                "trustwallet",
                "irs",
                "social security",
                "medicare",
                "usps",
                "fedex",
                "ups",
            ]

            # Regex patterns
            phone_pat = _re.compile(
                r"(?:call|dial|phone|contact)[^0-9]{0,20}(\+?1?\s*)?(\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4})",
                _re.I,
            )
            error_pat = _re.compile(
                r"error\s*(code|#|number)?\s*[0x]*[0-9a-f\-]+", _re.I
            )

            # Extra phrases via environment for rapid expansion
            import os as _os

            extra_raw = _os.environ.get("PAYGUARD_SCAM_PHRASES", "")
            extra_phrases = [
                s.strip().lower() for s in extra_raw.split(",") if s.strip()
            ]

            # Phishing Keywords (New Category)
            phishing_phrases = [
                "verify your identity",
                "verify your account",
                "unlock your account",
                "account suspended",
                "unusual activity detected",
                "confirm your password",
                "sign in to continue",
                "update payment details",
                "security alert",
                "unauthorized access",
                "validate your account",
            ]

            # Sensitive input fields (often found in phishing)
            input_labels = [
                "password",
                "ssn",
                "social security",
                "credit card",
                "card number",
                "cvv",
                "pin",
            ]

            # Pattern detection with scoring
            confidence_score = 0
            patterns_found = []

            # Check for typosquatted/scam emails
            email_scams = self.email_guardian.detect_scam_emails(tl_norm)
            for scam in email_scams:
                confidence_score += int(scam["confidence"] * 50)  # Up to 50 points
                patterns_found.append(f"suspicious_email:{scam['email']}")
                result["detected_patterns"].append(scam["reason"])

            # Check virus/malware keywords (15 points)
            virus_hit = any(w in tl_norm for w in virus_words)
            if virus_hit:
                confidence_score += 15
                patterns_found.append("virus_warning")

            # Check scare tactics (20 points - highly indicative)
            scare_hit = any(p in tl_norm for p in scare_phrases)
            if scare_hit:
                confidence_score += 20
                patterns_found.append("scare_tactics")

            # Check action demands (15 points)
            action_hit = any(p in tl_norm for p in action_phrases)
            if action_hit:
                confidence_score += 15
                patterns_found.append("action_demand")

            # Check payment requests (25 points - very suspicious)
            payment_hit = any(p in tl_norm for p in payment_phrases)
            if payment_hit:
                confidence_score += 25
                patterns_found.append("payment_request")

            # Check urgency (10 points)
            urgency_hit = any(p in tl_norm for p in urgency_indicators)
            if urgency_hit:
                confidence_score += 10
                patterns_found.append("urgency")

            # Check for phone numbers (20 points)
            phone_match = phone_pat.search(tl_norm)
            if phone_match:
                confidence_score += 20
                patterns_found.append("phone_number")

            # Check for fake error codes (15 points)
            error_match = error_pat.search(tl_norm)
            if error_match:
                confidence_score += 15
                patterns_found.append("error_code")

            # Check for brand impersonation (10 points)
            brand_hit = any(b in tl_norm for b in brands)
            if brand_hit:
                confidence_score += 10
                patterns_found.append("brand_impersonation")

            # Check for "do not close" (15 points - classic scam tactic)
            if "do not close" in tl_norm or "dont close" in tl_norm:
                confidence_score += 15
                patterns_found.append("do_not_close")

            # Extra phrases boost (10 points)
            extra_hit = (
                any(ep in tl_norm for ep in extra_phrases) if extra_phrases else False
            )
            if extra_hit:
                confidence_score += 10
                patterns_found.append("custom_phrase")

            # Check for Phishing (20 points)
            phishing_hit = any(p in tl_norm for p in phishing_phrases)
            input_hit = any(i in tl_norm for i in input_labels)
            if phishing_hit:
                confidence_score += 20
                patterns_found.append("phishing_attempt")
            if input_hit and (phishing_hit or brand_hit):
                confidence_score += 15
                patterns_found.append("sensitive_input_request")

            # Determine if it's a scam based on pattern combinations
            # High confidence scam indicators:
            is_scam = False

            # Debug: Print found patterns
            if patterns_found:
                logger.debug(f"Patterns: {patterns_found} | Score: {confidence_score}")

            # Rule 0: Suspicious email address detected
            if email_scams:
                is_scam = True
                max_email_conf = max(s["confidence"] for s in email_scams)
                confidence_score = max(confidence_score, int(max_email_conf * 100))

            # RE-EVALUATE RULES: Making them more inclusive for easier testing
            # Rule 1: Virus + (Action OR Payment OR Phone OR Scare) = SCAM
            if virus_hit and (
                action_hit or payment_hit or phone_match or scare_hit or extra_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 2: Scare + (Payment OR Action OR Phone) = SCAM
            if scare_hit and (payment_hit or action_hit or phone_match):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 3: Fake error + (Phone OR Action OR Virus) = SCAM
            if error_match and (phone_match or action_hit or virus_hit):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 4: "Do not close" + (Phone OR Action OR Brand OR Scare) = SCAM
            if ("do not close" in tl_norm or "dont close" in tl_norm) and (
                phone_match or action_hit or brand_hit or scare_hit or extra_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 90)

            # Rule 5: Multiple strong indicators (2+) = Likely SCAM
            # Reduced from 3 to 2 for more responsive detection during testing
            strong_indicators = sum(
                [
                    virus_hit,
                    scare_hit,
                    payment_hit,
                    bool(phone_match),
                    bool(error_match),
                    extra_hit,
                    phishing_hit,
                ]
            )
            if strong_indicators >= 2:
                is_scam = True
                confidence_score = max(confidence_score, 80)

            # Rule 7: Claim prize + (Payment OR Action) = SCAM
            if ("claim" in tl_norm and "prize" in tl_norm) and (
                payment_hit or action_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 90)

            # Rule 8: Account suspended/locked + (Action OR Phishing OR Payment OR Brand) = SCAM
            if ("suspended" in tl_norm or "locked" in tl_norm) and (
                action_hit or phishing_hit or payment_hit or brand_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 6: Phishing + (Brand OR Input OR Action) = SCAM
            if phishing_hit and (brand_hit or input_hit or action_hit):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 9: Phone number + (Brand OR Action) = SCAM
            if phone_match and (brand_hit or action_hit):
                is_scam = True
                confidence_score = max(confidence_score, 80)

            # --- NEW: Legitimate UI Whitelist (Moved here to ensure it overrides rules) ---
            if is_safe_ui:
                confidence_score -= 50
                if confidence_score < 75:
                    is_scam = False
                logger.debug(
                    f"Legitimate UI detected, applying -50 penalty. New Score: {confidence_score}"
                )

            if len(tl) < 40:
                confidence_score -= 20
                if confidence_score < 75:
                    is_scam = False
                logger.debug(
                    f"Text too short, applying -20 penalty. New Score: {confidence_score}"
                )

            # Cap confidence at 100
            confidence_score = min(confidence_score, 100)
            confidence_score = max(0, confidence_score)

            if (
                confidence_score >= 60 and is_scam
            ):  # Lowered from 75 to 60 for better detection
                result["is_scam"] = True
                result["confidence"] = confidence_score
                result["detected_patterns"] = patterns_found

                if email_scams:
                    scam_emails_str = ", ".join([s["email"] for s in email_scams])
                    result["senior_message"] = (
                        f"BE CAREFUL! We found a fake email address: {scam_emails_str}. This is a SCAM attempt."
                    )
                    advice_parts = [
                        "❌ Do NOT reply to this email",
                        "❌ Do NOT click any links",
                    ]
                else:
                    # Generate senior-friendly message
                    result["senior_message"] = (
                        "STOP! This is a FAKE warning. Your computer is SAFE. This pop-up is trying to SCARE you."
                    )
                    advice_parts = ["✅ Just close this window"]

                if phone_match:
                    advice_parts.append("❌ Do NOT call any phone numbers")
                if payment_hit:
                    advice_parts.append("❌ Do NOT pay any money")
                if action_hit and "download" in tl_norm:
                    advice_parts.append("❌ Do NOT download anything")
                if "click" in tl_norm:
                    advice_parts.append("❌ Do NOT click any links")

                result["action_advice"] = " | ".join(advice_parts)

        except Exception as e:
            logger.debug(f"Screen text analysis error: {e}")
            pass

        return result

    def _analyze_text_for_scam(self, text: str) -> dict:
        result = {
            "is_scam": False,
            "confidence": 0.0,
            "detected_patterns": [],
            "senior_message": "",
            "action_advice": "",
        }
        try:
            import os as _os
            import re as _re

            tl = (text or "").lower()
            tl_norm = _re.sub(r"[^a-z0-9\s]", " ", tl)
            tl_norm = _re.sub(r"\s+", " ", tl_norm).strip()
            virus_words = [
                "virus",
                "malware",
                "spyware",
                "adware",
                "trojan",
                "worm",
                "keylogger",
                "ransomware",
                "infection",
                "infected",
                "threat",
            ]
            scare_phrases = [
                "your computer has a virus",
                "your pc is infected",
                "your mac is infected",
                "device is infected",
                "critical alert",
                "security alert",
                "security warning",
                "threats found",
                "system is heavily damaged",
                "browser has been locked",
                "your computer is blocked",
                "your pc is blocked",
                "your mac is blocked",
                "system error",
                "critical error",
                "fatal error",
                "your system is at risk",
                "severe damage",
                "hard drive failure",
                "data breach detected",
                "hacked",
                "account suspended",
                "account locked",
                "unauthorized login",
                "suspicious activity",
            ]
            action_phrases = [
                "call support",
                "call microsoft",
                "call apple",
                "call customer support",
                "toll free",
                "do not close",
                "contact support",
                "contact us",
                "immediate action required",
                "click allow",
                "click ok",
                "download antivirus",
                "install antivirus",
                "update required",
                "pay a fine",
                "verify your computer",
                "run a scan now",
                "renew your subscription",
                "click here to fix",
                "update now",
                "activate now",
                "confirm your identity",
                "verify account",
                "sign in to",
                "log in to verify",
                "claim your prize",
                "claim reward",
            ]
            payment_phrases = [
                "pay now",
                "payment required",
                "enter credit card",
                "gift card",
                "bitcoin",
                "cryptocurrency",
                "wire transfer",
                "send money",
                "pay a fee",
                "subscription fee",
                "renewal fee",
                "activation fee",
                "update payment info",
                "update billing",
                "billing information",
                "avoid service suspension",
            ]
            urgency_indicators = [
                "expires in",
                "limited time",
                "act now",
                "within 24 hours",
                "immediately",
                "urgent",
                "time sensitive",
                "before it",
                "will be deleted",
                "will expire",
                "last chance",
                "final warning",
                "asap",
            ]
            brands = [
                "microsoft",
                "apple",
                "windows",
                "macos",
                "google",
                "norton",
                "mcafee",
                "totalav",
                "avg",
                "avast",
                "kaspersky",
                "bitdefender",
                "amazon",
                "paypal",
                "facebook",
                "netflix",
                "bank",
            ]
            phishing_phrases = [
                "verify account",
                "confirm your identity",
                "update your account",
                "reset your password",
                "unusual activity",
                "suspicious activity",
                "unlock your account",
                "confirm your password",
                "sign in to verify",
                "click to verify",
            ]
            input_labels = [
                "password",
                "credit card",
                "ssn",
                "social security",
                "cvv",
                "security code",
                "routing number",
                "account number",
                "passcode",
            ]
            phone_pat = _re.compile(
                r"(call|dial|phone|contact)\s*(us\s*)?(at\s*)?(\+?1?\s*)?(\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4})"
            )
            error_pat = _re.compile(
                r"error\s*(code|#|number)?\s*[0x]*[0-9a-f\-]+", _re.I
            )
            extra_raw = _os.environ.get("PAYGUARD_SCAM_PHRASES", "")
            extra_phrases = [
                s.strip().lower() for s in extra_raw.split(",") if s.strip()
            ]
            confidence_score = 0
            patterns_found = []

            # Check for typosquatted/scam emails
            email_scams = self.email_guardian.detect_scam_emails(text)
            for scam in email_scams:
                confidence_score += int(scam["confidence"] * 50)  # Up to 50 points
                patterns_found.append(f"suspicious_email:{scam['email']}")
                result["detected_patterns"].append(scam["reason"])

            # Check for SMS-specific scams (smishing)
            sms_scams = self.email_guardian.detect_scam_sms(text)
            for scam in sms_scams:
                confidence_score += int(scam["confidence"] * 40)
                patterns_found.append(f"sms_scam:{scam['type']}")
                result["detected_patterns"].append(scam["reason"])

            virus_hit = any(w in tl_norm for w in virus_words)
            if virus_hit:
                confidence_score += 15
                patterns_found.append("virus_warning")
            scare_hit = any(p in tl_norm for p in scare_phrases)
            if scare_hit:
                confidence_score += 20
                patterns_found.append("scare_tactics")
            
            urgency_hit = any(p in tl_norm for p in urgency_indicators)
            if urgency_hit:
                confidence_score += 10
                patterns_found.append("urgency")
            
            phone_match = phone_pat.search(tl_norm)
            if phone_match:
                confidence_score += 20
                patterns_found.append("phone_number")

            action_hit = any(p in tl_norm for p in action_phrases)
            if action_hit:
                confidence_score += 15
                patterns_found.append("action_demand")
            
            # Additional check for action verbs with phone numbers or urgent phrases
            if not action_hit:
                if any(w in tl_norm for w in ["call", "dial", "contact", "verify", "update", "click"]):
                    if phone_match or urgency_hit:
                        action_hit = True
                        confidence_score += 10
                        patterns_found.append("action_demand_implied")

            payment_hit = any(p in tl_norm for p in payment_phrases)
            if payment_hit:
                confidence_score += 25
                patterns_found.append("payment_request")
            error_match = error_pat.search(tl_norm)
            if error_match:
                confidence_score += 15
                patterns_found.append("error_code")
            brand_hit = any(
                (b + " support") in tl_norm or (b + " security") in tl_norm
                for b in brands
            )
            if brand_hit:
                confidence_score += 10
                patterns_found.append("brand_impersonation")
            if "do not close" in tl_norm or "dont close" in tl_norm:
                confidence_score += 15
                patterns_found.append("do_not_close")
            extra_hit = (
                any(ep in tl_norm for ep in extra_phrases) if extra_phrases else False
            )
            phishing_hit = any(p in tl_norm for p in phishing_phrases)
            input_hit = any(i in tl_norm for i in input_labels)
            if phishing_hit:
                confidence_score += 15
                patterns_found.append("phishing_attempt")
            if input_hit:
                confidence_score += 15
                patterns_found.append("sensitive_input_request")
            if extra_hit:
                confidence_score += 10
                patterns_found.append("custom_phrase")
            is_scam = False

            # Rule 0: Suspicious email address detected
            if email_scams:
                is_scam = True
                # Use the max confidence from all detected email scams
                max_email_conf = max(s["confidence"] for s in email_scams)
                confidence_score = max(confidence_score, int(max_email_conf * 100))

            # Rule 0.1: Suspicious SMS patterns detected
            if sms_scams:
                is_scam = True
                max_sms_conf = max(s["confidence"] for s in sms_scams)
                confidence_score = max(confidence_score, int(max_sms_conf * 100))

            if virus_hit and (action_hit or payment_hit or phone_match or extra_hit):
                is_scam = True
                confidence_score = max(confidence_score, 85)
            if scare_hit and payment_hit:
                is_scam = True
                confidence_score = max(confidence_score, 90)
            if error_match and (phone_match or action_hit):
                is_scam = True
                confidence_score = max(confidence_score, 85)
            if ("do not close" in tl_norm or "dont close" in tl_norm) and (
                phone_match or action_hit or brand_hit or extra_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 90)
            # Phishing-style rules for chat messages
            if (
                brand_hit
                and (phishing_hit or action_hit)
                and (urgency_hit or input_hit)
            ):
                is_scam = True
                confidence_score = max(confidence_score, 80)
            if phishing_hit and input_hit:
                is_scam = True
                confidence_score = max(confidence_score, 80)

            if urgency_hit and payment_hit and action_hit:
                is_scam = True
                confidence_score = max(confidence_score, 85)

            # Rule 6b: Urgency + Payment = SCAM (even without explicit action)
            if urgency_hit and payment_hit:
                is_scam = True
                confidence_score = max(confidence_score, 75)

            # Rule 7: Claim prize + Payment = SCAM
            if ("claim" in tl_norm and "prize" in tl_norm) and payment_hit:
                is_scam = True
                confidence_score = max(confidence_score, 90)

            # Rule 8: Account suspended/locked + Action/Phishing = SCAM
            if ("suspended" in tl_norm or "locked" in tl_norm) and (
                action_hit or phishing_hit
            ):
                is_scam = True
                confidence_score = max(confidence_score, 85)

            strong_indicators = sum(
                [
                    virus_hit,
                    scare_hit,
                    payment_hit,
                    bool(phone_match),
                    bool(error_match),
                    extra_hit,
                    phishing_hit,
                ]
            )
            if strong_indicators >= 3:
                is_scam = True
                confidence_score = max(confidence_score, 80)
            # Advanced URL and handle heuristics
            url_pat = _re.compile(r"https?://[\w\-\.]+(?:/[\S]*)?", _re.I)
            urls = url_pat.findall(text or "")
            suspicious_tlds = [
                ".top",
                ".xyz",
                ".work",
                ".zip",
                ".review",
                ".country",
                ".bid",
                ".lol",
                ".link",
                ".kim",
                ".men",
                ".live",
                ".ru",
            ]
            shorteners = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "rebrand.ly",
            ]
            suspicious_url_hit = False
            for u in urls:
                host = u.split("/")[2].lower() if "://" in u else u
                if any(host.endswith(t) for t in suspicious_tlds):
                    confidence_score += 10
                    patterns_found.append("suspicious_tld")
                    suspicious_url_hit = True
                if any(s in host for s in shorteners):
                    confidence_score += 5
                    patterns_found.append("url_shortener")
            # Crypto address patterns
            btc_pat = _re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
            eth_pat = _re.compile(r"\b0x[a-fA-F0-9]{40}\b")
            if btc_pat.search(text or "") or eth_pat.search(text or ""):
                confidence_score += 15
                patterns_found.append("crypto_address")
            # Homoglyph / obfuscation signal (presence of mixed scripts or suspicious unicode)
            try:
                uni_weird = any(ord(c) > 127 for c in (text or ""))
                if uni_weird:
                    confidence_score += 5
                    patterns_found.append("unicode_obfuscation")
            except Exception:
                pass
            confidence_score = min(confidence_score, 100)
            if confidence_score >= 70 and is_scam:
                result["is_scam"] = True
                result["confidence"] = confidence_score
                result["detected_patterns"] = patterns_found

                if email_scams:
                    scam_emails_str = ", ".join([s["email"] for s in email_scams])
                    result["senior_message"] = (
                        f"BE CAREFUL! We found a fake email address: {scam_emails_str}. This is a SCAM attempt."
                    )
                    advice_parts = [
                        "❌ Do NOT reply to this email",
                        "❌ Do NOT click any links in it",
                    ]
                elif sms_scams:
                    result["senior_message"] = (
                        "STOP! This looks like a FAKE text message (Smishing). Do NOT click any links."
                    )
                    advice_parts = [
                        "❌ Do NOT click the links in this message",
                        "❌ Do NOT provide any personal info",
                    ]
                else:
                    result["senior_message"] = (
                        "STOP! This is a FAKE warning. Your computer is SAFE. This pop-up is trying to SCARE you."
                    )
                    advice_parts = ["✅ Just close this window"]

                if phone_match:
                    advice_parts.append("❌ Do NOT call any phone numbers")
                if payment_hit:
                    advice_parts.append("❌ Do NOT pay any money")
                if action_hit and "download" in tl_norm:
                    advice_parts.append("❌ Do NOT download anything")
                if "click" in tl_norm:
                    advice_parts.append("❌ Do NOT click any links")
                result["action_advice"] = " | ".join(advice_parts)
        except Exception as e:
            logger.debug(f"Text scam analysis error: {e}")
        return result

    def _screen_visual_cues(self, b: bytes) -> dict:
        try:
            import io

            import numpy as _np
            from PIL import Image

            img = Image.open(io.BytesIO(b)).convert("RGB")
            hsv = img.convert("HSV")
            H, S, V = [_np.array(ch, dtype=_np.uint8) for ch in hsv.split()]
            total = H.size
            red_mask = ((H < 16) | (H > 240)) & (S > 128) & (V > 32)
            orange_mask = ((H >= 16) & (H < 40)) & (S > 128) & (V > 32)
            yellow_mask = ((H >= 40) & (H < 60)) & (S > 128) & (V > 32)
            red_ratio = float(red_mask.sum()) / float(total)
            orange_ratio = float(orange_mask.sum()) / float(total)
            yellow_ratio = float(yellow_mask.sum()) / float(total)
            visual_flag = (red_ratio + orange_ratio + yellow_ratio) >= 0.06
            h, w = H.shape
            tile_max = 0.0
            grid = 4
            th = h // grid
            tw = w // grid
            for gy in range(grid):
                for gx in range(grid):
                    y0 = gy * th
                    x0 = gx * tw
                    y1 = (gy + 1) * th if gy < grid - 1 else h
                    x1 = (gx + 1) * tw if gx < grid - 1 else w
                    area = (y1 - y0) * (x1 - x0)
                    if area <= 0:
                        continue
                    r = float(red_mask[y0:y1, x0:x1].sum()) / float(area)
                    o = float(orange_mask[y0:y1, x0:x1].sum()) / float(area)
                    yel = float(yellow_mask[y0:y1, x0:x1].sum()) / float(area)
                    tile_ratio = r + o + yel
                    if tile_ratio > tile_max:
                        tile_max = tile_ratio
            visual_any = visual_flag or (tile_max >= 0.12)
            return {
                "red_ratio": round(red_ratio, 3),
                "orange_ratio": round(orange_ratio, 3),
                "yellow_ratio": round(yellow_ratio, 3),
                "visual_scam_cues": visual_flag,
                "tile_max_ratio": round(tile_max, 3),
                "visual_scam_any": visual_any,
            }
        except Exception:
            return {
                "red_ratio": 0.0,
                "orange_ratio": 0.0,
                "yellow_ratio": 0.0,
                "visual_scam_cues": False,
                "tile_max_ratio": 0.0,
                "visual_scam_any": False,
            }

    async def fast_validate(self, url: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=0.4) as client:
                resp = await client.head(
                    url, headers={"User-Agent": "PayGuard/1.0"}, follow_redirects=True
                )
                h = resp.headers
                hdrs = [
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "strict-transport-security",
                ]
                count = sum(1 for k in hdrs if h.get(k) is not None)
                return {
                    "status": resp.status_code,
                    "security_headers_count": count,
                    "hsts": bool(h.get("strict-transport-security")),
                }
        except Exception:
            return {"status": 0, "security_headers_count": 0, "hsts": False}

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.netloc or parsed.path.split("/")[0]

    def _check_ssl(self, domain: str) -> bool:
        """Check if domain has valid SSL certificate"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert is not None
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            return False

    async def _check_domain_age(self, domain: str) -> Optional[int]:
        """Check domain age using WHOIS with fallback for trusted domains"""
        try:
            import whois

            w = await self._run_blocking(lambda: whois.whois(domain))
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if not created:
                return None
            if isinstance(created, datetime):
                delta = datetime.now(timezone.utc) - created
            else:
                # attempt to parse string
                try:
                    from dateutil import parser

                    dt = parser.parse(str(created))
                    delta = datetime.now(timezone.utc) - dt
                except Exception:
                    return None
            return max(0, delta.days)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            # Fallback: return conservative estimate for trusted domains
            if self._is_trusted_domain(domain):
                logger.debug(f"Using fallback age for trusted domain: {domain}")
                return 1825  # ~5 years for trusted domains
            return None

    def _detect_payment_gateways(self, url: str, domain: str) -> List[PaymentGateway]:
        """Detect payment gateways conservatively using host only"""
        detected = []
        host = self._extract_domain(url)
        h = host.lower()
        if h.endswith("stripe.com"):
            detected.append(PaymentGateway.STRIPE)
        elif h.endswith("paypal.com") or h.endswith("braintreepayments.com"):
            detected.append(PaymentGateway.PAYPAL)
        elif h.endswith("square.com"):
            detected.append(PaymentGateway.SQUARE)
        return detected

    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain (or its apex) is in the trusted domains list."""
        if not domain:
            return False
        d = domain.lower().lstrip(".")
        # Direct match (e.g. amazon.com)
        if d in self.TRUSTED_DOMAINS:
            return True
        # Subdomain match (e.g. www.amazon.com -> amazon.com)
        parts = d.split(".")
        for i in range(1, len(parts)):
            apex = ".".join(parts[i:])
            if apex in self.TRUSTED_DOMAINS:
                return True
        return False

    def _has_suspicious_patterns(self, url: str, domain: Optional[str] = None) -> bool:
        """Check for suspicious patterns in URL"""
        url_lower = url.lower()
        if any(re.search(pattern, url_lower) for pattern in self.SUSPICIOUS_PATTERNS):
            return True
        if domain:
            d = domain.lower()
            # generic indicator: presence of 'com.' within subdomains (e.g., brand.com.phish.tld)
            labels = d.split(".")
            if len(labels) >= 3 and "com" in labels[:-2]:
                return True
            if any(lbl.startswith("xn--") for lbl in labels):
                return True
        return False

    def _check_tls_details(self, domain: str) -> Tuple[bool, bool, bool]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return False, False, False
                    cn = None
                    try:
                        subj = cert.get("subject", [])
                        for tup in subj:
                            for k, v in tup:
                                if k == "commonName":
                                    cn = v
                    except Exception:
                        cn = None
                    sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]  # type: ignore[misc]
                    cn_match = bool(cn and cn.lower() == domain.lower())
                    san_match = any(domain.lower() == str(s).lower() or domain.lower().endswith("." + str(s).lower()) for s in sans)  # type: ignore[union-attr]
                    return True, cn_match, san_match
        except Exception:
            return False, False, False

    async def _check_hsts(self, domain: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.head(
                    f"https://{domain}/", headers={"User-Agent": "PayGuard/1.0"}
                )
                return bool(resp.headers.get("strict-transport-security"))
        except Exception:
            return False

    async def _check_ssl_http(self, domain: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                resp = await client.head(
                    f"https://{domain}/", headers={"User-Agent": "PayGuard/1.0"}
                )
                return resp.status_code > 0
        except Exception:
            return False

    async def _get_merchant_reputation(self, domain: str) -> Optional[dict]:
        """Get merchant reputation from database"""
        try:
            if self.db is None:
                return None
            merchant = await self.db.merchants.find_one({"domain": domain})
            return merchant
        except Exception:
            return None

    async def _is_blacklisted(self, domain: str, url: Optional[str] = None) -> bool:
        """Check if domain/url is blacklisted using DB and OpenPhish"""
        try:
            if self.db is not None:
                fraud_count = await self.db.fraud_reports.count_documents(
                    {"domain": domain, "verified": True}
                )
                if fraud_count >= 3:
                    return True
        except Exception:
            pass
        try:
            await self._update_openphish_cache()
            if url and url in self.openphish_urls:
                return True
            # domain match
            import urllib.parse as _up

            for d in self.openphish_urls:
                try:
                    host = _up.urlparse(d).netloc
                    if not host:
                        continue
                    if domain == host or domain.endswith("." + host):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    async def _update_openphish_cache(self):
        try:
            if self.openphish_last_fetch and (
                datetime.now(timezone.utc) - self.openphish_last_fetch
            ) < timedelta(hours=1):
                return
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get("https://openphish.com/feed.txt")
                resp.raise_for_status()
                lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
                self.openphish_urls = set(lines)
                self.openphish_last_fetch = datetime.now(timezone.utc)
        except Exception as e:
            logger.debug(f"OpenPhish update failed: {e}")

    async def _run_blocking(self, fn):
        """Run blocking function in thread to avoid blocking event loop"""
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn)

    def _generate_education_message(
        self,
        risk_level: RiskLevel,
        risk_factors: List[str],
        safety_indicators: List[str],
    ) -> str:
        """Generate educational message for users"""
        if risk_level == RiskLevel.LOW:
            return (
                "✅ This website appears safe for transactions. It has valid security measures "
                "and no significant red flags. Always verify the URL before entering payment details."
            )
        elif risk_level == RiskLevel.MEDIUM:
            msg = "⚠️ Exercise caution with this website. "
            if risk_factors:
                msg += f"Issues found: {', '.join(risk_factors[:2])}. "
            msg += "Verify the merchant's legitimacy before making payments."
            return msg
        else:
            msg = "🚨 HIGH RISK - We strongly recommend avoiding transactions on this website. "
            if risk_factors:
                msg += f"Red flags: {', '.join(risk_factors[:2])}. "
            msg += "This site may be a scam or unsafe for financial transactions."
            return msg

    def _url_features(self, url: str) -> np.ndarray:
        """Extract URL features for ML model prediction.
        Returns 36 features when enhanced model is loaded, 12 for legacy."""
        u = url.lower().strip()
        # Check if we have the enhanced model (36 features) or legacy (12)
        try:
            n_features = (
                self.ml_model.num_features()
                if hasattr(self.ml_model, "num_features")
                else 12
            )
        except Exception:
            n_features = 12

        if n_features > 12:
            from collections import Counter as _Counter
            from urllib.parse import urlparse as _urlparse

            if not u.startswith(("http://", "https://", "ftp://")):
                _up = _urlparse("http://" + u)
            else:
                _up = _urlparse(u)
            hostname = _up.hostname or ""
            path = _up.path or ""
            query = _up.query or ""
            _SUSPICIOUS_TLDS = {
                ".tk",
                ".ml",
                ".ga",
                ".cf",
                ".gq",
                ".xyz",
                ".top",
                ".club",
                ".work",
                ".buzz",
                ".rest",
                ".fit",
                ".bid",
                ".click",
                ".link",
                ".stream",
                ".download",
                ".win",
                ".racing",
                ".review",
                ".date",
                ".accountant",
                ".science",
                ".party",
                ".cricket",
                ".faith",
            }
            _BRAND_KW = {
                "paypal",
                "apple",
                "google",
                "microsoft",
                "amazon",
                "netflix",
                "facebook",
                "instagram",
                "whatsapp",
                "bank",
                "chase",
                "wellsfargo",
                "citibank",
                "hsbc",
                "barclays",
                "linkedin",
                "dropbox",
                "icloud",
                "outlook",
                "yahoo",
                "ebay",
                "coinbase",
                "binance",
                "metamask",
            }
            hostname_dots = hostname.count(".")
            tld = ("." + hostname.rsplit(".", 1)[-1]) if "." in hostname else ""
            digit_count = sum(c.isdigit() for c in url)
            brand_in_url = 0
            for _b in _BRAND_KW:
                if _b in u:
                    parts = hostname.split(".")
                    actual = parts[-2] if len(parts) >= 2 else hostname
                    if _b != actual and _b in hostname:
                        brand_in_url = 1
                        break
            if url:
                freq = _Counter(url)
                probs = [c / len(url) for c in freq.values()]
                entropy = -sum(p * np.log2(p) for p in probs if p > 0)
            else:
                entropy = 0.0
            _SUSP_WORDS = {
                "login",
                "signin",
                "verify",
                "secure",
                "account",
                "update",
                "confirm",
                "password",
                "credential",
                "authenticate",
                "suspend",
                "limited",
                "unlock",
                "restore",
                "wallet",
                "billing",
                "invoice",
            }
            feats = [
                len(url),
                url.count("."),
                url.count("/"),
                url.count("-"),
                url.count("_"),
                url.count("?"),
                url.count("="),
                url.count("&"),
                int(any(w in u for w in ["login", "signin", "log-in", "sign-in"])),
                int("secure" in u),
                int("account" in u),
                int(any(w in u for w in ["verify", "confirm", "validate"])),
                len(hostname),
                len(path),
                len(query),
                url.count("@"),
                url.count("~"),
                url.count("%"),
                hostname_dots,
                hostname.count("-"),
                sum(c.isdigit() for c in url) / max(len(url), 1),
                sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
                int(url.lower().startswith("https://")),
                int(bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))),
                int(_up.port is not None and _up.port not in (80, 443)),
                max(0, hostname_dots - 1),
                int(tld in _SUSPICIOUS_TLDS),
                path.count("/") - 1 if path else 0,
                int("//" in path[1:]) if len(path) > 1 else 0,
                int(
                    hostname
                    in {
                        "bit.ly",
                        "goo.gl",
                        "tinyurl.com",
                        "t.co",
                        "is.gd",
                        "ow.ly",
                        "buff.ly",
                    }
                ),
                int("update" in u),
                int(any(w in u for w in ["suspend", "locked", "limited", "restrict"])),
                int(any(w in u for w in ["bank", "paypal", "wallet", "billing"])),
                brand_in_url,
                entropy,
                sum(1 for w in _SUSP_WORDS if w in u),
            ]
        else:
            feats = [
                len(url),
                url.count("."),
                url.count("/"),
                url.count("-"),
                url.count("_"),
                url.count("?"),
                url.count("="),
                url.count("&"),
                int("login" in u),
                int("secure" in u),
                int("account" in u),
                int("verify" in u),
            ]
        return np.array(feats, dtype=float).reshape(1, -1)

    def _html_features(self, content: str) -> np.ndarray:
        cl = content.lower()
        scripts = re.findall(r"<script[^>]*>", content, flags=re.I)
        ext_scripts = re.findall(
            r'<script[^>]*src=["\"][^"\"]+["\"]', content, flags=re.I
        )
        inline_scripts = len(scripts) - len(ext_scripts)
        iframes = content.count("<iframe")
        anchors = content.count("<a")
        events = len(
            re.findall(r'\son[a-z]+\s*=\s*["\"][^"\"]+["\"]', content, flags=re.I)
        )
        mailto = len(re.findall(r'href\s*=\s*["\"]mailto:', content, flags=re.I))
        feats = [
            len(content),
            content.count("<"),
            int("<form" in cl),
            int("<input" in cl),
            int("<script" in cl),
            content.count("!"),
            int("login" in cl),
            int("password" in cl),
            int("verify" in cl),
            int("secure" in cl),
            content.count("href"),
            content.count("<img"),
            iframes,
            anchors,
            len(ext_scripts),
            inline_scripts,
            events,
            mailto,
        ]
        return np.array(feats, dtype=float).reshape(1, -1)

    def _content_signals(
        self, url: str, content: str
    ) -> Tuple[float, List[str], List[str]]:
        u = urlparse(url if url.startswith("http") else f"http://{url}")
        host = u.netloc
        cl = content.lower()
        risk = []
        safe = []
        delta = 0.0
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content, flags=re.I)
        for a in forms[:10]:
            try:
                au = urlparse(urljoin(url, a))
                if au.netloc and au.netloc != host:
                    risk.append("Form posts cross-origin")
                    delta -= 10.0
                else:
                    safe.append("Form posts same-origin")
                    delta += 5.0
            except Exception:
                pass
        scripts = re.findall(
            r'<script[^>]*src=["\']([^"\']+)["\']', content, flags=re.I
        )
        ext_scripts = 0
        for s in scripts[:20]:
            su = urlparse(urljoin(url, s))
            if su.netloc and su.netloc != host:
                ext_scripts += 1
        if ext_scripts >= 5:
            risk.append("Many external scripts")
            delta -= 5.0
        inputs = re.findall(r'<input[^>]*type=["\']([^"\']+)["\']', content, flags=re.I)
        # Don't penalize just for having a password input - legitimate sites have login forms
        # Only flag if combined with other high-risk signals
        has_password = any(t.lower() == "password" for t in inputs)

        links = re.findall(r'href=["\']([^"\']+)["\']', content, flags=re.I)
        cross_links = 0
        for h in links[:50]:
            lu = urlparse(urljoin(url, h))
            if lu.netloc and lu.netloc != host:
                cross_links += 1
        if cross_links >= 10:
            risk.append("Many cross-domain links")
            delta -= 5.0
        try:
            sri = re.findall(
                r'<(?:script|link)[^>]+integrity\s*=\s*["\"][^"\"]+["\"]',
                content,
                flags=re.I,
            )
            if sri:
                safe.append("Subresource Integrity present")
                delta += 5.0
        except Exception:
            pass
        try:
            nonce_attrs = re.findall(
                r'<(?:script|style)[^>]+nonce\s*=\s*["\"][^"\"]+["\"]',
                content,
                flags=re.I,
            )
            if len(nonce_attrs) >= 1:
                safe.append("Nonce-based script/style detected")
                delta += 3.0
        except Exception:
            pass
        try:
            eval_count = cl.count("eval(")
            atob_count = (
                cl.count("atob(") + cl.count("unescape(") + cl.count("fromcharcode")
            )
            if eval_count >= 3 or atob_count >= 3:
                risk.append("Obfuscated script patterns")
                delta -= 5.0
        except Exception:
            pass
        try:
            data_uri_count = len(re.findall(r'data:[^\s"\"]+', content, flags=re.I))
            if data_uri_count >= 20:
                risk.append("Many inline data URIs")
                delta -= 5.0
        except Exception:
            pass
        try:
            noopener = len(
                re.findall(
                    r'rel\s*=\s*["\"]noopener(?:\s+noreferrer)?["\"]',
                    content,
                    flags=re.I,
                )
            )
            if noopener >= 5:
                safe.append("Links use noopener/noreferrer")
                delta += 2.0
        except Exception:
            pass
        return delta, risk, safe

    def _html_code_analysis(self, url: str, content: str) -> Tuple[bool, str]:
        """
        Analyze actual HTML code structure for phishing patterns.
        Returns (is_phishing, reason) - much more accurate than text analysis.
        """
        try:
            from urllib.parse import urljoin, urlparse

            host = urlparse(url).netloc.lower()
            if not host:
                return False, ""

            cl = content.lower()
            risk_signals = []

            # 1. Check forms submitting to external domains (major phishing indicator)
            form_actions = re.findall(
                r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', content, flags=re.I
            )
            for action in form_actions[:10]:
                if action.startswith("http"):
                    action_host = urlparse(action).netloc.lower()
                    if (
                        action_host
                        and action_host != host
                        and not action_host.endswith(
                            ("google.com", "facebook.com", "microsoft.com", "apple.com")
                        )
                    ):
                        risk_signals.append(
                            f"Form submits to external domain: {action_host}"
                        )

            # 2. Check for hidden form fields (credential harvesting) - require more for legitimate sites
            hidden_inputs = re.findall(
                r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>', content, flags=re.I
            )
            if len(hidden_inputs) >= 15:
                risk_signals.append(
                    f"Multiple hidden form fields ({len(hidden_inputs)})"
                )

            # 3. Check for fake login buttons (deceptive copy)
            login_buttons = re.findall(
                r'<button[^>]*>([^<]*)</button>|<input[^>]*type\s*=\s*["\']submit["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
                content,
                flags=re.I,
            )
            deceptive_words = [
                "verify now",
                "confirm now",
                "secure now",
                "update now",
                "validate now",
            ]
            for btn_text in login_buttons:
                btn = " ".join(btn_text).lower()
                if any(w in btn for w in deceptive_words):
                    risk_signals.append(f"Deceptive button text: {btn}")

            # 4. REMOVED: Password field without autocomplete - too common on legitimate sites
            # 5. REMOVED: Suspicious external scripts - too many false positives with modern CDNs

            # 6. Check for IP addresses in URLs (red flag)
            ip_pattern = re.findall(
                r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content
            )
            if ip_pattern:
                risk_signals.append("Page contains IP address URL")

            # 7. Check for data: URIs (can hide malicious content)
            data_uri_count = len(
                re.findall(r'<script[^>]*src\s*=\s*["\']data:', content, flags=re.I)
            )
            if data_uri_count >= 2:
                risk_signals.append(f"Inline data scripts ({data_uri_count})")

            # 8. Check for iframe embedding (clickjacking)
            iframes = re.findall(
                r'<iframe[^>]*src\s*=\s*["\']([^"\']+)["\']', content, flags=re.I
            )
            for iframe in iframes[:5]:
                if (
                    iframe.startswith("http")
                    and urlparse(iframe).netloc.lower() != host
                ):
                    risk_signals.append(f"External iframe: {iframe[:40]}")

            # 9. Check for onmouseover events (fake URL bar)
            mouse_events = re.findall(
                r'onmouseover\s*=\s*["\'][^"\']*location', content, flags=re.I
            )
            if mouse_events:
                risk_signals.append("Fake URL bar via mouse events")

            # 10. Check for base64-encoded content (obfuscation)
            base64_patterns = len(re.findall(r"[a-zA-Z0-9+/]{50,}={0,2}", content))
            if base64_patterns >= 10:
                risk_signals.append("Heavy base64 encoding detected")

            # 11. CLICKJACKING DETECTION - Full-screen overlays
            # Check for full-viewport iframes
            fullscreen_iframe = re.findall(
                r'<iframe[^>]*(?:width\s*=\s*["\']100%|height\s*=\s*["\']100%|style\s*=\s*["\'][^"\']*(?:width|height)[^"\']*100%)[^>]*>',
                content, flags=re.I
            )
            if fullscreen_iframe:
                risk_signals.append("Full-screen iframe detected (clickjacking)")

            # Check for full-screen divs with high z-index
            overlay_divs = re.findall(
                r'<div[^>]*(?:style|class)[^>]*>',
                content, flags=re.I
            )
            for div in overlay_divs:
                div_lower = div.lower()
                has_position = 'position:' in div_lower or 'position :' in div_lower.replace(' ', '')
                has_full_size = ('100vh' in div_lower or '100vw' in div_lower or 
                              ('100%' in div_lower and ('width' in div_lower or 'height' in div_lower)))
                has_high_z = 'z-index' in div_lower
                if has_position and has_full_size and has_high_z:
                    risk_signals.append("Full-screen overlay div detected (clickjacking)")
                    break

            # 12. Check for aggressive click hijacking
            # onClick that navigates or opens windows
            click_hijack = re.findall(
                r'onclick\s*=\s*["\'][^"\']*(?:window\.|location\.|open\()',
                content, flags=re.I
            )
            if len(click_hijack) >= 3:
                risk_signals.append(f"Multiple click handlers that redirect ({len(click_hijack)})")

            # 13. Check for body onClick hijacking
            body_onclick = re.findall(
                r'<body[^>]*onclick\s*=\s*["\'][^"\']+',
                content, flags=re.I
            )
            if body_onclick:
                risk_signals.append("Body onclick redirect detected")

            # 14. Check for preventDefault blocking (stops user from closing)
            prevent_default = re.findall(
                r'(?:addEventListener|on)\s*\(\s*["\']?(?:beforeunload|unload|keydown)["\']?.*preventDefault',
                content, flags=re.I
            )
            if prevent_default:
                risk_signals.append("Event blocking detected (preventDefault)")

            # 15. Check for aggressive popups (multiple window.open)
            window_open_count = len(re.findall(r'window\.open\s*\(', content, flags=re.I))
            if window_open_count >= 2:
                risk_signals.append(f"Multiple popup attempts ({window_open_count})")

            # 16. Check for document.write abuse (malicious content injection)
            doc_write_count = len(re.findall(r'document\.write\s*\(', content, flags=re.I))
            if doc_write_count >= 3:
                risk_signals.append(f"Multiple document.write calls ({doc_write_count})")

            # 17. Check for display:none but still clickable elements (hidden traps)
            hidden_traps = re.findall(
                r'<[^>]+style\s*=\s*["\'][^"\']*display\s*:\s*none[^"\']*>[^<]*(?:button|a|input)',
                content, flags=re.I
            )
            if hidden_traps:
                risk_signals.append("Hidden clickable elements detected")

            # Only flag as phishing if we find 2+ REAL risk signals
            # This catches actual phishing while avoiding false positives
            strong_signals = [
                r
                for r in risk_signals
                if "external domain" in r.lower()
                or "ip address" in r.lower()
                or "iframe" in r.lower()
                or "mouse" in r.lower()
                or "hidden" in r.lower()
                or "clickjack" in r.lower()
                or "overlay" in r.lower()
                or "redirect" in r.lower()
                or "popup" in r.lower()
            ]

            if len(strong_signals) >= 1:
                return True, f"HTML code analysis: {strong_signals[0]}"

            return False, ""

        except Exception:
            return False, ""

    def _predict_image_fake_bytes(self, b: bytes, static: bool = False):
        try:
            import io

            from PIL import Image

            img = Image.open(io.BytesIO(b)).convert("RGB")
            w, h = img.size
            if min(w, h) < 128:
                return 0.0

            # 1. DIRE Model Prediction (Primary) - but only if image looks suspicious
            p_dire = None
            if (
                self.dire_home
                and self.dire_model_path
                and self.dire_model_path.exists()
            ):
                if self._dire_busy:
                    # Another call is already running DIRE; skip to avoid queue buildup
                    return 0.0

                # Fast-path: Check if image is worth AI analysis
                # Tiny images or very simple ones are almost certainly UI/graphics
                try:
                    import io as _io

                    from PIL import Image as _I

                    img = _I.open(_io.BytesIO(b)).convert("RGB")
                    # Basic validity check
                    w, h = img.size
                    if w < 128 or h < 128:
                        return 0.0

                    # FAST PRE-CHECK: Skip DIRE for obviously real images
                    # Real photos have: many colors, natural texture variation
                    # UI/graphics have: few colors, flat areas
                    import numpy as _np

                    small = img.copy()
                    small.thumbnail((100, 100))
                    colors = small.getcolors(maxcolors=10000)

                    if colors:
                        num_colors = len(colors)
                        # Calculate color variance
                        arr = _np.array(small)
                        variance = arr.var()

                        # Low color count + low variance = UI/graphic (skip DIRE)
                        # High color count OR high variance = photo/possible AI (run DIRE)
                        if num_colors < 100 and variance < 1000:
                            logger.debug(
                                f"Skipping DIRE: simple image (colors={num_colors}, var={variance:.0f})"
                            )
                            return 0.0

                        logger.debug(
                            f"Running DIRE: complex image (colors={num_colors}, var={variance:.0f})"
                        )

                except Exception as e:
                    logger.debug(f"Image load error: {e}")
                    return 0.0

                try:
                    self._dire_busy = True
                    import os as _os
                    import subprocess as _sp
                    import tempfile as _tf

                    with _tf.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                        img.save(tmp.name, format="PNG")
                        tmp_path = tmp.name

                    # Try to use conda if available, otherwise fallback to direct python
                    import shutil as _sh

                    if _sh.which("conda"):
                        cmd = [
                            "conda",
                            "run",
                            "-n",
                            "dire",
                            "python",
                            str(self.dire_home / "demo.py"),
                            "-f",
                            tmp_path,
                            "-m",
                            str(self.dire_model_path),
                            "--use_cpu",
                        ]
                    else:
                        cmd = [
                            "python3",
                            str(self.dire_home / "demo.py"),
                            "-f",
                            tmp_path,
                            "-m",
                            str(self.dire_model_path),
                            "--use_cpu",
                        ]

                    # Log the command being run
                    logger.debug(f"Running DIRE: {' '.join(cmd)}")

                    out = _sp.run(cmd, stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=45)
                    _os.unlink(tmp_path)

                    txt = (out.stdout or b"").decode("utf-8", errors="ignore")
                    err = (out.stderr or b"").decode("utf-8", errors="ignore")

                    if out.returncode != 0:
                        logger.debug(f"DIRE Error (code {out.returncode}): {err[:100]}")

                    import re as _re

                    m = _re.search(r"prob[^0-9]*([0-9]*\.?[0-9]+)", txt, _re.I)
                    if m:
                        p_dire = float(m.group(1))
                        if p_dire > 1.0:
                            p_dire = p_dire / 100.0
                        logger.debug(f"DIRE Result: {p_dire:.4f}")
                    else:
                        if (
                            ("fake" in txt.lower())
                            or ("generated" in txt.lower())
                            or ("synthetic" in txt.lower())
                        ):
                            p_dire = 0.8
                            logger.debug(f"DIRE Result (text-match): {p_dire}")
                        elif "real" in txt.lower():
                            p_dire = 0.2
                            logger.debug(f"DIRE Result (text-match): {p_dire}")
                except Exception as e:
                    logger.debug(f"DIRE exception: {e}")
                    p_dire = None
                finally:
                    self._dire_busy = False

            if p_dire is None:
                return 0.0

            # 2. Refine score with heuristics to reduce false positives
            p = float(p_dire)

            # Check for camera metadata (strong indicator of real photo)
            try:
                exif = getattr(img, "getexif", lambda: None)()
                if exif and any(exif.get(k) for k in [271, 272, 42036]):
                    if p < 0.995:
                        p *= 0.2
            except Exception:
                pass

            # Check for text-heavy images
            def _text_heavy(cimg):
                try:
                    import shutil as _sh

                    import pytesseract

                    cmd = _sh.which("tesseract") or "/opt/homebrew/bin/tesseract"
                    if cmd:
                        pytesseract.pytesseract.tesseract_cmd = cmd
                    import io as _io

                    from PIL import Image as _I

                    b2 = _io.BytesIO()
                    cimg.save(b2, format="JPEG", quality=70)
                    im2 = _I.open(_io.BytesIO(b2.getvalue())).convert("L")
                    t = pytesseract.image_to_string(
                        im2, config="--psm 7 -l eng --oem 3"
                    )
                    tl = (t or "").strip().lower()
                    alnum = sum(ch.isalnum() for ch in tl)
                    return len(tl) >= 25 and (alnum / max(1, len(tl))) >= 0.4
                except Exception:
                    return False

            if p >= 0.8 and _text_heavy(img):
                p *= 0.5

            # Low complexity checks (logos, graphics)
            try:
                import numpy as _np
                from PIL import ImageFilter

                hh = img.getcolors(maxcolors=2000)
                # UI elements often have very few unique colors
                low_colors = (hh is not None) and (len(hh) < 64)

                g = img.convert("L")
                e = g.filter(ImageFilter.FIND_EDGES)
                arr = _np.array(e, dtype=_np.uint8)
                mean_edge = float(arr.mean())

                # Digital UI elements often have extremely sparse edges (mean_edge < 3.0)
                # or very sharp, clean lines.
                # BUT: Don't penalize if DIRE is already very confident (>90%)
                # This avoids suppressing actual AI-generated faces
                if p < 0.90:  # Only apply UI penalties to uncertain detections
                    if low_colors or mean_edge < 3.5:
                        p *= 0.05  # Massive penalty for flat UI
                    elif mean_edge < 8.0:
                        p *= 0.2  # Heavy penalty for simple UI
                    elif mean_edge < 15.0:
                        p *= 0.5  # Moderate penalty
                elif mean_edge > 40.0:  # Very noisy/textured (AI often looks like this)
                    p = min(1.0, p * 1.1)
            except Exception:
                pass

            # Photo realism guardrail (false-positive reducer)
            # Many real camera/photos (news/editorial) carry ICC profiles and non-square framing.
            # DIRE can over-score these as synthetic, so down-weight unless confidence is near-certain.
            try:
                info = getattr(img, "info", {}) or {}
                has_icc = bool(info.get("icc_profile"))
                ar = float(max(w, h)) / float(max(1, min(w, h)))
                is_squareish = ar <= 1.12

                if has_icc and (not is_squareish) and p < 0.999:
                    p *= 0.25
                elif has_icc and p < 0.95:
                    p *= 0.5
            except Exception:
                pass

            return float(p)
        except Exception as e:
            logger.error(f"Image prediction failed: {e}")
            return 0.0

    def _is_graphic_or_logo_bytes(self, b: bytes) -> bool:
        try:
            import io

            import numpy as _np
            from PIL import Image, ImageFilter

            img = Image.open(io.BytesIO(b)).convert("RGB")
            w, h = img.size
            if min(w, h) < 256:
                return True
            try:
                hh = img.getcolors(maxcolors=1000000)
                low_colors = (hh is not None) and (len(hh) < 64)
            except Exception:
                low_colors = False
            try:
                g = img.convert("L")
                e = g.filter(ImageFilter.FIND_EDGES)
                arr = _np.array(e, dtype=_np.uint8)
                mean_edge = float(arr.mean())
                low_edges = mean_edge < 8.0
            except Exception:
                low_edges = False
            return bool(low_colors or low_edges)
        except Exception:
            return False
