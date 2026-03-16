#!/usr/bin/env python3
"""
Tests for RiskScoringEngine — the core scoring logic in backend/risk_engine.py.

These tests use the mock_db fixture from conftest.py so no real MongoDB is needed.
Network calls (SSL, WHOIS, httpx, OpenPhish) are patched to keep tests fast and deterministic.
"""

import asyncio
import re
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from backend.risk_engine import RiskScoringEngine
from backend.models import RiskLevel, PaymentGateway


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(mock_db):
    """Create a RiskScoringEngine with mocked DB and no ML models loaded."""
    with patch.object(RiskScoringEngine, "__init__", lambda self, db: None):
        eng = RiskScoringEngine.__new__(RiskScoringEngine)
    # Manually set required attributes (mirrors __init__ without loading model files)
    eng.db = mock_db
    eng.ml_model = None
    eng.ml_scaler = None
    eng.shap_explainer = None
    eng.html_model = None
    eng.html_scaler = None
    eng.html_cnn = None
    eng.html_cnn_seq_len = 4096
    eng.image_model = None
    eng.image_processor = None
    eng.image_device = "cpu"
    eng.local_image_model = None
    eng.local_image_device = "cpu"
    eng.dire_home = None
    eng.dire_model_path = None
    eng.text_model = None
    eng.text_tokenizer = None
    eng._dire_busy = False
    eng._dire_lock = asyncio.Lock()
    eng.openphish_urls = set()
    eng.openphish_last_fetch = None
    # Provide a minimal EmailGuardian
    from backend.email_guardian import EmailGuardian
    eng.email_guardian = EmailGuardian()
    return eng


# ---------------------------------------------------------------------------
# _extract_domain
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_simple_https(self, engine):
        assert engine._extract_domain("https://example.com/path") == "example.com"

    def test_http_with_port(self, engine):
        assert engine._extract_domain("http://example.com:8080/page") == "example.com:8080"

    def test_no_scheme(self, engine):
        # Should prepend http:// internally
        assert engine._extract_domain("example.com/path") == "example.com"

    def test_subdomain(self, engine):
        assert engine._extract_domain("https://sub.domain.example.com") == "sub.domain.example.com"

    def test_ip_address(self, engine):
        assert engine._extract_domain("http://192.168.1.1/admin") == "192.168.1.1"


# ---------------------------------------------------------------------------
# _has_suspicious_patterns
# ---------------------------------------------------------------------------

class TestSuspiciousPatterns:
    def test_ip_address_url(self, engine):
        assert engine._has_suspicious_patterns("http://192.168.1.1/login") is True

    def test_verify_account(self, engine):
        assert engine._has_suspicious_patterns("https://verify-account.example.com") is True

    def test_secure_login(self, engine):
        assert engine._has_suspicious_patterns("https://secure-login.phish.com") is True

    def test_normal_url(self, engine):
        assert engine._has_suspicious_patterns("https://github.com/repo") is False

    def test_suspicious_domain_com_trick(self, engine):
        # e.g. paypal.com.evil.tk  →  labels = ['paypal', 'com', 'evil', 'tk']
        assert engine._has_suspicious_patterns(
            "https://paypal.com.evil.tk/login", domain="paypal.com.evil.tk"
        ) is True

    def test_punycode_domain(self, engine):
        assert engine._has_suspicious_patterns(
            "https://xn--pple-43d.com", domain="xn--pple-43d.com"
        ) is True


# ---------------------------------------------------------------------------
# _detect_payment_gateways
# ---------------------------------------------------------------------------

class TestDetectPaymentGateways:
    def test_stripe(self, engine):
        gw = engine._detect_payment_gateways("https://checkout.stripe.com/pay", "checkout.stripe.com")
        assert PaymentGateway.STRIPE in gw

    def test_paypal(self, engine):
        gw = engine._detect_payment_gateways("https://www.paypal.com/cgi-bin", "www.paypal.com")
        assert PaymentGateway.PAYPAL in gw

    def test_no_gateway(self, engine):
        gw = engine._detect_payment_gateways("https://example.com", "example.com")
        assert gw == []


# ---------------------------------------------------------------------------
# _is_trusted_domain
# ---------------------------------------------------------------------------

class TestIsTrustedDomain:
    def test_exact_match(self, engine):
        assert engine._is_trusted_domain("amazon.com") is True

    def test_www_subdomain(self, engine):
        assert engine._is_trusted_domain("www.amazon.com") is True

    def test_deep_subdomain(self, engine):
        assert engine._is_trusted_domain("smile.www.amazon.com") is True

    def test_unknown_domain(self, engine):
        assert engine._is_trusted_domain("totallylegit-shop.xyz") is False

    def test_none_domain(self, engine):
        assert engine._is_trusted_domain(None) is False

    def test_empty_domain(self, engine):
        assert engine._is_trusted_domain("") is False

    def test_partial_match_not_trusted(self, engine):
        """amazon.com.evil.com should NOT match."""
        assert engine._is_trusted_domain("amazon.com.evil.com") is False


# ---------------------------------------------------------------------------
# _url_features
# ---------------------------------------------------------------------------

class TestUrlFeatures:
    def test_shape_legacy(self, engine):
        """With ml_model=None, should return 12-feature legacy vector."""
        feats = engine._url_features("https://example.com")
        assert feats.shape == (1, 12)

    def test_login_flag(self, engine):
        feats = engine._url_features("https://example.com/login")
        # index 8 is 'has_login'
        assert feats[0, 8] == 1.0

    def test_no_login_flag(self, engine):
        feats = engine._url_features("https://example.com/home")
        assert feats[0, 8] == 0.0

    def test_shape_enhanced(self, engine):
        """With enhanced model (36 features), should return 36-feature vector."""
        mock_model = MagicMock()
        mock_model.num_features.return_value = 36
        engine.ml_model = mock_model
        feats = engine._url_features("https://example.com/login?user=test")
        assert feats.shape == (1, 36)
        engine.ml_model = None  # restore

    def test_enhanced_features_content(self, engine):
        """Verify specific features in the 36-feature vector."""
        mock_model = MagicMock()
        mock_model.num_features.return_value = 36
        engine.ml_model = mock_model
        feats = engine._url_features("https://example.com/login?user=test&action=verify")
        # index 0 = url_length
        assert feats[0, 0] == len("https://example.com/login?user=test&action=verify")
        # index 8 = has_login (login is in URL)
        assert feats[0, 8] == 1.0
        # index 11 = has_verify (verify is in URL)
        assert feats[0, 11] == 1.0
        # index 22 = is_https
        assert feats[0, 22] == 1.0
        # index 23 = is_ip (not an IP)
        assert feats[0, 23] == 0.0
        engine.ml_model = None  # restore

    def test_enhanced_ip_detection(self, engine):
        """Verify IP address detection in enhanced features."""
        mock_model = MagicMock()
        mock_model.num_features.return_value = 36
        engine.ml_model = mock_model
        feats = engine._url_features("http://192.168.1.1/phishing")
        # index 23 = is_ip
        assert feats[0, 23] == 1.0
        # index 22 = is_https (http, not https)
        assert feats[0, 22] == 0.0
        engine.ml_model = None  # restore


# ---------------------------------------------------------------------------
# _html_features
# ---------------------------------------------------------------------------

class TestHtmlFeatures:
    def test_shape(self, engine):
        html = "<html><body>hello</body></html>"
        feats = engine._html_features(html)
        assert feats.shape == (1, 18)

    def test_form_detection(self, engine):
        html = '<form action="/submit"><input type="password"></form>'
        feats = engine._html_features(html)
        # index 2 = has_form, index 3 = has_input
        assert feats[0, 2] == 1.0
        assert feats[0, 3] == 1.0

    def test_password_keyword(self, engine):
        html = '<input type="password">'
        feats = engine._html_features(html)
        # index 7 = has 'password'
        assert feats[0, 7] == 1.0


# ---------------------------------------------------------------------------
# _generate_education_message
# ---------------------------------------------------------------------------

class TestEducationMessage:
    def test_low_risk(self, engine):
        msg = engine._generate_education_message(RiskLevel.LOW, [], ["Valid SSL"])
        assert "safe" in msg.lower() or "appears safe" in msg.lower()

    def test_medium_risk(self, engine):
        msg = engine._generate_education_message(RiskLevel.MEDIUM, ["No SSL"], [])
        assert "caution" in msg.lower()

    def test_high_risk(self, engine):
        msg = engine._generate_education_message(RiskLevel.HIGH, ["IP address URL"], [])
        assert "high risk" in msg.lower()


# ---------------------------------------------------------------------------
# _content_signals
# ---------------------------------------------------------------------------

class TestContentSignals:
    def test_cross_origin_form(self, engine):
        html = '<form action="https://evil.com/steal"><input type="password"></form>'
        delta, risk, safe = engine._content_signals("https://example.com", html)
        assert delta < 0
        assert any("cross-origin" in r.lower() for r in risk)

    def test_same_origin_form(self, engine):
        html = '<form action="/submit"><input type="text"></form>'
        delta, risk, safe = engine._content_signals("https://example.com", html)
        assert any("same-origin" in s.lower() for s in safe)

    def test_password_input(self, engine):
        """Password input alone should NOT be flagged as risky — legitimate sites have login forms."""
        html = '<input type="password">'
        delta, risk, safe = engine._content_signals("https://example.com", html)
        # Intentionally removed: password-only detection causes FPs on legitimate login pages
        assert not any("password" in r.lower() for r in risk)


# ---------------------------------------------------------------------------
# _screen_visual_cues
# ---------------------------------------------------------------------------

class TestScreenVisualCues:
    def test_red_image(self, engine):
        from PIL import Image
        import io
        img = Image.new("RGB", (200, 200), color="red")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        cues = engine._screen_visual_cues(buf.getvalue())
        assert cues["red_ratio"] > 0.5
        assert cues["visual_scam_any"] is True

    def test_white_image(self, engine):
        from PIL import Image
        import io
        img = Image.new("RGB", (200, 200), color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        cues = engine._screen_visual_cues(buf.getvalue())
        assert cues["red_ratio"] < 0.01
        assert cues["visual_scam_any"] is False

    def test_invalid_bytes(self, engine):
        cues = engine._screen_visual_cues(b"not an image")
        assert cues["visual_scam_any"] is False


# ---------------------------------------------------------------------------
# _analyze_text_for_scam
# ---------------------------------------------------------------------------

class TestAnalyzeTextForScam:
    def test_obvious_scam(self, engine):
        text = (
            "URGENT: Your computer has a virus! "
            "Call Microsoft Support at 1-800-555-0199 immediately. "
            "Do not close this window!"
        )
        result = engine._analyze_text_for_scam(text)
        assert result["is_scam"] is True
        assert result["confidence"] >= 80

    def test_safe_text(self, engine):
        text = "Thank you for your purchase. Your order has shipped."
        result = engine._analyze_text_for_scam(text)
        assert result["is_scam"] is False

    def test_phishing_text(self, engine):
        text = (
            "Your PayPal account has been suspended due to suspicious activity. "
            "Please verify account and confirm your password immediately."
        )
        result = engine._analyze_text_for_scam(text)
        assert result["is_scam"] is True
        assert any("phishing" in p for p in result["detected_patterns"])

    def test_payment_scam(self, engine):
        text = (
            "CRITICAL ERROR: Your system is heavily damaged. "
            "Pay now with gift card to restore access."
        )
        result = engine._analyze_text_for_scam(text)
        assert result["is_scam"] is True
        assert result["confidence"] >= 80


# ---------------------------------------------------------------------------
# calculate_risk (rule-based path, no ML model)
# ---------------------------------------------------------------------------

class TestCalculateRisk:
    """Test the rule-based calculate_risk path (ml_model is None)."""

    @pytest.fixture(autouse=True)
    def _patch_network(self, engine):
        """Patch all network calls so tests are fast and deterministic."""
        with (
            patch.object(engine, "_check_ssl", return_value=True),
            patch.object(engine, "_check_ssl_http", new_callable=AsyncMock, return_value=True),
            patch.object(engine, "_check_domain_age", new_callable=AsyncMock, return_value=730),
            patch.object(engine, "_check_tls_details", return_value=(True, True, True)),
            patch.object(engine, "_check_hsts", new_callable=AsyncMock, return_value=True),
            patch.object(engine, "_is_blacklisted", new_callable=AsyncMock, return_value=False),
            patch.object(engine, "fast_validate", new_callable=AsyncMock, return_value={
                "status": 200, "security_headers_count": 4, "hsts": True
            }),
        ):
            yield

    @pytest.mark.asyncio
    async def test_safe_url(self, engine):
        score = await engine.calculate_risk("https://github.com")
        assert score.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)
        assert score.trust_score >= 40

    @pytest.mark.asyncio
    async def test_suspicious_url(self, engine):
        with (
            patch.object(engine, "_check_ssl", return_value=False),
            patch.object(engine, "_check_ssl_http", new_callable=AsyncMock, return_value=False),
            patch.object(engine, "_check_domain_age", new_callable=AsyncMock, return_value=10),
            patch.object(engine, "_check_tls_details", return_value=(False, False, False)),
            patch.object(engine, "_check_hsts", new_callable=AsyncMock, return_value=False),
            patch.object(engine, "fast_validate", new_callable=AsyncMock, return_value={
                "status": 0, "security_headers_count": 0, "hsts": False
            }),
        ):
            score = await engine.calculate_risk("http://192.168.1.1/verify-account")
            assert score.trust_score < 50

    @pytest.mark.asyncio
    async def test_blacklisted_url(self, engine):
        with (
            patch.object(engine, "_is_blacklisted", new_callable=AsyncMock, return_value=True),
            patch.object(engine, "_check_ssl", return_value=False),
            patch.object(engine, "_check_ssl_http", new_callable=AsyncMock, return_value=False),
            patch.object(engine, "_check_domain_age", new_callable=AsyncMock, return_value=10),
            patch.object(engine, "_check_tls_details", return_value=(False, False, False)),
            patch.object(engine, "_check_hsts", new_callable=AsyncMock, return_value=False),
            patch.object(engine, "fast_validate", new_callable=AsyncMock, return_value={
                "status": 0, "security_headers_count": 0, "hsts": False
            }),
        ):
            score = await engine.calculate_risk("https://known-bad-site.com")
            assert "Domain flagged in fraud database" in score.risk_factors
            assert score.trust_score < 60

    @pytest.mark.asyncio
    async def test_risk_score_fields(self, engine):
        score = await engine.calculate_risk("https://example.com")
        assert score.url == "https://example.com"
        assert score.domain == "example.com"
        assert 0 <= score.trust_score <= 100
        assert score.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)
        assert isinstance(score.risk_factors, list)
        assert isinstance(score.safety_indicators, list)
        assert isinstance(score.education_message, str)
        assert score.ssl_valid is True


# ---------------------------------------------------------------------------
# _predict_image_fake_bytes
# ---------------------------------------------------------------------------

class TestPredictImageFakeBytes:
    def test_small_image_returns_zero(self, engine):
        """Images below 128px should immediately return 0.0."""
        from PIL import Image
        import io
        img = Image.new("RGB", (64, 64), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        assert engine._predict_image_fake_bytes(buf.getvalue()) == 0.0

    def test_no_dire_returns_zero(self, engine):
        """Without DIRE model, should return 0.0 for valid images."""
        from PIL import Image
        import io
        img = Image.new("RGB", (256, 256), color="green")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        result = engine._predict_image_fake_bytes(buf.getvalue())
        assert result == 0.0

    def test_invalid_bytes(self, engine):
        result = engine._predict_image_fake_bytes(b"not an image at all")
        assert result == 0.0


# ---------------------------------------------------------------------------
# fast_validate
# ---------------------------------------------------------------------------

class TestFastValidate:
    @pytest.mark.asyncio
    async def test_returns_dict(self, engine):
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
            }
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=MagicMock(head=AsyncMock(return_value=mock_resp)))
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = ctx

            result = await engine.fast_validate("https://example.com")
            assert isinstance(result, dict)
            assert "status" in result
            assert "security_headers_count" in result
            assert "hsts" in result
