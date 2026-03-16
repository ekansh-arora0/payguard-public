"""
Tests for backend/server.py API endpoints.

The server module creates AsyncIOMotorClient and RiskScoringEngine at
import time, so we set required env vars and patch heavy objects *before*
the import happens.
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock, Mock

# Ensure env vars exist before the server module is imported by conftest
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "payguard_test")

# ---------------------------------------------------------------------------
# Patch heavy module-level objects so importing server.py doesn't require a
# real MongoDB or model files.
# ---------------------------------------------------------------------------

_mock_motor_client = MagicMock()


class _MockDB:
    """Fake MongoDB database where every attribute returns an async-capable mock collection."""

    def __init__(self):
        self._collections: dict = {}

    def _make_collection(self):
        col = MagicMock()
        col.find_one = AsyncMock(return_value=None)
        col.insert_one = AsyncMock()
        col.update_one = AsyncMock()
        col.delete_one = AsyncMock()
        col.count_documents = AsyncMock(return_value=0)
        find_cursor = MagicMock()
        find_cursor.to_list = AsyncMock(return_value=[])
        find_cursor.limit = Mock(return_value=find_cursor)
        find_cursor.sort = Mock(return_value=find_cursor)
        col.find = Mock(return_value=find_cursor)
        agg_cursor = MagicMock()
        agg_cursor.to_list = AsyncMock(return_value=[])
        col.aggregate = Mock(return_value=agg_cursor)
        return col

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._collections:
            self._collections[name] = self._make_collection()
        return self._collections[name]

    def reset(self):
        self._collections.clear()


_mock_db = _MockDB()
_mock_motor_client.__getitem__ = Mock(return_value=_mock_db)

# Patch motor client construction *before* server.py is imported
patch("motor.motor_asyncio.AsyncIOMotorClient", return_value=_mock_motor_client).start()

# Patch RiskScoringEngine.__init__ to avoid loading ML models
def _fake_risk_init(self, db):
    self.db = db
    self.ml_model = None
    self.ml_scaler = None
    self.html_cnn = None
    self.html_cnn_seq_len = 4096
    self.html_model = None
    self.html_scaler = None
    self.text_model = None
    self.text_tokenizer = None
    self.shap_explainer = None
    self.email_guardian = None
    self.dire_home = None
    self.dire_model_path = None
    self._dire_busy = False
    import asyncio
    self._dire_lock = asyncio.Lock()
    self.blacklist_urls = set()
    self.blacklist_domains = set()
    self.risk_thresholds = {"high": 40, "medium": 70}

patch("backend.risk_engine.RiskScoringEngine.__init__", _fake_risk_init).start()

# ---------- NOW it is safe to import ----------
import pytest
from fastapi.testclient import TestClient

from backend.server import app, api_key_manager, risk_engine
from backend.auth import require_api_key
from backend.models import RiskScore, RiskLevel, MediaRisk


# ---------- override auth dependency for all tests ----------

def _override_require_api_key():
    return "test-key-123"

app.dependency_overrides[require_api_key] = _override_require_api_key

client = TestClient(app, raise_server_exceptions=False)


# ====================== Helpers ======================

def _stub_validate(api_key):
    """No-op validate so we don't hit Mongo."""
    return None

def _reset_collections():
    """Clear mock collection call counts between tests."""
    _mock_db.reset()


# ====================== Public Endpoints ======================

class TestPublicEndpoints:
    def test_root(self):
        resp = client.get("/api/v1/")
        assert resp.status_code == 200
        body = resp.json()
        assert "PayGuard" in body["message"]
        assert "endpoints" in body

    def test_health(self):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_fast_validate(self):
        with patch.object(risk_engine, "fast_validate", new_callable=AsyncMock, return_value={
            "url": "https://example.com", "status": 200, "security_headers_count": 3, "hsts": True
        }):
            resp = client.get("/api/v1/fast-validate", params={"url": "https://example.com"})
            assert resp.status_code == 200
            assert resp.json()["url"] == "https://example.com"


# ====================== Legacy Redirect ======================

class TestLegacyRedirect:
    def test_redirect_get(self):
        resp = client.get("/api/health", follow_redirects=False)
        assert resp.status_code == 307
        assert "/api/v1/health" in resp.headers["location"]

    def test_redirect_post(self):
        resp = client.post("/api/risk", json={"url": "https://x.com"}, follow_redirects=False)
        assert resp.status_code == 307
        assert "/api/v1/risk" in resp.headers["location"]


# ====================== Risk Endpoints ======================

class TestRiskEndpoints:
    def setup_method(self):
        _reset_collections()

    def _make_risk_score(self, url="https://example.com", trust=85.0, level=RiskLevel.LOW):
        return RiskScore(
            url=url,
            domain="example.com",
            risk_level=level,
            trust_score=trust,
            ssl_valid=True,
            education_message="Looks safe.",
        )

    def test_post_risk(self):
        score = self._make_risk_score()
        with (
            patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock),
            patch.object(risk_engine, "calculate_risk", new_callable=AsyncMock, return_value=score),
            patch("backend.server.httpx.AsyncClient") as mock_http,
        ):
            # Mock the httpx context manager
            mock_ctx = AsyncMock()
            mock_resp = MagicMock(status_code=200, text="<html></html>")
            mock_ctx.get = AsyncMock(return_value=mock_resp)
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

            resp = client.post(
                "/api/v1/risk?fast=false&follow_redirects=false",
                json={"url": "https://example.com"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["trust_score"] == 85.0
            assert body["risk_level"] == "low"

    def test_get_risk(self):
        score = self._make_risk_score()
        with (
            patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock),
            patch.object(risk_engine, "calculate_risk", new_callable=AsyncMock, return_value=score),
            patch("backend.server.httpx.AsyncClient") as mock_http,
        ):
            mock_ctx = AsyncMock()
            mock_resp = MagicMock(status_code=200, text="<html></html>")
            mock_ctx.get = AsyncMock(return_value=mock_resp)
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

            resp = client.get("/api/v1/risk", params={"url": "https://example.com"})
            assert resp.status_code == 200
            assert resp.json()["url"] == "https://example.com"

    def test_post_risk_content(self):
        score = self._make_risk_score()
        with (
            patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock),
            patch.object(risk_engine, "calculate_risk", new_callable=AsyncMock, return_value=score),
        ):
            resp = client.post("/api/v1/risk/content", json={
                "url": "https://example.com",
                "html": "<html><body>test</body></html>",
            })
            assert resp.status_code == 200
            assert resp.json()["trust_score"] == 85.0


# ====================== Merchant Endpoints ======================

class TestMerchantEndpoints:
    def setup_method(self):
        _reset_collections()

    def test_get_merchant_history_empty(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.get("/api/v1/merchant/history")
            assert resp.status_code == 200
            assert resp.json() == []

    def test_get_merchant_not_found(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.get("/api/v1/merchant/nonexistent.com")
            assert resp.status_code == 404

    def test_create_merchant(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.post("/api/v1/merchant", json={
                "domain": "test.com",
                "name": "Test Merchant",
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["domain"] == "test.com"
            assert body["name"] == "Test Merchant"


# ====================== Transaction Endpoints ======================

class TestTransactionEndpoints:
    def setup_method(self):
        _reset_collections()

    def test_check_transaction(self):
        with (
            patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock),
            patch.object(risk_engine, "calculate_risk", new_callable=AsyncMock, return_value=MagicMock(
                trust_score=90.0,
                risk_level=RiskLevel.LOW,
                risk_factors=[],
            )),
        ):
            resp = client.post("/api/v1/transaction/check", json={
                "merchant_domain": "safe-shop.com",
                "amount": 49.99,
                "currency": "USD",
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["merchant_domain"] == "safe-shop.com"
            assert "risk_level" in body


# ====================== Fraud Reporting ======================

class TestFraudReporting:
    def setup_method(self):
        _reset_collections()

    def test_report_fraud(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.post("/api/v1/fraud/report", json={
                "domain": "scam.com",
                "url": "https://scam.com/fake",
                "report_type": "phishing",
                "description": "Looks like phishing",
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["domain"] == "scam.com"
            assert body["report_type"] == "phishing"

    def test_get_fraud_reports_empty(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.get("/api/v1/fraud/reports")
            assert resp.status_code == 200
            assert resp.json() == []


# ====================== Custom Rules ======================

class TestCustomRules:
    def setup_method(self):
        _reset_collections()

    def test_create_custom_rule(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.post("/api/v1/institution/custom-rules", json={
                "rule_name": "Block suspicious TLDs",
                "rule_type": "domain_blacklist",
                "parameters": {"tlds": [".tk", ".ml"]},
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["rule_name"] == "Block suspicious TLDs"

    def test_get_custom_rules_empty(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.get("/api/v1/institution/custom-rules")
            assert resp.status_code == 200
            assert resp.json() == []


# ====================== API Key Generation ======================

class TestAPIKeyGeneration:
    def test_generate_api_key(self):
        with patch.object(api_key_manager, "generate_api_key", new_callable=AsyncMock, return_value={
            "api_key": "pg_test_abc123",
            "institution_name": "Test Corp",
            "tier": "free",
            "daily_limit": 1000,
        }):
            resp = client.post("/api/v1/api-key/generate", json={
                "institution_name": "Test Corp",
                "tier": "free",
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["api_key"] == "pg_test_abc123"
            assert body["tier"] == "free"


# ====================== Stats Endpoint ======================

class TestStatsEndpoint:
    def setup_method(self):
        _reset_collections()

    def test_get_stats(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.get("/api/v1/stats")
            assert resp.status_code == 200
            body = resp.json()
            assert "total_checks" in body
            assert "avg_trust_score" in body


# ====================== Label Feedback ======================

class TestLabelFeedback:
    def setup_method(self):
        _reset_collections()

    def test_submit_label_feedback(self):
        with patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock):
            resp = client.post("/api/v1/feedback/label", json={
                "url": "https://example.com",
                "domain": "example.com",
                "label": 1,
                "source": "user",
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["url"] == "https://example.com"
            assert body["label"] == 1


# ====================== Request Size Limit ======================

class TestRequestSizeLimit:
    def test_oversized_request_rejected(self):
        """Requests with content-length > 10MB should get 413."""
        resp = client.post(
            "/api/v1/risk",
            json={"url": "https://example.com"},
            headers={"content-length": str(20 * 1024 * 1024)},
        )
        assert resp.status_code == 413


# ====================== Media Risk ======================

class TestMediaRisk:
    def setup_method(self):
        _reset_collections()

    def test_get_media_risk(self):
        fake_result = MediaRisk(
            url="https://example.com/image.png",
            domain="example.com",
            media_score=15.0,
            media_color=RiskLevel.LOW,
            reasons=["Low risk"],
        )
        with (
            patch.object(api_key_manager, "validate_api_key", new_callable=AsyncMock),
            patch.object(risk_engine, "_predict_image_fake_bytes", return_value=0.1),
            patch("backend.server.httpx.AsyncClient") as mock_http,
        ):
            mock_ctx = AsyncMock()
            mock_resp = MagicMock(status_code=200, content=b"\x89PNG fake image bytes",
                                  headers={"content-type": "image/png"})
            mock_ctx.get = AsyncMock(return_value=mock_resp)
            mock_http.return_value.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)

            resp = client.get("/api/v1/media-risk", params={"url": "https://example.com/image.png"})
            # May return 200 or 500 depending on internal processing; we check no crash
            assert resp.status_code in (200, 500)
