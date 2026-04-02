import hashlib
import logging
import os
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
admin_token_header = APIKeyHeader(name="X-Admin-Token", auto_error=False)

# Per-minute rate limits by tier
_MINUTE_LIMITS: Dict[str, int] = {
    "free": 60,
    "premium": 300,
    "enterprise": 1000,
}

# Optional Redis for persistent rate limiting
_redis_client = None


def _init_redis() -> Optional[object]:
    """Lazily connect to Redis if REDIS_URL is set. Returns None if unavailable."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return None
    try:
        import redis

        _redis_client = redis.from_url(redis_url, decode_responses=True)
        _redis_client.ping()
        logger.info("Redis connected for persistent rate limiting")
        return _redis_client
    except Exception as e:
        logger.warning(
            f"Redis unavailable, falling back to in-memory rate limiting: {e}"
        )
        _redis_client = None
        return None


class APIKeyManager:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        # In-memory per-minute tracking (fallback when Redis is unavailable)
        self._minute_log: Dict[str, List[datetime]] = defaultdict(list)

    async def generate_api_key(self, institution_name: str, tier: str = "free") -> dict:
        """Generate a new API key for an institution"""
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        daily_limits = {"free": 1000, "premium": 10000, "enterprise": 100000}

        api_key_doc = {
            "key_hash": key_hash,
            "institution_name": institution_name,
            "tier": tier,
            "requests_count": 0,
            "daily_limit": daily_limits.get(tier, 1000),
            "created_at": datetime.now(timezone.utc),
            "is_active": True,
            "last_reset": datetime.now(timezone.utc),
        }

        await self.db.api_keys.insert_one(api_key_doc)

        return {
            "api_key": raw_key,
            "institution_name": institution_name,
            "tier": tier,
            "daily_limit": api_key_doc["daily_limit"],
        }

    def _check_minute_limit(self, key_hash: str, tier: str) -> None:
        """Check per-minute rate limit. Uses Redis if available, else in-memory."""
        limit = _MINUTE_LIMITS.get(tier, _MINUTE_LIMITS["free"])

        r = _init_redis()
        if r is not None:
            # Redis-based: use a sliding window counter
            redis_key = f"payguard:ratelimit:{key_hash}"
            try:
                current = r.incr(redis_key)
                if current == 1:
                    r.expire(redis_key, 60)
                if current > limit:
                    raise HTTPException(
                        status_code=429,
                        detail=f"Rate limit exceeded: {limit} requests per minute",
                        headers={"Retry-After": "60"},
                    )
                return
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(
                    f"Redis rate limit check failed, falling back to in-memory: {e}"
                )

        # In-memory fallback
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=1)
        self._minute_log[key_hash] = [
            t for t in self._minute_log[key_hash] if t > cutoff
        ]
        if len(self._minute_log[key_hash]) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {limit} requests per minute",
                headers={"Retry-After": "60"},
            )
        self._minute_log[key_hash].append(now)

    async def validate_api_key(self, api_key: str) -> dict:
        """Validate API key and check rate limits"""
        if not api_key:
            raise HTTPException(status_code=401, detail="API key required")

        # Allow demo key for testing
        if api_key == "demo_key":
            allow_demo = os.environ.get("PAYGUARD_ALLOW_DEMO_KEY", "false").lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if allow_demo:
                return {"tier": "free", "is_active": True}
            raise HTTPException(status_code=401, detail="Invalid API key")

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        api_key_doc = await self.db.api_keys.find_one({"key_hash": key_hash})

        if not api_key_doc:
            raise HTTPException(status_code=401, detail="Invalid API key")

        if not api_key_doc.get("is_active"):
            raise HTTPException(status_code=401, detail="API key is inactive")

        tier = api_key_doc.get("tier", "free")

        # Per-minute rate limit
        self._check_minute_limit(key_hash, tier)

        # Check if we need to reset daily counter
        last_reset = api_key_doc.get("last_reset", datetime.now(timezone.utc))
        if last_reset.tzinfo is None:
            last_reset = last_reset.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - last_reset > timedelta(days=1):
            await self.db.api_keys.update_one(
                {"key_hash": key_hash},
                {
                    "$set": {
                        "requests_count": 0,
                        "last_reset": datetime.now(timezone.utc),
                    }
                },
            )
            api_key_doc["requests_count"] = 0

        # Check daily rate limit
        if api_key_doc["requests_count"] >= api_key_doc["daily_limit"]:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Daily limit: {api_key_doc['daily_limit']}",
                headers={"Retry-After": "3600"},
            )

        # Increment request count
        await self.db.api_keys.update_one(
            {"key_hash": key_hash}, {"$inc": {"requests_count": 1}}
        )

        return api_key_doc


async def get_api_key(api_key: str = Security(api_key_header)):
    """Dependency for API key validation - returns the raw key string (may be None)."""
    return api_key


async def require_api_key(api_key: str = Security(api_key_header)):
    """Dependency that *requires* a valid API key header. Raises 401 if missing."""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key


async def require_admin_token(admin_token: str = Security(admin_token_header)):
    """Dependency that requires a valid admin token for privileged endpoints."""
    expected = os.environ.get("PAYGUARD_API_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin token is not configured",
        )
    if not admin_token or not secrets.compare_digest(admin_token, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid admin token",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return admin_token
