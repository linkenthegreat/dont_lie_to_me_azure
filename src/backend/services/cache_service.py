"""Azure Cache for Redis service for caching analysis results."""

import json
import logging
import hashlib
from typing import Optional

logger = logging.getLogger(__name__)


class CacheService:
    """Wrapper around Azure Cache for Redis."""

    def __init__(self, connection_string: str, default_ttl: int = 3600):
        import redis

        self._client = redis.Redis.from_url(connection_string, decode_responses=True)
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[dict]:
        """Get cached result by key."""
        try:
            data = self._client.get(key)
            if data:
                return json.loads(data)
        except Exception as exc:
            logger.warning("Cache GET failed for key %s: %s", key, exc)
        return None

    def set(self, key: str, value: dict, ttl: Optional[int] = None) -> None:
        """Set cache entry with TTL."""
        try:
            self._client.setex(
                key,
                ttl or self._default_ttl,
                json.dumps(value, default=str),
            )
        except Exception as exc:
            logger.warning("Cache SET failed for key %s: %s", key, exc)

    def delete(self, key: str) -> None:
        """Delete cache entry."""
        try:
            self._client.delete(key)
        except Exception as exc:
            logger.warning("Cache DELETE failed for key %s: %s", key, exc)

    @staticmethod
    def make_key(prefix: str, text: str) -> str:
        """Create a cache key from prefix and text content."""
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        return f"{prefix}:{text_hash}"

    def health_check(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self._client.ping()
        except Exception:
            return False


_instance: Optional[CacheService] = None


def get_cache_service() -> Optional[CacheService]:
    """Lazy singleton accessor. Returns None if Redis not configured."""
    global _instance
    if _instance is None:
        import os

        conn_str = os.environ.get("AZURE_REDIS_CONNECTION_STRING", "")
        if conn_str:
            try:
                _instance = CacheService(conn_str)
            except Exception as exc:
                logger.warning("Failed to initialize Redis cache: %s", exc)
    return _instance
