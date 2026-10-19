"""Thread-safe in-memory TTL cache for list payloads (assets, tags, etc.)."""

import threading
from datetime import datetime, timedelta, timezone


class TtlCache:

    def __init__(self, ttl_sec: int):
        self._ttl = max(0, ttl_sec)
        self._lock = threading.Lock()
        self._fetch_lock = threading.Lock()
        self._entry = None

    def _is_expired(self, fetched_at: datetime) -> bool:
        if self._ttl == 0:
            return True
        return datetime.now(timezone.utc) >= fetched_at + timedelta(seconds=self._ttl)

    def get(self, *, include_expired: bool = False) -> dict | None:
        with self._lock:
            if not self._entry:
                return None
            expired = self._is_expired(self._entry["fetched_at"])
            if expired and not include_expired:
                self._entry = None
                return None
            return self._build_response(cached=True)

    def set(self, items: list, last_sync: str) -> dict:
        fetched_at = datetime.now(timezone.utc)
        expires_at = fetched_at + timedelta(seconds=self._ttl) if self._ttl else fetched_at
        with self._lock:
            self._entry = {
                "assets": items,
                "lastSync": last_sync,
                "count": len(items),
                "fetched_at": fetched_at,
                "cacheExpiresAt": expires_at.isoformat(),
            }
            return self._build_response(cached=False)

    def invalidate(self) -> None:
        with self._lock:
            self._entry = None

    def fetch_lock(self):
        return self._fetch_lock

    def _build_response(self, cached: bool) -> dict:
        entry = self._entry
        return {
            "assets": entry["assets"],
            "lastSync": entry["lastSync"],
            "count": entry["count"],
            "cached": cached,
            "cacheExpiresAt": entry["cacheExpiresAt"],
        }


# Backward-compatible alias (older name implied assets-only use).
AssetCache = TtlCache
