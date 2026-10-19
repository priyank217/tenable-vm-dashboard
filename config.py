"""
Application settings loaded from `.env` next to this file.

Keep names and defaults in sync with `.env.example`.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_BASE_DIR = Path(__file__).resolve().parent
load_dotenv(_BASE_DIR / ".env")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, default: str = "false") -> bool:
    return _env(name, default).lower() in ("1", "true", "yes")


def _env_int(name: str, default: str) -> int:
    return int(_env(name, default))


def _env_float(name: str, default: str) -> float:
    return float(_env(name, default))


def _env_csv(name: str, default: str) -> tuple[str, ...]:
    values = tuple(
        part.strip().upper()
        for part in _env(name, default).split(",")
        if part.strip()
    )
    return values


# ── Tenable API ──────────────────────────────────────────────────────────────
TENABLE_ACCESS_KEY = _env("TENABLE_ACCESS_KEY")
TENABLE_SECRET_KEY = _env("TENABLE_SECRET_KEY")
TENABLE_BASE_URL = _env("TENABLE_BASE_URL", "https://cloud.tenable.com").rstrip("/")

# ── Server ───────────────────────────────────────────────────────────────────
PORT = _env_int("PORT", "7200")

# ── Cache ────────────────────────────────────────────────────────────────────
CACHE_TTL_SEC = _env_int("CACHE_TTL_SEC", "7200")

# ── Asset export ─────────────────────────────────────────────────────────────
INCLUDE_OPEN_PORTS = _env_bool("INCLUDE_OPEN_PORTS", "true")
CHUNK_SIZE = 1000
POLL_INTERVAL_SEC = 5
POLL_MAX_ATTEMPTS = 120
EXPORT_FILTERS: dict = {}

# ── Vulnerability sync / export ──────────────────────────────────────────────
VULN_EXPORT_NUM_ASSETS = _env_int("VULN_EXPORT_NUM_ASSETS", "500")
VULN_EXPORT_INCLUDE_UNLICENSED = _env_bool("VULN_EXPORT_INCLUDE_UNLICENSED", "true")
VULN_SYNC_POLL_INTERVAL_SEC = _env_int("VULN_SYNC_POLL_INTERVAL_SEC", "60")
VULN_SYNC_POLL_MAX_ATTEMPTS = _env_int("VULN_SYNC_POLL_MAX_ATTEMPTS", "20")
VULN_FULL_SYNC_SINCE = _env_int("VULN_FULL_SYNC_SINCE", "0")
VULN_EXPORT_SEVERITY_MODIFICATION_TYPES = _env_csv(
    "VULN_EXPORT_SEVERITY_MODIFICATION_TYPES",
    "NONE,RECASTED,ACCEPTED",
) or ("NONE", "RECASTED", "ACCEPTED")

# ── Storage ──────────────────────────────────────────────────────────────────
VULN_DB_PATH = _env("VULN_DB_PATH", str(_BASE_DIR / "vulnerabilities.db"))
VULN_RAW_JSON_DIR = _env("VULN_RAW_JSON_DIR", str(_BASE_DIR / "data" / "vuln_raw"))

# ── HTTP / download ──────────────────────────────────────────────────────────
CHUNK_DOWNLOAD_TIMEOUT_SEC = _env_int("CHUNK_DOWNLOAD_TIMEOUT_SEC", "600")
CHUNK_DOWNLOAD_DELAY_SEC = _env_float("CHUNK_DOWNLOAD_DELAY_SEC", "1")
API_RETRY_MAX_ATTEMPTS = _env_int("API_RETRY_MAX_ATTEMPTS", "5")
API_RETRY_BACKOFF_SEC = _env_float("API_RETRY_BACKOFF_SEC", "2")
