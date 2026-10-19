"""Parse Tenable last-reboot plugins into server health rows.

Plugins (Tenable):
  56468 — Time of Last System Startup (Unix / Linux)
  92366 — Microsoft Windows Last Boot Time (ISO 8601)
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

LINUX_PLUGIN_ID = 56468
WINDOWS_PLUGIN_ID = 92366
SERVER_HEALTH_PLUGIN_IDS = (LINUX_PLUGIN_ID, WINDOWS_PLUGIN_ID)

_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S %Z %Y",
    "%b %d %H:%M:%S %Y",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d",
)

# Prefer labeled lines, then fall back to any ISO-like token in the output.
_LABELED_RE = re.compile(
    r"(?im)^\s*(?:Last\s+(?:boot|reboot|startup)|"
    r"System\s+(?:boot|startup|start)|"
    r"Boot\s+time|"
    r"The\s+system\s+has\s+been\s+(?:up\s+)?since|"
    r"Host\s+was\s+last\s+(?:booted|rebooted|started))\s*[:=]?\s*(.+?)\s*$"
)
_ISO_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
_UPTIME_SINCE_RE = re.compile(
    r"(?i)(?:up\s+since|last\s+boot(?:ed)?|started(?:\s+at)?)\s*[:=]?\s*(.+)$"
)
# Plugin 56468: output of `last reboot` / `last -x reboot` (no year on boot lines).
_LINUX_LAST_REBOOT_RE = re.compile(
    r"reboot\s+system\s+boot\s+.+\s+"
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(\d{1,2})\s+"
    r"(\d{1,2}:\d{2})"
    r"(?:\s+still running|\s+-|\s*$)",
    re.IGNORECASE,
)
def _parse_date(raw: str) -> datetime | None:
    text = (raw or "").strip().strip(".")
    if not text:
        return None
    text = re.sub(r"\s+", " ", text)
    if text.endswith("Z") and "T" in text:
        candidate = text[:-1] + "+0000"
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
            try:
                return datetime.strptime(candidate, fmt).astimezone(timezone.utc)
            except ValueError:
                continue
    no_colon_tz = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
    for candidate in (text, no_colon_tz):
        for fmt in _DATE_FORMATS:
            try:
                dt = datetime.strptime(candidate, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    return None


def _infer_year_for_last_reboot(month: int, day: int, *, ref: datetime) -> int:
    ref = ref.astimezone(timezone.utc)
    for year in (ref.year, ref.year - 1):
        try:
            candidate = datetime(year, month, day, tzinfo=timezone.utc)
        except ValueError:
            continue
        if candidate <= ref + timedelta(days=1):
            return year
    return ref.year


def _parse_linux_last_reboot(text: str, *, now: datetime | None = None) -> datetime | None:
    if not text or "reboot" not in text.lower() or "system boot" not in text.lower():
        return None
    ref = now or datetime.now(timezone.utc)

    still = None
    first = None
    for match in _LINUX_LAST_REBOOT_RE.finditer(text):
        if first is None:
            first = match
        if "still running" in match.group(0).lower():
            still = match
            break
    match = still or first
    if not match:
        return None

    weekday, mon, day_s, time_s = match.group(1, 2, 3, 4)
    del weekday
    try:
        month = datetime.strptime(mon, "%b").month
        day = int(day_s)
        hour, minute = (int(x) for x in time_s.split(":", 1))
    except (ValueError, TypeError):
        return None
    year = _infer_year_for_last_reboot(month, day, ref=ref)
    try:
        return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_last_reboot(output: str, *, now: datetime | None = None) -> datetime | None:
    text = output or ""
    linux_dt = _parse_linux_last_reboot(text, now=now)
    if linux_dt:
        return linux_dt
    for pattern in (_LABELED_RE, _UPTIME_SINCE_RE):
        match = pattern.search(text)
        if match:
            dt = _parse_date(match.group(1))
            if dt:
                return dt
    iso = _ISO_RE.search(text)
    if iso:
        dt = _parse_date(iso.group(1))
        if dt:
            return dt
    return _parse_date(text.strip().splitlines()[0] if text.strip() else "")


def days_since_reboot(last_reboot: datetime | None, *, now: datetime | None = None) -> float | None:
    if last_reboot is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    delta = current.astimezone(timezone.utc) - last_reboot.astimezone(timezone.utc)
    days = delta.total_seconds() / 86400.0
    return round(max(0.0, days), 1)


def reboot_status(days: float | None) -> str:
    if days is None:
        return "unknown"
    if days < 1:
        return "healthy"
    if days < 21:
        return "attention"
    if days <= 30:
        return "warning"
    return "critical"


def os_family_for_plugin(plugin_id: int | str | None) -> str:
    try:
        pid = int(plugin_id)
    except (TypeError, ValueError):
        return "unknown"
    if pid == LINUX_PLUGIN_ID:
        return "linux"
    if pid == WINDOWS_PLUGIN_ID:
        return "windows"
    return "unknown"


def _asset_hostname(asset: dict) -> str:
    for key in ("hostname", "fqdn", "netbios_name"):
        value = asset.get(key)
        if value:
            return str(value)
    return ""


def _asset_os_name(asset: dict) -> str:
    os_list = asset.get("operating_system") or []
    if isinstance(os_list, list) and os_list:
        return str(os_list[0])
    if isinstance(os_list, str) and os_list.strip():
        return os_list.strip()
    return ""


def map_server_health_row(
    raw: dict, *, synced_at: str, now: datetime | None = None
) -> dict | None:
    finding_id = raw.get("finding_id")
    if not finding_id:
        return None

    plugin = raw.get("plugin") or {}
    asset = raw.get("asset") or {}
    plugin_id = plugin.get("id")
    asset_uuid = asset.get("uuid")
    if plugin_id is None or not asset_uuid:
        return None

    try:
        plugin_id_int = int(plugin_id)
    except (TypeError, ValueError):
        return None

    if plugin_id_int not in SERVER_HEALTH_PLUGIN_IDS:
        return None

    output = str(raw.get("output") or plugin.get("plugin_output") or "")
    last_reboot_dt = parse_last_reboot(output, now=now)
    days = days_since_reboot(last_reboot_dt, now=now)
    os_family = os_family_for_plugin(plugin_id_int)
    os_name = _asset_os_name(asset)
    if not os_name:
        os_name = "Linux" if os_family == "linux" else "Windows" if os_family == "windows" else ""

    return {
        "finding_id": str(finding_id),
        "asset_uuid": str(asset_uuid),
        "hostname": _asset_hostname(asset),
        "ipv4": str(asset.get("ipv4") or ""),
        "os_family": os_family,
        "os_name": os_name,
        "plugin_id": plugin_id_int,
        "last_reboot": (
            last_reboot_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if last_reboot_dt else None
        ),
        "days_since_reboot": days,
        "status": reboot_status(days),
        "plugin_output": output,
        "first_found": str(raw.get("first_found") or raw.get("first_seen") or "") or None,
        "last_found": str(raw.get("last_found") or raw.get("last_seen") or "") or None,
        "synced_at": synced_at,
    }
