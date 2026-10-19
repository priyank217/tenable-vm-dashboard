"""Parse Nessus plugin 10863 (SSL Certificate Information) plugin_output."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Common Nessus / OpenSSL date forms, e.g. "Apr 12 12:48:49 2018 GMT"
_DATE_FORMATS = (
    "%b %d %H:%M:%S %Y %Z",
    "%b %d %H:%M:%S %Y",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)

_SUBJECT_RE = re.compile(
    r"(?im)^\s*(?:Subject|subject)\s*[:=]\s*(.+?)\s*$"
)
_ISSUER_RE = re.compile(
    r"(?im)^\s*(?:Issuer|issuer)\s*[:=]\s*(.+?)\s*$"
)
_NOT_BEFORE_RE = re.compile(
    r"(?im)^\s*(?:Not\s+valid\s+before|Not\s+Before|notBefore|Valid\s+From)"
    r"\s*[:=]?\s*(.+?)\s*$"
)
_NOT_AFTER_RE = re.compile(
    r"(?im)^\s*(?:Not\s+valid\s+after|Not\s+After|notAfter|Valid\s+(?:Until|To)|Expires)"
    r"\s*[:=]?\s*(.+?)\s*$"
)
_CN_RE = re.compile(r"(?i)(?:^|/|,)\s*CN\s*=\s*([^,/]+)")


def _parse_date(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    text = re.sub(r"\s+", " ", text)
    if text.endswith("Z") and "T" in text and len(text) == 20:
        text = text[:-1] + "+0000"
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text or "")
    return match.group(1).strip() if match else ""


def _cn_or_value(value: str) -> str:
    if not value:
        return ""
    cn = _CN_RE.search(value)
    return cn.group(1).strip() if cn else value.strip()


def days_remaining(valid_to: datetime | None, *, now: datetime | None = None) -> int | None:
    if valid_to is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    delta = valid_to - current.astimezone(timezone.utc)
    return int(delta.total_seconds() // 86400)


def cert_status(days: int | None) -> str:
    if days is None:
        return "unknown"
    if days < 0:
        return "expired"
    if days <= 30:
        return "expiring"
    return "valid"


def parse_plugin_output(output: str, *, now: datetime | None = None) -> dict[str, Any]:
    text = output or ""
    subject = _first_match(_SUBJECT_RE, text)
    issuer = _first_match(_ISSUER_RE, text)
    valid_from_dt = _parse_date(_first_match(_NOT_BEFORE_RE, text))
    valid_to_dt = _parse_date(_first_match(_NOT_AFTER_RE, text))
    remaining = days_remaining(valid_to_dt, now=now)
    return {
        "subject": subject,
        "subject_cn": _cn_or_value(subject),
        "issuer": issuer,
        "issuer_cn": _cn_or_value(issuer),
        "valid_from": valid_from_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if valid_from_dt else None,
        "valid_to": valid_to_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if valid_to_dt else None,
        "days_remaining": remaining,
        "status": cert_status(remaining),
    }


def map_ssl_cert_row(raw: dict, *, synced_at: str, now: datetime | None = None) -> dict | None:
    finding_id = raw.get("finding_id")
    if not finding_id:
        return None

    plugin = raw.get("plugin") or {}
    asset = raw.get("asset") or {}
    port_info = raw.get("port") or {}
    plugin_id = plugin.get("id")
    asset_uuid = asset.get("uuid")
    if plugin_id is None or not asset_uuid:
        return None

    output = str(raw.get("output") or plugin.get("plugin_output") or "")
    parsed = parse_plugin_output(output, now=now)

    hostname = ""
    for key in ("hostname", "fqdn", "netbios_name"):
        value = asset.get(key)
        if value:
            hostname = str(value)
            break

    port_val = port_info.get("port")
    try:
        port = int(port_val) if port_val is not None else None
    except (TypeError, ValueError):
        port = None

    return {
        "finding_id": str(finding_id),
        "asset_uuid": str(asset_uuid),
        "hostname": hostname,
        "ipv4": str(asset.get("ipv4") or ""),
        "port": port,
        "protocol": str(port_info.get("protocol") or "").upper() or None,
        "subject": parsed["subject"],
        "subject_cn": parsed["subject_cn"],
        "issuer": parsed["issuer"],
        "issuer_cn": parsed["issuer_cn"],
        "valid_from": parsed["valid_from"],
        "valid_to": parsed["valid_to"],
        "days_remaining": parsed["days_remaining"],
        "status": parsed["status"],
        "plugin_output": output,
        "first_found": str(raw.get("first_found") or raw.get("first_seen") or "") or None,
        "last_found": str(raw.get("last_found") or raw.get("last_seen") or "") or None,
        "synced_at": synced_at,
    }
