"""Aggregate SSL certificate health metrics for stakeholder view."""

from __future__ import annotations

from typing import Any

from utils.asset_normalizer import SOURCE_LABELS


def _format_sources(sources_raw: list[str]) -> str:
    labels = []
    for name in sources_raw or []:
        if not name:
            continue
        labels.append(SOURCE_LABELS.get(name, str(name).replace("_", " ")))
    return ", ".join(labels) if labels else "—"


def enrich_certificates_with_assets(
    certs: list[dict], assets: list[dict]
) -> list[dict]:
    by_id = {a.get("id") or a.get("uuid"): a for a in assets if a.get("id") or a.get("uuid")}
    enriched = []
    for cert in certs:
        asset = by_id.get(cert.get("asset_uuid")) or {}
        sources_raw = list(asset.get("sourcesRaw") or [])
        sources = asset.get("sources") or _format_sources(sources_raw)
        internet_facing = "NESSUS_SCAN" in sources_raw
        name = (
            cert.get("hostname")
            or asset.get("name")
            or asset.get("hostname")
            or cert.get("ipv4")
            or "—"
        )
        ipv4 = cert.get("ipv4") or asset.get("ipAddress") or asset.get("ipv4") or "—"
        if isinstance(ipv4, list):
            ipv4 = ipv4[0] if ipv4 else "—"

        days = cert.get("days_remaining")
        status = cert.get("status") or "unknown"
        enriched.append({
            **cert,
            "assetName": name,
            "ipAddress": ipv4,
            "sources": sources,
            "sourcesRaw": sources_raw,
            "internetFacing": internet_facing,
            "daysRemaining": days,
            "status": status,
        })
    return enriched


def compute_ssl_cert_summary(certs: list[dict]) -> dict[str, Any]:
    total = len(certs)
    valid = 0
    expiring_30 = 0
    expiring_7 = 0
    expired = 0
    unknown = 0
    timeline_8_30 = 0
    timeline_31_90 = 0

    internet = 0
    internet_valid = 0
    internet_expiring = 0
    internet_expired = 0

    for cert in certs:
        days = cert.get("daysRemaining")
        if days is None:
            days = cert.get("days_remaining")
        status = cert.get("status") or "unknown"
        internet_facing = bool(cert.get("internetFacing"))

        if status == "expired" or (isinstance(days, int) and days < 0):
            expired += 1
            if internet_facing:
                internet_expired += 1
        elif status == "expiring" or (isinstance(days, int) and 0 <= days <= 30):
            expiring_30 += 1
            if isinstance(days, int) and days <= 7:
                expiring_7 += 1
            if isinstance(days, int) and 8 <= days <= 30:
                timeline_8_30 += 1
            if internet_facing:
                internet_expiring += 1
        elif status == "valid" or (isinstance(days, int) and days > 30):
            valid += 1
            if isinstance(days, int) and 31 <= days <= 90:
                timeline_31_90 += 1
            if internet_facing:
                internet_valid += 1
        else:
            unknown += 1

        if internet_facing:
            internet += 1

    def pct(n: int) -> float:
        return round((n / total) * 100, 1) if total else 0.0

    return {
        "total": total,
        "valid": valid,
        "expiring30": expiring_30,
        "expiring7": expiring_7,
        "expired": expired,
        "unknown": unknown,
        "validPct": pct(valid),
        "expiringPct": pct(expiring_30),
        "expiredPct": pct(expired),
        "internetFacing": internet,
        "internet": {
            "total": internet,
            "valid": internet_valid,
            "expiring": internet_expiring,
            "expired": internet_expired,
        },
        "timeline": {
            "expired": expired,
            "next7": expiring_7,
            "days8to30": timeline_8_30,
            "days31to90": timeline_31_90,
        },
    }
