"""Server health summary helpers for the reboot dashboard."""

from __future__ import annotations

from typing import Any


def compute_server_health_summary(servers: list[dict]) -> dict[str, Any]:
    counts = {
        "total": len(servers),
        "healthy": 0,
        "attention": 0,
        "warning": 0,
        "critical": 0,
        "unknown": 0,
        "linux": 0,
        "windows": 0,
    }
    for row in servers:
        status = (row.get("status") or "unknown").lower()
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1
        os_family = (row.get("os_family") or "").lower()
        if os_family == "linux":
            counts["linux"] += 1
        elif os_family == "windows":
            counts["windows"] += 1

    total = counts["total"] or 0

    def pct(n: int) -> float | None:
        if not total:
            return None
        return round(n / total * 100.0, 1)

    return {
        **counts,
        "pct": {
            "healthy": pct(counts["healthy"]),
            "attention": pct(counts["attention"]),
            "warning": pct(counts["warning"]),
            "critical": pct(counts["critical"]),
        },
    }


def servers_for_api(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        out.append({
            "id": row.get("finding_id") or row.get("asset_uuid"),
            "assetUuid": row.get("asset_uuid") or "",
            "hostname": row.get("hostname") or "—",
            "ip": row.get("ipv4") or "—",
            "os": (row.get("os_family") or "unknown").lower(),
            "osName": row.get("os_name") or "",
            "daysSinceReboot": row.get("days_since_reboot"),
            "lastReboot": row.get("last_reboot"),
            "status": (row.get("status") or "unknown").lower(),
            "tenablePlugin": row.get("plugin_id"),
            "pluginOutput": row.get("plugin_output") or "",
            "firstFound": row.get("first_found"),
            "lastFound": row.get("last_found"),
        })
    return out
