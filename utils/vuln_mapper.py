from datetime import datetime, timezone

from utils.vuln_raw_storage import save_finding_raw


def _iso(value) -> str | None:
    if value is None:
        return None
    return str(value)


def _vpr_score(raw: dict) -> float | None:
    plugin = raw.get("plugin") or {}
    for key in ("vpr", "vpr_v2"):
        block = plugin.get(key) or {}
        score = block.get("score")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    return None


def _exploit_maturity(raw: dict) -> str:
    value = raw.get("exploit_maturity")
    if value:
        return str(value).lower()
    plugin = raw.get("plugin") or {}
    for key in ("vpr", "vpr_v2"):
        drivers = (plugin.get(key) or {}).get("drivers") or {}
        maturity = drivers.get("exploit_code_maturity")
        if maturity:
            return str(maturity).lower()
    return ""


def _days_to_fix(raw: dict) -> float | None:
    raw_seconds = raw.get("time_taken_to_fix")
    if raw_seconds is not None:
        try:
            seconds = float(raw_seconds)
            if seconds > 0:
                return round(seconds / 86400.0, 2)
        except (TypeError, ValueError):
            pass
    return None


def _asset_hostname(asset: dict) -> str:
    for key in ("hostname", "fqdn", "netbios_name"):
        value = asset.get(key)
        if value:
            return str(value)
    return ""


def map_vulnerability_row(raw: dict, *, sync_date: str) -> dict | None:
    finding_id = raw.get("finding_id")
    if not finding_id:
        return None

    plugin = raw.get("plugin") or {}
    asset = raw.get("asset") or {}
    plugin_id = plugin.get("id")
    asset_uuid = asset.get("uuid")
    if plugin_id is None or not asset_uuid:
        return None

    synced_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_json_filename = save_finding_raw(raw, sync_date)

    return {
        "finding_id": str(finding_id),
        "plugin_id": str(plugin_id),
        "asset_uuid": str(asset_uuid),
        "severity": (raw.get("severity") or "info").lower(),
        "state": (raw.get("state") or "OPEN").upper(),
        "first_found": _iso(raw.get("first_found") or raw.get("first_seen")),
        "last_found": _iso(raw.get("last_found") or raw.get("last_seen")),
        "last_fixed": _iso(raw.get("last_fixed")),
        "resurfaced_date": _iso(raw.get("resurfaced_date")),
        "vpr_score": _vpr_score(raw),
        "exploit_maturity": _exploit_maturity(raw),
        "hostname": _asset_hostname(asset),
        "ipv4": str(asset.get("ipv4") or ""),
        "severity_modification_type": (raw.get("severity_modification_type") or "NONE").upper(),
        "recast_rule_uuid": str(raw.get("recast_rule_uuid") or ""),
        "source": str(raw.get("source") or ""),
        "plugin_name": str(plugin.get("name") or ""),
        "asset_fqdn": str(asset.get("fqdn") or ""),
        "days_to_fix": _days_to_fix(raw),
        "synced_at": synced_at,
        "raw_json_filename": raw_json_filename,
    }
