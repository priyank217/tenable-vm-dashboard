"""Recast & Accept risk aggregations shared by the Lumin dashboard."""

from services.recast_rules_service import lookup_rule_dates

_RISK_MODIFIED_WHERE = """
    UPPER(severity_modification_type) IN ('ACCEPTED', 'RECASTED')
    AND vpr_score >= 0.1
    AND state IN ('OPEN', 'REOPENED')
"""


def _format_iso_date(value: str | None) -> str:
    if not value:
        return "—"
    try:
        from datetime import datetime

        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return value[:10] if len(value) >= 10 else value


def recast_accept_by_plugin(
    conn, asset_clause: str, asset_params: tuple, rules_index: dict
) -> list[dict]:
    rows = conn.execute(
        f"""
        SELECT
            plugin_id,
            plugin_name,
            severity_modification_type,
            recast_rule_uuid,
            asset_uuid,
            hostname,
            ipv4
        FROM vulnerabilities
        WHERE {_RISK_MODIFIED_WHERE}
          {asset_clause}
        """,
        asset_params,
    ).fetchall()

    groups: dict[tuple, dict] = {}
    for row in rows:
        mod_type = (row["severity_modification_type"] or "").upper()
        key = (str(row["plugin_id"]), mod_type)
        group = groups.get(key)
        if group is None:
            group = {
                "plugin_id": str(row["plugin_id"]),
                "plugin_name": row["plugin_name"] or "—",
                "modification_type": mod_type,
                "recast_rule_uuid": row["recast_rule_uuid"] or "",
                "finding_count": 0,
                "assets_map": {},
            }
            groups[key] = group

        group["finding_count"] += 1
        if row["plugin_name"]:
            group["plugin_name"] = row["plugin_name"]
        if row["recast_rule_uuid"] and not group["recast_rule_uuid"]:
            group["recast_rule_uuid"] = row["recast_rule_uuid"]

        asset_uuid = str(row["asset_uuid"] or "")
        if not asset_uuid:
            continue
        asset = group["assets_map"].get(asset_uuid)
        if asset is None:
            asset = {
                "asset_uuid": asset_uuid,
                "hostname": row["hostname"] or "",
                "ipv4": row["ipv4"] or "",
                "finding_count": 0,
            }
            group["assets_map"][asset_uuid] = asset
        asset["finding_count"] += 1
        if row["hostname"]:
            asset["hostname"] = row["hostname"]
        if row["ipv4"]:
            asset["ipv4"] = row["ipv4"]

    ranked = sorted(
        groups.values(),
        key=lambda g: (-int(g["finding_count"]), g["plugin_id"]),
    )[:50]

    results = []
    for group in ranked:
        mod_type = group["modification_type"]
        risk_label, created_at, expires_at = lookup_rule_dates(
            rule_id=group["recast_rule_uuid"] or None,
            plugin_id=group["plugin_id"],
            modification_type=mod_type,
            rules_index=rules_index,
        )
        assets = sorted(
            group["assets_map"].values(),
            key=lambda a: (-int(a["finding_count"]), (a["hostname"] or "").lower()),
        )
        results.append({
            "plugin_id": group["plugin_id"],
            "plugin_name": group["plugin_name"] or "—",
            "risk_type": risk_label,
            "modification_type": mod_type,
            "asset_count": len(assets),
            "finding_count": int(group["finding_count"] or 0),
            "created_at": created_at,
            "expires_at": expires_at,
            "created_at_display": _format_iso_date(created_at),
            "expires_at_display": _format_iso_date(expires_at)
            if expires_at
            else "Never",
            "assets": assets,
        })
    return results
