"""
Lumin Index metrics — Tenable-aligned monthly remediation flow with frozen months.

Definitions (Tenable Vulnerability States / Findings Filters / Lumin Metrics):
  Active          state OPEN or REOPENED (UI: New, Active, Resurfaced)
  Backlog start   Active at 00:00 UTC on the 1st, Risk Modified = NONE, VPR >= 0.1
  New             First Seen in month
  Resurfaced      Resurfaced Date in month
  Fixed           Last Fixed in month (the fix event, regardless of current state)
  Backlog end     start + new + resurfaced - fixed   (must equal next month's start)
  Coverage %      fixed / (start + new + resurfaced)              (Lumin "coverage")
  Days to fix     Tenable time_taken_to_fix, median, split Crit/High vs Med/Low
                                                                  (Lumin "responsiveness")
  SLA date        Resurfaced Date if REOPENED else First Seen     (Tenable "Vuln SLA Date")

"As of the 1st" is resolved from finding_history when the history baseline predates the
1st (method=frozen); otherwise from live timestamps (method=reconstructed). Closed months
are written once to monthly_snapshot and locked; they never recompute.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

from services.recast_rules_service import get_recast_rules_index
from services.vuln_db import get_connection, init_db, latest_synced_at
from utils.recast_metrics import recast_accept_by_plugin
from utils.vpr_tiers import VPR_MIN, vpr_tier, vpr_tier_sql

SCOPE_ALL = "all"
CLOSED_MONTHS = 6

SLA_DAYS = {"critical": 14, "high": 30}

_BASE = f"""
    UPPER(COALESCE(severity_modification_type, 'NONE')) = 'NONE'
    AND vpr_score >= {VPR_MIN}
"""

_VPR_TIER = vpr_tier_sql("vpr_score")

_ACTIVE_NOW = f"""
    {_BASE}
    AND state IN ('OPEN', 'REOPENED')
    AND missing_since IS NULL
"""

# SLA clock: Tenable resets it on resurface.
_SLA_DATE = """
    CASE
      WHEN state = 'REOPENED' AND resurfaced_date IS NOT NULL AND resurfaced_date <> ''
        THEN resurfaced_date
      ELSE first_found
    END
"""


# ─────────────────────────── time helpers ───────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc) if month == 12 else datetime(
        year, month + 1, 1, tzinfo=timezone.utc
    )
    return start, end


def _shift_month(year: int, month: int, delta: int) -> tuple[int, int]:
    idx = year * 12 + (month - 1) + delta
    return idx // 12, idx % 12 + 1


def _ym(year: int, month: int) -> str:
    return f"{year:04d}-{month:02d}"


def _pct(num: float, den: float) -> float | None:
    if not den:
        return None
    return round(num / den * 100.0, 1)


def _scope(asset_uuids: frozenset[str] | None, column: str = "asset_uuid") -> tuple[str, tuple]:
    if asset_uuids is None:
        return "", ()
    if not asset_uuids:
        return " AND 1=0", ()
    marks = ",".join("?" * len(asset_uuids))
    return f" AND {column} IN ({marks})", tuple(asset_uuids)


def _count(conn, sql: str, params: tuple) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0] or 0)


# ─────────────────────────── as-of resolution ───────────────────────────


def _history_baseline(conn) -> str | None:
    row = conn.execute("SELECT MIN(synced_at) AS b FROM finding_history").fetchone()
    return row["b"] if row and row["b"] else None


def _history_covers(conn, at_iso: str) -> bool:
    baseline = _history_baseline(conn)
    return bool(baseline) and baseline <= at_iso


def _active_as_of_history(conn, at_iso: str, asset_uuids) -> int:
    clause, params = _scope(asset_uuids, "x.asset_uuid")
    return _count(
        conn,
        f"""
        SELECT COUNT(*) FROM (
            SELECT h.finding_id, h.state, h.vpr_score, h.severity_modification_type,
                   h.missing_since, h.asset_uuid, h.first_found
            FROM finding_history h
            JOIN (
                SELECT finding_id, MAX(synced_at) AS s
                FROM finding_history
                WHERE synced_at <= ?
                GROUP BY finding_id
            ) m ON m.finding_id = h.finding_id AND m.s = h.synced_at
        ) x
        WHERE x.state IN ('OPEN', 'REOPENED')
          AND UPPER(COALESCE(x.severity_modification_type, 'NONE')) = 'NONE'
          AND x.vpr_score >= 0.1
          AND x.missing_since IS NULL
          AND (x.first_found IS NULL OR x.first_found < ?)
          {clause}
        """,
        (at_iso, at_iso) + params,
    )


def _active_as_of_reconstructed(conn, at_iso: str, asset_uuids) -> int:
    clause, params = _scope(asset_uuids)
    return _count(
        conn,
        f"""
        SELECT COUNT(*) FROM vulnerabilities
        WHERE {_BASE}
          AND first_found < ?
          AND (
                state = 'OPEN'
             OR (state = 'REOPENED' AND (
                    (resurfaced_date IS NOT NULL AND resurfaced_date <> '' AND resurfaced_date < ?)
                    OR last_fixed IS NULL OR last_fixed = '' OR last_fixed >= ?
                ))
             OR (state = 'FIXED'
                 AND last_fixed >= ?
                 AND (resurfaced_date IS NULL OR resurfaced_date = '' OR resurfaced_date < ?))
          )
          {clause}
        """,
        (at_iso, at_iso, at_iso, at_iso, at_iso) + params,
    )


def _active_as_of(conn, at_iso: str, asset_uuids) -> tuple[int, str]:
    if _history_covers(conn, at_iso):
        return _active_as_of_history(conn, at_iso, asset_uuids), "frozen"
    return _active_as_of_reconstructed(conn, at_iso, asset_uuids), "reconstructed"


# ─────────────────────────── monthly flow ───────────────────────────


def _median(values: list[float]) -> float | None:
    values = [v for v in values if v is not None]
    if not values:
        return None
    return round(statistics.median(values), 1)


def _percentile(values: list[float], p: float) -> float | None:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return round(vals[0], 1)
    rank = (p / 100.0) * (len(vals) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(vals) - 1)
    frac = rank - lo
    return round(vals[lo] * (1 - frac) + vals[hi] * frac, 1)


def _sla_limit_for_vpr(vpr: float) -> int:
    return SLA_DAYS["critical"] if vpr >= 9.0 else SLA_DAYS["high"]


def _fix_time_insights(conn, asset_uuids) -> dict:
    now = _now()
    year, month = _shift_month(now.year, now.month, -1)
    ym = _ym(year, month)
    window_start, window_end = _month_bounds(year, month)
    start_iso, end_iso = _iso(window_start), _iso(window_end)
    clause, params = _scope(asset_uuids)
    scoped = asset_uuids is not None

    snap = None if scoped else _read_snapshot(conn, ym, SCOPE_ALL)
    frozen = bool(snap and snap.get("locked") and snap.get("median_days_to_fix_crit_high") is not None)

    rows = conn.execute(
        f"""
        SELECT plugin_id, plugin_name, hostname, asset_fqdn, ipv4,
               vpr_score, days_to_fix, last_fixed
        FROM vulnerabilities
        WHERE {_BASE}
          AND last_fixed >= ? AND last_fixed < ?
          AND days_to_fix IS NOT NULL
          AND vpr_score >= 7.0
          {clause}
        """,
        (start_iso, end_iso) + params,
    ).fetchall()

    live_days: list[float] = []
    live_within = 0
    live_over = 0
    live_immediate = 0
    by_plugin: dict[str, dict] = {}

    for r in rows:
        days = float(r["days_to_fix"])
        vpr = float(r["vpr_score"] or 0)
        limit = _sla_limit_for_vpr(vpr)
        host = r["hostname"] or r["asset_fqdn"] or "—"
        ipv4 = r["ipv4"] or ""
        live_days.append(days)
        if days <= 1:
            live_immediate += 1
        if days <= limit:
            live_within += 1
        else:
            live_over += 1

        pid = str(r["plugin_id"] or "")
        if not pid:
            continue
        bucket = by_plugin.get(pid)
        if not bucket:
            bucket = {
                "plugin_id": pid,
                "plugin_name": r["plugin_name"] or "",
                "days": [],
                "hosts_map": {},
            }
            by_plugin[pid] = bucket
        bucket["days"].append(round(days, 1))
        if not bucket["plugin_name"] and r["plugin_name"]:
            bucket["plugin_name"] = r["plugin_name"]

        host_key = f"{host}|{ipv4}"
        asset = bucket["hosts_map"].get(host_key)
        if not asset:
            asset = {"hostname": host, "ipv4": ipv4, "days": []}
            bucket["hosts_map"][host_key] = asset
        asset["days"].append(round(days, 1))

    live_median = _median(live_days)
    if frozen:
        month_median = float(snap["median_days_to_fix_crit_high"])
        total = int(snap.get("crit_high_fixed") or 0)
        within_sla = int(snap.get("crit_high_within_sla") or 0)
        over_sla = max(total - within_sla, 0)
        median_source = "frozen"
    else:
        month_median = live_median
        total = len(live_days)
        within_sla = live_within
        over_sla = live_over
        median_source = "live"

    plugin_rows = []
    for bucket in by_plugin.values():
        d = bucket["days"]
        plugin_median = _median(d)
        vs = None
        if month_median is not None and plugin_median is not None:
            if plugin_median < month_median:
                vs = "before"
            elif plugin_median > month_median:
                vs = "after"
            else:
                vs = "at"
        hosts = []
        for asset in bucket["hosts_map"].values():
            hosts.append({
                "hostname": asset["hostname"],
                "ipv4": asset["ipv4"],
                "days_to_fix": _median(asset["days"]),
                "finding_count": len(asset["days"]),
            })
        hosts.sort(
            key=lambda a: (
                -(a["days_to_fix"] if a["days_to_fix"] is not None else -1),
                (a["hostname"] or "").lower(),
            )
        )
        plugin_rows.append({
            "plugin_id": bucket["plugin_id"],
            "plugin_name": bucket["plugin_name"] or "—",
            "fixed_count": len(d),
            "host_count": len(hosts),
            "median_days": plugin_median,
            "vs_month_median": vs,
            "hosts": hosts,
        })

    plugins_before = sorted(
        [r for r in plugin_rows if r["vs_month_median"] == "before"],
        key=lambda r: (
            r["median_days"] if r["median_days"] is not None else 1e9,
            -r["fixed_count"],
        ),
    )
    plugins_after = sorted(
        [r for r in plugin_rows if r["vs_month_median"] == "after"],
        key=lambda r: (
            -(r["median_days"] if r["median_days"] is not None else -1),
            -r["fixed_count"],
        ),
    )

    return {
        "month": ym,
        "window_start": start_iso,
        "window_end": end_iso,
        "scope": "critical_high",
        "median_source": median_source,
        "month_median_days": month_median,
        "live_median_days": live_median,
        "live_fixed_count": len(live_days),
        "distribution": {
            "total": total,
            "immediate": live_immediate if not frozen else None,
            "immediate_pct": _pct(live_immediate, len(live_days)) if not frozen else None,
            "within_sla": within_sla,
            "within_sla_pct": _pct(within_sla, total),
            "over_sla": over_sla,
            "over_sla_pct": _pct(over_sla, total),
            "median_days": month_median,
            "p95_days": _percentile(live_days, 95),
            "max_days": round(max(live_days), 1) if live_days else None,
            "min_days": round(min(live_days), 1) if live_days else None,
        },
        "plugins_before_median": plugins_before,
        "plugins_after_median": plugins_after,
        "plugins_before_count": len(plugins_before),
        "plugins_after_count": len(plugins_after),
    }


def _month_flows(conn, start_iso: str, end_iso: str, asset_uuids) -> dict:
    clause, params = _scope(asset_uuids)

    new = _count(
        conn,
        f"SELECT COUNT(*) FROM vulnerabilities WHERE {_BASE} AND first_found >= ? AND first_found < ? {clause}",
        (start_iso, end_iso) + params,
    )
    resurfaced = _count(
        conn,
        f"""SELECT COUNT(*) FROM vulnerabilities WHERE {_BASE}
            AND resurfaced_date >= ? AND resurfaced_date < ? {clause}""",
        (start_iso, end_iso) + params,
    )
    fixed = _count(
        conn,
        f"SELECT COUNT(*) FROM vulnerabilities WHERE {_BASE} AND last_fixed >= ? AND last_fixed < ? {clause}",
        (start_iso, end_iso) + params,
    )
    cleared = _count(
        conn,
        f"""SELECT COUNT(*) FROM vulnerabilities WHERE {_BASE}
            AND last_fixed >= ? AND last_fixed < ? AND first_found < ? {clause}""",
        (start_iso, end_iso, start_iso) + params,
    )

    rows = conn.execute(
        f"""
        SELECT vpr_score, days_to_fix FROM vulnerabilities
        WHERE {_BASE} AND last_fixed >= ? AND last_fixed < ?
          AND days_to_fix IS NOT NULL {clause}
        """,
        (start_iso, end_iso) + params,
    ).fetchall()

    crit_high_days: list[float] = []
    med_low_days: list[float] = []
    crit_high_fixed = 0
    within_sla = 0
    for r in rows:
        vpr = float(r["vpr_score"] or 0)
        days = float(r["days_to_fix"])
        if vpr >= 7.0:
            crit_high_days.append(days)
            crit_high_fixed += 1
            limit = SLA_DAYS["critical"] if vpr >= 9.0 else SLA_DAYS["high"]
            if days <= limit:
                within_sla += 1
        else:
            med_low_days.append(days)

    return {
        "new_findings": new,
        "resurfaced": resurfaced,
        "fixed": fixed,
        "backlog_cleared": cleared,
        "median_days_to_fix_crit_high": _median(crit_high_days),
        "median_days_to_fix_med_low": _median(med_low_days),
        "crit_high_fixed": crit_high_fixed,
        "crit_high_within_sla": within_sla,
        "sla_attainment_pct": _pct(within_sla, crit_high_fixed),
    }


def _compute_month(
    conn, year: int, month: int, asset_uuids, *, backlog_start_override: int | None = None,
    method_override: str | None = None,
) -> dict:
    start, end = _month_bounds(year, month)
    start_iso, end_iso = _iso(start), _iso(end)
    now_iso = _iso(_now())

    if backlog_start_override is not None:
        backlog_start, method = backlog_start_override, (method_override or "frozen")
    else:
        backlog_start, method = _active_as_of(conn, start_iso, asset_uuids)

    flows = _month_flows(conn, start_iso, end_iso, asset_uuids)
    workload = backlog_start + flows["new_findings"] + flows["resurfaced"]
    backlog_end = workload - flows["fixed"]

    observed = None
    if end_iso <= now_iso:
        observed, _ = _active_as_of(conn, end_iso, asset_uuids)

    end_for_rate = observed if observed is not None else backlog_end
    resolved = workload - end_for_rate

    return {
        "month": _ym(year, month),
        "backlog_start": backlog_start,
        **flows,
        "workload": workload,
        "backlog_end": backlog_end,
        "backlog_end_observed": observed,
        "flow_gap": (observed - backlog_end) if observed is not None else None,
        "coverage_pct": _pct(flows["fixed"], workload),
        "resolved_pct": _pct(max(resolved, 0), workload),
        "net_change": end_for_rate - backlog_start,
        "backlog_cleared_pct": _pct(flows["backlog_cleared"], backlog_start),
        "method": method,
        "computed_at": now_iso,
    }


# ─────────────────────────── snapshots ───────────────────────────

_SNAPSHOT_COLS = (
    "month", "scope_key", "backlog_start", "new_findings", "resurfaced", "fixed",
    "workload", "backlog_end", "backlog_end_observed", "flow_gap", "backlog_cleared",
    "coverage_pct", "resolved_pct", "net_change",
    "backlog_cleared_pct", "median_days_to_fix_crit_high", "median_days_to_fix_med_low",
    "sla_attainment_pct", "crit_high_fixed", "crit_high_within_sla", "method",
    "computed_at", "locked",
)


def _write_snapshot(conn, row: dict, *, scope_key: str, locked: bool) -> None:
    payload = {c: row.get(c) for c in _SNAPSHOT_COLS}
    payload["scope_key"] = scope_key
    payload["locked"] = 1 if locked else 0
    cols = ", ".join(_SNAPSHOT_COLS)
    marks = ", ".join(f":{c}" for c in _SNAPSHOT_COLS)
    conn.execute(
        f"INSERT OR REPLACE INTO monthly_snapshot ({cols}) VALUES ({marks})", payload
    )


def _read_snapshot(conn, ym: str, scope_key: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM monthly_snapshot WHERE month = ? AND scope_key = ?", (ym, scope_key)
    ).fetchone()
    return dict(row) if row else None


def refresh_monthly_snapshots(*, scope_key: str = SCOPE_ALL) -> dict:
    init_db()
    now = _now()
    written, skipped = [], []
    with get_connection() as conn:
        for k in range(CLOSED_MONTHS, 0, -1):
            y, m = _shift_month(now.year, now.month, -k)
            ym = _ym(y, m)
            existing = _read_snapshot(conn, ym, scope_key)
            if existing and existing.get("locked"):
                skipped.append(ym)
                continue
            override = existing["backlog_start"] if existing else None
            method = existing["method"] if existing else None
            row = _compute_month(
                conn, y, m, None, backlog_start_override=override, method_override=method
            )
            _write_snapshot(conn, row, scope_key=scope_key, locked=True)
            written.append(ym)

        ym = _ym(now.year, now.month)
        if not _read_snapshot(conn, ym, scope_key):
            row = _compute_month(conn, now.year, now.month, None)
            _write_snapshot(conn, row, scope_key=scope_key, locked=False)
            written.append(ym)
        conn.commit()
    return {"scope": scope_key, "written": written, "locked_skipped": skipped}


# ─────────────────────────── current-state KPIs ───────────────────────────


def _now_kpis(conn, asset_uuids) -> dict:
    clause, params = _scope(asset_uuids)
    now = _now()
    crit_cutoff = _iso(now - timedelta(days=SLA_DAYS["critical"]))
    high_cutoff = _iso(now - timedelta(days=SLA_DAYS["high"]))

    row = conn.execute(
        f"""
        SELECT
          COUNT(*) AS active,
          SUM(CASE WHEN {_VPR_TIER} = 'critical' THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN {_VPR_TIER} = 'high' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN {_VPR_TIER} = 'medium' THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN {_VPR_TIER} = 'low' THEN 1 ELSE 0 END) AS low,
          SUM(CASE WHEN {_VPR_TIER} = 'critical' AND {_SLA_DATE} < ? THEN 1 ELSE 0 END) AS sla_crit,
          SUM(CASE WHEN {_VPR_TIER} = 'high' AND {_SLA_DATE} < ? THEN 1 ELSE 0 END) AS sla_high,
          SUM(CASE WHEN state = 'REOPENED' THEN 1 ELSE 0 END) AS resurfaced_active,
          SUM(CASE WHEN LOWER(COALESCE(exploit_maturity,'')) IN ('functional','high') THEN 1 ELSE 0 END) AS weaponized
        FROM vulnerabilities
        WHERE {_ACTIVE_NOW} {clause}
        """,
        (crit_cutoff, high_cutoff) + params,
    ).fetchone()

    return {
        "active": int(row["active"] or 0),
        "critical": int(row["critical"] or 0),
        "high": int(row["high"] or 0),
        "medium": int(row["medium"] or 0),
        "low": int(row["low"] or 0),
        "critical_high": int(row["critical"] or 0) + int(row["high"] or 0),
        "sla_breach_critical": int(row["sla_crit"] or 0),
        "sla_breach_high": int(row["sla_high"] or 0),
        "resurfaced_active": int(row["resurfaced_active"] or 0),
        "weaponized": int(row["weaponized"] or 0),
    }


def _top_assets(conn, asset_uuids, limit: int = 5) -> list[dict]:
    clause, params = _scope(asset_uuids)
    rows = conn.execute(
        f"""
        SELECT
          COALESCE(hostname, '') AS hostname,
          MAX(COALESCE(ipv4, '')) AS ipv4,
          SUM(CASE WHEN {_VPR_TIER} = 'critical' THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN {_VPR_TIER} = 'high' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN {_VPR_TIER} = 'medium' THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN {_VPR_TIER} = 'low' THEN 1 ELSE 0 END) AS low,
          MAX(vpr_score) AS max_vpr,
          SUM(vpr_score) AS vpr_sum,
          COUNT(*) AS total
        FROM vulnerabilities
        WHERE {_ACTIVE_NOW} {clause}
        GROUP BY hostname, asset_uuid
        ORDER BY vpr_sum DESC, critical DESC, high DESC
        LIMIT ?
        """,
        params + (limit,),
    ).fetchall()
    return [
        {
            "hostname": r["hostname"],
            "ipv4": r["ipv4"],
            "critical": int(r["critical"] or 0),
            "high": int(r["high"] or 0),
            "medium": int(r["medium"] or 0),
            "low": int(r["low"] or 0),
            "vpr_score": round(float(r["max_vpr"] or 0), 1),
            "total_vulns": int(r["total"] or 0),
        }
        for r in rows
    ]


def _list_mtd_new_findings(
    conn, start_iso: str, end_iso: str, asset_uuids
) -> list[dict]:
    clause, params = _scope(asset_uuids)
    rows = conn.execute(
        f"""
        SELECT
          finding_id,
          plugin_id,
          plugin_name,
          hostname,
          ipv4,
          state,
          vpr_score,
          first_found,
          last_found
        FROM vulnerabilities
        WHERE {_BASE}
          AND first_found >= ? AND first_found < ?
          {clause}
        ORDER BY vpr_score DESC, first_found DESC, hostname COLLATE NOCASE
        """,
        (start_iso, end_iso) + params,
    ).fetchall()
    results = []
    for r in rows:
        score = float(r["vpr_score"]) if r["vpr_score"] is not None else None
        results.append({
            "finding_id": r["finding_id"] or "",
            "plugin_id": str(r["plugin_id"] or ""),
            "plugin_name": r["plugin_name"] or "—",
            "hostname": r["hostname"] or "",
            "ipv4": r["ipv4"] or "",
            "state": r["state"] or "",
            "vpr_score": round(score, 1) if score is not None else None,
            "vpr_tier": vpr_tier(score) or "low",
            "first_found": r["first_found"] or "",
            "last_found": r["last_found"] or "",
        })
    return results


# ─────────────────────────── public entry point ───────────────────────────


def compute_lumin_metrics(
    *, asset_uuids: frozenset[str] | None = None, tag_filter: dict | None = None
) -> dict:
    init_db()
    now = _now()
    scoped = asset_uuids is not None
    scope_key = SCOPE_ALL if not scoped else "scoped"

    with get_connection() as conn:
        kpis = _now_kpis(conn, asset_uuids)

        closed: list[dict] = []
        for k in range(CLOSED_MONTHS, 0, -1):
            y, m = _shift_month(now.year, now.month, -k)
            ym = _ym(y, m)
            snap = _read_snapshot(conn, ym, SCOPE_ALL) if not scoped else None
            if snap and snap.get("locked"):
                closed.append(snap)
            else:
                row = _compute_month(conn, y, m, asset_uuids)
                if scoped:
                    row["method"] = "live"
                closed.append(row)

        cur_ym = _ym(now.year, now.month)
        cur_snap = _read_snapshot(conn, cur_ym, SCOPE_ALL) if not scoped else None
        mtd = _compute_month(
            conn, now.year, now.month, asset_uuids,
            backlog_start_override=cur_snap["backlog_start"] if cur_snap else None,
            method_override=cur_snap["method"] if cur_snap else None,
        )
        if scoped:
            mtd["method"] = "live"
        mtd["active_now"] = kpis["active"]
        mtd["days_elapsed"] = now.day
        mtd["provisional"] = True

        start, end = _month_bounds(now.year, now.month)
        mtd["new_findings_rows"] = _list_mtd_new_findings(
            conn, _iso(start), _iso(end), asset_uuids
        )

        last_closed = closed[-1] if closed else None
        last_end = last_closed["backlog_end"] if last_closed else None

        top_assets = _top_assets(conn, asset_uuids)
        fix_time = _fix_time_insights(conn, asset_uuids)
        rules_index = get_recast_rules_index()
        clause, params = _scope(asset_uuids)
        recast = recast_accept_by_plugin(conn, clause, params, rules_index)

    reconciliation = []
    for prev, nxt in zip(closed, closed[1:]):
        if prev.get("backlog_end") is not None and nxt.get("backlog_start") is not None:
            reconciliation.append({
                "from": prev["month"],
                "to": nxt["month"],
                "end": prev["backlog_end"],
                "next_start": nxt["backlog_start"],
                "delta": nxt["backlog_start"] - prev["backlog_end"],
            })

    return {
        "generated_at": latest_synced_at() or _iso(now),
        "computed_at": _iso(now),
        "methodology": "lumin_index_frozen_months",
        "scope_key": scope_key,
        "tag_filter": tag_filter,
        "scoped_asset_count": len(asset_uuids) if scoped else None,
        "now": {
            **kpis,
            "last_month_end": last_end,
            "change_vs_last_month_end": (kpis["active"] - last_end) if last_end is not None else None,
        },
        "closed_months": closed,
        "month_to_date": mtd,
        "reconciliation": reconciliation,
        "top_risky_assets": top_assets,
        "fix_time_insights": fix_time,
        "recast_accept_risks": recast,
    }
