import sqlite3
import threading
from pathlib import Path

from config import VULN_DB_PATH

_lock = threading.Lock()
_initialized = False

REPORTABLE_SEVERITIES = ("critical", "high", "medium", "low")

_VULNERABILITIES_DDL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    finding_id TEXT PRIMARY KEY,
    plugin_id TEXT,
    asset_uuid TEXT,
    severity TEXT,
    state TEXT,
    first_found TEXT,
    last_found TEXT,
    last_fixed TEXT,
    resurfaced_date TEXT,
    vpr_score REAL,
    exploit_maturity TEXT,
    hostname TEXT,
    ipv4 TEXT,
    severity_modification_type TEXT,
    recast_rule_uuid TEXT,
    source TEXT,
    plugin_name TEXT,
    asset_fqdn TEXT,
    days_to_fix REAL,
    synced_at TEXT NOT NULL,
    raw_json_filename TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_state ON vulnerabilities(state);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_first_found ON vulnerabilities(first_found);
CREATE INDEX IF NOT EXISTS idx_vulns_last_fixed ON vulnerabilities(last_fixed);
CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_uuid);
"""

# Append-only, change-only history. One row per finding per sync in which a
# tracked field changed. Powers "as of the 1st" reconstruction for the Lumin tab.
_HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS finding_history (
    finding_id TEXT NOT NULL,
    synced_at TEXT NOT NULL,
    state TEXT,
    first_found TEXT,
    last_fixed TEXT,
    resurfaced_date TEXT,
    vpr_score REAL,
    severity_modification_type TEXT,
    recast_rule_uuid TEXT,
    asset_uuid TEXT,
    plugin_id TEXT,
    missing_since TEXT,
    PRIMARY KEY (finding_id, synced_at)
);

CREATE INDEX IF NOT EXISTS idx_hist_synced ON finding_history(synced_at);
CREATE INDEX IF NOT EXISTS idx_hist_finding_synced
    ON finding_history(finding_id, synced_at DESC);

CREATE TABLE IF NOT EXISTS monthly_snapshot (
    month TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    backlog_start INTEGER,
    new_findings INTEGER,
    resurfaced INTEGER,
    fixed INTEGER,
    workload INTEGER,
    backlog_end INTEGER,
    backlog_end_observed INTEGER,
    flow_gap INTEGER,
    backlog_cleared INTEGER,
    coverage_pct REAL,
    resolved_pct REAL,
    net_change INTEGER,
    backlog_cleared_pct REAL,
    median_days_to_fix_crit_high REAL,
    median_days_to_fix_med_low REAL,
    sla_attainment_pct REAL,
    crit_high_fixed INTEGER,
    crit_high_within_sla INTEGER,
    method TEXT,
    computed_at TEXT,
    locked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (month, scope_key)
);
"""

# Fields whose change produces a new history row.
HISTORY_TRACKED_FIELDS = (
    "state",
    "first_found",
    "last_fixed",
    "resurfaced_date",
    "vpr_score",
    "severity_modification_type",
    "recast_rule_uuid",
    "missing_since",
)


def _db_path() -> Path:
    path = Path(VULN_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migrate_add_resurfaced_date(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
    }
    if "vulnerabilities" not in {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }:
        return
    if "resurfaced_date" in cols:
        return
    conn.execute("ALTER TABLE vulnerabilities ADD COLUMN resurfaced_date TEXT")


def _migrate_drop_raw_json_column(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
    }
    if "vulnerabilities" not in {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }:
        return
    if "raw_json" not in cols:
        return

    conn.executescript(
        """
        CREATE TABLE vulnerabilities_new (
            finding_id TEXT PRIMARY KEY,
            plugin_id TEXT,
            asset_uuid TEXT,
            severity TEXT,
            state TEXT,
            first_found TEXT,
            last_found TEXT,
            last_fixed TEXT,
            resurfaced_date TEXT,
            vpr_score REAL,
            exploit_maturity TEXT,
            hostname TEXT,
            ipv4 TEXT,
            severity_modification_type TEXT,
            source TEXT,
            plugin_name TEXT,
            asset_fqdn TEXT,
            days_to_fix REAL,
            synced_at TEXT NOT NULL,
            raw_json_filename TEXT
        );
        INSERT INTO vulnerabilities_new (
            finding_id, plugin_id, asset_uuid, severity, state,
            first_found, last_found, last_fixed, resurfaced_date, vpr_score,
            exploit_maturity, hostname, ipv4, severity_modification_type, source,
            plugin_name, asset_fqdn, days_to_fix, synced_at, raw_json_filename
        )
        SELECT
            finding_id, plugin_id, asset_uuid, severity, state,
            first_found, last_found, last_fixed,
            NULL AS resurfaced_date,
            vpr_score, exploit_maturity, hostname, ipv4,
            severity_modification_type, source, plugin_name, asset_fqdn,
            days_to_fix, synced_at, raw_json_filename
        FROM vulnerabilities;
        DROP TABLE vulnerabilities;
        ALTER TABLE vulnerabilities_new RENAME TO vulnerabilities;
        """
    )
    _ensure_indexes(conn)


def _migrate_add_recast_rule_uuid(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
    }
    if "recast_rule_uuid" not in cols:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN recast_rule_uuid TEXT")


def _migrate_add_missing_since(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
    }
    if "missing_since" not in cols:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN missing_since TEXT")


def _migrate_snapshot_columns(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(monthly_snapshot)").fetchall()
    }
    for name, typ in (
        ("flow_gap", "INTEGER"),
        ("workload", "INTEGER"),
        ("resolved_pct", "REAL"),
        ("net_change", "INTEGER"),
    ):
        if name not in cols:
            conn.execute(f"ALTER TABLE monthly_snapshot ADD COLUMN {name} {typ}")


def _seed_history_baseline(conn: sqlite3.Connection) -> int:
    has_history = conn.execute("SELECT 1 FROM finding_history LIMIT 1").fetchone()
    if has_history:
        return 0
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO finding_history (
            finding_id, synced_at, state, first_found, last_fixed, resurfaced_date,
            vpr_score, severity_modification_type, recast_rule_uuid,
            asset_uuid, plugin_id, missing_since
        )
        SELECT
            finding_id, synced_at, state, first_found, last_fixed, resurfaced_date,
            vpr_score, severity_modification_type, recast_rule_uuid,
            asset_uuid, plugin_id, missing_since
        FROM vulnerabilities
        """
    )
    return cur.rowcount or 0


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    for stmt in (
        "CREATE INDEX IF NOT EXISTS idx_vulns_state ON vulnerabilities(state)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_first_found ON vulnerabilities(first_found)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_last_fixed ON vulnerabilities(last_fixed)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_resurfaced ON vulnerabilities(resurfaced_date)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_uuid)",
        "CREATE INDEX IF NOT EXISTS idx_vulns_sev_mod ON vulnerabilities(severity_modification_type)",
    ):
        conn.execute(stmt)


def init_db() -> None:
    global _initialized
    with _lock:
        if _initialized:
            return
        with get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_status (
                    id INTEGER PRIMARY KEY,
                    last_sync INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.executescript(_VULNERABILITIES_DDL)
            _migrate_add_resurfaced_date(conn)
            _migrate_add_recast_rule_uuid(conn)
            _migrate_drop_raw_json_column(conn)
            _migrate_add_missing_since(conn)
            _ensure_indexes(conn)
            conn.executescript(_HISTORY_DDL)
            _migrate_snapshot_columns(conn)
            _seed_history_baseline(conn)
            conn.execute(
                """
                INSERT INTO sync_status (id, last_sync)
                VALUES (1, 0)
                ON CONFLICT(id) DO NOTHING
                """
            )
            conn.commit()
        _initialized = True


def get_last_sync() -> int:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_sync FROM sync_status WHERE id = 1"
        ).fetchone()
        return int(row["last_sync"] or 0) if row else 0


def set_last_sync(timestamp: int) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute(
            "UPDATE sync_status SET last_sync = ? WHERE id = 1",
            (timestamp,),
        )
        conn.commit()


def count_vulnerabilities() -> int:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM vulnerabilities").fetchone()
        return int(row["cnt"] or 0)


def _history_signature(row) -> tuple:
    def norm(value):
        if value is None or value == "":
            return None
        if isinstance(value, float):
            return round(value, 2)
        return str(value)

    return tuple(norm(row[field]) for field in HISTORY_TRACKED_FIELDS)


def _append_history(conn: sqlite3.Connection, rows: list[dict]) -> int:
    if not rows:
        return 0
    ids = [r["finding_id"] for r in rows]
    placeholders = ",".join("?" * len(ids))
    existing = {
        r["finding_id"]: r
        for r in conn.execute(
            f"""
            SELECT finding_id, state, first_found, last_fixed, resurfaced_date,
                   vpr_score, severity_modification_type, recast_rule_uuid, missing_since
            FROM vulnerabilities WHERE finding_id IN ({placeholders})
            """,
            ids,
        ).fetchall()
    }
    with_history = {
        r["finding_id"]
        for r in conn.execute(
            f"SELECT DISTINCT finding_id FROM finding_history WHERE finding_id IN ({placeholders})",
            ids,
        ).fetchall()
    }

    to_insert = []
    for row in rows:
        fid = row["finding_id"]
        prev = existing.get(fid)
        changed = (
            prev is None
            or fid not in with_history
            or _history_signature(prev) != _history_signature(row)
        )
        if not changed:
            continue
        to_insert.append({
            "finding_id": fid,
            "synced_at": row["synced_at"],
            "state": row.get("state"),
            "first_found": row.get("first_found"),
            "last_fixed": row.get("last_fixed"),
            "resurfaced_date": row.get("resurfaced_date"),
            "vpr_score": row.get("vpr_score"),
            "severity_modification_type": row.get("severity_modification_type"),
            "recast_rule_uuid": row.get("recast_rule_uuid"),
            "asset_uuid": row.get("asset_uuid"),
            "plugin_id": row.get("plugin_id"),
            "missing_since": row.get("missing_since"),
        })

    if to_insert:
        conn.executemany(
            """
            INSERT OR REPLACE INTO finding_history (
                finding_id, synced_at, state, first_found, last_fixed, resurfaced_date,
                vpr_score, severity_modification_type, recast_rule_uuid,
                asset_uuid, plugin_id, missing_since
            ) VALUES (
                :finding_id, :synced_at, :state, :first_found, :last_fixed, :resurfaced_date,
                :vpr_score, :severity_modification_type, :recast_rule_uuid,
                :asset_uuid, :plugin_id, :missing_since
            )
            """,
            to_insert,
        )
    return len(to_insert)


def upsert_vulnerabilities(rows: list[dict]) -> int:
    if not rows:
        return 0
    init_db()
    for row in rows:
        row.setdefault("missing_since", None)
    sql = """
        INSERT INTO vulnerabilities (
            finding_id, plugin_id, asset_uuid, severity, state,
            first_found, last_found, last_fixed, resurfaced_date, vpr_score,
            exploit_maturity, hostname, ipv4, severity_modification_type, recast_rule_uuid, source,
            plugin_name, asset_fqdn, days_to_fix, synced_at, raw_json_filename, missing_since
        ) VALUES (
            :finding_id, :plugin_id, :asset_uuid, :severity, :state,
            :first_found, :last_found, :last_fixed, :resurfaced_date, :vpr_score,
            :exploit_maturity, :hostname, :ipv4, :severity_modification_type, :recast_rule_uuid, :source,
            :plugin_name, :asset_fqdn, :days_to_fix, :synced_at, :raw_json_filename, :missing_since
        )
        ON CONFLICT(finding_id) DO UPDATE SET
            plugin_id = excluded.plugin_id,
            asset_uuid = excluded.asset_uuid,
            severity = excluded.severity,
            state = excluded.state,
            first_found = excluded.first_found,
            last_found = excluded.last_found,
            last_fixed = excluded.last_fixed,
            resurfaced_date = excluded.resurfaced_date,
            vpr_score = excluded.vpr_score,
            exploit_maturity = excluded.exploit_maturity,
            hostname = excluded.hostname,
            ipv4 = excluded.ipv4,
            severity_modification_type = excluded.severity_modification_type,
            recast_rule_uuid = excluded.recast_rule_uuid,
            source = excluded.source,
            plugin_name = excluded.plugin_name,
            asset_fqdn = excluded.asset_fqdn,
            days_to_fix = excluded.days_to_fix,
            synced_at = excluded.synced_at,
            raw_json_filename = excluded.raw_json_filename,
            missing_since = NULL
    """
    with get_connection() as conn:
        _append_history(conn, rows)
        conn.executemany(sql, rows)
        conn.commit()
    return len(rows)


def mark_missing_open_findings(
    present_finding_ids: set[str], *, marked_at: str
) -> int:
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT finding_id, state, first_found, last_fixed, resurfaced_date,
                   vpr_score, severity_modification_type, recast_rule_uuid,
                   asset_uuid, plugin_id
            FROM vulnerabilities
            WHERE state IN ('OPEN', 'REOPENED') AND missing_since IS NULL
            """
        ).fetchall()
        missing = [r for r in rows if r["finding_id"] not in present_finding_ids]
        if not missing:
            return 0
        conn.executemany(
            """
            INSERT OR REPLACE INTO finding_history (
                finding_id, synced_at, state, first_found, last_fixed, resurfaced_date,
                vpr_score, severity_modification_type, recast_rule_uuid,
                asset_uuid, plugin_id, missing_since
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    r["finding_id"], marked_at, r["state"], r["first_found"], r["last_fixed"],
                    r["resurfaced_date"], r["vpr_score"], r["severity_modification_type"],
                    r["recast_rule_uuid"], r["asset_uuid"], r["plugin_id"], marked_at,
                )
                for r in missing
            ],
        )
        conn.executemany(
            "UPDATE vulnerabilities SET missing_since = ? WHERE finding_id = ?",
            [(marked_at, r["finding_id"]) for r in missing],
        )
        conn.commit()
        return len(missing)


def reset_sync_state() -> None:
    from utils.vuln_raw_storage import clear_raw_storage

    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM vulnerabilities")
        conn.execute("UPDATE sync_status SET last_sync = 0 WHERE id = 1")
        conn.commit()
    clear_raw_storage()


def latest_synced_at() -> str | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT MAX(synced_at) AS latest FROM vulnerabilities"
        ).fetchone()
        return row["latest"] if row and row["latest"] else None
