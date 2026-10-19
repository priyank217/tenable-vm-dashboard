"""SQLite store for server last-reboot health (plugins 56468 / 92366)."""

from __future__ import annotations

from services.vuln_db import get_connection, init_db

_SERVER_HEALTH_DDL = """
CREATE TABLE IF NOT EXISTS server_health (
    finding_id TEXT PRIMARY KEY,
    asset_uuid TEXT NOT NULL,
    hostname TEXT,
    ipv4 TEXT,
    os_family TEXT,
    os_name TEXT,
    plugin_id INTEGER NOT NULL,
    last_reboot TEXT,
    days_since_reboot REAL,
    status TEXT,
    plugin_output TEXT,
    first_found TEXT,
    last_found TEXT,
    synced_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_server_health_asset ON server_health(asset_uuid);
CREATE INDEX IF NOT EXISTS idx_server_health_status ON server_health(status);
CREATE INDEX IF NOT EXISTS idx_server_health_os ON server_health(os_family);
CREATE INDEX IF NOT EXISTS idx_server_health_days ON server_health(days_since_reboot);

CREATE TABLE IF NOT EXISTS server_health_sync_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_sync INTEGER NOT NULL DEFAULT 0,
    last_sync_iso TEXT,
    last_count INTEGER NOT NULL DEFAULT 0
);
"""


def ensure_server_health_schema() -> None:
    init_db()
    with get_connection() as conn:
        conn.executescript(_SERVER_HEALTH_DDL)
        conn.execute(
            """
            INSERT INTO server_health_sync_status (id, last_sync, last_sync_iso, last_count)
            VALUES (1, 0, NULL, 0)
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.commit()


def get_server_health_last_sync() -> dict:
    ensure_server_health_schema()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_sync, last_sync_iso, last_count FROM server_health_sync_status WHERE id = 1"
        ).fetchone()
        if not row:
            return {"last_sync": 0, "last_sync_iso": None, "last_count": 0}
        return {
            "last_sync": int(row["last_sync"] or 0),
            "last_sync_iso": row["last_sync_iso"],
            "last_count": int(row["last_count"] or 0),
        }


def set_server_health_last_sync(
    timestamp: int, *, last_sync_iso: str, last_count: int
) -> None:
    ensure_server_health_schema()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE server_health_sync_status
            SET last_sync = ?, last_sync_iso = ?, last_count = ?
            WHERE id = 1
            """,
            (timestamp, last_sync_iso, last_count),
        )
        conn.commit()


def replace_server_health(rows: list[dict]) -> int:
    ensure_server_health_schema()
    sql = """
        INSERT INTO server_health (
            finding_id, asset_uuid, hostname, ipv4, os_family, os_name,
            plugin_id, last_reboot, days_since_reboot, status,
            plugin_output, first_found, last_found, synced_at
        ) VALUES (
            :finding_id, :asset_uuid, :hostname, :ipv4, :os_family, :os_name,
            :plugin_id, :last_reboot, :days_since_reboot, :status,
            :plugin_output, :first_found, :last_found, :synced_at
        )
    """
    with get_connection() as conn:
        conn.execute("DELETE FROM server_health")
        if rows:
            conn.executemany(sql, rows)
        conn.commit()
    return len(rows)


def list_server_health() -> list[dict]:
    ensure_server_health_schema()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT finding_id, asset_uuid, hostname, ipv4, os_family, os_name,
                   plugin_id, last_reboot, days_since_reboot, status,
                   plugin_output, first_found, last_found, synced_at
            FROM server_health
            ORDER BY
                CASE status
                    WHEN 'critical' THEN 0
                    WHEN 'warning' THEN 1
                    WHEN 'attention' THEN 2
                    WHEN 'healthy' THEN 3
                    ELSE 4
                END,
                CASE WHEN days_since_reboot IS NULL THEN 1 ELSE 0 END,
                days_since_reboot DESC,
                hostname COLLATE NOCASE
            """
        ).fetchall()
        return [dict(row) for row in rows]


def count_server_health() -> int:
    ensure_server_health_schema()
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM server_health").fetchone()
        return int(row["cnt"] or 0)
