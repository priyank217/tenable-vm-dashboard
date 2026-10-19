"""SQLite store for SSL certificates from Tenable plugin 10863."""

from __future__ import annotations

import sqlite3

from services.vuln_db import get_connection, init_db

_SSL_CERTS_DDL = """
CREATE TABLE IF NOT EXISTS ssl_certificates (
    finding_id TEXT PRIMARY KEY,
    asset_uuid TEXT NOT NULL,
    hostname TEXT,
    ipv4 TEXT,
    port INTEGER,
    protocol TEXT,
    subject TEXT,
    subject_cn TEXT,
    issuer TEXT,
    issuer_cn TEXT,
    valid_from TEXT,
    valid_to TEXT,
    days_remaining INTEGER,
    status TEXT,
    plugin_output TEXT,
    first_found TEXT,
    last_found TEXT,
    synced_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssl_certs_asset ON ssl_certificates(asset_uuid);
CREATE INDEX IF NOT EXISTS idx_ssl_certs_status ON ssl_certificates(status);
CREATE INDEX IF NOT EXISTS idx_ssl_certs_days ON ssl_certificates(days_remaining);

CREATE TABLE IF NOT EXISTS ssl_cert_sync_status (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_sync INTEGER NOT NULL DEFAULT 0,
    last_sync_iso TEXT,
    last_count INTEGER NOT NULL DEFAULT 0
);
"""


def ensure_ssl_cert_schema() -> None:
    init_db()
    with get_connection() as conn:
        conn.executescript(_SSL_CERTS_DDL)
        conn.execute(
            """
            INSERT INTO ssl_cert_sync_status (id, last_sync, last_sync_iso, last_count)
            VALUES (1, 0, NULL, 0)
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.commit()


def get_ssl_cert_last_sync() -> dict:
    ensure_ssl_cert_schema()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT last_sync, last_sync_iso, last_count FROM ssl_cert_sync_status WHERE id = 1"
        ).fetchone()
        if not row:
            return {"last_sync": 0, "last_sync_iso": None, "last_count": 0}
        return {
            "last_sync": int(row["last_sync"] or 0),
            "last_sync_iso": row["last_sync_iso"],
            "last_count": int(row["last_count"] or 0),
        }


def set_ssl_cert_last_sync(
    timestamp: int, *, last_sync_iso: str, last_count: int
) -> None:
    ensure_ssl_cert_schema()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE ssl_cert_sync_status
            SET last_sync = ?, last_sync_iso = ?, last_count = ?
            WHERE id = 1
            """,
            (timestamp, last_sync_iso, last_count),
        )
        conn.commit()


def replace_ssl_certificates(rows: list[dict]) -> int:
    ensure_ssl_cert_schema()
    sql = """
        INSERT INTO ssl_certificates (
            finding_id, asset_uuid, hostname, ipv4, port, protocol,
            subject, subject_cn, issuer, issuer_cn,
            valid_from, valid_to, days_remaining, status,
            plugin_output, first_found, last_found, synced_at
        ) VALUES (
            :finding_id, :asset_uuid, :hostname, :ipv4, :port, :protocol,
            :subject, :subject_cn, :issuer, :issuer_cn,
            :valid_from, :valid_to, :days_remaining, :status,
            :plugin_output, :first_found, :last_found, :synced_at
        )
    """
    with get_connection() as conn:
        conn.execute("DELETE FROM ssl_certificates")
        if rows:
            conn.executemany(sql, rows)
        conn.commit()
    return len(rows)


def list_ssl_certificates() -> list[dict]:
    ensure_ssl_cert_schema()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT finding_id, asset_uuid, hostname, ipv4, port, protocol,
                   subject, subject_cn, issuer, issuer_cn,
                   valid_from, valid_to, days_remaining, status,
                   plugin_output, first_found, last_found, synced_at
            FROM ssl_certificates
            ORDER BY
                CASE status
                    WHEN 'expired' THEN 0
                    WHEN 'expiring' THEN 1
                    WHEN 'valid' THEN 2
                    ELSE 3
                END,
                CASE WHEN days_remaining IS NULL THEN 1 ELSE 0 END,
                days_remaining ASC,
                hostname COLLATE NOCASE
            """
        ).fetchall()
        return [dict(row) for row in rows]


def count_ssl_certificates() -> int:
    ensure_ssl_cert_schema()
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM ssl_certificates").fetchone()
        return int(row["cnt"] or 0)
