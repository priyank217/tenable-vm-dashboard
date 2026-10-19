"""Sync SSL Certificate Information (plugin 10863) from Tenable VM."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from config import VULN_SYNC_POLL_MAX_ATTEMPTS
from services.ssl_cert_db import (
    ensure_ssl_cert_schema,
    replace_ssl_certificates,
    set_ssl_cert_last_sync,
)
from services.vuln_export_service import VulnExportService
from utils.ssl_cert_parser import map_ssl_cert_row

logger = logging.getLogger(__name__)

SSL_CERT_PLUGIN_ID = 10863

_sync_lock = threading.Lock()
_worker_lock = threading.Lock()
_sync_in_progress = False

_sync_state: dict[str, Any] = {
    "in_progress": False,
    "phase": "idle",
    "message": "",
    "export_uuid": None,
    "poll_attempt": 0,
    "poll_max": VULN_SYNC_POLL_MAX_ATTEMPTS,
    "export_status": None,
    "chunks_total": 0,
    "chunks_done": 0,
    "records_received": 0,
    "records_upserted": 0,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "result": None,
}


def build_ssl_cert_export_filters() -> dict:
    return {
        "plugin_id": [SSL_CERT_PLUGIN_ID],
        "state": ["OPEN", "REOPENED"],
        "since": 0,
    }


def _reset_sync_state() -> None:
    _sync_state.update({
        "in_progress": False,
        "phase": "idle",
        "message": "",
        "export_uuid": None,
        "poll_attempt": 0,
        "poll_max": VULN_SYNC_POLL_MAX_ATTEMPTS,
        "export_status": None,
        "chunks_total": 0,
        "chunks_done": 0,
        "records_received": 0,
        "records_upserted": 0,
        "started_at": None,
        "finished_at": None,
        "error": None,
        "result": None,
    })


def _set_phase(phase: str, message: str) -> None:
    _sync_state["phase"] = phase
    _sync_state["message"] = message


def get_ssl_cert_sync_progress() -> dict[str, Any]:
    return dict(_sync_state)


def is_ssl_cert_sync_in_progress() -> bool:
    return _sync_in_progress


def _on_poll(attempt: int, poll_max: int, status: dict) -> None:
    _sync_state["poll_attempt"] = attempt
    _sync_state["poll_max"] = poll_max
    _sync_state["export_status"] = status.get("status")
    _sync_state["export_uuid"] = status.get("export_uuid") or _sync_state.get("export_uuid")
    _set_phase(
        "polling",
        f"Waiting for SSL cert export ({status.get('status', 'UNKNOWN')}) — "
        f"poll {attempt}/{poll_max}",
    )


def run_ssl_cert_sync() -> dict:
    global _sync_in_progress

    if not _worker_lock.acquire(blocking=False):
        raise RuntimeError("An SSL certificate sync is already in progress.")

    ensure_ssl_cert_schema()
    _reset_sync_state()
    _sync_in_progress = True
    _sync_state["in_progress"] = True
    started = time.time()
    sync_started_at = int(started)
    synced_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _sync_state["started_at"] = synced_at

    try:
        filters = build_ssl_cert_export_filters()
        service = VulnExportService(filters=filters, include_plugin_output=True)
        export_body = service._export_body()
        logger.info("SSL cert export body filters=%s", export_body.get("filters"))

        _set_phase("requesting", "Requesting plugin 10863 SSL certificate export…")
        export_uuid = service.request_export()
        _sync_state["export_uuid"] = export_uuid
        _set_phase(
            "polling",
            f"Export requested — polling Tenable (UUID …{export_uuid[-8:]})",
        )

        final_status = service.poll_export_status(export_uuid, on_poll=_on_poll)
        chunks = sorted(final_status.get("chunks_available") or [])
        _sync_state["chunks_total"] = len(chunks)

        rows: list[dict] = []
        received = 0
        for index, chunk_id in enumerate(chunks):
            batch = service.download_chunk(export_uuid, chunk_id)
            received += len(batch)
            _sync_state["chunks_done"] = index + 1
            _sync_state["records_received"] = received
            _set_phase(
                "downloading",
                f"Downloading SSL cert chunk {index + 1}/{len(chunks)} "
                f"({received:,} findings)…",
            )
            for raw in batch:
                mapped = map_ssl_cert_row(raw, synced_at=synced_at)
                if mapped:
                    rows.append(mapped)

        _set_phase("importing", f"Storing {len(rows):,} SSL certificates…")
        upserted = replace_ssl_certificates(rows)
        _sync_state["records_upserted"] = upserted

        set_ssl_cert_last_sync(
            sync_started_at, last_sync_iso=synced_at, last_count=upserted
        )

        duration_sec = round(time.time() - started, 1)
        result = {
            "ok": True,
            "export_uuid": export_uuid,
            "chunks": len(chunks),
            "records_received": received,
            "records_upserted": upserted,
            "last_sync": sync_started_at,
            "last_sync_iso": synced_at,
            "duration_sec": duration_sec,
        }
        _sync_state["result"] = result
        _sync_state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _set_phase("complete", f"SSL cert sync complete — {upserted:,} certificates.")
        logger.info(
            "SSL cert sync complete — received=%d upserted=%d duration=%ss",
            received,
            upserted,
            duration_sec,
        )
        return result
    except Exception as err:
        _sync_state["error"] = str(err)
        _sync_state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _set_phase("error", str(err))
        raise
    finally:
        _sync_in_progress = False
        _sync_state["in_progress"] = False
        _worker_lock.release()


def start_ssl_cert_sync() -> dict:
    if is_ssl_cert_sync_in_progress():
        raise RuntimeError("An SSL certificate sync is already in progress.")

    if not _sync_lock.acquire(blocking=False):
        raise RuntimeError("An SSL certificate sync is already in progress.")

    def _worker() -> None:
        try:
            run_ssl_cert_sync()
        except Exception:
            logger.exception("Background SSL certificate sync failed")
        finally:
            _sync_lock.release()

    thread = threading.Thread(target=_worker, name="ssl-cert-sync", daemon=True)
    thread.start()
    return {
        "ok": True,
        "started": True,
        "async": True,
        "message": "SSL certificate sync started in background.",
    }
