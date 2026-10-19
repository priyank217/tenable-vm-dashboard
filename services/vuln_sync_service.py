import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from config import VULN_FULL_SYNC_SINCE, VULN_SYNC_POLL_MAX_ATTEMPTS
from services.vuln_db import (
    get_last_sync,
    mark_missing_open_findings,
    reset_sync_state,
    set_last_sync,
    upsert_vulnerabilities,
)
from services.vuln_export_service import (
    VulnExportService,
    build_export_filters,
    build_open_set_filters,
)
from utils.vuln_mapper import map_vulnerability_row
from utils.vuln_raw_storage import save_chunk_raw

logger = logging.getLogger(__name__)

_sync_lock = threading.Lock()
_worker_lock = threading.Lock()
_sync_in_progress = False

BATCH_SIZE = 500

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
    "mode": None,
    "started_at": None,
    "finished_at": None,
    "error": None,
    "result": None,
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
        "mode": None,
        "started_at": None,
        "finished_at": None,
        "error": None,
        "result": None,
    })


def _set_phase(phase: str, message: str) -> None:
    _sync_state["phase"] = phase
    _sync_state["message"] = message


def get_sync_progress() -> dict[str, Any]:
    return dict(_sync_state)


def is_sync_in_progress() -> bool:
    return _sync_in_progress


def _archive_chunk(
    export_uuid: str, chunk_id: int, batch: list[dict], sync_date: str
) -> str:
    if not batch:
        return ""
    return save_chunk_raw(export_uuid, chunk_id, batch, sync_date)


def _on_poll(attempt: int, poll_max: int, status: dict) -> None:
    _sync_state["poll_attempt"] = attempt
    _sync_state["poll_max"] = poll_max
    _sync_state["export_status"] = status.get("status")
    _sync_state["export_uuid"] = status.get("export_uuid") or _sync_state.get("export_uuid")
    _set_phase(
        "polling",
        f"Waiting for Tenable export ({status.get('status', 'UNKNOWN')}) — "
        f"poll {attempt}/{poll_max}",
    )


def _run_one_export(
    filters: dict,
    *,
    sync_date: str,
    label: str,
    collect_ids: bool = False,
) -> dict:
    service = VulnExportService(filters=filters)
    export_uuid = service.request_export()
    _sync_state["export_uuid"] = export_uuid
    _set_phase("polling", f"{label}: export requested — polling Tenable (UUID …{export_uuid[-8:]})")

    final_status = service.poll_export_status(export_uuid, on_poll=_on_poll)
    chunks = sorted(final_status.get("chunks_available") or [])
    _sync_state["chunks_total"] = len(chunks)
    _sync_state["chunks_done"] = 0
    _set_phase("downloading", f"{label}: downloading {len(chunks)} chunk(s) from Tenable…")

    total_raw = 0
    total_upserted = 0
    buffer: list[dict] = []
    finding_ids: set[str] = set()

    for index, chunk_id in enumerate(chunks):
        batch = service.download_chunk(export_uuid, chunk_id)
        _sync_state["chunks_done"] = index + 1
        total_raw += len(batch)
        _sync_state["records_received"] = _sync_state.get("records_received", 0) + len(batch)
        _set_phase(
            "downloading",
            f"{label}: chunk {index + 1}/{len(chunks)} ({total_raw:,} records so far)…",
        )

        if batch:
            _archive_chunk(export_uuid, chunk_id, batch, sync_date)

        _set_phase("importing", f"{label}: importing chunk {index + 1}/{len(chunks)}…")
        for raw in batch:
            row = map_vulnerability_row(raw, sync_date=sync_date)
            if not row:
                continue
            if collect_ids:
                finding_ids.add(row["finding_id"])
            buffer.append(row)
            if len(buffer) >= BATCH_SIZE:
                total_upserted += upsert_vulnerabilities(buffer)
                buffer.clear()
                _sync_state["records_upserted"] = (
                    _sync_state.get("records_upserted", 0) + BATCH_SIZE
                )

    if buffer:
        total_upserted += upsert_vulnerabilities(buffer)
        _sync_state["records_upserted"] = _sync_state.get("records_upserted", 0) + len(buffer)

    return {
        "export_uuid": export_uuid,
        "chunks": len(chunks),
        "records_received": total_raw,
        "records_upserted": total_upserted,
        "finding_ids": finding_ids,
        "since": filters.get("since"),
    }


def run_vulnerability_sync(
    *,
    force_full: bool = False,
    reset: bool = False,
    open_refresh: bool = False,
) -> dict:
    global _sync_in_progress

    if not _worker_lock.acquire(blocking=False):
        raise RuntimeError("A vulnerability sync is already in progress.")

    _sync_in_progress = True
    _reset_sync_state()
    _sync_state["in_progress"] = True
    _sync_state["started_at"] = datetime.now(timezone.utc).isoformat()

    started = time.time()
    sync_started_at = int(time.time())
    sync_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    marked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        if reset:
            reset_sync_state()

        last_sync = get_last_sync()
        full_sync = last_sync == 0 or force_full
        if full_sync:
            mode = "full"
        elif open_refresh:
            mode = "daily"
        else:
            mode = "incremental"
        _sync_state["mode"] = mode

        if full_sync:
            filters = build_export_filters(full=True)
            _set_phase("requesting", "Starting full vulnerability export from Tenable…")
            logger.info(
                "Starting FULL vulnerability export (since=%d, last_sync=%d)",
                VULN_FULL_SYNC_SINCE,
                last_sync,
            )
            primary = _run_one_export(
                filters, sync_date=sync_date, label="Full export", collect_ids=True
            )
        else:
            filters = build_export_filters(since=last_sync)
            _set_phase("requesting", "Starting incremental vulnerability export…")
            logger.info("Starting INCREMENTAL vulnerability export (since=%d)", last_sync)
            primary = _run_one_export(filters, sync_date=sync_date, label="Incremental")

        missing_flagged = 0
        open_refresh_result = None
        if open_refresh and not full_sync:
            _set_phase("requesting", "Refreshing complete open set (recast / VPR / expiry)…")
            logger.info("Starting OPEN-SET refresh export (since=0, OPEN/REOPENED)")
            open_refresh_result = _run_one_export(
                build_open_set_filters(),
                sync_date=sync_date,
                label="Open-set refresh",
                collect_ids=True,
            )
            missing_flagged = mark_missing_open_findings(
                open_refresh_result["finding_ids"], marked_at=marked_at
            )
            if missing_flagged:
                logger.info(
                    "Open-set refresh: %d previously-open findings not returned; flagged missing_since",
                    missing_flagged,
                )
        elif full_sync:
            missing_flagged = mark_missing_open_findings(
                primary["finding_ids"], marked_at=marked_at
            )

        set_last_sync(sync_started_at)

        _set_phase("importing", "Closing months — writing locked monthly snapshots…")
        from utils.lumin_metrics import refresh_monthly_snapshots

        snapshot_summary = refresh_monthly_snapshots()

        total_raw = primary["records_received"] + (
            open_refresh_result["records_received"] if open_refresh_result else 0
        )
        total_upserted = primary["records_upserted"] + (
            open_refresh_result["records_upserted"] if open_refresh_result else 0
        )

        duration_sec = round(time.time() - started, 1)
        logger.info(
            "Sync complete — mode=%s, raw=%d, upserted=%d, missing_flagged=%d, duration=%ss",
            mode,
            total_raw,
            total_upserted,
            missing_flagged,
            duration_sec,
        )

        result = {
            "ok": True,
            "mode": mode,
            "since": primary.get("since"),
            "export_uuid": primary["export_uuid"],
            "chunks": primary["chunks"] + (open_refresh_result["chunks"] if open_refresh_result else 0),
            "records_received": total_raw,
            "records_upserted": total_upserted,
            "open_refresh": (
                {
                    "export_uuid": open_refresh_result["export_uuid"],
                    "records_received": open_refresh_result["records_received"],
                    "missing_flagged": missing_flagged,
                }
                if open_refresh_result
                else None
            ),
            "snapshots": snapshot_summary,
            "last_sync": sync_started_at,
            "last_sync_iso": datetime.fromtimestamp(
                sync_started_at, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_sec": duration_sec,
        }
        _sync_state["result"] = result
        _sync_state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _set_phase("complete", f"Sync complete — {total_upserted:,} records imported.")
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


def start_vulnerability_sync(
    *, force_full: bool = False, reset: bool = False, open_refresh: bool = False
) -> dict:
    if is_sync_in_progress():
        raise RuntimeError("A vulnerability sync is already in progress.")

    if not _sync_lock.acquire(blocking=False):
        raise RuntimeError("A vulnerability sync is already in progress.")

    def _worker() -> None:
        try:
            run_vulnerability_sync(
                force_full=force_full, reset=reset, open_refresh=open_refresh
            )
        except Exception:
            logger.exception("Background vulnerability sync failed")
        finally:
            _sync_lock.release()

    thread = threading.Thread(target=_worker, name="vuln-sync", daemon=True)
    thread.start()
    return {
        "ok": True,
        "started": True,
        "async": True,
        "message": "Vulnerability sync started in background.",
    }
