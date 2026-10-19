"""Dashboard API: Lumin metrics, vulnerability sync, and tag filter options."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from config import TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from routes.helpers import (
    cached_fetch,
    credentials_error,
    ensure_assets_cached,
    fetch_tags_from_tenable,
    load_lumin_metrics,
    refresh_flag,
    tags_api_payload,
    tags_cache,
    tenable_error,
)
from services.vuln_db import count_vulnerabilities, get_last_sync, latest_synced_at
from services.vuln_sync_service import (
    get_sync_progress,
    is_sync_in_progress,
    start_vulnerability_sync,
)
from utils.asset_tag_filter import tag_options_for_dashboard
from utils.lumin_metrics import refresh_monthly_snapshots

bp = Blueprint("dashboard", __name__)


@bp.get("/api/lumin/metrics")
def get_lumin_metrics():
    try:
        tag_uuid = request.args.get("tag_uuid", "").strip() or None
        return jsonify(load_lumin_metrics(tag_uuid=tag_uuid))
    except Exception as err:
        return jsonify({
            "error": "Failed to compute Lumin Index metrics from local database.",
            "detail": str(err),
        }), 500


@bp.post("/api/lumin/snapshots/refresh")
def refresh_lumin_snapshots():
    try:
        return jsonify(refresh_monthly_snapshots())
    except Exception as err:
        return jsonify({"error": str(err)}), 500


@bp.get("/api/dashboard/tags")
def dashboard_tag_options():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()
    try:
        assets = ensure_assets_cached()
        tags_payload, err = cached_fetch(
            tags_cache,
            force_refresh=refresh_flag(),
            fetch_fn=fetch_tags_from_tenable,
            format_fn=lambda entry: tags_api_payload(entry, cached=True),
        )
        if err and not tags_payload:
            return jsonify({"error": err}), 502
        registry = (tags_payload or {}).get("tags") or []
        return jsonify({
            "options": tag_options_for_dashboard(assets, registry),
            "assets_cached": len(assets),
        })
    except Exception as err:
        return tenable_error(err)


@bp.get("/api/sync/status")
def sync_status():
    last_sync = get_last_sync()
    progress = get_sync_progress()
    return jsonify({
        "last_sync": last_sync,
        "last_sync_iso": (
            datetime.fromtimestamp(last_sync, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            if last_sync
            else None
        ),
        "vulnerability_count": count_vulnerabilities(),
        "latest_record_synced_at": latest_synced_at(),
        "sync_in_progress": is_sync_in_progress(),
        "progress": progress,
    })


@bp.post("/api/sync")
def sync_vulnerabilities():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    body = request.get_json(silent=True) or {}
    force_full = body.get("full") is True or request.args.get("full", "").lower() in (
        "1",
        "true",
        "yes",
    )
    reset = body.get("reset") is True or request.args.get("reset", "").lower() in (
        "1",
        "true",
        "yes",
    )
    daily = body.get("daily") is True or request.args.get("daily", "").lower() in (
        "1",
        "true",
        "yes",
    )

    try:
        result = start_vulnerability_sync(
            force_full=force_full, reset=reset, open_refresh=daily
        )
        return jsonify(result), 202
    except RuntimeError as err:
        return jsonify({"error": str(err)}), 409
    except Exception as err:
        return tenable_error(err)
