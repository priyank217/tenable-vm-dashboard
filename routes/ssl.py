"""SSL certificate list, status, and sync API routes."""

from flask import Blueprint, jsonify

from config import TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from routes.helpers import (
    credentials_error,
    ensure_assets_cached,
    get_cached_assets,
    refresh_flag,
    tenable_error,
)
from services.ssl_cert_db import (
    count_ssl_certificates,
    get_ssl_cert_last_sync,
    list_ssl_certificates,
)
from services.ssl_cert_sync_service import (
    get_ssl_cert_sync_progress,
    is_ssl_cert_sync_in_progress,
    start_ssl_cert_sync,
)
from utils.ssl_cert_metrics import compute_ssl_cert_summary, enrich_certificates_with_assets

bp = Blueprint("ssl", __name__)


@bp.get("/api/ssl-certificates")
def get_ssl_certificates():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        if refresh_flag():
            if is_ssl_cert_sync_in_progress():
                return jsonify({
                    "error": "An SSL certificate sync is already in progress.",
                    "sync_in_progress": True,
                    "progress": get_ssl_cert_sync_progress(),
                }), 409
            start_ssl_cert_sync()

        try:
            assets = ensure_assets_cached(force_refresh=False)
        except Exception:
            assets = get_cached_assets()

        certs = enrich_certificates_with_assets(list_ssl_certificates(), assets)
        summary = compute_ssl_cert_summary(certs)
        sync_meta = get_ssl_cert_last_sync()
        progress = get_ssl_cert_sync_progress()

        response = {
            "certs": certs,
            "count": len(certs),
            "summary": summary,
            "lastSync": sync_meta.get("last_sync_iso"),
            "lastSyncUnix": sync_meta.get("last_sync") or 0,
            "sync_in_progress": is_ssl_cert_sync_in_progress(),
            "progress": progress,
            "pluginId": 10863,
        }
        if progress.get("phase") == "error" and progress.get("error"):
            response["error"] = progress["error"]
            response["warning"] = f"SSL certificate sync failed: {progress['error']}"
        elif not certs and not is_ssl_cert_sync_in_progress():
            response["warning"] = (
                "No SSL certificate data yet. Click Refresh to export plugin 10863 from Tenable."
            )
        return jsonify(response)
    except RuntimeError as err:
        return jsonify({"error": str(err)}), 409
    except Exception as err:
        return tenable_error(err)


@bp.get("/api/ssl-certificates/status")
def ssl_certificates_status():
    sync_meta = get_ssl_cert_last_sync()
    return jsonify({
        "last_sync": sync_meta.get("last_sync") or 0,
        "last_sync_iso": sync_meta.get("last_sync_iso"),
        "certificate_count": count_ssl_certificates(),
        "sync_in_progress": is_ssl_cert_sync_in_progress(),
        "progress": get_ssl_cert_sync_progress(),
    })


@bp.post("/api/ssl-certificates/sync")
def sync_ssl_certificates():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()
    try:
        result = start_ssl_cert_sync()
        return jsonify(result), 202
    except RuntimeError as err:
        return jsonify({"error": str(err)}), 409
    except Exception as err:
        return tenable_error(err)
