"""Server Health API — last reboot posture (plugins 56468 / 92366)."""

from flask import Blueprint, jsonify

from config import TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from routes.helpers import credentials_error, refresh_flag, tenable_error
from services.server_health_db import (
    count_server_health,
    get_server_health_last_sync,
    list_server_health,
)
from services.server_health_sync_service import (
    get_server_health_sync_progress,
    is_server_health_sync_in_progress,
    start_server_health_sync,
)
from utils.server_health_metrics import compute_server_health_summary, servers_for_api
from utils.server_health_parser import LINUX_PLUGIN_ID, WINDOWS_PLUGIN_ID

bp = Blueprint("server_health", __name__)


@bp.get("/api/server-health")
def get_server_health():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        if refresh_flag():
            if is_server_health_sync_in_progress():
                return jsonify({
                    "error": "A server health sync is already in progress.",
                    "sync_in_progress": True,
                    "progress": get_server_health_sync_progress(),
                }), 409
            start_server_health_sync()

        rows = list_server_health()
        servers = servers_for_api(rows)
        summary = compute_server_health_summary(servers)
        sync_meta = get_server_health_last_sync()
        progress = get_server_health_sync_progress()

        response = {
            "servers": servers,
            "count": len(servers),
            "summary": summary,
            "lastSync": sync_meta.get("last_sync_iso"),
            "lastSyncUnix": sync_meta.get("last_sync") or 0,
            "sync_in_progress": is_server_health_sync_in_progress(),
            "progress": progress,
            "plugins": {
                "linux": LINUX_PLUGIN_ID,
                "windows": WINDOWS_PLUGIN_ID,
            },
        }
        if progress.get("phase") == "error" and progress.get("error"):
            response["error"] = progress["error"]
            response["warning"] = f"Server health sync failed: {progress['error']}"
        elif not servers and not is_server_health_sync_in_progress():
            response["warning"] = (
                "No server health data yet. Click Refresh to export "
                "last-reboot plugins 56468 (Linux) and 92366 (Windows) from Tenable."
            )
        return jsonify(response)
    except RuntimeError as err:
        return jsonify({"error": str(err)}), 409
    except Exception as err:
        return tenable_error(err)


@bp.get("/api/server-health/status")
def server_health_status():
    sync_meta = get_server_health_last_sync()
    return jsonify({
        "last_sync": sync_meta.get("last_sync") or 0,
        "last_sync_iso": sync_meta.get("last_sync_iso"),
        "server_count": count_server_health(),
        "sync_in_progress": is_server_health_sync_in_progress(),
        "progress": get_server_health_sync_progress(),
    })


@bp.post("/api/server-health/sync")
def sync_server_health():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()
    try:
        result = start_server_health_sync()
        return jsonify(result), 202
    except RuntimeError as err:
        return jsonify({"error": str(err)}), 409
    except Exception as err:
        return tenable_error(err)
