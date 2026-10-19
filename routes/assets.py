"""Asset inventory, open ports, and health API routes."""

from flask import Blueprint, jsonify

from config import CACHE_TTL_SEC, PORT, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from routes.helpers import (
    asset_cache,
    cached_fetch,
    credentials_error,
    fetch_assets_from_tenable,
    refresh_flag,
    tags_cache,
    tenable_error,
)
from services.vuln_db import count_vulnerabilities, get_last_sync
from services.vuln_sync_service import is_sync_in_progress
from utils.asset_normalizer import flatten_open_ports

bp = Blueprint("assets", __name__)


@bp.get("/api/health")
def health():
    cached = asset_cache.get()
    tags_warm = tags_cache.get()
    return jsonify({
        "ok": True,
        "configured": bool(TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY),
        "vulnerability_count": count_vulnerabilities(),
        "last_sync": get_last_sync(),
        "sync_in_progress": is_sync_in_progress(),
        "cache": {
            "ttlSec": CACHE_TTL_SEC,
            "assetsWarm": cached is not None,
            "assetsExpiresAt": cached["cacheExpiresAt"] if cached else None,
            "tagsWarm": tags_warm is not None,
            "tagsExpiresAt": tags_warm["cacheExpiresAt"] if tags_warm else None,
        },
        "port": PORT,
    })


@bp.get("/api/assets")
def get_assets():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        payload, err = cached_fetch(
            asset_cache,
            force_refresh=refresh_flag(),
            fetch_fn=fetch_assets_from_tenable,
        )
        if err:
            return jsonify(payload)
        return jsonify(payload)
    except Exception as err:
        return tenable_error(err)


@bp.get("/api/open-ports")
def get_open_ports():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        payload, err = cached_fetch(
            asset_cache,
            force_refresh=refresh_flag(),
            fetch_fn=fetch_assets_from_tenable,
        )
        assets = payload.get("assets") or []
        ports = flatten_open_ports(assets)
        response = {
            "ports": ports,
            "count": len(ports),
            "assetCount": len(assets),
            "assetsWithPorts": len({p["assetId"] for p in ports if p.get("assetId")}),
            "lastSync": payload.get("lastSync"),
            "cached": payload.get("cached", False),
            "cacheExpiresAt": payload.get("cacheExpiresAt"),
        }
        if payload.get("stale"):
            response["stale"] = True
        if payload.get("warning"):
            response["warning"] = payload["warning"]
        if err and not ports:
            return jsonify(response)
        return jsonify(response)
    except Exception as err:
        return tenable_error(err)
