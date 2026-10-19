"""
Shared HTTP helpers and in-memory cache orchestration for route modules.

Caches and fetch helpers live here so blueprints share one asset/tag cache
without circular imports.
"""

from datetime import datetime, timezone

from flask import jsonify, request

from config import CACHE_TTL_SEC, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from services.asset_cache import TtlCache
from services.asset_export_service import AssetExportService
from services.tags_service import TagsService
from services.tenable_client import TenableApiError
from services.vuln_db import count_vulnerabilities
from utils.asset_normalizer import normalize_assets
from utils.asset_tag_filter import asset_uuids_for_tag, resolve_tag_meta
from utils.lumin_metrics import compute_lumin_metrics, refresh_monthly_snapshots
from utils.tag_normalizer import (
    apply_asset_counts,
    count_tagged_assets,
    dedupe_tags,
    enrich_categories,
    group_tags_by_category,
    normalize_tag_values,
)

asset_cache = TtlCache(CACHE_TTL_SEC)
tags_cache = TtlCache(CACHE_TTL_SEC)


def credentials_error():
    missing = []
    if not TENABLE_ACCESS_KEY:
        missing.append("TENABLE_ACCESS_KEY")
    if not TENABLE_SECRET_KEY:
        missing.append("TENABLE_SECRET_KEY")
    return jsonify({
        "error": (
            f"Missing in .env: {', '.join(missing)}. "
            "TENABLE_BASE_URL should be https://cloud.tenable.com"
        ),
    }), 500


def tenable_error(err):
    if isinstance(err, TenableApiError):
        status = err.status_code or 502
        return jsonify({"error": str(err)}), status
    if isinstance(err, ValueError):
        return jsonify({"error": str(err)}), 400
    return jsonify({"error": str(err)}), 502


def parse_tag_assignment_body(body: dict) -> tuple[str, list[str], list]:
    action = (body.get("action") or "").strip().lower()
    assets = body.get("assets") or body.get("asset_uuids") or []
    if isinstance(assets, str):
        assets = [assets]
    tags = body.get("tags") or body.get("tag_uuids") or body.get("tag_values") or []
    if not isinstance(assets, list):
        raise ValueError("assets must be an array of asset UUIDs.")
    if not isinstance(tags, list):
        raise ValueError("tags must be an array of tag UUIDs or {category, value} objects.")
    return action, assets, tags


def refresh_flag() -> bool:
    return request.args.get("refresh", "").lower() in ("1", "true", "yes")


def cached_fetch(cache, *, force_refresh, fetch_fn, format_fn=None):
    format_fn = format_fn or (lambda entry: entry)

    if not force_refresh:
        cached = cache.get()
        if cached:
            return format_fn(cached), None

    try:
        with cache.fetch_lock():
            if not force_refresh:
                cached = cache.get()
                if cached:
                    return format_fn(cached), None
            if force_refresh:
                cache.invalidate()
            return fetch_fn(), None
    except Exception as err:
        stale = cache.get(include_expired=True)
        if stale:
            payload = format_fn(stale)
            payload["cached"] = True
            payload["stale"] = True
            payload["warning"] = f"Showing cached data; refresh failed: {err}"
            return payload, err
        raise


def fetch_assets_from_tenable():
    service = AssetExportService()
    raw_assets = service.export_all_assets()
    assets = normalize_assets(raw_assets)
    last_sync = datetime.now(timezone.utc).isoformat()
    return asset_cache.set(assets, last_sync)


def get_cached_assets():
    cached = asset_cache.get(include_expired=True)
    return (cached or {}).get("assets") or []


def ensure_assets_cached(force_refresh=False):
    payload, err = cached_fetch(
        asset_cache,
        force_refresh=force_refresh,
        fetch_fn=fetch_assets_from_tenable,
    )
    if err:
        raise err
    return payload.get("assets") or []


def assets_for_tag_counts():
    assets = get_cached_assets()
    if assets:
        return assets
    try:
        return ensure_assets_cached()
    except Exception:
        return []


def tags_api_payload(cache_entry, *, cached=False):
    assets = assets_for_tag_counts()
    tags = apply_asset_counts(dedupe_tags(cache_entry["assets"]), assets)
    categories = enrich_categories(group_tags_by_category(tags), assets, tags)
    payload = {
        "tags": tags,
        "categories": categories,
        "stats": {
            "categoryCount": len(categories),
            "tagValueCount": len(tags),
            "taggedAssetCount": count_tagged_assets(assets),
            "totalAssetCount": len(assets),
        },
        "lastSync": cache_entry["lastSync"],
        "count": len(tags),
        "categoryCount": len(categories),
        "cached": cached,
        "cacheExpiresAt": cache_entry["cacheExpiresAt"],
    }
    if not assets:
        payload["warning"] = (
            "Asset counts are unavailable until the asset export is cached. "
            "Open Asset Inventory or click Refresh."
        )
    return payload


def fetch_tags_from_tenable():
    service = TagsService()
    raw_values = service.list_all_tag_values()
    assets = assets_for_tag_counts()
    tags = apply_asset_counts(normalize_tag_values(raw_values), assets)
    last_sync = datetime.now(timezone.utc).isoformat()
    stored = tags_cache.set(tags, last_sync)
    return tags_api_payload(stored, cached=False)


def load_lumin_metrics(*, tag_uuid: str | None = None):
    assets = ensure_assets_cached() if tag_uuid else get_cached_assets()
    asset_uuids = asset_uuids_for_tag(assets, tag_uuid)
    tag_filter = resolve_tag_meta(assets, tag_uuid) if tag_uuid else None
    if asset_uuids is None:
        refresh_monthly_snapshots()
    data = compute_lumin_metrics(asset_uuids=asset_uuids, tag_filter=tag_filter)
    if tag_filter:
        data["tag_filter"]["asset_count"] = len(asset_uuids or ())
    if (data.get("now") or {}).get("active", 0) == 0:
        if count_vulnerabilities() == 0:
            data["warning"] = (
                "No vulnerability data in local database. "
                "Run a sync from Tenable first."
            )
        elif tag_uuid and asset_uuids is not None and len(asset_uuids) == 0:
            data["warning"] = (
                "No assets in cache match the selected tag. "
                "Refresh asset inventory or choose another tag."
            )
    return data
