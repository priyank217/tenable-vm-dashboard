"""Tags CRUD and asset–tag assignment API routes."""

from flask import Blueprint, jsonify, request

from config import TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
from routes.helpers import (
    asset_cache,
    cached_fetch,
    credentials_error,
    fetch_tags_from_tenable,
    parse_tag_assignment_body,
    refresh_flag,
    tags_api_payload,
    tags_cache,
    tenable_error,
)
from services.tags_service import TagsService

bp = Blueprint("tags", __name__)


@bp.get("/api/tags")
def list_tags():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        payload, err = cached_fetch(
            tags_cache,
            force_refresh=refresh_flag(),
            fetch_fn=fetch_tags_from_tenable,
            format_fn=lambda entry: tags_api_payload(entry, cached=True),
        )
        if err:
            return jsonify(payload)
        return jsonify(payload)
    except Exception as err:
        return tenable_error(err)


@bp.post("/api/tags")
def create_tag():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    body = request.get_json(silent=True) or {}
    category = (body.get("category") or body.get("category_name") or "").strip()
    value = (body.get("value") or "").strip()
    description = (body.get("description") or "").strip()

    if not category or not value:
        return jsonify({"error": "category and value are required"}), 400

    try:
        service = TagsService()
        result = service.create_tag_value(
            category_name=category,
            value=value,
            description=description,
        )
        tags_cache.invalidate()
        asset_cache.invalidate()
        return jsonify(result), 201
    except Exception as err:
        return tenable_error(err)


@bp.put("/api/tags/<tag_uuid>")
def update_tag(tag_uuid):
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    body = request.get_json(silent=True) or {}
    value = body.get("value")
    description = body.get("description")

    if value is None and description is None:
        return jsonify({"error": "value or description is required"}), 400

    try:
        service = TagsService()
        result = service.update_tag_value(
            tag_uuid,
            value=value.strip() if isinstance(value, str) else value,
            description=description.strip() if isinstance(description, str) else description,
        )
        tags_cache.invalidate()
        return jsonify(result)
    except Exception as err:
        return tenable_error(err)


@bp.delete("/api/tags/<tag_uuid>")
def delete_tag(tag_uuid):
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        service = TagsService()
        service.delete_tag_value(tag_uuid)
        tags_cache.invalidate()
        asset_cache.invalidate()
        return jsonify({"ok": True})
    except Exception as err:
        return tenable_error(err)


@bp.get("/api/assets/<asset_uuid>/tags")
def get_asset_tags(asset_uuid):
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    try:
        service = TagsService()
        result = service.list_asset_tag_assignments(asset_uuid)
        return jsonify(result)
    except Exception as err:
        return tenable_error(err)


@bp.post("/api/assets/tags/assignments")
def assign_asset_tags():
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    body = request.get_json(silent=True) or {}
    try:
        action, assets, tags = parse_tag_assignment_body(body)
        service = TagsService()
        tag_uuids = service.resolve_tag_uuids(tags)
        result = service.assign_tags_to_assets(
            action=action,
            asset_uuids=assets,
            tag_uuids=tag_uuids,
        )
        asset_cache.invalidate()
        tags_cache.invalidate()
        return jsonify({
            "ok": True,
            "action": action,
            "assets": assets,
            "tags": tag_uuids,
            "tenable": result,
        })
    except Exception as err:
        return tenable_error(err)


@bp.post("/api/assets/<asset_uuid>/tags")
def update_asset_tags(asset_uuid):
    if not TENABLE_ACCESS_KEY or not TENABLE_SECRET_KEY:
        return credentials_error()

    body = request.get_json(silent=True) or {}
    try:
        action = (body.get("action") or "").strip().lower()
        tags = body.get("tags") or body.get("tag_uuids") or body.get("tag_values") or []
        if not isinstance(tags, list):
            raise ValueError("tags must be an array of tag UUIDs or {category, value} objects.")
        service = TagsService()
        tag_uuids = service.resolve_tag_uuids(tags)
        result = service.assign_tags_to_assets(
            action=action,
            asset_uuids=[asset_uuid],
            tag_uuids=tag_uuids,
        )
        asset_cache.invalidate()
        tags_cache.invalidate()
        return jsonify({
            "ok": True,
            "action": action,
            "asset": asset_uuid,
            "tags": tag_uuids,
            "tenable": result,
        })
    except Exception as err:
        return tenable_error(err)
