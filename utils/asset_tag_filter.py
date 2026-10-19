"""Resolve asset UUIDs for dashboard tag filtering from cached asset export data."""

from utils.tag_normalizer import tag_fields


def resolve_tag_meta(assets: list[dict], tag_uuid: str | None) -> dict | None:
    if not tag_uuid:
        return None
    tag_uuid = tag_uuid.strip()
    if not tag_uuid:
        return None

    for asset in assets:
        for tag in asset.get("tags") or []:
            fields = tag_fields(tag)
            if fields["uuid"] == tag_uuid:
                category = fields["key"] or "Uncategorized"
                value = fields["value"] or ""
                return {
                    "uuid": tag_uuid,
                    "category": category,
                    "value": value,
                    "label": f"{category}: {value}" if value else category,
                }
    return {
        "uuid": tag_uuid,
        "category": "",
        "value": "",
        "label": tag_uuid,
    }


def asset_uuids_for_tag(assets: list[dict], tag_uuid: str | None) -> frozenset[str] | None:
    if not tag_uuid or not str(tag_uuid).strip():
        return None

    tag_uuid = str(tag_uuid).strip()
    matched: set[str] = set()
    for asset in assets:
        asset_id = asset.get("id")
        if not asset_id:
            continue
        for tag in asset.get("tags") or []:
            if tag_fields(tag)["uuid"] == tag_uuid:
                matched.add(str(asset_id))
                break
    return frozenset(matched)


def tag_options_for_dashboard(assets: list[dict], registry_tags: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}

    for tag in registry_tags:
        uuid = (tag.get("uuid") or "").strip()
        if not uuid:
            continue
        key = tag.get("key") or ""
        value = tag.get("value") or ""
        labels[uuid] = f"{key}: {value}" if value else key

    for asset in assets:
        seen: set[str] = set()
        for tag in asset.get("tags") or []:
            fields = tag_fields(tag)
            uuid = fields["uuid"]
            if not uuid or uuid in seen:
                continue
            seen.add(uuid)
            counts[uuid] = counts.get(uuid, 0) + 1
            if uuid not in labels:
                key = fields["key"] or "Uncategorized"
                value = fields["value"] or ""
                labels[uuid] = f"{key}: {value}" if value else key

    options = [
        {
            "uuid": uuid,
            "label": labels.get(uuid, uuid),
            "asset_count": count,
        }
        for uuid, count in counts.items()
    ]
    options.sort(key=lambda o: o["label"].lower())
    return options
