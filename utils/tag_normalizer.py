def _normalize_category_key(key):
    return (key or "").strip() or "Uncategorized"


def tag_fields(tag):
    return {
        "uuid": tag.get("uuid") or tag.get("tag_uuid") or "",
        "key": tag.get("key") or tag.get("tag_key") or tag.get("category_name") or "",
        "value": tag.get("value") or tag.get("tag_value") or "",
        "addedBy": tag.get("added_by") or tag.get("created_by") or "",
        "addedAt": tag.get("added_at") or tag.get("created_at") or "",
        "source": tag.get("source") or "",
    }


def _tag_dedupe_key(tag):
    fields = tag_fields(tag)
    if fields["uuid"]:
        return f"uuid:{fields['uuid']}"
    return f"kv:{fields['key'].lower()}:{fields['value'].lower()}"


def normalize_tag_value(raw):
    tag_type = raw.get("type") or "static"
    return {
        "uuid": raw.get("uuid", ""),
        "key": _normalize_category_key(raw.get("category_name", "")),
        "value": (raw.get("value") or "").strip(),
        "type": tag_type,
        "categoryUuid": raw.get("category_uuid", ""),
        "description": raw.get("description", ""),
        "added": raw.get("created_at", ""),
        "updatedAt": raw.get("updated_at", ""),
        "assets": 0,
    }


def normalize_tag_values(raw_values):
    seen = set()
    tags = []
    for raw in raw_values:
        value = (raw.get("value") or "").strip()
        if not value:
            continue
        tag = normalize_tag_value(raw)
        dedupe_key = _tag_dedupe_key(tag)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        tags.append(tag)
    return tags


def dedupe_tags(tags):
    seen = set()
    result = []
    for tag in tags:
        dedupe_key = _tag_dedupe_key(tag)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        result.append(tag)
    return result


def _category_type_label(static_count, dynamic_count):
    if dynamic_count > 0 and static_count > 0:
        return "Mixed"
    if dynamic_count > 0:
        return "Dynamic"
    return "Static"


def count_unique_assets_per_category(assets, registry_tags=None):
    registry_tags = registry_tags or []
    uuid_to_category = {}
    for tag in registry_tags:
        uuid = tag.get("uuid")
        if uuid:
            uuid_to_category[uuid] = _normalize_category_key(tag.get("key"))

    counts = {}
    for asset in assets:
        seen_cats = set()
        for tag in asset.get("tags") or []:
            fields = tag_fields(tag)
            cat = uuid_to_category.get(fields["uuid"]) or _normalize_category_key(fields["key"])
            if not cat or cat in seen_cats:
                continue
            seen_cats.add(cat)
            counts[cat] = counts.get(cat, 0) + 1
    return counts


def count_assets_for_category_values(assets, values):
    tag_uuids = {value.get("uuid") for value in values if value.get("uuid")}
    if not tag_uuids:
        return 0

    count = 0
    for asset in assets:
        asset_uuids = {
            tag_fields(tag)["uuid"]
            for tag in (asset.get("tags") or [])
            if tag_fields(tag)["uuid"]
        }
        if asset_uuids & tag_uuids:
            count += 1
    return count


def count_tagged_assets(assets):
    return sum(1 for asset in assets if asset.get("tags"))


def enrich_categories(categories, assets, registry_tags=None):
    unique_counts = count_unique_assets_per_category(assets, registry_tags) if assets else {}
    for category in categories:
        values = category.get("values") or []
        cat_name = category["category"]
        asset_count = unique_counts.get(cat_name, 0)
        if assets and not asset_count:
            asset_count = count_assets_for_category_values(assets, values)
        if not asset_count and values:
            asset_count = max((value.get("assets", 0) for value in values), default=0)
        category["assetCount"] = asset_count
        category["typeLabel"] = _category_type_label(
            category.get("staticCount", 0),
            category.get("dynamicCount", 0),
        )
    return categories


def group_tags_by_category(tags):
    groups = {}
    for tag in tags:
        category = tag["key"]
        if category not in groups:
            groups[category] = {
                "category": category,
                "categoryUuid": tag.get("categoryUuid", ""),
                "values": [],
                "assetCount": 0,
                "staticCount": 0,
                "dynamicCount": 0,
                "typeLabel": "Static",
            }
        group = groups[category]
        group["values"].append(tag)
        if tag.get("type") == "dynamic":
            group["dynamicCount"] += 1
        else:
            group["staticCount"] += 1

    for group in groups.values():
        group["values"].sort(key=lambda item: item.get("value", "").lower())
        group["typeLabel"] = _category_type_label(
            group["staticCount"],
            group["dynamicCount"],
        )

    return sorted(groups.values(), key=lambda item: item["category"].lower())


def count_assets_per_tag(assets):
    counts = {}
    for asset in assets:
        seen = set()
        for tag in asset.get("tags") or []:
            tag_uuid = tag_fields(tag)["uuid"]
            dedupe_key = tag_uuid or _tag_dedupe_key(tag)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            if tag_uuid:
                counts[tag_uuid] = counts.get(tag_uuid, 0) + 1
            else:
                compound = f"{tag_fields(tag)['key']}:{tag_fields(tag)['value']}"
                counts[compound] = counts.get(compound, 0) + 1
    return counts


def apply_asset_counts(tags, assets):
    counts = count_assets_per_tag(assets)
    for tag in tags:
        if tag.get("uuid") and tag["uuid"] in counts:
            tag["assets"] = counts[tag["uuid"]]
        else:
            compound = f"{tag['key']}:{tag['value']}"
            tag["assets"] = counts.get(compound, 0)
    return tags
