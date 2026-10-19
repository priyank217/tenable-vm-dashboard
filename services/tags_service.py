from services.tenable_client import TenableApiError, TenableClient


class TagsService:
    PAGE_SIZE = 1000
    VALID_ASSIGN_ACTIONS = ("add", "remove")

    def __init__(self, client=None):
        self.client = client or TenableClient()

    def list_tag_values_page(self, *, limit=None, offset=0, search=None, category=None):
        params = {
            "limit": limit or self.PAGE_SIZE,
            "offset": offset,
            "sort": "category_name:asc,value:asc",
        }
        if search:
            params["wf"] = "category_name,value"
            params["w"] = search
        if category:
            params["f"] = f"category_name:eq:{category}"
        return self.client.get("/tags/values", params=params) or {}

    def list_all_tag_values(self, *, search=None, category=None):
        all_values = []
        offset = 0
        while True:
            data = self.list_tag_values_page(offset=offset, search=search, category=category)
            values = data.get("values") or []
            all_values.extend(values)
            pagination = data.get("pagination") or {}
            total = pagination.get("total", len(all_values))
            offset += self.PAGE_SIZE
            if offset >= total or not values:
                break
        return all_values

    def create_tag_value(self, *, category_name, value, description=""):
        body = {
            "category_name": category_name,
            "value": value,
        }
        if description:
            body["description"] = description
        return self.client.post("/tags/values", body)

    def update_tag_value(self, tag_uuid, *, value=None, description=None):
        body = {}
        if value is not None:
            body["value"] = value
        if description is not None:
            body["description"] = description
        return self.client.put(f"/tags/values/{tag_uuid}", body)

    def delete_tag_value(self, tag_uuid):
        return self.client.delete(f"/tags/values/{tag_uuid}")

    def find_tag_value_uuid(self, *, category_name: str, value: str) -> str | None:
        category_name = (category_name or "").strip()
        value = (value or "").strip()
        if not category_name or not value:
            return None
        for tag in self.list_all_tag_values(category=category_name):
            tag_category = (tag.get("category_name") or tag.get("category") or "").strip()
            tag_value = (tag.get("value") or "").strip()
            if tag_category.lower() == category_name.lower() and tag_value.lower() == value.lower():
                return tag.get("uuid")
        return None

    def resolve_tag_uuids(self, tags: list) -> list[str]:
        if not tags:
            raise ValueError("At least one tag is required.")

        uuids: list[str] = []
        missing: list[str] = []

        for item in tags:
            if isinstance(item, str):
                tag_uuid = item.strip()
                if tag_uuid:
                    uuids.append(tag_uuid)
                continue

            if not isinstance(item, dict):
                raise ValueError("Each tag must be a UUID string or {category, value} object.")

            tag_uuid = (item.get("uuid") or item.get("tag_uuid") or "").strip()
            if tag_uuid:
                uuids.append(tag_uuid)
                continue

            category = (item.get("category") or item.get("category_name") or item.get("key") or "").strip()
            value = (item.get("value") or "").strip()
            if not category or not value:
                raise ValueError("Tag objects require uuid or category + value.")

            resolved = self.find_tag_value_uuid(category_name=category, value=value)
            if resolved:
                uuids.append(resolved)
            else:
                missing.append(f"{category}:{value}")

        if missing:
            raise ValueError(f"Tag value(s) not found: {', '.join(missing)}")

        seen: set[str] = set()
        unique: list[str] = []
        for tag_uuid in uuids:
            if tag_uuid not in seen:
                seen.add(tag_uuid)
                unique.append(tag_uuid)
        return unique

    def assign_tags_to_assets(
        self,
        *,
        action: str,
        asset_uuids: list[str],
        tag_uuids: list[str],
    ) -> dict:
        action = (action or "").strip().lower()
        if action not in self.VALID_ASSIGN_ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(self.VALID_ASSIGN_ACTIONS)}")

        assets = [a.strip() for a in asset_uuids if a and str(a).strip()]
        tags = [t.strip() for t in tag_uuids if t and str(t).strip()]

        if not assets:
            raise ValueError("At least one asset UUID is required.")
        if not tags:
            raise ValueError("At least one tag value UUID is required.")

        return self.client.post(
            "/tags/assets/assignments",
            {
                "action": action,
                "assets": assets,
                "tags": tags,
            },
        )

    def list_asset_tag_assignments(self, asset_uuid: str) -> dict:
        asset_uuid = (asset_uuid or "").strip()
        if not asset_uuid:
            raise ValueError("asset UUID is required.")
        return self.client.get(f"/tags/assets/{asset_uuid}/assignments")
