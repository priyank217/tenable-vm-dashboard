import logging
import time
from typing import Any

from config import CACHE_TTL_SEC
from services.tenable_client import TenableApiError, TenableClient

logger = logging.getLogger(__name__)

_cache: dict[str, Any] = {
    "fetched_at": 0.0,
    "by_id": {},
    "by_plugin": {},
}


def _walk_filter(node: Any, plugin_ids: list[str]) -> None:
    if isinstance(node, dict):
        prop = str(node.get("property") or "").lower().replace(" ", "_")
        if prop in ("plugin_id", "pluginid", "definition.id", "definition_id"):
            value = node.get("value")
            if isinstance(value, list):
                plugin_ids.extend(str(v) for v in value if v is not None)
            elif value is not None:
                plugin_ids.append(str(value))
        for child in node.values():
            _walk_filter(child, plugin_ids)
    elif isinstance(node, list):
        for child in node:
            _walk_filter(child, plugin_ids)


def _plugin_ids_from_rule_name(rule_name: str) -> list[str]:
    import re

    match = re.search(r"Plugin ID:\s*(\d+)", rule_name or "", re.IGNORECASE)
    return [match.group(1)] if match else []


def _rule_summary(rule: dict) -> dict:
    rule_value = rule.get("rule_value") or {}
    action = str(rule_value.get("action") or "").upper()
    plugin_ids: list[str] = []
    _walk_filter(rule.get("filter"), plugin_ids)
    if not plugin_ids:
        plugin_ids.extend(_plugin_ids_from_rule_name(rule.get("rule_name") or ""))
    return {
        "rule_id": rule.get("rule_id") or "",
        "action": action,
        "created_at": rule.get("created_at") or "",
        "expires_at": rule.get("expires_at") or "",
        "rule_name": rule.get("rule_name") or "",
        "plugin_ids": plugin_ids,
    }


def _fetch_all_host_rules(client: TenableClient) -> list[dict]:
    rules: list[dict] = []
    next_token = None
    while True:
        body: dict[str, Any] = {
            "resource_type": ["HOST"],
            "limit": 500,
        }
        if next_token:
            body["next"] = next_token
        data = client.post("/v1/recast/rules/search", body) or {}
        batch = data.get("rules") or data.get("items") or []
        if isinstance(batch, list):
            rules.extend(batch)
        next_token = data.get("next")
        if not next_token:
            break
    return rules


def get_recast_rules_index(*, force_refresh: bool = False) -> dict[str, dict]:
    ttl = max(CACHE_TTL_SEC, 300)
    now = time.time()
    if not force_refresh and _cache["by_id"] and (now - _cache["fetched_at"]) < ttl:
        return {"by_id": _cache["by_id"], "by_plugin": _cache["by_plugin"]}

    by_id: dict[str, dict] = {}
    by_plugin: dict[str, dict] = {}
    try:
        client = TenableClient()
        for rule in _fetch_all_host_rules(client):
            summary = _rule_summary(rule)
            rule_id = summary["rule_id"]
            if rule_id:
                by_id[rule_id] = summary
            for plugin_id in summary["plugin_ids"]:
                existing = by_plugin.get(plugin_id)
                if not existing or summary["created_at"] > existing.get("created_at", ""):
                    by_plugin[plugin_id] = summary
    except TenableApiError as err:
        logger.warning("Recast rules fetch failed: %s", err)
        if _cache["by_id"]:
            return {"by_id": _cache["by_id"], "by_plugin": _cache["by_plugin"]}

    _cache["fetched_at"] = now
    _cache["by_id"] = by_id
    _cache["by_plugin"] = by_plugin
    return {"by_id": by_id, "by_plugin": by_plugin}


def lookup_rule_dates(
    *,
    rule_id: str | None,
    plugin_id: str | None,
    modification_type: str,
    rules_index: dict[str, dict] | None = None,
) -> tuple[str, str, str]:
    index = rules_index or get_recast_rules_index()
    by_id = index.get("by_id") or {}
    by_plugin = index.get("by_plugin") or {}

    rule = None
    if rule_id and rule_id in by_id:
        rule = by_id[rule_id]
    elif plugin_id and plugin_id in by_plugin:
        rule = by_plugin[plugin_id]

    mod = (modification_type or "").upper()
    if rule:
        action = rule.get("action") or ""
        if action in ("ACCEPT", "ACCEPT_RESULT"):
            label = "Accept"
        elif action in ("RECAST", "CHANGE_RESULT"):
            label = "Recast"
        else:
            label = "Accept" if mod == "ACCEPTED" else "Recast"
        return label, rule.get("created_at") or "", rule.get("expires_at") or ""

    return ("Accept" if mod == "ACCEPTED" else "Recast", "", "")
