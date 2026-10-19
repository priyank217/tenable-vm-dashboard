import json
import shutil
from pathlib import Path

from config import VULN_RAW_JSON_DIR


def raw_json_root() -> Path:
    return Path(VULN_RAW_JSON_DIR)


def save_finding_raw(raw: dict, sync_date: str) -> str:
    finding_id = raw["finding_id"]
    rel = f"{sync_date}/{finding_id}.json"
    path = raw_json_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return rel


def save_chunk_raw(
    export_uuid: str, chunk_id: int, batch: list[dict], sync_date: str
) -> str:
    rel = f"{sync_date}/chunks/export-{export_uuid}-chunk-{chunk_id}.json"
    path = raw_json_root() / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(batch, indent=2), encoding="utf-8")
    return rel


def clear_raw_storage() -> None:
    root = raw_json_root()
    if root.is_dir():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
