import logging
import time
from typing import Callable

from config import (
    CHUNK_DOWNLOAD_DELAY_SEC,
    CHUNK_DOWNLOAD_TIMEOUT_SEC,
    VULN_EXPORT_INCLUDE_UNLICENSED,
    VULN_EXPORT_NUM_ASSETS,
    VULN_EXPORT_SEVERITY_MODIFICATION_TYPES,
    VULN_FULL_SYNC_SINCE,
    VULN_SYNC_POLL_INTERVAL_SEC,
    VULN_SYNC_POLL_MAX_ATTEMPTS,
)
from services.tenable_client import TenableApiError, TenableClient
from utils.vuln_chunk_parser import parse_chunk_payload

logger = logging.getLogger(__name__)

# Sync: include NONE + RECASTED + ACCEPTED so recast/accept changes update SQLite.
# Dashboard metrics still filter severity_modification_type = NONE at query time.
BASE_EXPORT_FILTERS = {
    "severity_modification_type": list(VULN_EXPORT_SEVERITY_MODIFICATION_TYPES),
    "state": ["OPEN", "REOPENED", "FIXED"],
    "vpr_score": {"gte": 0.1},
}


class VulnExportService:
    def __init__(self, client=None, *, filters=None, include_plugin_output=None):
        self.client = client or TenableClient()
        self.filters = dict(filters or {})
        self.include_plugin_output = include_plugin_output

    def _export_body(self) -> dict:
        body = {
            "num_assets": VULN_EXPORT_NUM_ASSETS,
            "include_unlicensed": VULN_EXPORT_INCLUDE_UNLICENSED,
            "filters": self.filters,
        }
        if self.include_plugin_output is not None:
            body["include_plugin_output"] = bool(self.include_plugin_output)
        return body

    def request_export(self) -> str:
        try:
            data = self.client.post("/vulns/export", self._export_body())
            return data["export_uuid"]
        except TenableApiError as err:
            if err.status_code == 409:
                active = (err.body or {}).get("active_job_id")
                if active:
                    return active
            raise

    def poll_export_status(
        self,
        export_uuid: str,
        *,
        on_poll: Callable[[int, int, dict], None] | None = None,
    ) -> dict:
        for attempt in range(1, VULN_SYNC_POLL_MAX_ATTEMPTS + 1):
            status = self.client.get(f"/vulns/export/{export_uuid}/status")
            state = status.get("status")
            if on_poll:
                on_poll(attempt, VULN_SYNC_POLL_MAX_ATTEMPTS, status)
            logger.info(
                "Export %s status: %s (poll %d/%d)",
                export_uuid,
                state,
                attempt,
                VULN_SYNC_POLL_MAX_ATTEMPTS,
            )

            if state == "FINISHED":
                failed = status.get("chunks_failed") or []
                if failed:
                    logger.warning(
                        "Export %s finished with %d failed chunk(s): %s",
                        export_uuid,
                        len(failed),
                        failed,
                    )
                return status
            if state == "ERROR":
                raise RuntimeError(
                    "Vulnerability export failed. Retry the request or contact Tenable Support."
                )
            if state == "CANCELLED":
                raise RuntimeError("Vulnerability export was cancelled.")

            if attempt < VULN_SYNC_POLL_MAX_ATTEMPTS:
                time.sleep(VULN_SYNC_POLL_INTERVAL_SEC)

        raise RuntimeError(
            "Vulnerability export timed out while waiting for completion."
        )

    def download_chunk(self, export_uuid: str, chunk_id: int) -> list[dict]:
        response = self.client.get(
            f"/vulns/export/{export_uuid}/chunks/{chunk_id}",
            timeout=CHUNK_DOWNLOAD_TIMEOUT_SEC,
            raw=True,
        )
        return parse_chunk_payload(response.content)

    def run_export(self) -> tuple[str, list[tuple[int, list[dict]]]]:
        export_uuid = self.request_export()
        final_status = self.poll_export_status(export_uuid)
        chunks = sorted(final_status.get("chunks_available") or [])
        results = []
        for index, chunk_id in enumerate(chunks):
            batch = self.download_chunk(export_uuid, chunk_id)
            results.append((chunk_id, batch))
            if index < len(chunks) - 1 and CHUNK_DOWNLOAD_DELAY_SEC > 0:
                time.sleep(CHUNK_DOWNLOAD_DELAY_SEC)
        return export_uuid, results


def build_export_filters(*, since: int | None = None, full: bool = False) -> dict:
    filters = dict(BASE_EXPORT_FILTERS)
    if full:
        filters["since"] = VULN_FULL_SYNC_SINCE
    elif since is not None:
        filters["since"] = since
    return filters


def build_open_set_filters() -> dict:
    filters = dict(BASE_EXPORT_FILTERS)
    filters["state"] = ["OPEN", "REOPENED"]
    filters["since"] = 0
    return filters
