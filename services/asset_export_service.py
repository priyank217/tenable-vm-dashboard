import logging
import time

from config import (
    CHUNK_SIZE,
    EXPORT_FILTERS,
    INCLUDE_OPEN_PORTS,
    POLL_INTERVAL_SEC,
    POLL_MAX_ATTEMPTS,
)
from services.tenable_client import TenableApiError, TenableClient
from utils.export_filter_match import asset_filters_match

logger = logging.getLogger(__name__)


def _is_stale_export_error(err: Exception) -> bool:
    if isinstance(err, TenableApiError):
        if err.status_code in (404, 410):
            return True
        msg = str(err).lower()
        return "expired" in msg or "not found" in msg
    return False


class AssetExportService:
    def __init__(self, client=None):
        self.client = client or TenableClient()
        self.export_body = {
            "chunk_size": CHUNK_SIZE,
            "include_open_ports": INCLUDE_OPEN_PORTS,
            "filters": EXPORT_FILTERS,
        }

    @staticmethod
    def _filters_match(job_filters):
        return asset_filters_match(job_filters, EXPORT_FILTERS)

    def find_reusable_export_job(self):
        data = self.client.get("/assets/export/status") or {}
        exports = data.get("exports") or []
        candidates = []
        for job in exports:
            if not self._filters_match(job.get("filters")):
                continue
            status = job.get("status")
            if status in ("QUEUED", "PROCESSING"):
                candidates.append(job)
            elif status == "FINISHED" and not INCLUDE_OPEN_PORTS:
                candidates.append(job)
        if not candidates:
            return None
        candidates.sort(key=lambda j: j.get("created") or 0, reverse=True)
        finished = [j for j in candidates if j.get("status") == "FINISHED"]
        if finished:
            return finished[0]
        in_flight = [j for j in candidates if j.get("status") in ("QUEUED", "PROCESSING")]
        return in_flight[0] if in_flight else None

    def request_export(self):
        try:
            data = self.client.post("/assets/v2/export", self.export_body)
            return data["export_uuid"]
        except TenableApiError as err:
            if err.status_code == 409:
                existing = self.find_reusable_export_job()
                if existing and existing.get("uuid"):
                    return existing["uuid"]
            raise

    def poll_export_status(self, export_uuid):
        for _ in range(POLL_MAX_ATTEMPTS):
            status = self.client.get(f"/assets/export/{export_uuid}/status")
            state = status.get("status")

            if state == "FINISHED":
                return status
            if state == "ERROR":
                raise RuntimeError(
                    "Asset export failed. Retry the request or contact Tenable Support."
                )
            if state == "CANCELLED":
                raise RuntimeError("Asset export was cancelled.")

            time.sleep(POLL_INTERVAL_SEC)

        raise RuntimeError("Asset export timed out while waiting for completion.")

    def download_chunks(self, export_uuid, chunks_available):
        assets = []
        for chunk_id in sorted(chunks_available):
            chunk = self.client.get(f"/assets/export/{export_uuid}/chunks/{chunk_id}")
            if isinstance(chunk, list):
                assets.extend(chunk)
        return assets

    def _download_finished_export(self, export_uuid: str) -> list:
        final_status = self.client.get(f"/assets/export/{export_uuid}/status")
        chunks = final_status.get("chunks_available") or []
        if not chunks:
            return []
        return self.download_chunks(export_uuid, chunks)

    def _start_new_export(self) -> list:
        logger.info("Requesting new asset export")
        export_uuid = self.request_export()
        final_status = self.poll_export_status(export_uuid)
        chunks = final_status.get("chunks_available") or []
        if not chunks:
            return []
        return self.download_chunks(export_uuid, chunks)

    def export_all_assets(self):
        reusable = self.find_reusable_export_job()

        if reusable and reusable.get("status") == "FINISHED":
            export_uuid = reusable["uuid"]
            logger.info(
                "Reusing FINISHED asset export %s — skipping new export request",
                export_uuid,
            )
            try:
                return self._download_finished_export(export_uuid)
            except TenableApiError as err:
                if not _is_stale_export_error(err):
                    raise
                logger.warning(
                    "Asset export %s expired or missing — starting a new export",
                    export_uuid,
                )
                return self._start_new_export()

        if reusable and reusable.get("status") in ("QUEUED", "PROCESSING"):
            export_uuid = reusable["uuid"]
            logger.info(
                "Reusing in-flight asset export %s (%s)",
                export_uuid,
                reusable.get("status"),
            )
            final_status = self.poll_export_status(export_uuid)
            chunks = final_status.get("chunks_available") or []
            if not chunks:
                return []
            return self.download_chunks(export_uuid, chunks)

        return self._start_new_export()
