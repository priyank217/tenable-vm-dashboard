import json
import logging

logger = logging.getLogger(__name__)


def parse_chunk_payload(content: str | bytes) -> list[dict]:
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace").strip()
    else:
        text = (content or "").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [row for row in parsed if isinstance(row, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                findings.append(row)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed NDJSON line in export chunk")
    return findings
