import json


def _normalize_filters(job_filters) -> dict:
    if job_filters is None:
        return {}
    if isinstance(job_filters, str):
        try:
            job_filters = json.loads(job_filters)
        except ValueError:
            return {}
    return job_filters if isinstance(job_filters, dict) else {}


def asset_filters_match(job_filters, expected: dict) -> bool:
    if not expected:
        parsed = _normalize_filters(job_filters)
        ignored_zeros = {
            "since", "first_found", "last_found", "last_fixed",
            "first_seen", "last_seen", "indexed_at",
        }
        for key, val in parsed.items():
            if key in ignored_zeros and not val:
                continue
            if key == "tags" and (not val or val == {}):
                continue
            if val not in (None, 0, "", [], {}):
                return False
        return True
    parsed = _normalize_filters(job_filters)
    return parsed == expected
