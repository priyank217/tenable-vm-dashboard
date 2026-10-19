import time

import requests

from config import (
    API_RETRY_BACKOFF_SEC,
    API_RETRY_MAX_ATTEMPTS,
    TENABLE_ACCESS_KEY,
    TENABLE_SECRET_KEY,
    TENABLE_BASE_URL,
)


class TenableApiError(Exception):
    def __init__(self, message, status_code=None, body=None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class TenableClient:
    def __init__(self, base_url=TENABLE_BASE_URL, access_key=TENABLE_ACCESS_KEY, secret_key=TENABLE_SECRET_KEY):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        })

    def _request(self, method, path, json_body=None, params=None, timeout=120, raw=False):
        url = f"{self.base_url}{path}"
        last_error = None

        for attempt in range(API_RETRY_MAX_ATTEMPTS):
            response = self.session.request(
                method, url, json=json_body, params=params, timeout=timeout
            )

            if response.status_code == 429:
                wait = API_RETRY_BACKOFF_SEC * (attempt + 1)
                time.sleep(wait)
                continue

            if raw:
                if not response.ok:
                    raise TenableApiError(
                        f"Request failed with status {response.status_code}",
                        response.status_code,
                        response.text,
                    )
                return response

            data = None
            if response.content:
                try:
                    data = response.json()
                except ValueError:
                    content_type = response.headers.get("content-type", "")
                    if "application/json" in content_type:
                        data = None

            if not response.ok:
                message = "Request failed"
                if isinstance(data, dict):
                    message = data.get("message") or data.get("error") or message
                last_error = TenableApiError(message, response.status_code, data)
                if response.status_code >= 500 and attempt < API_RETRY_MAX_ATTEMPTS - 1:
                    time.sleep(API_RETRY_BACKOFF_SEC * (attempt + 1))
                    continue
                raise last_error

            return data

        if last_error:
            raise last_error
        raise TenableApiError("Request failed after retries")

    def get(self, path, params=None, timeout=120, raw=False):
        return self._request("GET", path, params=params, timeout=timeout, raw=raw)

    def post(self, path, body=None):
        return self._request("POST", path, body)

    def put(self, path, body=None):
        return self._request("PUT", path, body)

    def delete(self, path):
        return self._request("DELETE", path)
