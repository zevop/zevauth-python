"""The transport under the API clients: retries, errors, headers.

Retry only what certainly did not run (``spec/SERVER_SDK.md`` §3.5):
429, 502, 503 and 504, and failures to connect. Never a 500: the server
ran and failed, possibly after writing, and retrying is how one
``create`` becomes two.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, Mapping, Optional

import httpx

from ._version import __version__
from .errors import ZevAuthError

DEFAULT_API_URL = "https://api.zevauth.net"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_RETRIES = 2
RETRY_STATUSES = frozenset({429, 502, 503, 504})
USER_AGENT = f"zevauth-python/{__version__}"


Query = Optional[Mapping[str, Any]]


def check_secret_key(secret_key: Optional[str]) -> str:
    if not secret_key:
        raise ZevAuthError(
            "A secret key (sk_test_… or sk_live_…) is required. Find it in the ZevAuth console under API keys.",
            "missing_secret_key",
        )
    if secret_key.startswith("pk_"):
        raise ZevAuthError(
            "That is a publishable key. The backend API needs your secret key (sk_test_… or sk_live_…); "
            "publishable keys belong in the browser.",
            "wrong_key_type",
        )
    return secret_key


def default_headers(secret_key: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def clean_query(query: Query) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in (query or {}).items():
        if value is None:
            continue
        out[key] = ("true" if value else "false") if isinstance(value, bool) else str(value)
    return out


def error_from(response: httpx.Response) -> ZevAuthError:
    """The error for a failed response: the server's code, or the default for its status."""
    request_id = response.headers.get("x-request-id")
    code = None
    message = None
    try:
        envelope = response.json()
        error = envelope.get("error") if isinstance(envelope, dict) else None
        if isinstance(error, dict):
            code = error.get("code") if isinstance(error.get("code"), str) else None
            message = error.get("message") if isinstance(error.get("message"), str) else None
    except ValueError:
        pass
    return ZevAuthError(
        message or f"ZevAuth answered {response.status_code}.",
        code or "request_failed",
        response.status_code,
        request_id,
    )


def should_retry(status: int) -> bool:
    return status in RETRY_STATUSES


def retry_after_seconds(response: httpx.Response) -> Optional[float]:
    """``Retry-After`` in seconds, capped at 10: a server asking for an hour is not worth blocking on."""
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return min(max(float(raw), 0.0), 10.0)
    except ValueError:
        return None


def backoff_seconds(attempt: int) -> float:
    """200 ms, 400 ms, 800 ms… capped at 4 s."""
    return min(0.2 * float(2 ** (attempt - 1)), 4.0)


def _decode(response: httpx.Response) -> Any:
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


class SyncTransport:
    def __init__(
        self,
        secret_key: Optional[str],
        *,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: Optional[httpx.Client] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._headers = default_headers(check_secret_key(secret_key))
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = http_client or httpx.Client()
        self._sleep = sleep

    def request(self, method: str, path: str, *, query: Query = None, body: Any = None) -> Any:
        last: Optional[ZevAuthError] = None
        wait: Optional[float] = None
        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                self._sleep(wait if wait is not None else backoff_seconds(attempt))
            wait = None
            try:
                response = self._client.request(
                    method,
                    self._api_url + path,
                    params=clean_query(query),
                    json=body,
                    headers=self._headers,
                    timeout=self._timeout,
                )
            except httpx.HTTPError as error:
                last = ZevAuthError(f"Could not reach ZevAuth: {error}", "network_error", 0)
                continue
            if response.status_code < 400:
                return _decode(response)
            last = error_from(response)
            if not should_retry(response.status_code):
                raise last
            wait = retry_after_seconds(response)
        assert last is not None
        raise last


class AsyncTransport:
    def __init__(
        self,
        secret_key: Optional[str],
        *,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: Optional[httpx.AsyncClient] = None,
        sleep: Optional[Callable[[float], Any]] = None,
    ) -> None:
        self._headers = default_headers(check_secret_key(secret_key))
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = http_client or httpx.AsyncClient()
        self._sleep = sleep or asyncio.sleep

    async def request(self, method: str, path: str, *, query: Query = None, body: Any = None) -> Any:
        last: Optional[ZevAuthError] = None
        wait: Optional[float] = None
        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                await self._sleep(wait if wait is not None else backoff_seconds(attempt))
            wait = None
            try:
                response = await self._client.request(
                    method,
                    self._api_url + path,
                    params=clean_query(query),
                    json=body,
                    headers=self._headers,
                    timeout=self._timeout,
                )
            except httpx.HTTPError as error:
                last = ZevAuthError(f"Could not reach ZevAuth: {error}", "network_error", 0)
                continue
            if response.status_code < 400:
                return _decode(response)
            last = error_from(response)
            if not should_retry(response.status_code):
                raise last
            wait = retry_after_seconds(response)
        assert last is not None
        raise last
