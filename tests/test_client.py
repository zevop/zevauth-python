"""The backend API client: keys, headers, wire format, pagination, retries."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List

import httpx
import pytest

from zevauth import AsyncZevAuthClient, ZevAuthClient, ZevAuthError, __version__


class Recorder:
    def __init__(self, responses: List[httpx.Response]) -> None:
        self.responses = responses
        self.requests: List[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses[min(len(self.requests), len(self.responses)) - 1]

    def client(self, **options: Any) -> ZevAuthClient:
        return ZevAuthClient(
            "sk_test_abc",
            api_url="https://api.zevauth.test",
            http_client=httpx.Client(transport=httpx.MockTransport(self.handler)),
            sleep=lambda _: None,
            **options,
        )

    def body(self, index: int = -1) -> Dict[str, Any]:
        return json.loads(self.requests[index].content or b"null")


def test_refuses_a_missing_or_publishable_key() -> None:
    with pytest.raises(ZevAuthError) as missing:
        ZevAuthClient("")
    assert missing.value.code == "missing_secret_key"
    with pytest.raises(ZevAuthError) as wrong:
        ZevAuthClient("pk_live_abc")
    assert wrong.value.code == "wrong_key_type"


def test_sends_the_key_and_the_user_agent() -> None:
    recorder = Recorder([httpx.Response(200, json={"id": "user_1"})])
    recorder.client().users.get("user_1")
    request = recorder.requests[0]
    assert request.headers["authorization"] == "Bearer sk_test_abc"
    assert request.headers["user-agent"] == f"zevauth-python/{__version__}"
    assert "idempotency-key" not in request.headers


def test_ids_are_encoded_into_paths() -> None:
    recorder = Recorder([httpx.Response(200, json={})])
    recorder.client().organizations.remove_member("org/1", "user 2")
    assert recorder.requests[0].url.raw_path == b"/v1/organizations/org%2F1/members/user%202"


def test_keyword_arguments_go_out_in_camel_case_and_unset_is_left_out() -> None:
    recorder = Recorder([httpx.Response(200, json={"id": "user_1"})])
    client = recorder.client()
    client.users.create(email="a@example.com", first_name="Ada", public_metadata={"plan": "pro"})
    assert recorder.body() == {"email": "a@example.com", "firstName": "Ada", "publicMetadata": {"plan": "pro"}}
    client.users.update("user_1", last_name=None)
    assert recorder.body() == {"lastName": None}  # None clears; leaving it out keeps it
    client.organizations.update("org_1", require_mfa=True)
    assert recorder.body() == {"requireMfa": True}


def test_list_filters_and_metadata() -> None:
    recorder = Recorder([httpx.Response(200, json={"data": [], "hasMore": False, "next": None, "totalCount": 0})])
    recorder.client().users.list(limit=10, metadata={"plan": "pro", "beta": True})
    params = dict(recorder.requests[0].url.params)
    assert params == {"limit": "10", "metadata[plan]": "pro", "metadata[beta]": "true"}


def test_reset_mfa_only_revokes_sessions_when_asked() -> None:
    recorder = Recorder([httpx.Response(200, json={})])
    client = recorder.client()
    client.users.reset_mfa("user_1")
    client.users.reset_mfa("user_1", revoke_sessions=True)
    assert recorder.requests[0].method == "DELETE"
    assert recorder.requests[0].url.query == b""
    assert recorder.requests[1].url.params["revokeSessions"] == "true"


def test_iterate_follows_the_cursor() -> None:
    pages = [
        httpx.Response(
            200, json={"data": [{"id": "u1"}, {"id": "u2"}], "hasMore": True, "next": "c1", "totalCount": 3}
        ),
        httpx.Response(200, json={"data": [{"id": "u3"}], "hasMore": False, "next": None, "totalCount": 3}),
    ]
    recorder = Recorder(pages)
    assert [u["id"] for u in recorder.client().users.iterate(limit=2)] == ["u1", "u2", "u3"]
    assert recorder.requests[1].url.params["after"] == "c1"


def test_network_failures_retry_then_report_network_error() -> None:
    calls: List[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("refused", request=request)

    client = ZevAuthClient(
        "sk_test_abc",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=lambda _: None,
    )
    with pytest.raises(ZevAuthError) as failed:
        client.users.get("user_1")
    assert (failed.value.code, failed.value.status, len(calls)) == ("network_error", 0, 3)


def test_backoff_without_retry_after() -> None:
    waits: List[float] = []
    recorder = Recorder([httpx.Response(503)])
    client = ZevAuthClient(
        "sk_test_abc",
        http_client=httpx.Client(transport=httpx.MockTransport(recorder.handler)),
        sleep=waits.append,
        max_retries=3,
    )
    with pytest.raises(ZevAuthError):
        client.users.get("user_1")
    assert waits == [0.2, 0.4, 0.8]


def test_retry_after_is_capped_at_ten_seconds() -> None:
    waits: List[float] = []
    recorder = Recorder([httpx.Response(429, headers={"retry-after": "3600"})])
    client = ZevAuthClient(
        "sk_test_abc",
        http_client=httpx.Client(transport=httpx.MockTransport(recorder.handler)),
        sleep=waits.append,
        max_retries=1,
    )
    with pytest.raises(ZevAuthError):
        client.users.get("user_1")
    assert waits == [10.0]


def test_a_retry_that_succeeds_returns_the_result() -> None:
    recorder = Recorder([httpx.Response(502), httpx.Response(200, json={"id": "user_1"})])
    assert recorder.client().users.get("user_1")["id"] == "user_1"


def test_async_client_matches() -> None:
    pages = [
        httpx.Response(200, json={"data": [{"id": "u1"}], "hasMore": True, "next": "c1", "totalCount": 2}),
        httpx.Response(200, json={"data": [{"id": "u2"}], "hasMore": False, "next": None, "totalCount": 2}),
    ]
    recorder = Recorder(pages)

    async def run() -> List[str]:
        async def no_sleep(_: float) -> None:
            return None

        client = AsyncZevAuthClient(
            "sk_test_abc",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(recorder.handler)),
            sleep=no_sleep,
        )
        return [u["id"] async for u in client.users.iterate()]

    assert asyncio.run(run()) == ["u1", "u2"]
    assert recorder.requests[0].headers["user-agent"].startswith("zevauth-python/")


def test_async_client_never_retries_a_500() -> None:
    recorder = Recorder([httpx.Response(500, json={"error": {"code": "internal_error", "message": "x"}})])

    async def run() -> None:
        client = AsyncZevAuthClient(
            "sk_test_abc", http_client=httpx.AsyncClient(transport=httpx.MockTransport(recorder.handler))
        )
        await client.users.create(email="a@example.com")

    with pytest.raises(ZevAuthError) as failed:
        asyncio.run(run())
    assert failed.value.code == "internal_error" and len(recorder.requests) == 1
