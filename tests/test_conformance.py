"""The shared conformance fixtures, every case, with the clock fixed to their ``now``.

Passing these is what makes this library behave like every other ZevAuth
server library: https://github.com/zevop/zevauth-sdk/tree/main/spec
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx
import pytest

from zevauth import (
    AuthRefusal,
    Request,
    TokenVerifier,
    ZevAuth,
    ZevAuthClient,
    ZevAuthError,
    ZevAuthVerifyError,
    ZevAuthWebhookError,
    bearer_from,
    bridge_cookie_names,
    verify_webhook,
)

from .conftest import API_URL, ENV, NOW, TOKENS, KeyServer, load


def verifier_for(case: Dict[str, Any], server: KeyServer) -> TokenVerifier:
    return TokenVerifier(
        ENV,
        api_url=API_URL,
        clock_skew_seconds=TOKENS["clockSkewSeconds"],
        now=lambda: NOW,
        http_client=server.client(),
        async_http_client=server.async_client(),
    )


def server_for(case: Dict[str, Any]) -> KeyServer:
    return KeyServer(case["jwks"], case.get("jwksAfterRefetch"))


def outcome(verify: Any, token: str) -> Dict[str, Any]:
    try:
        verify(token)
        return {"ok": True}
    except ZevAuthVerifyError as error:
        return {"ok": False, "error": error.code}


TOKEN_CASES = TOKENS["cases"]


@pytest.mark.parametrize("case", TOKEN_CASES, ids=[c["name"] for c in TOKEN_CASES])
def test_token_verification(case: Dict[str, Any]) -> None:
    server = server_for(case)
    assert outcome(verifier_for(case, server).verify, case["token"]) == case["expect"]


@pytest.mark.parametrize("case", TOKEN_CASES, ids=[c["name"] for c in TOKEN_CASES])
def test_token_verification_async(case: Dict[str, Any]) -> None:
    server = server_for(case)
    verifier = verifier_for(case, server)

    async def run() -> Dict[str, Any]:
        try:
            await verifier.verify_async(case["token"])
            return {"ok": True}
        except ZevAuthVerifyError as error:
            return {"ok": False, "error": error.code}

    assert asyncio.run(run()) == case["expect"]


def zevauth_for(case: Dict[str, Any]) -> ZevAuth:
    server = server_for(case)
    return ZevAuth(
        ENV,
        api_url=API_URL,
        now=lambda: NOW,
        http_client=server.client(),
        async_http_client=server.async_client(),
    )


def bearer_request(token: str) -> Request:
    return Request("GET", "https://app.example.com/", {"Authorization": f"Bearer {token}"})


def auth_view(auth: Any) -> Dict[str, Any]:
    return {
        "isSignedIn": auth.is_signed_in,
        "userId": auth.user_id,
        "sessionId": auth.session_id,
        "organizationId": auth.organization_id,
        "organizationRole": auth.organization_role,
        "pendingTasks": list(auth.pending_tasks),
        "isMfaVerified": auth.is_mfa_verified,
    }


AUTH_CASES = [c for c in TOKEN_CASES if "auth" in c]


@pytest.mark.parametrize("case", AUTH_CASES, ids=[c["name"] for c in AUTH_CASES])
def test_get_auth(case: Dict[str, Any]) -> None:
    auth = zevauth_for(case).get_auth(bearer_request(case["token"]))
    view = auth_view(auth)
    for key, value in case["auth"].items():
        assert view[key] == value, key


HAS_CASES = [(c, check) for c in TOKEN_CASES for check in c.get("has", [])]


@pytest.mark.parametrize(
    ("case", "check"),
    HAS_CASES,
    ids=[f"{c['name']}:{json.dumps(h['check'])}" for c, h in HAS_CASES],
)
def test_has(case: Dict[str, Any], check: Dict[str, Any]) -> None:
    auth = zevauth_for(case).get_auth(bearer_request(case["token"]))
    assert auth.has(**check["check"]) is check["result"]


REQUIRE_CASES = [(c, r) for c in TOKEN_CASES for r in c.get("requireAuth", [])]


def _snake(options: Dict[str, Any]) -> Dict[str, Any]:
    names = {"allowPendingTasks": "allow_pending_tasks", "requireMfa": "require_mfa"}
    return {names[key]: value for key, value in options.items()}


@pytest.mark.parametrize(
    ("case", "rule"),
    REQUIRE_CASES,
    ids=[f"{c['name']}:{json.dumps(r['options'])}" for c, r in REQUIRE_CASES],
)
def test_require_auth(case: Dict[str, Any], rule: Dict[str, Any]) -> None:
    zevauth = zevauth_for(case)
    expected = rule["result"]
    for run in (
        lambda: zevauth.require_auth(bearer_request(case["token"]), **_snake(rule["options"])),
        lambda: asyncio.run(zevauth.require_auth_async(bearer_request(case["token"]), **_snake(rule["options"]))),
    ):
        if expected["ok"]:
            assert run().is_signed_in
        else:
            with pytest.raises(AuthRefusal) as refused:
                run()
            assert (refused.value.status, refused.value.code) == (expected["status"], expected["code"])
            assert refused.value.body()["error"]["code"] == expected["code"]
            if expected["code"] == "session_task_pending":
                assert refused.value.body()["error"]["pendingTasks"] == ["setup_mfa"]


def test_get_auth_never_raises_for_any_bad_token() -> None:
    for case in TOKEN_CASES:
        if case["expect"]["ok"]:
            continue
        auth = zevauth_for(case).get_auth(bearer_request(case["token"]))
        assert auth.is_signed_in is False, case["name"]


# ── Keys: caching, rotation, cooldown ───────────────────────────────


def _case(name: str) -> Dict[str, Any]:
    return next(c for c in TOKEN_CASES if c["name"] == name)


def test_keys_are_cached_between_requests() -> None:
    server = KeyServer()
    verifier = verifier_for(_case("valid"), server)
    for _ in range(5):
        verifier.verify(_case("valid")["token"])
    assert (server.discovery_fetches, server.jwks_fetches) == (1, 1)


def test_unknown_kid_refetch_has_a_cooldown() -> None:
    server = KeyServer()
    clock = {"now": NOW}
    verifier = TokenVerifier(ENV, api_url=API_URL, now=lambda: clock["now"], http_client=server.client())
    unknown = _case("unknown_kid")["token"]
    for _ in range(10):
        with pytest.raises(ZevAuthVerifyError):
            verifier.verify(unknown)
    # One initial fetch, one refetch for the unknown kid, then the cooldown holds.
    assert server.jwks_fetches == 2
    clock["now"] = NOW + 31
    with pytest.raises(ZevAuthVerifyError):
        verifier.verify(unknown)
    assert server.jwks_fetches == 3


def test_rotated_key_is_found_after_one_refetch() -> None:
    case = _case("rotated_key")
    server = server_for(case)
    verifier_for(case, server).verify(case["token"])
    assert server.jwks_fetches == 2


def test_key_set_expires_after_ten_minutes() -> None:
    server = KeyServer()
    clock = {"now": NOW}
    verifier = TokenVerifier(
        ENV, api_url=API_URL, now=lambda: clock["now"], clock_skew_seconds=10**9, http_client=server.client()
    )
    verifier.verify(_case("valid")["token"])
    clock["now"] = NOW + 601
    verifier.verify(_case("valid")["token"])
    assert server.jwks_fetches == 2


def test_local_key_set_needs_no_network() -> None:
    verifier = TokenVerifier(ENV, jwks=load("jwks.json"), issuer=TOKENS["issuer"], now=lambda: NOW)
    assert verifier.verify(_case("valid")["token"])["sub"] == "user_fixture_1"


def test_discovery_failure_is_jwks_unavailable_and_not_cached() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    verifier = TokenVerifier(
        ENV, api_url=API_URL, now=lambda: NOW, http_client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    for _ in range(2):
        with pytest.raises(ZevAuthVerifyError) as refused:
            verifier.verify(_case("valid")["token"])
        assert refused.value.code == "jwks_unavailable"
    assert calls["n"] == 2


# ── Bearer extraction ───────────────────────────────────────────────

BEARER_CASES = load("bearer.json")["cases"]


@pytest.mark.parametrize("case", BEARER_CASES, ids=[str(i) for i in range(len(BEARER_CASES))])
def test_bearer_extraction(case: Dict[str, Any]) -> None:
    assert bearer_from(case["header"]) == case["token"]


# ── Webhooks ────────────────────────────────────────────────────────

WEBHOOKS = load("webhooks.json")


@pytest.mark.parametrize("case", WEBHOOKS["cases"], ids=[c["name"] for c in WEBHOOKS["cases"]])
def test_webhook(case: Dict[str, Any]) -> None:
    secret = case.get("secret", WEBHOOKS["secret"])
    for payload in (case["payload"], case["payload"].encode("utf-8")):
        if case["valid"]:
            verify_webhook(payload, case["signature"], secret, now=WEBHOOKS["now"])
        else:
            with pytest.raises(ZevAuthWebhookError) as refused:
                verify_webhook(payload, case["signature"], secret, now=WEBHOOKS["now"])
            assert refused.value.code == case["error"]


# ── API errors ──────────────────────────────────────────────────────

API_ERRORS = load("api-errors.json")["cases"]


def _response_for(case: Dict[str, Any]) -> httpx.Response:
    headers = dict(case.get("headers") or {})
    if "bodyText" in case:
        return httpx.Response(case["status"], headers=headers, text=case["bodyText"])
    if case.get("body") is None:
        return httpx.Response(case["status"], headers=headers)
    return httpx.Response(case["status"], headers=headers, json=case["body"])


@pytest.mark.parametrize("case", API_ERRORS, ids=[c["name"] for c in API_ERRORS])
def test_api_error(case: Dict[str, Any]) -> None:
    attempts: List[int] = []
    slept: List[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return _response_for(case)

    client = ZevAuthClient(
        "sk_test_fixture",
        api_url=API_URL,
        max_retries=2,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleep=slept.append,
    )
    with pytest.raises(ZevAuthError) as failed:
        client.users.get("user_fixture_1")
    expect = case["expect"]
    assert (failed.value.code, failed.value.status) == (expect["code"], expect["status"])
    assert len(attempts) == (3 if expect["retry"] else 1)
    if "requestId" in expect:
        assert failed.value.request_id == expect["requestId"]
    if "retryAfterSeconds" in expect:
        assert slept == [expect["retryAfterSeconds"]] * 2


# ── Session bridge ──────────────────────────────────────────────────

BRIDGE = load("bridge.json")


def _bridge_request(spec: Dict[str, Any]) -> Request:
    headers: Dict[str, str] = {"content-type": "application/json"}
    if spec.get("origin"):
        headers["origin"] = spec["origin"]
    if spec.get("bridgeHeader"):
        headers[BRIDGE["header"]["name"]] = BRIDGE["header"]["value"]
    body: Optional[bytes] = json.dumps(spec["body"]).encode() if "body" in spec else b""
    return Request(spec["method"], f"{BRIDGE['appOrigin']}/zevauth/session", headers, body or b"")


def _cookie_effect(response: Any) -> str:
    cookies = response.header_values("set-cookie")
    if not cookies:
        return "unchanged"
    session_name, _ = bridge_cookie_names()
    session = next(c for c in cookies if c.startswith(f"{session_name}="))
    return "cleared" if "Max-Age=0" in session else "set"


@pytest.mark.parametrize("case", BRIDGE["cases"], ids=[c["name"] for c in BRIDGE["cases"]])
def test_bridge(case: Dict[str, Any]) -> None:
    server = KeyServer()
    zevauth = ZevAuth(
        ENV,
        api_url=API_URL,
        now=lambda: BRIDGE["now"],
        session_bridge=True,
        http_client=server.client(),
        async_http_client=server.async_client(),
    )
    expect = case["expect"]
    for response in (
        zevauth.handle_session_bridge(_bridge_request(case["request"])),
        asyncio.run(zevauth.handle_session_bridge_async(_bridge_request(case["request"]))),
    ):
        assert response.status == expect["status"]
        if "code" in expect:
            assert json.loads(response.body)["error"]["code"] == expect["code"]
        assert _cookie_effect(response) == expect["cookie"]
        if "maxAgeSeconds" in expect:
            assert f"Max-Age={expect['maxAgeSeconds']}" in response.header_values("set-cookie")[0]
