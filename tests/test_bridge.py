"""Reading the bridge cookie, and the handshake with its two guards."""

from __future__ import annotations

import asyncio
from typing import Dict, Optional

from zevauth import Request, SessionBridgeOptions, ZevAuth

from .conftest import API_URL, ENV, NOW, TOKENS, KeyServer

VALID = next(c for c in TOKENS["cases"] if c["name"] == "valid")["token"]
EXPIRED = next(c for c in TOKENS["cases"] if c["name"] == "expired")["token"]
SESSION = "__Host-zevauth_session"
CLIENT = "__Host-zevauth_client"


def make(**options: object) -> ZevAuth:
    server = KeyServer()
    return ZevAuth(
        ENV,
        api_url=API_URL,
        publishable_key="pk_test_fixture",
        now=lambda: NOW,
        session_bridge=SessionBridgeOptions(**options) if options else True,  # type: ignore[arg-type]
        http_client=server.client(),
        async_http_client=server.async_client(),
    )


def page(
    cookies: Dict[str, str],
    url: str = "https://app.example.com/dashboard?tab=1",
    accept: str = "text/html",
    authorization: Optional[str] = None,
    method: str = "GET",
) -> Request:
    headers = {"accept": accept, "cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())}
    if authorization:
        headers["authorization"] = authorization
    return Request(method, url, headers)


def test_reads_the_session_from_the_cookie() -> None:
    auth, handshake = make().authenticate(page({SESSION: VALID, CLIENT: "1"}))
    assert auth.is_signed_in and auth.user_id == "user_fixture_1"
    assert handshake is None


def test_the_header_wins_over_the_cookie() -> None:
    auth = make().get_auth(page({SESSION: EXPIRED, CLIENT: "1"}, authorization=f"Bearer {VALID}"))
    assert auth.is_signed_in


def test_nobody_ever_signed_in_gets_no_handshake() -> None:
    auth, handshake = make().authenticate(page({}))
    assert not auth.is_signed_in and handshake is None


def test_expired_cookie_on_a_page_redirects_to_the_handshake() -> None:
    auth, handshake = make().authenticate(page({SESSION: EXPIRED, CLIENT: "1"}))
    assert not auth.is_signed_in
    assert handshake is not None and handshake.status == 302
    assert handshake.header("location") == "/zevauth/handshake?redirect_url=%2Fdashboard%3Ftab%3D1"
    assert handshake.header("cache-control") == "no-store"


def test_session_cookie_gone_but_client_cookie_left_also_hands_shake() -> None:
    _, handshake = make().authenticate(page({CLIENT: "1"}))
    assert handshake is not None and handshake.status == 302


def test_an_api_call_gets_401_not_a_redirect() -> None:
    _, handshake = make().authenticate(page({SESSION: EXPIRED, CLIENT: "1"}, accept="application/json"))
    assert handshake is not None and handshake.status == 401
    assert b"session_refresh_required" in handshake.body


def test_back_from_a_handshake_renders_signed_out_instead_of_looping() -> None:
    url = "https://app.example.com/dashboard?__zevauth_handshake=1"
    auth, handshake = make().authenticate(page({CLIENT: "1"}, url=url))
    assert not auth.is_signed_in and handshake is None


def test_async_matches_sync() -> None:
    zevauth = make()
    auth, handshake = asyncio.run(zevauth.authenticate_async(page({SESSION: EXPIRED, CLIENT: "1"})))
    assert not auth.is_signed_in and handshake is not None and handshake.status == 302


def test_custom_handshake_path() -> None:
    _, handshake = make(handshake_path="/auth/hs").authenticate(page({CLIENT: "1"}))
    assert handshake is not None and (handshake.header("location") or "").startswith("/auth/hs?")


def test_handshake_page_returns_to_a_same_site_path_with_the_marker() -> None:
    response = make().handshake_page(
        Request("GET", "https://app.example.com/zevauth/handshake?redirect_url=/a%3Fb%3D1")
    )
    html = response.body.decode()
    assert response.status == 200 and response.header("cache-control") == "no-store"
    assert '"back": "/a?b=1&__zevauth_handshake=1"' in html
    assert '"publishableKey": "pk_test_fixture"' in html
    assert '"bridge": "/zevauth/session"' in html


def test_handshake_page_refuses_to_leave_the_site() -> None:
    for target in ("//evil.example/x", "/\\evil.example", "https://evil.example/", "javascript:alert(1)"):
        response = make().handshake_page(
            Request("GET", f"https://app.example.com/zevauth/handshake?redirect_url={target}")
        )
        assert '"back": "/?__zevauth_handshake=1"' in response.body.decode(), target


def test_handshake_page_cannot_be_broken_out_of() -> None:
    response = make().handshake_page(
        Request("GET", "https://app.example.com/zevauth/handshake?redirect_url=/</script><script>alert(1)")
    )
    assert "</script><script>alert" not in response.body.decode()


def test_cookie_names_and_attributes_follow_configuration() -> None:
    zevauth = make(cookie_domain="example.com", allowed_origins=["https://app.example.com"])
    request = Request(
        "POST",
        "https://app.example.com/zevauth/session",
        {"x-zevauth-bridge": "1", "origin": "https://app.example.com"},
        b'{"token": "%s"}' % VALID.encode(),
    )
    cookies = zevauth.handle_session_bridge(request).header_values("set-cookie")
    assert cookies[0].startswith("__Secure-zevauth_session=")
    assert "Domain=example.com" in cookies[0] and "HttpOnly" in cookies[0] and "Secure" in cookies[0]
    assert cookies[1].startswith("__Secure-zevauth_client=1") and "Max-Age=2592000" in cookies[1]

    local = make(secure=False)
    cookies = local.handle_session_bridge(
        Request("POST", "http://localhost:8000/zevauth/session", {"x-zevauth-bridge": "1"}, b'{"token": null}')
    ).header_values("set-cookie")
    assert cookies[0].startswith("zevauth_session=;") and "Secure" not in cookies[0]


def test_the_refresh_token_is_never_accepted_or_stored() -> None:
    # Only one field is read from the body: the access token.
    zevauth = make()
    request = Request(
        "POST",
        "https://app.example.com/zevauth/session",
        {"x-zevauth-bridge": "1"},
        b'{"token": "%s", "refreshToken": "rt_secret"}' % VALID.encode(),
    )
    cookies = " ".join(zevauth.handle_session_bridge(request).header_values("set-cookie"))
    assert "rt_secret" not in cookies
