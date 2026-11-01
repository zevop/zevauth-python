from __future__ import annotations

from typing import Any, Dict, Iterator

import django
import pytest
from django.conf import settings

from .conftest import ENV, NOW, TOKENS, load

TOKEN = {c["name"]: c["token"] for c in TOKENS["cases"]}

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="test-only",
        ALLOWED_HOSTS=["app.example.com", "testserver"],
        ROOT_URLCONF="tests.django_urls",
        MIDDLEWARE=["django.middleware.csrf.CsrfViewMiddleware", "zevauth.django.ZevAuthMiddleware"],
        INSTALLED_APPS=[],
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        ZEVAUTH={
            "ENVIRONMENT_ID": ENV,
            "PUBLISHABLE_KEY": "pk_test_fixture",
            "JWKS": load("jwks.json"),
            "ISSUER": TOKENS["issuer"],
            "SESSION_BRIDGE": True,
        },
    )
    django.setup()

from django.test import Client  # noqa: E402

from zevauth.django import get_zevauth  # noqa: E402


@pytest.fixture(autouse=True)
def fixed_clock() -> Iterator[None]:
    zevauth = get_zevauth()
    original = zevauth.verifier._now
    zevauth.verifier._now = lambda: NOW
    yield
    zevauth.verifier._now = original


def client() -> Client:
    return Client(HTTP_HOST="app.example.com", HTTP_X_FORWARDED_PROTO="https")


def bearer(name: str) -> Dict[str, Any]:
    return {"HTTP_AUTHORIZATION": f"Bearer {TOKEN[name]}"}


def test_request_zevauth_is_set_by_the_middleware() -> None:
    assert client().get("/page", **bearer("valid")).json() == {"signedIn": True, "userId": "user_fixture_1"}
    assert client().get("/page").json() == {"signedIn": False, "userId": None}


def test_require_auth_refuses_with_the_envelope() -> None:
    response = client().get("/api/me")
    assert response.status_code == 401 and response.json()["error"]["code"] == "unauthorized"
    response = client().get("/api/me", **bearer("valid_pending_task"))
    assert response.status_code == 403 and response.json()["error"]["pendingTasks"] == ["setup_mfa"]
    assert client().get("/api/sensitive", **bearer("valid")).json()["error"]["code"] == "mfa_required"
    assert client().get("/api/sensitive", **bearer("valid_mfa")).status_code == 200
    assert client().get("/api/me", **bearer("valid")).json() == {"userId": "user_fixture_1"}


def test_bridge_sets_cookies_despite_csrf_middleware() -> None:
    c = client()
    response = c.post(
        "/zevauth/session",
        data=f'{{"token": "{TOKEN["valid"]}"}}',
        content_type="application/json",
        HTTP_X_ZEVAUTH_BRIDGE="1",
        HTTP_ORIGIN="https://app.example.com",
    )
    assert response.status_code == 204
    session = response.cookies["__Host-zevauth_session"]
    assert session.value == TOKEN["valid"] and session["httponly"] and session["secure"]
    assert session["samesite"] == "Lax" and session["max-age"] == 840
    assert c.get("/page").json()["signedIn"] is True


def test_foreign_origin_is_refused() -> None:
    response = client().post(
        "/zevauth/session",
        data=f'{{"token": "{TOKEN["valid"]}"}}',
        content_type="application/json",
        HTTP_X_ZEVAUTH_BRIDGE="1",
        HTTP_ORIGIN="https://evil.example",
    )
    assert response.status_code == 403 and response.json()["error"]["code"] == "bridge_origin_not_allowed"


def test_expired_cookie_page_goes_through_the_handshake() -> None:
    c = client()
    c.cookies["__Host-zevauth_session"] = TOKEN["expired"]
    c.cookies["__Host-zevauth_client"] = "1"
    response = c.get("/page", HTTP_ACCEPT="text/html")
    assert response.status_code == 302
    assert response["Location"] == "/zevauth/handshake?redirect_url=%2Fpage"
    handshake = c.get("/zevauth/handshake?redirect_url=/page")
    assert handshake.status_code == 200 and b"syncSessionBridge" in handshake.content
