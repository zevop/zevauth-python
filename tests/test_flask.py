from __future__ import annotations

from typing import Any, Dict

from flask import Flask, g
from flask.testing import FlaskClient

from zevauth import ZevAuth
from zevauth.flask import ZevAuthFlask, require_auth

from .conftest import ENV, NOW, TOKENS, load

TOKEN = {c["name"]: c["token"] for c in TOKENS["cases"]}


def app_with(**options: Any) -> FlaskClient:
    app = Flask(__name__)
    zevauth = ZevAuth(
        ENV,
        publishable_key="pk_test_fixture",
        jwks=load("jwks.json"),
        issuer=TOKENS["issuer"],
        now=lambda: NOW,
        **options,
    )
    ZevAuthFlask(app, zevauth)

    @app.get("/page")
    def page() -> Dict[str, Any]:
        return {"signedIn": g.zevauth.is_signed_in}

    @app.get("/api/me")
    @require_auth
    def me() -> Dict[str, Any]:
        return {"userId": g.zevauth.user_id}

    @app.get("/api/sensitive")
    @require_auth(require_mfa=True)
    def sensitive() -> Dict[str, Any]:
        return {"ok": True}

    return app.test_client()


def bearer(name: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN[name]}"}


def test_g_zevauth_and_require_auth() -> None:
    client = app_with()
    assert client.get("/page", headers=bearer("valid")).get_json() == {"signedIn": True}
    assert client.get("/api/me", headers=bearer("valid")).get_json() == {"userId": "user_fixture_1"}
    response = client.get("/api/me")
    assert response.status_code == 401 and response.get_json()["error"]["code"] == "unauthorized"
    response = client.get("/api/me", headers=bearer("valid_pending_task"))
    assert response.status_code == 403 and response.get_json()["error"]["code"] == "session_task_pending"
    assert client.get("/api/sensitive", headers=bearer("valid")).get_json()["error"]["code"] == "mfa_required"
    assert client.get("/api/sensitive", headers=bearer("valid_mfa")).status_code == 200


def test_bridge_blueprint_and_handshake() -> None:
    client = app_with(session_bridge=True)
    response = client.post(
        "/zevauth/session",
        json={"token": TOKEN["valid"]},
        headers={"x-zevauth-bridge": "1", "origin": "http://localhost"},
        base_url="https://app.example.com",
    )
    # Flask's test client sends Origin as given; the request's own origin is https://app.example.com.
    assert response.status_code == 403

    response = client.post(
        "/zevauth/session",
        json={"token": TOKEN["valid"]},
        headers={"x-zevauth-bridge": "1", "origin": "https://app.example.com"},
        base_url="https://app.example.com",
    )
    assert response.status_code == 204
    assert len(response.headers.getlist("Set-Cookie")) == 2

    # A fresh client: this one now holds the valid cookie it was just given.
    client = app_with(session_bridge=True)
    client.set_cookie("__Host-zevauth_session", TOKEN["expired"], domain="app.example.com", secure=True)
    client.set_cookie("__Host-zevauth_client", "1", domain="app.example.com", secure=True)
    page = client.get("/page", headers={"Accept": "text/html"}, base_url="https://app.example.com")
    assert page.status_code == 302
    assert page.headers["Location"] == "/zevauth/handshake?redirect_url=%2Fpage"
    handshake = client.get("/zevauth/handshake?redirect_url=/page", base_url="https://app.example.com")
    assert handshake.status_code == 200 and b"ZevAuthUI" in handshake.data
