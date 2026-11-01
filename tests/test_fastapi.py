from __future__ import annotations

from typing import Any, Dict

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from zevauth import Auth, ZevAuth
from zevauth.fastapi import ZevAuthFastAPI

from .conftest import API_URL, ENV, NOW, TOKENS, KeyServer

TOKEN = {c["name"]: c["token"] for c in TOKENS["cases"]}


def app_with(**options: Any) -> TestClient:
    server = KeyServer()
    zevauth = ZevAuth(
        ENV,
        api_url=API_URL,
        publishable_key="pk_test_fixture",
        now=lambda: NOW,
        async_http_client=server.async_client(),
        **options,
    )
    za = ZevAuthFastAPI(zevauth)
    app = FastAPI()
    za.install(app)

    @app.get("/me")
    async def me(auth: Auth = Depends(za.require_auth())) -> Dict[str, Any]:
        return {"userId": auth.user_id}

    @app.get("/sensitive")
    async def sensitive(auth: Auth = Depends(za.require_auth(require_mfa=True))) -> Dict[str, Any]:
        return {"ok": True}

    @app.get("/setup")
    async def setup(auth: Auth = Depends(za.require_auth(allow_pending_tasks=True))) -> Dict[str, Any]:
        return {"tasks": list(auth.pending_tasks)}

    @app.get("/page")
    async def page(auth: Auth = Depends(za.auth)) -> Dict[str, Any]:
        return {"signedIn": auth.is_signed_in}

    return TestClient(app, base_url="https://app.example.com")


def bearer(name: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN[name]}"}


def test_signed_in_request_reaches_the_route() -> None:
    assert app_with().get("/me", headers=bearer("valid")).json() == {"userId": "user_fixture_1"}


def test_refusals_use_the_zevauth_envelope() -> None:
    client = app_with()
    response = client.get("/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"

    response = client.get("/me", headers=bearer("valid_pending_task"))
    assert response.status_code == 403
    assert response.json()["error"] == {
        "code": "session_task_pending",
        "message": "Finish setting up two-step verification to continue.",
        "pendingTasks": ["setup_mfa"],
    }
    assert client.get("/sensitive", headers=bearer("valid")).json()["error"]["code"] == "mfa_required"
    assert client.get("/sensitive", headers=bearer("valid_mfa")).status_code == 200
    assert client.get("/setup", headers=bearer("valid_pending_task")).json() == {"tasks": ["setup_mfa"]}


def test_auth_dependency_never_refuses() -> None:
    assert app_with().get("/page", headers=bearer("expired")).json() == {"signedIn": False}


def test_bridge_routes_cookies_and_handshake() -> None:
    client = app_with(session_bridge=True)
    response = client.post(
        "/zevauth/session",
        json={"token": TOKEN["valid"]},
        headers={"x-zevauth-bridge": "1", "origin": "https://app.example.com"},
    )
    assert response.status_code == 204
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2 and cookies[0].startswith("__Host-zevauth_session=")

    page = client.get(
        "/page",
        headers={"cookie": f"__Host-zevauth_session={TOKEN['valid']}", "accept": "text/html"},
    )
    assert page.json() == {"signedIn": True}

    expired = client.get(
        "/page",
        headers={
            "cookie": f"__Host-zevauth_session={TOKEN['expired']}; __Host-zevauth_client=1",
            "accept": "text/html",
        },
        follow_redirects=False,
    )
    assert expired.status_code == 302
    assert expired.headers["location"] == "/zevauth/handshake?redirect_url=%2Fpage"

    handshake = client.get("/zevauth/handshake?redirect_url=/page")
    assert handshake.status_code == 200 and "ZevAuthUI.init" in handshake.text

    assert client.get("/zevauth/session").status_code == 405
    assert client.post("/zevauth/session", json={"token": None}).json()["error"]["code"] == "bridge_header_missing"
