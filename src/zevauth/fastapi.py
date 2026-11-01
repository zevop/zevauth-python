"""ZevAuth for FastAPI (and Starlette).

    from fastapi import Depends, FastAPI
    from zevauth import Auth, ZevAuth
    from zevauth.fastapi import ZevAuthFastAPI

    zevauth = ZevAuth("env_live_…", secret_key=…)
    za = ZevAuthFastAPI(zevauth)

    app = FastAPI()
    za.install(app)

    @app.get("/api/me")
    async def me(auth: Auth = Depends(za.require_auth())):
        return {"userId": auth.user_id}

``install`` turns refusals into the ZevAuth error envelope
(``{"error": {"code", "message"}}``) and, when the session bridge is on,
mounts its endpoint and handshake page.

Install with ``pip install "zevauth[fastapi]"``.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from fastapi import APIRouter, FastAPI
from fastapi import Request as FastAPIRequest
from fastapi.responses import JSONResponse
from starlette.responses import Response as StarletteResponse

from .auth import Auth, Request, Response, check_auth
from .errors import AuthRefusal
from .server import ZevAuth


class HandshakeRequired(Exception):
    """Raised by the ``auth`` dependency when the bridge cookie needs refreshing.

    ``install`` answers it with the handshake response (a redirect for a
    page, a 401 for an API call).
    """

    def __init__(self, response: Response) -> None:
        super().__init__("The session cookie needs refreshing.")
        self.response = response


def to_request(request: FastAPIRequest, body: bytes = b"") -> Request:
    return Request(request.method, str(request.url), dict(request.headers), body)


def to_response(response: Response) -> StarletteResponse:
    content_type = response.header("content-type")
    out = StarletteResponse(content=response.body, status_code=response.status, media_type=content_type)
    for name, value in response.headers:
        if name.lower() in ("content-type", "content-length"):
            continue
        out.raw_headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    return out


class ZevAuthFastAPI:
    """Dependencies, exception handlers and the bridge routes for one :class:`ZevAuth`."""

    def __init__(self, zevauth: ZevAuth) -> None:
        self.zevauth = zevauth

    def install(self, app: FastAPI) -> None:
        """Registers the refusal handlers, and the bridge routes when the bridge is on."""

        async def on_refusal(_: FastAPIRequest, exc: Exception) -> StarletteResponse:
            assert isinstance(exc, AuthRefusal)
            return JSONResponse(exc.body(), status_code=exc.status)

        async def on_handshake(_: FastAPIRequest, exc: Exception) -> StarletteResponse:
            assert isinstance(exc, HandshakeRequired)
            return to_response(exc.response)

        app.add_exception_handler(AuthRefusal, on_refusal)
        app.add_exception_handler(HandshakeRequired, on_handshake)
        if self.zevauth.bridge:
            app.include_router(self.bridge_router())

    async def auth(self, request: FastAPIRequest) -> Auth:
        """Dependency: who is signed in. Never refuses.

        With the session bridge on, a page whose cookie expired is sent
        through the handshake first.
        """
        auth, handshake = await self.zevauth.authenticate_async(to_request(request))
        if handshake is not None:
            raise HandshakeRequired(handshake)
        return auth

    def require_auth(
        self, *, allow_pending_tasks: bool = False, require_mfa: bool = False
    ) -> Callable[[FastAPIRequest], Awaitable[Auth]]:
        """Dependency factory: refuses with 401 or 403 unless the rules pass."""

        async def dependency(request: FastAPIRequest) -> Auth:
            auth = await self.auth(request)
            return check_auth(auth, allow_pending_tasks=allow_pending_tasks, require_mfa=require_mfa)

        return dependency

    def bridge_router(self) -> APIRouter:
        """The bridge endpoint (POST) and handshake page (GET), at the configured paths."""
        options = self.zevauth.bridge_options
        if options is None:
            raise ValueError("Turn the session bridge on first: ZevAuth(..., session_bridge=True).")
        router = APIRouter(include_in_schema=False)
        zevauth = self.zevauth

        async def session(request: FastAPIRequest) -> Any:
            return to_response(await zevauth.handle_session_bridge_async(to_request(request, await request.body())))

        async def handshake(request: FastAPIRequest) -> Any:
            return to_response(zevauth.handshake_page(to_request(request)))

        router.add_api_route(options.bridge_path, session, methods=["POST", "GET", "PUT", "DELETE"])
        router.add_api_route(options.handshake_path, handshake, methods=["GET"])
        return router
