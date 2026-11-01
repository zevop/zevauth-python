"""``ZevAuth``: configure once, use everywhere.

Holds the token verifier, the session bridge (when you turn it on) and
the API clients, so a framework integration needs nothing but this one
object. Create it when your app starts; the key cache lives inside it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple

import httpx

from .auth import SIGNED_OUT, Auth, Request, Response, check_auth
from .bridge import DEFAULT_HANDSHAKE_PATH, DEFAULT_UI_SCRIPT_URL, SessionBridge
from .client import AsyncZevAuthClient, ZevAuthClient
from .errors import ZevAuthVerifyError
from .verify import DEFAULT_API_URL, DEFAULT_CLOCK_SKEW_SECONDS, Claims, TokenVerifier, bearer_from

DEFAULT_BRIDGE_PATH = "/zevauth/session"


@dataclass(frozen=True)
class SessionBridgeOptions:
    """Turns on cookies for server-rendered pages. See the session bridge docs.

    Args:
        bridge_path: Where the endpoint is mounted; pass the same URL to
            the browser SDK's ``sessionBridge: { url }``.
        handshake_path: Where the handshake page is served.
        allowed_origins: Pages allowed to post sessions. Defaults to the
            request's own origin.
        cookie_domain: Share the cookies across subdomains.
        secure: ``False`` only for plain-http local development.
        ui_script_url: Serve your own copy of ``@zevauth/ui`` for the
            handshake page under a strict Content Security Policy.
    """

    bridge_path: str = DEFAULT_BRIDGE_PATH
    handshake_path: str = DEFAULT_HANDSHAKE_PATH
    allowed_origins: Optional[Sequence[str]] = None
    cookie_domain: Optional[str] = None
    secure: bool = True
    ui_script_url: str = DEFAULT_UI_SCRIPT_URL


class ZevAuth:
    """ZevAuth for your server.

    Args:
        environment_id: ``env_test_…`` or ``env_live_…``. Tokens from any
            other environment are refused.
        secret_key: For the backend API (``api``, ``api_async``). Optional
            if you only verify sessions.
        publishable_key: Needed only for the session bridge's handshake page.
        api_url: Where the ZevAuth API lives.
        session_bridge: ``True`` or :class:`SessionBridgeOptions` to read
            sessions from a cookie on server-rendered pages.
        jwks / issuer: A local key set instead of fetching one.
        clock_skew_seconds, now: Verification tolerance and clock.
        http_client / async_http_client: For fetching keys (and tests).
    """

    def __init__(
        self,
        environment_id: str,
        *,
        secret_key: Optional[str] = None,
        publishable_key: Optional[str] = None,
        api_url: str = DEFAULT_API_URL,
        session_bridge: Any = None,
        jwks: Optional[Mapping[str, Any]] = None,
        issuer: Optional[str] = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
        now: Optional[Callable[[], float]] = None,
        http_client: Optional[httpx.Client] = None,
        async_http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.environment_id = environment_id
        self.secret_key = secret_key
        self.publishable_key = publishable_key
        self.api_url = api_url
        self.verifier = TokenVerifier(
            environment_id,
            api_url=api_url,
            issuer=issuer,
            jwks=jwks,
            clock_skew_seconds=clock_skew_seconds,
            now=now,
            http_client=http_client,
            async_http_client=async_http_client,
        )

        options: Optional[SessionBridgeOptions]
        if session_bridge is True:
            options = SessionBridgeOptions()
        elif isinstance(session_bridge, SessionBridgeOptions):
            options = session_bridge
        elif isinstance(session_bridge, Mapping):
            options = SessionBridgeOptions(**session_bridge)
        else:
            options = None
        self.bridge_options = options
        self.bridge: Optional[SessionBridge] = (
            SessionBridge(
                self.verifier,
                allowed_origins=options.allowed_origins,
                cookie_domain=options.cookie_domain,
                secure=options.secure,
                handshake_path=options.handshake_path,
            )
            if options
            else None
        )

        self._api: Optional[ZevAuthClient] = None
        self._api_async: Optional[AsyncZevAuthClient] = None

    # ── Tokens ────────────────────────────────────────────────────

    def verify_token(self, token: str) -> Claims:
        """Verifies a token and returns its claims; raises :class:`ZevAuthVerifyError`."""
        return self.verifier.verify(token)

    async def verify_token_async(self, token: str) -> Claims:
        return await self.verifier.verify_async(token)

    # ── Who is signed in ──────────────────────────────────────────

    def get_auth(self, request: Request) -> Auth:
        """Who is signed in. Never raises for a missing, expired or bad token."""
        if self.bridge:
            return self.bridge.get_auth(request)
        token = bearer_from(request.header("authorization"))
        if not token:
            return SIGNED_OUT
        try:
            return Auth.from_claims(self.verifier.verify(token))
        except ZevAuthVerifyError:
            return SIGNED_OUT

    async def get_auth_async(self, request: Request) -> Auth:
        if self.bridge:
            return await self.bridge.get_auth_async(request)
        token = bearer_from(request.header("authorization"))
        if not token:
            return SIGNED_OUT
        try:
            return Auth.from_claims(await self.verifier.verify_async(token))
        except ZevAuthVerifyError:
            return SIGNED_OUT

    def require_auth(self, request: Request, *, allow_pending_tasks: bool = False, require_mfa: bool = False) -> Auth:
        """Like :meth:`get_auth`, but raises :class:`AuthRefusal` (401 or 403)."""
        return check_auth(self.get_auth(request), allow_pending_tasks=allow_pending_tasks, require_mfa=require_mfa)

    async def require_auth_async(
        self, request: Request, *, allow_pending_tasks: bool = False, require_mfa: bool = False
    ) -> Auth:
        return check_auth(
            await self.get_auth_async(request), allow_pending_tasks=allow_pending_tasks, require_mfa=require_mfa
        )

    def authenticate(self, request: Request) -> Tuple[Auth, Optional[Response]]:
        """``(auth, handshake)``. When ``handshake`` is not ``None``, send it instead of the page."""
        if not self.bridge:
            return self.get_auth(request), None
        return self.bridge.authenticate(request)

    async def authenticate_async(self, request: Request) -> Tuple[Auth, Optional[Response]]:
        if not self.bridge:
            return await self.get_auth_async(request), None
        return await self.bridge.authenticate_async(request)

    # ── The session bridge's two endpoints ────────────────────────

    def handle_session_bridge(self, request: Request) -> Response:
        return self._require_bridge().handle(request)

    async def handle_session_bridge_async(self, request: Request) -> Response:
        return await self._require_bridge().handle_async(request)

    def handshake_page(self, request: Request) -> Response:
        bridge = self._require_bridge()
        if not self.publishable_key:
            raise ValueError("The handshake page needs your publishable key: ZevAuth(..., publishable_key='pk_…').")
        options = self.bridge_options
        assert options is not None
        return bridge.handshake_page(
            request,
            publishable_key=self.publishable_key,
            bridge_path=options.bridge_path,
            api_url=None if self.api_url == DEFAULT_API_URL else self.api_url,
            ui_script_url=options.ui_script_url,
        )

    # ── The backend API ───────────────────────────────────────────

    @property
    def api(self) -> ZevAuthClient:
        """The backend API, synchronous. Needs ``secret_key``."""
        if self._api is None:
            self._api = ZevAuthClient(self.secret_key, api_url=self.api_url)
        return self._api

    @property
    def api_async(self) -> AsyncZevAuthClient:
        """The backend API for asyncio. Needs ``secret_key``."""
        if self._api_async is None:
            self._api_async = AsyncZevAuthClient(self.secret_key, api_url=self.api_url)
        return self._api_async

    def _require_bridge(self) -> SessionBridge:
        if not self.bridge:
            raise ValueError("Turn the session bridge on first: ZevAuth(..., session_bridge=True).")
        return self.bridge
