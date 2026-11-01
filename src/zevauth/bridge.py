"""The session bridge: sessions for server-rendered pages.

A server-rendered page is requested by the browser itself, with no
``Authorization`` header. The bridge gives the server a cookie it can read
instead: the browser SDK posts its access token to an endpoint you mount,
and that endpoint sets your own HttpOnly cookie.

The server never refreshes. Refresh tokens rotate on every use, and a
refresh token used twice ends the whole session, so a server refreshing
alongside the browser would sign people out. Only access tokens cross to
the server; when the cookie expires, a short redirect lets the browser
refresh and come straight back (the handshake).

Contract: ``spec/SERVER_SDK.md`` §5.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

from .auth import SIGNED_OUT, Auth, Request, Response
from .errors import ZevAuthVerifyError
from .verify import TokenVerifier, bearer_from

BRIDGE_HEADER = "x-zevauth-bridge"
HANDSHAKE_MARKER = "__zevauth_handshake"
DEFAULT_HANDSHAKE_PATH = "/zevauth/handshake"
DEFAULT_UI_SCRIPT_URL = "https://cdn.jsdelivr.net/npm/@zevauth/ui@0/dist/zevauth-ui.global.js"
CLIENT_COOKIE_MAX_AGE = 30 * 24 * 60 * 60

_SAFE_PATH = re.compile(r"^/(?![/\\])")


def bridge_cookie_names(*, cookie_domain: Optional[str] = None, secure: bool = True) -> Tuple[str, str]:
    """The (session, client) cookie names for a configuration.

    ``__Host-`` by default (no ``Domain``, ``Secure``, ``Path=/``: the
    strictest cookie a browser offers), ``__Secure-`` when shared across
    subdomains, and no prefix only for plain-http local development.
    """
    prefix = "" if not secure else ("__Secure-" if cookie_domain else "__Host-")
    return f"{prefix}zevauth_session", f"{prefix}zevauth_client"


class SessionBridge:
    """The endpoint, the cookie reader and the handshake, for one verifier.

    Args:
        verifier: Verifies the tokens posted and read back.
        allowed_origins: Pages allowed to post sessions. Defaults to the
            request's own origin. List every origin when pages live on
            several subdomains.
        cookie_domain: Share the cookies across subdomains.
        secure: ``False`` only for plain-http local development.
        handshake_path: Where the handshake page is served.
    """

    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        allowed_origins: Optional[Sequence[str]] = None,
        cookie_domain: Optional[str] = None,
        secure: bool = True,
        handshake_path: str = DEFAULT_HANDSHAKE_PATH,
    ) -> None:
        self.verifier = verifier
        self.allowed_origins = list(allowed_origins) if allowed_origins is not None else None
        self.cookie_domain = cookie_domain
        self.secure = secure
        self.handshake_path = handshake_path
        self.session_cookie, self.client_cookie = bridge_cookie_names(cookie_domain=cookie_domain, secure=secure)

    # ── The endpoint ──────────────────────────────────────────────

    def handle(self, request: Request) -> Response:
        """Answers a post from the browser SDK: sets or clears the cookies."""
        early, token = self._screen(request)
        if early is not None:
            return early
        if token is None:
            return self._cleared(204)
        try:
            claims = self.verifier.verify(token)
        except ZevAuthVerifyError as error:
            return self._refused(error.code)
        return self._adopted(token, claims)

    async def handle_async(self, request: Request) -> Response:
        early, token = self._screen(request)
        if early is not None:
            return early
        if token is None:
            return self._cleared(204)
        try:
            claims = await self.verifier.verify_async(token)
        except ZevAuthVerifyError as error:
            return self._refused(error.code)
        return self._adopted(token, claims)

    # ── Reading a request ─────────────────────────────────────────

    def get_auth(self, request: Request) -> Auth:
        """Who is signed in: the ``Authorization`` header first, then the cookie.

        Never raises for a missing, expired or bad token.
        """
        token, from_header, has_client = self._token(request)
        if token is None:
            return _with_handshake(SIGNED_OUT, not from_header and has_client)
        try:
            return Auth.from_claims(self.verifier.verify(token))
        except ZevAuthVerifyError as error:
            return self._signed_out_after(error, from_header, has_client)

    async def get_auth_async(self, request: Request) -> Auth:
        token, from_header, has_client = self._token(request)
        if token is None:
            return _with_handshake(SIGNED_OUT, not from_header and has_client)
        try:
            return Auth.from_claims(await self.verifier.verify_async(token))
        except ZevAuthVerifyError as error:
            return self._signed_out_after(error, from_header, has_client)

    def authenticate(self, request: Request) -> Tuple[Auth, Optional[Response]]:
        """``(auth, handshake)``: send ``handshake`` instead of the page when it is not ``None``."""
        auth = self.get_auth(request)
        return auth, self._handshake_for(request, auth)

    async def authenticate_async(self, request: Request) -> Tuple[Auth, Optional[Response]]:
        auth = await self.get_auth_async(request)
        return auth, self._handshake_for(request, auth)

    # ── The handshake page ────────────────────────────────────────

    def handshake_page(
        self,
        request: Request,
        *,
        publishable_key: str,
        bridge_path: str,
        api_url: Optional[str] = None,
        ui_script_url: str = DEFAULT_UI_SCRIPT_URL,
    ) -> Response:
        """A page that lets the browser refresh its session, then goes back.

        It loads ``@zevauth/ui``, which refreshes the session if the
        browser still has one, posts it through the bridge, and returns
        to ``redirect_url`` with the handshake marker so the page is not
        sent here a second time (the loop guard). ``redirect_url`` must be
        a path on this site, or the page returns to ``/`` instead (the
        open-redirect guard).
        """
        parts = urlsplit(request.url)
        requested = (parse_qs(parts.query).get("redirect_url") or ["/"])[0]
        safe = requested if _SAFE_PATH.match(requested) else "/"
        back = _with_query_param(safe, HANDSHAKE_MARKER, "1")
        config = json.dumps(
            {"publishableKey": publishable_key, "apiUrl": api_url, "bridge": bridge_path, "back": back}
        ).replace("<", "\\u003c")
        html = (
            '<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">'
            "<title>Signing in…</title>\n"
            f'<script src="{_escape_attribute(ui_script_url)}"></script>\n'
            "<script>\n(async function () {\n"
            f"  var c = {config};\n"
            "  try {\n"
            "    window.ZevAuthUI.init({\n"
            "      publishableKey: c.publishableKey, apiUrl: c.apiUrl, sessionBridge: { url: c.bridge }\n"
            "    });\n"
            "    var client = window.ZevAuthUI.getClient();\n"
            "    await client.load();\n"
            "    await client.syncSessionBridge();\n"
            "  } catch (e) {}\n"
            "  location.replace(c.back);\n"
            "})();\n</script>"
        )
        return Response(
            200,
            [
                ("content-type", "text/html; charset=utf-8"),
                ("cache-control", "no-store"),
                ("referrer-policy", "same-origin"),
            ],
            html.encode("utf-8"),
        )

    # ── Internals ─────────────────────────────────────────────────

    def _screen(self, request: Request) -> Tuple[Optional[Response], Optional[str]]:
        """Method, header, origin and body checks: (early response, token)."""
        if request.method != "POST":
            return _json(
                405, _error("method_not_allowed", "The session bridge accepts POST only."), [("allow", "POST")]
            ), None
        if request.header(BRIDGE_HEADER) != "1":
            return _json(
                403,
                _error(
                    "bridge_header_missing",
                    f"Send the {BRIDGE_HEADER}: 1 header. The ZevAuth browser SDK does this for you.",
                ),
            ), None
        origin = request.header("origin")
        allowed = self.allowed_origins if self.allowed_origins is not None else [_origin_of(request.url)]
        if origin and origin not in allowed:
            return _json(
                403,
                _error("bridge_origin_not_allowed", f"{origin} may not post sessions here. Add it to allowed_origins."),
            ), None
        try:
            body = json.loads(request.body or b"null")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return _json(400, _error("invalid_request", 'Expected a JSON body: { "token": string | null }.')), None
        token = body.get("token")
        if token is None or token == "":
            return None, None
        if not isinstance(token, str):
            return _json(400, _error("invalid_request", "`token` must be a string or null.")), None
        return None, token

    def _token(self, request: Request) -> Tuple[Optional[str], bool, bool]:
        header = bearer_from(request.header("authorization"))
        cookies = request.cookies()
        token = header or cookies.get(self.session_cookie) or None
        return token, header is not None, cookies.get(self.client_cookie) == "1"

    @staticmethod
    def _signed_out_after(error: ZevAuthVerifyError, from_header: bool, has_client: bool) -> Auth:
        expired = error.code == "token_expired"
        return _with_handshake(SIGNED_OUT, not from_header and (expired or has_client))

    def _handshake_for(self, request: Request, auth: Auth) -> Optional[Response]:
        if not auth.needs_handshake:
            return None
        parts = urlsplit(request.url)
        if HANDSHAKE_MARKER in parse_qs(parts.query, keep_blank_values=True):
            return None  # Back from one already: render signed out. The loop guard.
        navigation = request.method in ("GET", "HEAD") and "text/html" in (request.header("accept") or "")
        if not navigation:
            return _json(
                401,
                _error(
                    "session_refresh_required",
                    "The session cookie expired. Send the SDK token in Authorization, or reload the page.",
                ),
            )
        path = parts.path or "/"
        here = path + (f"?{parts.query}" if parts.query else "")
        location = f"{self.handshake_path}?{urlencode({'redirect_url': here})}"
        return Response(302, [("location", location), ("cache-control", "no-store")])

    def _adopted(self, token: str, claims: Dict[str, Any]) -> Response:
        now = int(self.verifier.now())
        max_age = max(0, int(claims.get("exp", now)) - now)
        return Response(
            204,
            [
                ("cache-control", "no-store"),
                ("set-cookie", self._cookie(self.session_cookie, token, max_age)),
                ("set-cookie", self._cookie(self.client_cookie, "1", CLIENT_COOKIE_MAX_AGE)),
            ],
        )

    def _refused(self, reason: str) -> Response:
        body = {"error": {"code": "unauthorized", "message": "That session token was refused.", "reason": reason}}
        return _json(401, body, self._clear_cookies())

    def _cleared(self, status: int) -> Response:
        return Response(status, [("cache-control", "no-store"), *self._clear_cookies()])

    def _clear_cookies(self) -> List[Tuple[str, str]]:
        return [
            ("set-cookie", self._cookie(self.session_cookie, "", 0)),
            ("set-cookie", self._cookie(self.client_cookie, "", 0)),
        ]

    def _cookie(self, name: str, value: str, max_age: int) -> str:
        parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", "HttpOnly", "SameSite=Lax"]
        if self.secure:
            parts.append("Secure")
        if self.cookie_domain:
            parts.append(f"Domain={self.cookie_domain}")
        return "; ".join(parts)


def _with_handshake(auth: Auth, needs: bool) -> Auth:
    if not needs:
        return auth
    return Auth(needs_handshake=True)


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _json(status: int, body: Dict[str, Any], headers: Sequence[Tuple[str, str]] = ()) -> Response:
    return Response(
        status,
        [("content-type", "application/json"), ("cache-control", "no-store"), *headers],
        json.dumps(body).encode("utf-8"),
    )


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _with_query_param(path: str, name: str, value: str) -> str:
    base, _, query = path.partition("?")
    pairs = [(k, v) for k, v in _pairs(query) if k != name]
    pairs.append((name, value))
    return f"{base}?{urlencode(pairs)}"


def _pairs(query: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for key, values in parse_qs(query, keep_blank_values=True).items():
        out.extend((key, v) for v in values)
    return out


def _escape_attribute(value: str) -> str:
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
