"""Verifying ZevAuth session tokens.

A session token is a short-lived JWT signed with RS256 by your
environment's own key. This module checks one in the order the shared
contract fixes (``spec/SERVER_SDK.md`` §1.3), so a refused token gets the
same code here as in every other ZevAuth server library.

Create one :class:`TokenVerifier` when your app starts and reuse it: it
caches the discovery document and the key set, and that cache is what
keeps verification off the network on every request.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from .errors import ZevAuthVerifyError

DEFAULT_API_URL = "https://api.zevauth.net"
DEFAULT_CLOCK_SKEW_SECONDS = 5
DEFAULT_JWKS_COOLDOWN_SECONDS = 30
KEY_SET_MAX_AGE_SECONDS = 10 * 60
_ALGORITHM = "RS256"

Claims = Dict[str, Any]


class TokenVerifier:
    """Verifies session tokens for one environment.

    Args:
        environment_id: Your environment's public id, ``env_test_…`` or
            ``env_live_…``. Tokens from any other environment are refused
            (``invalid_audience``), which is what stops a test token
            working on a live route.
        api_url: Where the ZevAuth API lives.
        issuer: Normally read from the discovery document. Required when
            you pass ``jwks``.
        jwks: A key set to use instead of fetching one, for tests and
            servers with no outbound network.
        clock_skew_seconds: Tolerance on ``exp`` and ``nbf``.
        jwks_cooldown_seconds: Minimum time between refetches caused by a
            token whose ``kid`` is not in the cached set, so a token with
            a made-up ``kid`` cannot make every request fetch keys.
        now: Returns the current time in epoch seconds. Inject a fixed
            clock in tests.
        http_client / async_http_client: Clients used to fetch discovery
            and keys. Defaults are created on first use.
    """

    def __init__(
        self,
        environment_id: str,
        *,
        api_url: str = DEFAULT_API_URL,
        issuer: Optional[str] = None,
        jwks: Optional[Mapping[str, Any]] = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
        jwks_cooldown_seconds: float = DEFAULT_JWKS_COOLDOWN_SECONDS,
        now: Optional[Callable[[], float]] = None,
        http_client: Optional[httpx.Client] = None,
        async_http_client: Optional[httpx.AsyncClient] = None,
        timeout: float = 10.0,
    ) -> None:
        if not environment_id:
            raise ValueError(
                "TokenVerifier needs your environment id (env_test_… or env_live_…). "
                "Find it in the ZevAuth console under API keys."
            )
        if jwks is not None and not issuer:
            raise ValueError("TokenVerifier: `issuer` is required when `jwks` is given.")

        self.environment_id = environment_id
        self.api_url = api_url.rstrip("/")
        self.clock_skew_seconds = clock_skew_seconds
        self.jwks_cooldown_seconds = jwks_cooldown_seconds
        self._now = now or time.time
        self._timeout = timeout
        self._http_client = http_client
        self._async_http_client = async_http_client

        self._local = jwks is not None
        self._issuer: Optional[str] = issuer
        self._jwks_uri: Optional[str] = None
        self._keys: Dict[str, Any] = _parse_key_set(jwks) if jwks is not None else {}
        self._keys_fetched_at: Optional[float] = None
        self._last_unknown_kid_refetch: Optional[float] = None

        self._lock = threading.Lock()
        self._async_locks: Dict[int, asyncio.Lock] = {}

    # ── Public ────────────────────────────────────────────────────

    def verify(self, token: str) -> Claims:
        """Verifies ``token`` and returns its claims.

        Raises:
            ZevAuthVerifyError: with one of the codes in §1.4.
        """
        header, payload = _parse(token)
        kid = header.get("kid")
        key = None
        if isinstance(kid, str):
            with self._lock:
                self._ensure_discovered_sync()
                key = self._key_for_sync(kid)
        return self._finish(token, payload, key)

    async def verify_async(self, token: str) -> Claims:
        """The same as :meth:`verify`, fetching keys without blocking the event loop."""
        header, payload = _parse(token)
        kid = header.get("kid")
        key = None
        if isinstance(kid, str):
            async with self._async_lock():
                await self._ensure_discovered_async()
                key = await self._key_for_async(kid)
        return self._finish(token, payload, key)

    def now(self) -> float:
        """The verifier's clock, in epoch seconds."""
        return self._now()

    # ── Checks after the key is known ─────────────────────────────

    def _finish(self, token: str, payload: Claims, key: Any) -> Claims:
        if key is None:
            raise ZevAuthVerifyError(
                "No key in this environment's key set matches the token's `kid`.",
                "unknown_key",
            )
        try:
            jwt.decode(
                token,
                key,
                algorithms=[_ALGORITHM],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "require": [],
                },
            )
        except jwt.InvalidSignatureError:
            raise ZevAuthVerifyError("The token's signature does not verify.", "invalid_signature") from None
        except jwt.PyJWTError as error:
            raise ZevAuthVerifyError(f"The token could not be read: {error}", "malformed_token") from None

        if payload.get("iss") != self._issuer:
            raise ZevAuthVerifyError("The token was issued by someone else (wrong `iss`).", "invalid_issuer")

        audience = payload.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self.environment_id not in audiences:
            raise ZevAuthVerifyError(
                f"The token is for another environment, not {self.environment_id}.",
                "invalid_audience",
            )

        exp: Any = payload.get("exp")
        nbf: Any = payload.get("nbf")
        if not _is_number(exp) or (nbf is not None and not _is_number(nbf)):
            raise ZevAuthVerifyError("`exp` or `nbf` is not a number.", "malformed_token")
        if not isinstance(payload.get("sub"), str) or not isinstance(payload.get("sid"), str):
            raise ZevAuthVerifyError("`sub` or `sid` is missing.", "malformed_token")

        now = self._now()
        if float(exp) <= now - self.clock_skew_seconds:
            raise ZevAuthVerifyError("The token has expired.", "token_expired")
        if nbf is not None and float(nbf) > now + self.clock_skew_seconds:
            raise ZevAuthVerifyError("The token is not valid yet.", "token_not_yet_valid")

        return payload

    # ── Discovery and keys (sync) ─────────────────────────────────

    def _client(self) -> httpx.Client:
        if self._http_client is None:
            self._http_client = httpx.Client(timeout=self._timeout)
        return self._http_client

    def _ensure_discovered_sync(self) -> None:
        if self._local or self._jwks_uri is not None:
            return
        try:
            response = self._client().get(self._discovery_url())
        except httpx.HTTPError as error:
            raise _unavailable(f"Could not reach ZevAuth to read the discovery document: {error}") from None
        self._adopt_discovery(response)

    def _key_for_sync(self, kid: str) -> Any:
        if self._local:
            return self._keys.get(kid)
        if self._keys_stale():
            self._keys = self._fetch_keys_sync()
        key = self._keys.get(kid)
        if key is None and self._may_refetch_for_unknown_kid():
            self._keys = self._fetch_keys_sync()
            key = self._keys.get(kid)
        return key

    def _fetch_keys_sync(self) -> Dict[str, Any]:
        assert self._jwks_uri is not None
        try:
            response = self._client().get(self._jwks_uri)
        except httpx.HTTPError as error:
            raise _unavailable(f"Could not fetch the key set: {error}") from None
        return self._adopt_keys(response)

    # ── Discovery and keys (async) ────────────────────────────────

    def _async_client(self) -> httpx.AsyncClient:
        if self._async_http_client is None:
            self._async_http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._async_http_client

    def _async_lock(self) -> asyncio.Lock:
        # One lock per event loop: an asyncio.Lock belongs to the loop it
        # was first used in, and tests (and some servers) run several.
        loop = asyncio.get_running_loop()
        lock = self._async_locks.get(id(loop))
        if lock is None:
            lock = self._async_locks[id(loop)] = asyncio.Lock()
        return lock

    async def _ensure_discovered_async(self) -> None:
        if self._local or self._jwks_uri is not None:
            return
        try:
            response = await self._async_client().get(self._discovery_url())
        except httpx.HTTPError as error:
            raise _unavailable(f"Could not reach ZevAuth to read the discovery document: {error}") from None
        self._adopt_discovery(response)

    async def _key_for_async(self, kid: str) -> Any:
        if self._local:
            return self._keys.get(kid)
        if self._keys_stale():
            self._keys = await self._fetch_keys_async()
        key = self._keys.get(kid)
        if key is None and self._may_refetch_for_unknown_kid():
            self._keys = await self._fetch_keys_async()
            key = self._keys.get(kid)
        return key

    async def _fetch_keys_async(self) -> Dict[str, Any]:
        assert self._jwks_uri is not None
        try:
            response = await self._async_client().get(self._jwks_uri)
        except httpx.HTTPError as error:
            raise _unavailable(f"Could not fetch the key set: {error}") from None
        return self._adopt_keys(response)

    # ── Shared bookkeeping ────────────────────────────────────────

    def _discovery_url(self) -> str:
        return f"{self.api_url}/v1/{self.environment_id}/.well-known/openid-configuration"

    def _adopt_discovery(self, response: httpx.Response) -> None:
        if response.status_code != 200:
            raise _unavailable(
                f"Could not read the ZevAuth discovery document for {self.environment_id} "
                f"({response.status_code}). Check the environment id and api_url."
            )
        try:
            document = response.json()
            jwks_uri = document["jwks_uri"]
            issuer = document["issuer"]
        except (ValueError, KeyError, TypeError):
            raise _unavailable("The discovery document is not in the expected shape.") from None
        # Read from discovery, never built from api_url: the two may
        # differ (self-hosting, local development).
        if self._issuer is None:
            self._issuer = str(issuer)
        self._jwks_uri = str(jwks_uri)

    def _adopt_keys(self, response: httpx.Response) -> Dict[str, Any]:
        if response.status_code != 200:
            raise _unavailable(f"Could not fetch the key set ({response.status_code}).")
        try:
            keys = _parse_key_set(response.json())
        except (ValueError, KeyError, TypeError):
            raise _unavailable("The key set is not in the expected shape.") from None
        self._keys_fetched_at = self._now()
        return keys

    def _keys_stale(self) -> bool:
        return self._keys_fetched_at is None or self._now() - self._keys_fetched_at >= KEY_SET_MAX_AGE_SECONDS

    def _may_refetch_for_unknown_kid(self) -> bool:
        now = self._now()
        last = self._last_unknown_kid_refetch
        if last is not None and now - last < self.jwks_cooldown_seconds:
            return False
        self._last_unknown_kid_refetch = now
        return True


def bearer_from(header_value: Optional[str]) -> Optional[str]:
    """The session token in an ``Authorization`` header, or ``None``.

    The scheme is case-sensitive ``Bearer ``. An API key sent there by
    mistake (``pk_…``, ``sk_…``) is not a session and reads as none.
    """
    if not header_value or not header_value.startswith("Bearer "):
        return None
    token = header_value[len("Bearer ") :].strip()
    if not token or token.startswith(("pk_", "sk_")):
        return None
    return token


# ── Helpers ─────────────────────────────────────────────────────────


def _b64url_json(segment: str) -> Any:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def _parse(token: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Steps 1 and 2: shape, then algorithm, before any key is looked at."""
    if not isinstance(token, str) or token.count(".") != 2:
        raise ZevAuthVerifyError("That is not a JWT.", "malformed_token")
    header_segment, payload_segment, _ = token.split(".")
    try:
        header = _b64url_json(header_segment)
        payload = _b64url_json(payload_segment)
    except (ValueError, UnicodeError, binascii.Error):
        raise ZevAuthVerifyError("The token's header or payload is not valid JSON.", "malformed_token") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ZevAuthVerifyError("The token's header or payload is not an object.", "malformed_token")
    # Never let the token choose the algorithm: `none` and HS256 (signed
    # with the public key as an HMAC secret) are refused here.
    if header.get("alg") != _ALGORITHM:
        raise ZevAuthVerifyError(
            f"Only {_ALGORITHM} tokens are accepted, not {header.get('alg')!r}.",
            "unsupported_algorithm",
        )
    return header, payload


def _parse_key_set(jwks: Mapping[str, Any]) -> Dict[str, Any]:
    keys: Dict[str, Any] = {}
    entries: List[Any] = list(jwks.get("keys") or [])
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA" or not entry.get("kid"):
            continue
        if entry.get("alg") not in (None, _ALGORITHM):
            continue
        keys[str(entry["kid"])] = RSAAlgorithm.from_jwk(json.dumps(entry))
    return keys


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _unavailable(message: str) -> ZevAuthVerifyError:
    return ZevAuthVerifyError(message, "jwks_unavailable")
