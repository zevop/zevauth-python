"""Who is signed in: the auth object, and the rules that refuse a request."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .errors import AuthRefusal


@dataclass(frozen=True)
class Auth:
    """The signed-in person, or nobody.

    Every field has a safe value when nobody is signed in, so a template
    can read ``auth.user_id`` without checking ``is_signed_in`` first.
    """

    is_signed_in: bool = False
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    organization_id: Optional[str] = None
    organization_role: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
    pending_tasks: Tuple[str, ...] = ()
    is_mfa_verified: bool = False
    needs_handshake: bool = field(default=False, compare=False)
    """True when a session-bridge cookie expired and the browser should
    refresh it. Only the session bridge sets it; see ``authenticate``."""

    def has(self, *, role: Optional[str] = None, permission: Optional[str] = None) -> bool:
        """Whether the active organization grants this role and/or permission.

        False with no active organization, and false when neither is given:
        an empty check that passed would read as permission to everything.
        """
        claims = self.claims or {}
        if not claims.get("org_id"):
            return False
        if role is None and permission is None:
            return False
        if role is not None and claims.get("org_role") != role:
            return False
        if permission is not None and permission not in (claims.get("org_permissions") or []):
            return False
        return True

    @classmethod
    def from_claims(cls, claims: Dict[str, Any]) -> Auth:
        return cls(
            is_signed_in=True,
            user_id=claims.get("sub"),
            session_id=claims.get("sid"),
            organization_id=claims.get("org_id"),
            organization_role=claims.get("org_role"),
            claims=claims,
            pending_tasks=tuple(claims.get("pending_tasks") or ()),
            is_mfa_verified="mfa" in (claims.get("amr") or ()),
        )


SIGNED_OUT = Auth()


def check_auth(
    auth: Auth,
    *,
    allow_pending_tasks: bool = False,
    require_mfa: bool = False,
) -> Auth:
    """Applies the three refusals, in order, and returns ``auth`` when none applies.

    Raises:
        AuthRefusal: 401 ``unauthorized``, 403 ``session_task_pending``
            or 403 ``mfa_required``.
    """
    if not auth.is_signed_in:
        raise AuthRefusal(401, "unauthorized", "Sign in to continue.")
    if auth.pending_tasks and not allow_pending_tasks:
        raise AuthRefusal(
            403,
            "session_task_pending",
            "Finish setting up two-step verification to continue.",
            {"pendingTasks": list(auth.pending_tasks)},
        )
    if require_mfa and not auth.is_mfa_verified:
        raise AuthRefusal(403, "mfa_required", "Sign in with two-step verification to continue.")
    return auth


@dataclass
class Request:
    """A request, in the few terms this library needs.

    The framework integrations build one for you. Build it yourself to
    use the library from any other framework.

    Args:
        method: ``GET``, ``POST``…
        url: The full URL, scheme and host included: the default allowed
            origin for the session bridge is the request's own.
        headers: Header names in any case.
        body: The raw body.
    """

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        self.headers = {key.lower(): value for key, value in self.headers.items()}

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def cookies(self) -> Dict[str, str]:
        jar: Dict[str, str] = {}
        for part in (self.header("cookie") or "").split(";"):
            name, sep, value = part.partition("=")
            if sep and name.strip():
                jar[name.strip()] = value.strip()
        return jar


@dataclass
class Response:
    """A response for the integration to send: status, headers, body.

    ``headers`` is a list because ``Set-Cookie`` repeats.
    """

    status: int
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def header_values(self, name: str) -> List[str]:
        return [value for key, value in self.headers if key.lower() == name.lower()]
