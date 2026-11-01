"""Every error this library raises, each with a stable ``code``.

The codes are the same in every ZevAuth server library, so a log line or
an alert written against one language reads the same in another. Match
on ``code``, never on the message: messages are written for people and
may be reworded.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class ZevAuthError(Exception):
    """A request to the ZevAuth backend API failed.

    ``status`` is the HTTP status, or 0 when no response arrived
    (``network_error``) or the client was misconfigured
    (``missing_secret_key``, ``wrong_key_type``). ``request_id`` comes
    from the ``x-request-id`` response header: quote it to ZevAuth
    support and they can find the request.
    """

    def __init__(
        self,
        message: str,
        code: str,
        status: int = 0,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.request_id = request_id

    def __repr__(self) -> str:
        return f"ZevAuthError(code={self.code!r}, status={self.status}, message={self.message!r})"


class ZevAuthVerifyError(Exception):
    """A session token was refused.

    ``code`` is one of: ``malformed_token``, ``unsupported_algorithm``,
    ``unknown_key``, ``invalid_signature``, ``invalid_issuer``,
    ``invalid_audience``, ``token_expired``, ``token_not_yet_valid``,
    ``jwks_unavailable``.

    Only the low-level ``verify_token`` raises this. ``get_auth`` turns
    every refusal into "signed out", because a page deciding what to
    render must not crash when a session lapses.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class ZevAuthWebhookError(Exception):
    """A webhook delivery failed verification.

    ``code`` is ``webhook_malformed_signature``,
    ``webhook_timestamp_out_of_range`` or ``webhook_signature_mismatch``.
    Answer it with a 400: ZevAuth retries, and a real delivery will verify.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class AuthRefusal(Exception):
    """``require_auth`` refused the request.

    Carries the HTTP status and the ZevAuth error envelope, so every
    framework integration answers with the same body:
    ``{"error": {"code": ..., "message": ...}}``.

    Codes: 401 ``unauthorized``, 403 ``session_task_pending`` (the body
    adds ``pendingTasks``), 403 ``mfa_required``.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.extra: Dict[str, Any] = dict(extra or {})

    def body(self) -> Dict[str, Any]:
        """The response body, in the envelope the ZevAuth API uses."""
        return {"error": {"code": self.code, "message": self.message, **self.extra}}
