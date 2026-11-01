"""Verifying webhook deliveries.

Each delivery carries ``zevauth-signature: t=<unix seconds>,v1=<hex>``,
an HMAC-SHA256 of ``"<t>.<raw body>"`` keyed with your endpoint's whole
secret, ``whsec_`` prefix included.

**Verify the raw body.** The signature covers the exact bytes received.
Parse JSON only after verifying: a body parsed and re-serialised fails,
correctly. Each framework section of the docs shows how to get the raw
bytes (``await request.body()`` in FastAPI, ``request.body`` in Django,
``request.get_data()`` in Flask).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from .errors import ZevAuthWebhookError

SIGNATURE_HEADER = "zevauth-signature"
DEFAULT_TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class WebhookEvent:
    """A verified delivery. ``id`` is stable across retries: use it to stay idempotent."""

    id: str
    type: str
    created_at: str
    data: Any
    raw: Dict[str, Any]


def verify_webhook(
    payload: Union[bytes, str],
    signature: Optional[str],
    secret: str,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> None:
    """Raises :class:`ZevAuthWebhookError` unless the delivery is genuine and recent.

    Args:
        payload: The raw request body, exactly as received.
        signature: The ``zevauth-signature`` header.
        secret: The endpoint's signing secret (``whsec_…``).
        tolerance_seconds: How far ``t`` may be from now, either way.
        now: The current time in epoch seconds, for tests.
    """
    parts: Dict[str, str] = {}
    for piece in (signature or "").split(","):
        name, sep, value = piece.partition("=")
        if sep and name.strip():
            parts[name.strip()] = value.strip()

    raw_timestamp = parts.get("t", "")
    provided = parts.get("v1", "")
    timestamp = int(raw_timestamp) if raw_timestamp.isdigit() else 0
    if timestamp <= 0 or not provided:
        raise ZevAuthWebhookError(
            "The zevauth-signature header is missing or not in the form t=<timestamp>,v1=<signature>.",
            "webhook_malformed_signature",
        )

    current = int(time.time() if now is None else now)
    if abs(current - timestamp) > tolerance_seconds:
        raise ZevAuthWebhookError(
            f"The delivery is {abs(current - timestamp)}s from now; at most {tolerance_seconds}s is accepted. "
            "Check the server clock, or this is a replay.",
            "webhook_timestamp_out_of_range",
        )

    body = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    message = str(timestamp).encode("ascii") + b"." + body
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    # Exact and constant-time: no case folding, no early exit.
    if not hmac.compare_digest(expected, provided):
        raise ZevAuthWebhookError(
            "The signature does not match. Check the endpoint secret, and that you verify the raw body, "
            "not a re-encoded one.",
            "webhook_signature_mismatch",
        )


def construct_webhook_event(
    payload: Union[bytes, str],
    signature: Optional[str],
    secret: str,
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> WebhookEvent:
    """Verifies the delivery, then returns the parsed event."""
    verify_webhook(payload, signature, secret, tolerance_seconds=tolerance_seconds, now=now)
    event = json.loads(payload)
    return WebhookEvent(
        id=event.get("id", ""),
        type=event.get("type", ""),
        created_at=event.get("createdAt", ""),
        data=event.get("data"),
        raw=event,
    )
