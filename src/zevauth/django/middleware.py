"""Sets ``request.zevauth`` on every request, and sends expired-cookie pages through the handshake."""

from __future__ import annotations

from typing import Callable

from django.http import HttpRequest, HttpResponse

from .conf import get_zevauth
from .http import to_request, to_response


class ZevAuthMiddleware:
    """``request.zevauth`` is an :class:`~zevauth.Auth`: signed in or not, never an error."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        zevauth = get_zevauth()
        options = zevauth.bridge_options
        # The bridge's own two routes must never be sent to the handshake.
        if options and request.path in (options.bridge_path, options.handshake_path):
            request.zevauth = zevauth.get_auth(to_request(request))  # type: ignore[attr-defined]
            return self.get_response(request)
        auth, handshake = zevauth.authenticate(to_request(request))
        if handshake is not None:
            return to_response(handshake)
        request.zevauth = auth  # type: ignore[attr-defined]
        return self.get_response(request)
