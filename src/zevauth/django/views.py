"""The session bridge's endpoint and handshake page."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt

from .conf import get_zevauth
from .http import to_request, to_response


@csrf_exempt  # Login CSRF is stopped by the bridge's own header and Origin checks.
def session_bridge(request: HttpRequest) -> HttpResponse:
    return to_response(get_zevauth().handle_session_bridge(to_request(request, with_body=True)))


def handshake(request: HttpRequest) -> HttpResponse:
    return to_response(get_zevauth().handshake_page(to_request(request)))
