"""Converting between Django's request and response and the library's."""

from __future__ import annotations

from typing import Optional

from django.http import HttpRequest, HttpResponse

from ..auth import Request, Response


def to_request(request: HttpRequest, *, with_body: bool = False) -> Request:
    headers = {key: value for key, value in request.headers.items()}
    body = request.body if with_body else b""
    return Request(request.method or "GET", request.build_absolute_uri(), headers, body)


def to_response(response: Response) -> HttpResponse:
    out = HttpResponse(response.body, status=response.status, content_type=response.header("content-type"))
    for name, value in response.headers:
        lower = name.lower()
        if lower == "content-type":
            continue
        if lower == "set-cookie":
            _set_cookie(out, value)
        else:
            out[name] = value
    return out


def _set_cookie(out: HttpResponse, header: str) -> None:
    """Django keeps cookies apart from headers, so each Set-Cookie is replayed through set_cookie."""
    first, *attributes = [part.strip() for part in header.split(";")]
    name, _, value = first.partition("=")
    max_age: Optional[int] = None
    domain: Optional[str] = None
    path = "/"
    samesite: Optional[str] = None
    flags = set()
    for attribute in attributes:
        key, _, attribute_value = attribute.partition("=")
        key = key.lower()
        if key == "max-age":
            max_age = int(attribute_value)
        elif key == "domain":
            domain = attribute_value
        elif key == "path":
            path = attribute_value
        elif key == "samesite":
            samesite = attribute_value
        else:
            flags.add(key)
    out.set_cookie(
        name,
        value,
        max_age=max_age,
        path=path,
        domain=domain,
        secure="secure" in flags,
        httponly="httponly" in flags,
        samesite=samesite,  # type: ignore[arg-type]
    )
