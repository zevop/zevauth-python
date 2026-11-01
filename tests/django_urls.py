from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.urls import include, path

from zevauth.django import require_auth


def page(request: HttpRequest) -> JsonResponse:
    auth = request.zevauth  # type: ignore[attr-defined]
    return JsonResponse({"signedIn": auth.is_signed_in, "userId": auth.user_id})


@require_auth
def me(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"userId": request.zevauth.user_id})  # type: ignore[attr-defined]


@require_auth(require_mfa=True)
def sensitive(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


urlpatterns = [
    path("page", page),
    path("api/me", me),
    path("api/sensitive", sensitive),
    path("zevauth/", include("zevauth.django.urls")),
]
