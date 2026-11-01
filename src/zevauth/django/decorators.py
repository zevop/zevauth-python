"""``@require_auth``: refuses a view with the ZevAuth error envelope unless the rules pass."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional, TypeVar, overload

from django.http import HttpRequest, HttpResponse, JsonResponse

from ..auth import Auth, check_auth
from ..errors import AuthRefusal
from .conf import get_zevauth
from .http import to_request

View = TypeVar("View", bound=Callable[..., Any])


def _auth(request: HttpRequest) -> Auth:
    existing = getattr(request, "zevauth", None)
    if isinstance(existing, Auth):
        return existing
    auth = get_zevauth().get_auth(to_request(request))
    request.zevauth = auth  # type: ignore[attr-defined]
    return auth


@overload
def require_auth(view: View) -> View: ...


@overload
def require_auth(
    view: None = None, *, allow_pending_tasks: bool = False, require_mfa: bool = False
) -> Callable[[View], View]: ...


def require_auth(view: Optional[View] = None, *, allow_pending_tasks: bool = False, require_mfa: bool = False) -> Any:
    """Use bare (``@require_auth``) or with options (``@require_auth(require_mfa=True)``).

    Refusals answer 401 ``unauthorized``, 403 ``session_task_pending`` or
    403 ``mfa_required`` as JSON. For a page that should redirect to your
    sign-in screen instead, check ``request.zevauth.is_signed_in`` yourself.
    """

    def decorate(inner: View) -> View:
        @wraps(inner)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            try:
                check_auth(_auth(request), allow_pending_tasks=allow_pending_tasks, require_mfa=require_mfa)
            except AuthRefusal as refused:
                return JsonResponse(refused.body(), status=refused.status)
            return inner(request, *args, **kwargs)  # type: ignore[no-any-return]

        return wrapper  # type: ignore[return-value]

    return decorate(view) if view is not None else decorate
