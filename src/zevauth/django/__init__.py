"""ZevAuth for Django.

settings.py::

    ZEVAUTH = {
        "ENVIRONMENT_ID": "env_live_…",
        "SECRET_KEY": os.environ["ZEVAUTH_SECRET_KEY"],      # for the backend API
        "PUBLISHABLE_KEY": "pk_live_…",                      # for the session bridge
        "SESSION_BRIDGE": True,                              # cookies for server-rendered pages
    }
    MIDDLEWARE = [..., "zevauth.django.ZevAuthMiddleware"]

urls.py::

    path("zevauth/", include("zevauth.django.urls")),        # bridge + handshake

views.py::

    from zevauth.django import require_auth

    @require_auth
    def dashboard(request):
        return render(request, "dashboard.html", {"user_id": request.zevauth.user_id})

Install with ``pip install "zevauth[django]"``.
"""

from .conf import get_zevauth
from .decorators import require_auth
from .middleware import ZevAuthMiddleware

__all__ = ["ZevAuthMiddleware", "get_zevauth", "require_auth"]
