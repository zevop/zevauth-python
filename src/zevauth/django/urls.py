"""``path("zevauth/", include("zevauth.django.urls"))`` serves ``/zevauth/session`` and ``/zevauth/handshake``.

Mounted elsewhere, set ``SESSION_BRIDGE = {"BRIDGE_PATH": …, "HANDSHAKE_PATH": …}``
to match, and pass the bridge URL to the browser SDK.
"""

from django.urls import path

from . import views

app_name = "zevauth"

urlpatterns = [
    path("session", views.session_bridge, name="session"),
    path("handshake", views.handshake, name="handshake"),
]
