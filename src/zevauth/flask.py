"""ZevAuth for Flask.

    from flask import Flask, g
    from zevauth import ZevAuth
    from zevauth.flask import ZevAuthFlask, require_auth

    app = Flask(__name__)
    ZevAuthFlask(app, ZevAuth("env_live_…", secret_key=…))

    @app.get("/api/me")
    @require_auth
    def me():
        return {"userId": g.zevauth.user_id}

``g.zevauth`` is set on every request. With the session bridge on, the
extension also serves the bridge endpoint and handshake page, and sends a
page whose cookie expired through the handshake first.

Install with ``pip install "zevauth[flask]"``.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union, overload

from flask import Blueprint, Flask, current_app, g, jsonify
from flask import Response as FlaskResponse
from flask import request as flask_request

from .auth import Auth, Request, Response, check_auth
from .errors import AuthRefusal
from .server import ZevAuth

View = TypeVar("View", bound=Callable[..., Any])
_EXTENSION = "zevauth"


def to_request(*, with_body: bool = False) -> Request:
    body = flask_request.get_data(cache=True) if with_body else b""
    return Request(flask_request.method, flask_request.url, dict(flask_request.headers), body)


def to_response(response: Response) -> FlaskResponse:
    return FlaskResponse(response.body, status=response.status, headers=response.headers)


class ZevAuthFlask:
    """The Flask extension. Use ``ZevAuthFlask(app, zevauth)`` or ``init_app`` with an app factory."""

    def __init__(self, app: Optional[Flask] = None, zevauth: Optional[ZevAuth] = None) -> None:
        self.zevauth = zevauth
        if app is not None:
            self.init_app(app, zevauth)

    def init_app(self, app: Flask, zevauth: Optional[ZevAuth] = None) -> None:
        zevauth = zevauth or self.zevauth
        if zevauth is None:
            raise ValueError("ZevAuthFlask needs a ZevAuth: ZevAuthFlask(app, ZevAuth('env_…')).")
        self.zevauth = zevauth
        app.extensions[_EXTENSION] = zevauth
        options = zevauth.bridge_options
        bridge_paths = (options.bridge_path, options.handshake_path) if options else ()

        @app.before_request
        def _authenticate() -> Optional[FlaskResponse]:
            if flask_request.path in bridge_paths:
                g.zevauth = zevauth.get_auth(to_request())
                return None
            auth, handshake = zevauth.authenticate(to_request())
            g.zevauth = auth
            return to_response(handshake) if handshake is not None else None

        @app.errorhandler(AuthRefusal)
        def _refused(error: AuthRefusal) -> Any:
            return jsonify(error.body()), error.status

        if options:
            app.register_blueprint(self.bridge_blueprint())

    def bridge_blueprint(self) -> Blueprint:
        """The bridge endpoint (POST) and handshake page (GET), at the configured paths."""
        zevauth = self.zevauth
        assert zevauth is not None and zevauth.bridge_options is not None
        options = zevauth.bridge_options
        blueprint = Blueprint("zevauth", __name__)

        @blueprint.route(options.bridge_path, methods=["POST", "GET", "PUT", "DELETE"])
        def session() -> FlaskResponse:
            return to_response(zevauth.handle_session_bridge(to_request(with_body=True)))

        @blueprint.route(options.handshake_path, methods=["GET"])
        def handshake() -> FlaskResponse:
            return to_response(zevauth.handshake_page(to_request()))

        return blueprint


def current_auth() -> Auth:
    """Who is signed in for this request."""
    auth = g.get("zevauth")
    if isinstance(auth, Auth):
        return auth
    zevauth: ZevAuth = current_app.extensions[_EXTENSION]
    auth = zevauth.get_auth(to_request())
    g.zevauth = auth
    return auth


@overload
def require_auth(view: View) -> View: ...


@overload
def require_auth(
    view: None = None, *, allow_pending_tasks: bool = False, require_mfa: bool = False
) -> Callable[[View], View]: ...


def require_auth(
    view: Optional[View] = None, *, allow_pending_tasks: bool = False, require_mfa: bool = False
) -> Union[View, Callable[[View], View]]:
    """Use bare (``@require_auth``) or with options. Refusals answer 401/403 as JSON."""

    def decorate(inner: View) -> View:
        @wraps(inner)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            check_auth(current_auth(), allow_pending_tasks=allow_pending_tasks, require_mfa=require_mfa)
            return inner(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate(view) if view is not None else decorate
