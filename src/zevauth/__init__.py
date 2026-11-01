"""ZevAuth for Python: verify sessions, call the backend API, check webhooks.

    from zevauth import ZevAuth

    zevauth = ZevAuth("env_live_…", secret_key=os.environ["ZEVAUTH_SECRET_KEY"])

Framework integrations: ``zevauth.fastapi``, ``zevauth.django``,
``zevauth.flask``. Contract shared with every ZevAuth server library:
https://github.com/zevop/zevauth-sdk/tree/main/spec
"""

from ._version import __version__
from .auth import SIGNED_OUT, Auth, Request, Response, check_auth
from .bridge import SessionBridge, bridge_cookie_names
from .client import UNSET, AsyncZevAuthClient, ZevAuthClient
from .errors import AuthRefusal, ZevAuthError, ZevAuthVerifyError, ZevAuthWebhookError
from .server import SessionBridgeOptions, ZevAuth
from .types import Organization, OrganizationMember, Page, User
from .verify import Claims, TokenVerifier, bearer_from
from .webhooks import WebhookEvent, construct_webhook_event, verify_webhook

__all__ = [
    "__version__",
    "Auth",
    "AuthRefusal",
    "AsyncZevAuthClient",
    "Claims",
    "Organization",
    "OrganizationMember",
    "Page",
    "Request",
    "Response",
    "SIGNED_OUT",
    "SessionBridge",
    "SessionBridgeOptions",
    "TokenVerifier",
    "UNSET",
    "User",
    "WebhookEvent",
    "ZevAuth",
    "ZevAuthClient",
    "ZevAuthError",
    "ZevAuthVerifyError",
    "ZevAuthWebhookError",
    "bearer_from",
    "bridge_cookie_names",
    "check_auth",
    "construct_webhook_event",
    "verify_webhook",
]
