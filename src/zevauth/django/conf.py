"""Builds the one :class:`~zevauth.ZevAuth` for the project from ``settings.ZEVAUTH``."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Mapping

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.dispatch import receiver

from ..server import SessionBridgeOptions, ZevAuth
from ..verify import DEFAULT_API_URL

_BRIDGE_KEYS = {
    "BRIDGE_PATH": "bridge_path",
    "HANDSHAKE_PATH": "handshake_path",
    "ALLOWED_ORIGINS": "allowed_origins",
    "COOKIE_DOMAIN": "cookie_domain",
    "SECURE": "secure",
    "UI_SCRIPT_URL": "ui_script_url",
}


def _bridge(value: Any) -> Any:
    if value in (None, False):
        return None
    if value is True:
        return SessionBridgeOptions()
    if isinstance(value, Mapping):
        return SessionBridgeOptions(**{_BRIDGE_KEYS.get(k, k.lower()): v for k, v in value.items()})
    raise ImproperlyConfigured("ZEVAUTH['SESSION_BRIDGE'] must be True, False or a dict of options.")


@lru_cache(maxsize=1)
def get_zevauth() -> ZevAuth:
    """The project's :class:`ZevAuth`, built once from ``settings.ZEVAUTH``."""
    config: Dict[str, Any] = dict(getattr(settings, "ZEVAUTH", None) or {})
    environment_id = config.get("ENVIRONMENT_ID")
    if not environment_id:
        raise ImproperlyConfigured(
            "Set ZEVAUTH = {'ENVIRONMENT_ID': 'env_…'} in settings. Find the id in the ZevAuth console under API keys."
        )
    return ZevAuth(
        environment_id,
        secret_key=config.get("SECRET_KEY"),
        publishable_key=config.get("PUBLISHABLE_KEY"),
        api_url=config.get("API_URL", DEFAULT_API_URL),
        session_bridge=_bridge(config.get("SESSION_BRIDGE")),
        jwks=config.get("JWKS"),
        issuer=config.get("ISSUER"),
    )


@receiver(setting_changed)
def _reset(setting: str, **_: Any) -> None:
    if setting == "ZEVAUTH":
        get_zevauth.cache_clear()
