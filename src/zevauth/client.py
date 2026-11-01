"""The ZevAuth backend API, with your secret key.

``ZevAuthClient`` is synchronous (Django, Flask, scripts);
``AsyncZevAuthClient`` is the same API for asyncio (FastAPI, Starlette).
Keyword arguments are snake_case; they are sent in the API's camelCase.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Iterator, Mapping, Optional, Tuple, Union, cast
from urllib.parse import quote

import httpx

from ._http import (
    DEFAULT_API_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT_SECONDS,
    AsyncTransport,
    Query,
    SyncTransport,
)
from .types import Page, User


class _Unset:
    def __repr__(self) -> str:
        return "UNSET"


UNSET: Any = _Unset()
"""Leaves a field unchanged in an update. ``None`` clears it instead."""

_Call = Tuple[str, str, Query, Any]
Metadata = Mapping[str, Union[str, int, float, bool]]


def _id(value: str) -> str:
    return quote(str(value), safe="")


def _body(**fields: Any) -> Dict[str, Any]:
    return {key: value for key, value in fields.items() if value is not UNSET}


# ── What each call sends ────────────────────────────────────────────


class _UserCalls:
    @staticmethod
    def list(
        limit: Optional[int] = None,
        after: Optional[str] = None,
        query: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> _Call:
        params: Dict[str, Any] = {"limit": limit, "after": after, "query": query}
        for key, value in (metadata or {}).items():
            params[f"metadata[{key}]"] = value
        return "GET", "/v1/users", params, None

    @staticmethod
    def get(user_id: str) -> _Call:
        return "GET", f"/v1/users/{_id(user_id)}", None, None

    @staticmethod
    def create(**fields: Any) -> _Call:
        return "POST", "/v1/users", None, _body(**fields)

    @staticmethod
    def update(user_id: str, **fields: Any) -> _Call:
        return "PATCH", f"/v1/users/{_id(user_id)}", None, _body(**fields)

    @staticmethod
    def set_blocked(user_id: str, blocked: bool) -> _Call:
        return "POST", f"/v1/users/{_id(user_id)}/blocked", None, {"blocked": blocked}

    @staticmethod
    def revoke_sessions(user_id: str) -> _Call:
        return "POST", f"/v1/users/{_id(user_id)}/sessions/revoke", None, None

    @staticmethod
    def reset_mfa(user_id: str, revoke_sessions: bool) -> _Call:
        query = {"revokeSessions": True} if revoke_sessions else None
        return "DELETE", f"/v1/users/{_id(user_id)}/mfa", query, None

    @staticmethod
    def delete(user_id: str) -> _Call:
        return "DELETE", f"/v1/users/{_id(user_id)}", None, None


class _OrganizationCalls:
    @staticmethod
    def list_for_user(user_id: str) -> _Call:
        return "GET", "/v1/organizations", {"userId": user_id}, None

    @staticmethod
    def get(organization_id: str) -> _Call:
        return "GET", f"/v1/organizations/{_id(organization_id)}", None, None

    @staticmethod
    def create(**fields: Any) -> _Call:
        return "POST", "/v1/organizations", None, _body(**fields)

    @staticmethod
    def update(organization_id: str, **fields: Any) -> _Call:
        return "PATCH", f"/v1/organizations/{_id(organization_id)}", None, _body(**fields)

    @staticmethod
    def delete(organization_id: str) -> _Call:
        return "DELETE", f"/v1/organizations/{_id(organization_id)}", None, None

    @staticmethod
    def add_member(organization_id: str, user_id: str, role: Any) -> _Call:
        return "POST", f"/v1/organizations/{_id(organization_id)}/members", None, _body(userId=user_id, role=role)

    @staticmethod
    def remove_member(organization_id: str, user_id: str) -> _Call:
        return "DELETE", f"/v1/organizations/{_id(organization_id)}/members/{_id(user_id)}", None, None


# ── Synchronous ─────────────────────────────────────────────────────


class Users:
    def __init__(self, transport: SyncTransport) -> None:
        self._t = transport

    def _send(self, call: _Call) -> Any:
        method, path, query, body = call
        return self._t.request(method, path, query=query, body=body)

    def list(
        self,
        *,
        limit: Optional[int] = None,
        after: Optional[str] = None,
        query: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> Page:
        """One page of users. ``metadata`` filters on public metadata, ANDed."""
        return cast(Page, self._send(_UserCalls.list(limit, after, query, metadata)))

    def iterate(
        self,
        *,
        limit: Optional[int] = None,
        query: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> Iterator[User]:
        """Every user, following the cursor page by page."""
        after: Optional[str] = None
        while True:
            page = self.list(limit=limit, after=after, query=query, metadata=metadata)
            yield from page.get("data", [])
            after = page.get("next") if page.get("hasMore") else None
            if not after:
                return

    def get(self, user_id: str) -> User:
        return cast(User, self._send(_UserCalls.get(user_id)))

    def create(
        self,
        *,
        email: str,
        password: Any = UNSET,
        first_name: Any = UNSET,
        last_name: Any = UNSET,
        email_verified: Any = UNSET,
        public_metadata: Any = UNSET,
        private_metadata: Any = UNSET,
    ) -> User:
        return cast(
            User,
            self._send(
                _UserCalls.create(
                    email=email,
                    password=password,
                    firstName=first_name,
                    lastName=last_name,
                    emailVerified=email_verified,
                    publicMetadata=public_metadata,
                    privateMetadata=private_metadata,
                )
            ),
        )

    def update(
        self,
        user_id: str,
        *,
        first_name: Any = UNSET,
        last_name: Any = UNSET,
        username: Any = UNSET,
        image_url: Any = UNSET,
        public_metadata: Any = UNSET,
        private_metadata: Any = UNSET,
        password: Any = UNSET,
        email_verified: Any = UNSET,
    ) -> User:
        """Changes only what you pass. ``None`` clears a field; leaving it out keeps it."""
        return cast(
            User,
            self._send(
                _UserCalls.update(
                    user_id,
                    firstName=first_name,
                    lastName=last_name,
                    username=username,
                    imageUrl=image_url,
                    publicMetadata=public_metadata,
                    privateMetadata=private_metadata,
                    password=password,
                    emailVerified=email_verified,
                )
            ),
        )

    def set_blocked(self, user_id: str, blocked: bool) -> Dict[str, Any]:
        """Blocks or unblocks. Returns ``{"user", "sessionsRevoked"}``."""
        return cast(Dict[str, Any], self._send(_UserCalls.set_blocked(user_id, blocked)))

    def revoke_sessions(self, user_id: str) -> Dict[str, Any]:
        """Signs the user out everywhere. Returns ``{"sessionsRevoked"}``."""
        return cast(Dict[str, Any], self._send(_UserCalls.revoke_sessions(user_id)))

    def reset_mfa(self, user_id: str, *, revoke_sessions: bool = False) -> Any:
        """Removes the user's two-step verification, for support. Optionally signs them out everywhere."""
        return self._send(_UserCalls.reset_mfa(user_id, revoke_sessions))

    def delete(self, user_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._send(_UserCalls.delete(user_id)))


class Organizations:
    def __init__(self, transport: SyncTransport) -> None:
        self._t = transport

    def _send(self, call: _Call) -> Any:
        method, path, query, body = call
        return self._t.request(method, path, query=query, body=body)

    def list_for_user(self, user_id: str) -> Dict[str, Any]:
        """The user's memberships: ``{"data": [{"organization", "role", "permissions"}]}``."""
        return cast(Dict[str, Any], self._send(_OrganizationCalls.list_for_user(user_id)))

    def get(self, organization_id: str) -> Dict[str, Any]:
        """``{"organization", "members"}``."""
        return cast(Dict[str, Any], self._send(_OrganizationCalls.get(organization_id)))

    def create(
        self,
        *,
        name: str,
        created_by: str,
        slug: Any = UNSET,
        max_members: Any = UNSET,
    ) -> Dict[str, Any]:
        return cast(
            Dict[str, Any],
            self._send(_OrganizationCalls.create(name=name, createdBy=created_by, slug=slug, maxMembers=max_members)),
        )

    def update(
        self,
        organization_id: str,
        *,
        name: Any = UNSET,
        slug: Any = UNSET,
        image_url: Any = UNSET,
        require_mfa: Any = UNSET,
    ) -> Dict[str, Any]:
        return cast(
            Dict[str, Any],
            self._send(
                _OrganizationCalls.update(
                    organization_id, name=name, slug=slug, imageUrl=image_url, requireMfa=require_mfa
                )
            ),
        )

    def delete(self, organization_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._send(_OrganizationCalls.delete(organization_id)))

    def add_member(self, organization_id: str, *, user_id: str, role: Any = UNSET) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._send(_OrganizationCalls.add_member(organization_id, user_id, role)))

    def remove_member(self, organization_id: str, user_id: str) -> Any:
        return self._send(_OrganizationCalls.remove_member(organization_id, user_id))


class ZevAuthClient:
    """The backend API, synchronous.

    Args:
        secret_key: ``sk_test_…`` or ``sk_live_…``. Never ship it to a browser.
        api_url: Where the ZevAuth API lives.
        timeout: Seconds per attempt.
        max_retries: Retries for 429, 502, 503, 504 and network failures. Never for a 500.
        http_client: Your own ``httpx.Client`` (proxies, tests).
    """

    def __init__(
        self,
        secret_key: Optional[str],
        *,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: Optional[httpx.Client] = None,
        **transport_options: Any,
    ) -> None:
        self._transport = SyncTransport(
            secret_key,
            api_url=api_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            **transport_options,
        )
        self.users = Users(self._transport)
        self.organizations = Organizations(self._transport)


# ── Asynchronous ────────────────────────────────────────────────────


class AsyncUsers:
    def __init__(self, transport: AsyncTransport) -> None:
        self._t = transport

    async def _send(self, call: _Call) -> Any:
        method, path, query, body = call
        return await self._t.request(method, path, query=query, body=body)

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        after: Optional[str] = None,
        query: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> Page:
        return cast(Page, await self._send(_UserCalls.list(limit, after, query, metadata)))

    async def iterate(
        self,
        *,
        limit: Optional[int] = None,
        query: Optional[str] = None,
        metadata: Optional[Metadata] = None,
    ) -> AsyncIterator[User]:
        after: Optional[str] = None
        while True:
            page = await self.list(limit=limit, after=after, query=query, metadata=metadata)
            for user in page.get("data", []):
                yield user
            after = page.get("next") if page.get("hasMore") else None
            if not after:
                return

    async def get(self, user_id: str) -> User:
        return cast(User, await self._send(_UserCalls.get(user_id)))

    async def create(
        self,
        *,
        email: str,
        password: Any = UNSET,
        first_name: Any = UNSET,
        last_name: Any = UNSET,
        email_verified: Any = UNSET,
        public_metadata: Any = UNSET,
        private_metadata: Any = UNSET,
    ) -> User:
        return cast(
            User,
            await self._send(
                _UserCalls.create(
                    email=email,
                    password=password,
                    firstName=first_name,
                    lastName=last_name,
                    emailVerified=email_verified,
                    publicMetadata=public_metadata,
                    privateMetadata=private_metadata,
                )
            ),
        )

    async def update(
        self,
        user_id: str,
        *,
        first_name: Any = UNSET,
        last_name: Any = UNSET,
        username: Any = UNSET,
        image_url: Any = UNSET,
        public_metadata: Any = UNSET,
        private_metadata: Any = UNSET,
        password: Any = UNSET,
        email_verified: Any = UNSET,
    ) -> User:
        return cast(
            User,
            await self._send(
                _UserCalls.update(
                    user_id,
                    firstName=first_name,
                    lastName=last_name,
                    username=username,
                    imageUrl=image_url,
                    publicMetadata=public_metadata,
                    privateMetadata=private_metadata,
                    password=password,
                    emailVerified=email_verified,
                )
            ),
        )

    async def set_blocked(self, user_id: str, blocked: bool) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_UserCalls.set_blocked(user_id, blocked)))

    async def revoke_sessions(self, user_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_UserCalls.revoke_sessions(user_id)))

    async def reset_mfa(self, user_id: str, *, revoke_sessions: bool = False) -> Any:
        return await self._send(_UserCalls.reset_mfa(user_id, revoke_sessions))

    async def delete(self, user_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_UserCalls.delete(user_id)))


class AsyncOrganizations:
    def __init__(self, transport: AsyncTransport) -> None:
        self._t = transport

    async def _send(self, call: _Call) -> Any:
        method, path, query, body = call
        return await self._t.request(method, path, query=query, body=body)

    async def list_for_user(self, user_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_OrganizationCalls.list_for_user(user_id)))

    async def get(self, organization_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_OrganizationCalls.get(organization_id)))

    async def create(
        self,
        *,
        name: str,
        created_by: str,
        slug: Any = UNSET,
        max_members: Any = UNSET,
    ) -> Dict[str, Any]:
        return cast(
            Dict[str, Any],
            await self._send(
                _OrganizationCalls.create(name=name, createdBy=created_by, slug=slug, maxMembers=max_members)
            ),
        )

    async def update(
        self,
        organization_id: str,
        *,
        name: Any = UNSET,
        slug: Any = UNSET,
        image_url: Any = UNSET,
        require_mfa: Any = UNSET,
    ) -> Dict[str, Any]:
        return cast(
            Dict[str, Any],
            await self._send(
                _OrganizationCalls.update(
                    organization_id, name=name, slug=slug, imageUrl=image_url, requireMfa=require_mfa
                )
            ),
        )

    async def delete(self, organization_id: str) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_OrganizationCalls.delete(organization_id)))

    async def add_member(self, organization_id: str, *, user_id: str, role: Any = UNSET) -> Dict[str, Any]:
        return cast(Dict[str, Any], await self._send(_OrganizationCalls.add_member(organization_id, user_id, role)))

    async def remove_member(self, organization_id: str, user_id: str) -> Any:
        return await self._send(_OrganizationCalls.remove_member(organization_id, user_id))


class AsyncZevAuthClient:
    """The backend API for asyncio. Same arguments as :class:`ZevAuthClient`."""

    def __init__(
        self,
        secret_key: Optional[str],
        *,
        api_url: str = DEFAULT_API_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        http_client: Optional[httpx.AsyncClient] = None,
        **transport_options: Any,
    ) -> None:
        self._transport = AsyncTransport(
            secret_key,
            api_url=api_url,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            **transport_options,
        )
        self.users = AsyncUsers(self._transport)
        self.organizations = AsyncOrganizations(self._transport)
