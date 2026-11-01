"""The shapes the API returns. Fields keep the API's camelCase, as on the wire."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class User(TypedDict, total=False):
    id: str
    email: Optional[str]
    emailVerified: bool
    username: Optional[str]
    phone: Optional[str]
    phoneVerified: bool
    firstName: Optional[str]
    lastName: Optional[str]
    imageUrl: Optional[str]
    publicMetadata: Dict[str, Any]
    status: str
    mfaEnabled: bool
    lastSignInAt: Optional[str]
    createdAt: str


class Organization(TypedDict, total=False):
    id: str
    name: str
    slug: Optional[str]
    imageUrl: Optional[str]
    publicMetadata: Any
    maxMembers: Optional[int]
    requireMfa: bool
    createdAt: str


class OrganizationMember(TypedDict, total=False):
    userId: str
    email: Optional[str]
    firstName: Optional[str]
    lastName: Optional[str]
    role: str
    joinedAt: str


class Page(TypedDict, total=False):
    """One page of a list. ``next`` is the cursor to pass as ``after``."""

    data: List[Any]
    hasMore: bool
    next: Optional[str]
    totalCount: int
