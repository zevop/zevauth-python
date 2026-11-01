from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


TOKENS = load("tokens.json")
NOW = float(TOKENS["now"])
ENV = TOKENS["environmentId"]
API_URL = "https://api.zevauth.test"


class KeyServer:
    """Serves discovery and a key set, switching sets after the first fetch.

    Counts fetches so tests can prove the cache and the unknown-kid
    cooldown hold.
    """

    def __init__(self, first: str = "jwks.json", later: Optional[str] = None) -> None:
        self.first = load(first)
        self.later = load(later) if later else self.first
        self.discovery = load("discovery.json")
        self.jwks_fetches = 0
        self.discovery_fetches = 0
        self.requests: List[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            self.discovery_fetches += 1
            return httpx.Response(200, json=self.discovery)
        if url == self.discovery["jwks_uri"]:
            self.jwks_fetches += 1
            body: Dict[str, Any] = self.first if self.jwks_fetches == 1 else self.later
            return httpx.Response(200, json=body)
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def key_server() -> KeyServer:
    return KeyServer()
