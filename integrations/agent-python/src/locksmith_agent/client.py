"""The Locksmith agent client: identity only, never a secret value. Mirrors packages/agent in snake_case."""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ._secret import Secret
from .types import GATEWAY_SLUGS, AgentError, Grant, RelayResponse

RENEW_BEFORE_S = 60.0
_TIMEOUT = httpx.Timeout(30.0)


def _env(name: str) -> str | None:
    return os.environ.get(name) or None


def _origin(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}".lower()


def _slug_of(status: int, body: Any) -> str:
    s = body.get("error") if isinstance(body, dict) else None
    if isinstance(s, str) and s in GATEWAY_SLUGS:
        return s
    return "unauthorized" if status == 401 else "transport"


def _json(res: httpx.Response) -> Any:
    try:
        return res.json()
    except ValueError:
        return None


class _GatewayAuth(httpx.Auth):
    """Adds the token only for the gateway origin; renews once after a 401."""

    def __init__(self, client: AgentClient) -> None:
        self._client = client

    def __repr__(self) -> str:
        return "GatewayAuth(<redacted>)"

    def _check(self, request: httpx.Request) -> None:
        if _origin(str(request.url)) != self._client._gateway_origin:
            raise AgentError("foreign_origin", 0)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        self._check(request)
        request.headers["Authorization"] = "Bearer " + self._client._token()
        response = yield request
        if response.status_code == 401 and self._client._renewable:
            self._client._drop()
            request.headers["Authorization"] = "Bearer " + self._client._token(force=True)
            yield request

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        self._check(request)
        request.headers["Authorization"] = "Bearer " + await asyncio.to_thread(self._client._token)
        response = yield request
        if response.status_code == 401 and self._client._renewable:
            self._client._drop()
            request.headers["Authorization"] = "Bearer " + await asyncio.to_thread(self._client._token, True)
            yield request


class AgentClient:
    """Secrets live in `Secret` holders only: no attribute prints, pickles or copies a token."""

    def __init__(
        self,
        *,
        gateway_url: str | None = None,
        control_plane_url: str | None = None,
        enrollment_secret: str | None = None,
        token: str | Callable[[], str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        gw = (gateway_url or _env("LOCKSMITH_GATEWAY_URL") or "").rstrip("/")
        if not gw or not urlsplit(gw).scheme or not urlsplit(gw).netloc:
            raise AgentError("bad_config", 0)
        enrol = enrollment_secret or _env("LOCKSMITH_ENROLLMENT_SECRET")
        if token is None and not enrol:
            raise AgentError("bad_config", 0)
        self._gateway_url = gw
        self._gateway_origin = _origin(gw)
        self._control_plane = (control_plane_url or _env("LOCKSMITH_CONTROL_PLANE_URL") or gw).rstrip("/")
        self._enrollment = Secret(enrol) if enrol else None
        self._source: Secret | Callable[[], str] | None = Secret(token) if isinstance(token, str) else token
        self._renewable = not isinstance(self._source, Secret)
        self._current: Secret | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()
        self._http = httpx.Client(transport=transport, timeout=_TIMEOUT, trust_env=True)
        self._auth = _GatewayAuth(self)

    def __repr__(self) -> str:
        return f"AgentClient(gateway={self._gateway_url!r})"

    # -- token handling -------------------------------------------------------------------------
    def _drop(self) -> None:
        with self._lock:
            self._current = None
            self._expires_at = 0.0

    def _mint(self) -> Secret:
        src = self._source
        if isinstance(src, Secret):
            return src
        if callable(src):
            try:
                return Secret(src())
            except Exception:  # noqa: BLE001 - never surface the caller's error text
                raise AgentError("unauthorized", 0) from None
        assert self._enrollment is not None
        try:
            res = self._http.post(
                f"{self._control_plane}/v1/agent-tokens",
                json={"enrollment_secret": self._enrollment.reveal()},
            )
        except httpx.HTTPError:
            raise AgentError("transport", 0) from None
        body = _json(res)
        if res.status_code >= 400:
            raise AgentError(_slug_of(res.status_code, body), res.status_code)
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            raise AgentError("transport", res.status_code)
        try:
            exp = datetime.fromisoformat(str(body.get("expires_at", "")).replace("Z", "+00:00")).timestamp()
        except ValueError:
            exp = time.time() + 300
        self._expires_at = exp
        return Secret(body["access_token"])

    def _token(self, force: bool = False) -> str:
        with self._lock:
            if self._current is None or force or time.time() >= self._expires_at - RENEW_BEFORE_S:
                if isinstance(self._source, Secret):
                    self._current = self._source
                else:
                    self._current = self._mint()
                    if callable(self._source):
                        self._expires_at = (
                            time.time() + RENEW_BEFORE_S
                        )  # function tokens: ask again each minute
            return self._current.reveal()

    # -- public surface -------------------------------------------------------------------------
    @property
    def mcp_url(self) -> str:
        return f"{self._gateway_url}/mcp"

    @property
    def auth(self) -> httpx.Auth:
        """An `httpx.Auth` that adds the token for the gateway origin and refuses any other."""
        return self._auth

    def bearer_token(self, renew: bool = False) -> str:
        """The current token for frameworks with a header hook; call per request and never store it."""
        return self._token(force=renew)

    def _request(self, method: str, path: str, **kw: Any) -> Any:
        url = urljoin(self._gateway_url + "/", path.lstrip("/"))
        try:
            res = self._http.request(method, url, auth=self._auth, **kw)
        except httpx.HTTPError:
            raise AgentError("transport", 0) from None
        body = _json(res)
        if res.status_code >= 400:
            raise AgentError(_slug_of(res.status_code, body), res.status_code)
        return body

    def list_grants(self) -> list[Grant]:
        body = self._request("GET", "/v1/grants")
        return body["grants"]

    def relay(
        self,
        *,
        secret_id: str,
        version: int,
        method: str,
        url: str,
        headers: list[tuple[str, str]] | None = None,
        body: str | None = None,
        body_base64: str | None = None,
    ) -> RelayResponse:
        wire = {
            "secret_id": secret_id,
            "version": version,
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "body_base64": body_base64,
        }
        return self._request("POST", "/v1/relay", json={k: v for k, v in wire.items() if v is not None})

    def close(self) -> None:
        self._drop()
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
