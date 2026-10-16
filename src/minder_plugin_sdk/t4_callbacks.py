"""The platform context of a remote (T4) plugin: signed grant callbacks.

Inside ``minder-plugin serve`` a plugin uses ``self.ctx`` exactly as it would
in-process (see ``context.py``). Each call becomes::

    POST <callback_base>/v1/plugin-callbacks/<capability>
    Authorization: Bearer <grant>
    Content-Type: application/json
    Content-Digest / Signature-Input / Signature   (the installation key)

The signature covers ``@method``, ``@authority`` (the Minder host from
``callback_base``), ``@path``, ``@query`` (``?``: callbacks carry no query),
``content-digest`` and ``authorization``.

where ``callback_base`` and the grant come from the invocation Minder sent.
The grant alone is not enough: Minder also checks the installation's
signature, which covers the ``Authorization`` header, so a leaked grant can't
be replayed by anyone else. Minder takes the tenant and owner from the grant;
the plugin never names one.

Request bodies (JSON) and the ``result`` each capability answers with:

- ``secrets.read``: ``{"key"}``; the value, or ``null`` when unset.
- ``plugins.invoke``: ``{"plugin", "action", "kwargs"}``; the action's result.
- ``documents.index``: ``{"kb_id", "filename", "content_b64",
  "content_type"}``; the upload response (an object).
- ``timeseries.write``: ``{"lines": [...], "precision"}``; points written.
- ``timeseries.latest``: ``{"measurement", "tag_key", "tag_value",
  "fields"}``; as ``ctx.timeseries.latest`` returns.

A 2xx answer is ``{"result": ...}``. Errors map to the context's exceptions:
401/403 to :class:`CapabilityDenied`; 400/404/409/413/422 to
:class:`CapabilityInvalid`; anything else (429, 5xx, a network failure, the
invocation's deadline passing) to :class:`CapabilityUnavailable`. The
exception carries the capability and a short reason, never a value.

``telegraf.*`` comes from ``MANAGES``, which remote plugins can't declare, so
those calls are denied locally without contacting Minder.

Needs ``httpx`` (``pip install 'minder-plugin-sdk[serve]'``).
"""

from __future__ import annotations

import base64
import json
import time
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    Optional,
    Union,
)
from urllib.parse import quote, urlsplit

from .context import (
    CAP_DOCUMENTS_INDEX,
    CAP_PLUGINS_INVOKE,
    CAP_SECRETS_READ,
    CAP_TELEGRAF_CLEAR_MANAGED_REGION,
    CAP_TELEGRAF_RELOAD,
    CAP_TELEGRAF_SET_MANAGED_REGION,
    CAP_TIMESERIES_LATEST,
    CAP_TIMESERIES_WRITE,
    capability_granted,
)
from .errors import CapabilityDenied, CapabilityInvalid, CapabilityUnavailable
from .t4 import CALLBACK_PATH_PREFIX, InstallationKey, origin_of

if TYPE_CHECKING:  # pragma: no cover
    import httpx

__all__ = ["CallbackPlatformContext", "REMOTE_CAPABILITIES"]

#: The context capabilities a remote plugin can be granted.
REMOTE_CAPABILITIES: FrozenSet[str] = frozenset(
    {
        CAP_SECRETS_READ,
        CAP_PLUGINS_INVOKE,
        CAP_DOCUMENTS_INDEX,
        CAP_TIMESERIES_WRITE,
        CAP_TIMESERIES_LATEST,
    }
)

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_DENIED = frozenset({401, 403})
_INVALID = frozenset({400, 404, 409, 413, 422})
_REMOTE_DENIAL = "not available to remote plugins"


class _Secrets:
    def __init__(self, ctx: "CallbackPlatformContext") -> None:
        self._ctx = ctx

    async def get(self, key: str) -> Optional[str]:
        value = await self._ctx.call(CAP_SECRETS_READ, {"key": key})
        if value is not None and not isinstance(value, str):
            raise CapabilityUnavailable(CAP_SECRETS_READ, "unexpected response")
        return value


class _Plugins:
    def __init__(self, ctx: "CallbackPlatformContext") -> None:
        self._ctx = ctx

    async def invoke(self, plugin: str, action: str, **kwargs: Any) -> Any:
        return await self._ctx.call(
            CAP_PLUGINS_INVOKE, {"plugin": plugin, "action": action, "kwargs": kwargs}
        )


class _Documents:
    def __init__(self, ctx: "CallbackPlatformContext") -> None:
        self._ctx = ctx

    async def index(
        self,
        kb_id: str,
        filename: str,
        content: Union[bytes, str],
        content_type: str,
    ) -> Dict[str, Any]:
        raw = content.encode("utf-8") if isinstance(content, str) else content
        result = await self._ctx.call(
            CAP_DOCUMENTS_INDEX,
            {
                "kb_id": kb_id,
                "filename": filename,
                "content_b64": base64.b64encode(raw).decode("ascii"),
                "content_type": content_type,
            },
        )
        return _as_dict(CAP_DOCUMENTS_INDEX, result)


class _Telegraf:
    async def set_managed_region(self, toml: str) -> Dict[str, Any]:
        raise CapabilityDenied(CAP_TELEGRAF_SET_MANAGED_REGION, _REMOTE_DENIAL)

    async def clear_managed_region(self) -> Dict[str, Any]:
        raise CapabilityDenied(CAP_TELEGRAF_CLEAR_MANAGED_REGION, _REMOTE_DENIAL)

    async def reload(self, force: bool = False) -> Dict[str, Any]:
        raise CapabilityDenied(CAP_TELEGRAF_RELOAD, _REMOTE_DENIAL)


class _Timeseries:
    def __init__(self, ctx: "CallbackPlatformContext") -> None:
        self._ctx = ctx

    async def write(
        self, lines: Union[str, Iterable[str]], precision: str = "s"
    ) -> int:
        items = lines.splitlines() if isinstance(lines, str) else list(lines)
        items = [line for line in items if line.strip()]
        result = await self._ctx.call(
            CAP_TIMESERIES_WRITE, {"lines": items, "precision": precision}
        )
        if isinstance(result, bool) or not isinstance(result, int):
            raise CapabilityUnavailable(CAP_TIMESERIES_WRITE, "unexpected response")
        return result

    async def latest(
        self,
        measurement: str,
        tag_key: str,
        tag_value: str,
        fields: Optional[Iterable[str]] = None,
    ) -> Union[None, str, Dict[str, Any]]:
        result = await self._ctx.call(
            CAP_TIMESERIES_LATEST,
            {
                "measurement": measurement,
                "tag_key": tag_key,
                "tag_value": tag_value,
                "fields": None if fields is None else list(fields),
            },
        )
        if result is not None and not isinstance(result, (str, dict)):
            raise CapabilityUnavailable(CAP_TIMESERIES_LATEST, "unexpected response")
        return result


def _as_dict(capability: str, value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise CapabilityUnavailable(capability, "unexpected response")
    return value


class CallbackPlatformContext:
    """A :class:`~minder_plugin_sdk.context.PlatformContext` whose calls are
    signed callbacks to Minder, for one invocation.

    - ``callback_base``: the invocation's ``callback_base`` (``https://...``;
      ``http`` only to a loopback host). Its path, if any, is kept.
    - ``grant``: the invocation's opaque grant token, sent as the bearer.
    - ``key``: the installation key; ``None`` makes every call
      :class:`CapabilityUnavailable` (the server has no key configured).
    - ``granted``: the capability names the grant lists, when Minder says;
      ``has()`` then answers from it. Without it ``has()`` is optimistic for
      every remote capability, and Minder decides at call time.
    - ``deadline``: a ``time.monotonic()`` instant after which calls fail
      fast; each call's timeout is the smaller of ``timeout`` and what is left.
    - ``client``: an ``httpx.AsyncClient`` to reuse (redirects are never
      followed); one per call otherwise.
    """

    def __init__(
        self,
        *,
        callback_base: str,
        grant: str,
        key: Optional[InstallationKey],
        granted: Optional[Iterable[str]] = None,
        deadline: Optional[float] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        client: Optional["httpx.AsyncClient"] = None,
        clock: Callable[[], float] = time.monotonic,
        sign_options: Optional[Dict[str, Any]] = None,
    ) -> None:
        origin = origin_of(callback_base)
        base_path = urlsplit(callback_base.strip()).path.rstrip("/")
        self._origin = origin
        self._base_path = base_path
        self._grant = grant
        self._key = key
        self._granted = None if granted is None else frozenset(granted)
        self._deadline = deadline
        self._timeout = timeout
        self._max_bytes = max_response_bytes
        self._client = client
        self._clock = clock
        # Test hook: fixed created/nonce for vector checks.
        self._sign_options = dict(sign_options or {})
        self.secrets = _Secrets(self)
        self.plugins = _Plugins(self)
        self.documents = _Documents(self)
        self.telegraf = _Telegraf()
        self.timeseries = _Timeseries(self)

    def has(self, capability: str) -> bool:
        if not capability_granted(REMOTE_CAPABILITIES, capability):
            return False
        if self._granted is None:
            return True
        return capability_granted(self._granted, capability)

    def callback_path(self, capability: str) -> str:
        """The ``@path`` a callback for ``capability`` is sent to."""
        return f"{self._base_path}{CALLBACK_PATH_PREFIX}{quote(capability, safe='.')}"

    def signed_request(
        self, capability: str, body: bytes
    ) -> "tuple[str, Dict[str, str]]":
        """The URL and headers of a callback (no network). Raises
        :class:`CapabilityUnavailable` without an installation key."""
        if self._key is None:
            raise CapabilityUnavailable(capability, "no installation key configured")
        path = self.callback_path(capability)
        authorization = f"Bearer {self._grant}"
        headers = {"Content-Type": "application/json", "Authorization": authorization}
        headers.update(
            self._key.sign_request(
                method="POST",
                authority=self._origin,
                path=path,
                query="",
                body=body,
                authorization=authorization,
                **self._sign_options,
            )
        )
        return self._origin + path, headers

    def _remaining(self, capability: str) -> float:
        if self._deadline is None:
            return self._timeout
        left = self._deadline - self._clock()
        if left <= 0:
            raise CapabilityUnavailable(capability, "the invocation deadline passed")
        return min(self._timeout, left)

    async def call(self, capability: str, payload: Dict[str, Any]) -> Any:
        """POST one callback and return its ``result``."""
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise CapabilityUnavailable(capability, "httpx is not installed") from exc
        timeout = self._remaining(capability)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        url, headers = self.signed_request(capability, body)
        client = self._client or httpx.AsyncClient(trust_env=False)
        try:
            async with client.stream(
                "POST",
                url,
                content=body,
                headers=headers,
                timeout=timeout,
                follow_redirects=False,
            ) as response:
                status = response.status_code
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > self._max_bytes:
                        raise CapabilityUnavailable(capability, "response too large")
        except httpx.HTTPError as exc:
            raise CapabilityUnavailable(capability, "Minder is unreachable") from exc
        finally:
            if self._client is None:
                await client.aclose()
        if status in _DENIED:
            raise CapabilityDenied(capability, f"HTTP {status}")
        if status in _INVALID:
            raise CapabilityInvalid(capability, f"HTTP {status}")
        if not 200 <= status < 300:
            raise CapabilityUnavailable(capability, f"HTTP {status}")
        try:
            document = json.loads(bytes(data))
        except ValueError as exc:
            raise CapabilityUnavailable(capability, "response is not JSON") from exc
        if not isinstance(document, dict) or "result" not in document:
            raise CapabilityUnavailable(capability, "unexpected response")
        return document["result"]

    def __repr__(self) -> str:
        return f"CallbackPlatformContext(origin={self._origin!r})"
