"""Anti-cache ASGI middleware for the honeypot public API.

Honeypot responses MUST reach the application on every request.  A CDN or
shared proxy that caches and replays a response defeats the deception entirely:
attackers get stale data, actor telemetry is never recorded, and rate-limiting
is bypassed.

What this middleware does
-------------------------
For every HTTP response it:

1. Adds ``Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private``
2. Adds ``Pragma: no-cache`` (HTTP/1.0 back-compat)
3. Adds ``Expires: 0`` (proxy back-compat)
4. Strips ``ETag`` and ``Last-Modified`` so clients cannot send conditional
   requests (``If-None-Match`` / ``If-Modified-Since``) that would produce
   a 304 Not Modified without hitting the app.
5. Converts any stray ``304 Not Modified`` response to ``200 OK`` with an
   empty body, preventing downstream caches from using a previously stored
   representation.

Configuration
-------------
``HP_NO_CACHE_ENABLED``
    Set to ``0`` / ``false`` / ``no`` to disable the middleware entirely
    (useful for local development where caching is harmless).  Default: ``true``.

``HP_NO_CACHE_SKIP_STATIC``
    Set to ``1`` / ``true`` / ``yes`` to skip ``/static/*`` paths (they are
    not honeypot endpoints and may be served by a CDN intentionally).
    Default: ``true``.

Limits
------
This middleware operates at the application layer.  It cannot override
``Cache-Control`` headers that a *reverse proxy or CDN layer* adds after
the response leaves the application.  Always configure your reverse proxy to
pass ``Cache-Control: no-store`` upstream or to forward the application
headers unchanged.  See docs/no_cache.md for Traefik, Nginx, and CDN guidance.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Iterable

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Header constants
# ---------------------------------------------------------------------------

_NO_CACHE_HEADERS: list[tuple[bytes, bytes]] = [
    (b"cache-control", b"no-store, no-cache, must-revalidate, max-age=0, private"),
    (b"pragma", b"no-cache"),
    (b"expires", b"0"),
]

# Header names that enable conditional requests — strip them from responses.
_STRIP_RESPONSE_HEADERS: frozenset[bytes] = frozenset(
    [b"etag", b"last-modified"]
)

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def _is_enabled() -> bool:
    raw = os.environ.get("HP_NO_CACHE_ENABLED", "true").strip().lower()
    return raw not in ("0", "false", "no")


def _skip_static() -> bool:
    raw = os.environ.get("HP_NO_CACHE_SKIP_STATIC", "true").strip().lower()
    return raw not in ("0", "false", "no")


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------


class NoCacheMiddleware:
    """ASGI middleware that injects no-cache headers and strips ETag/Last-Modified.

    Implemented at the raw ASGI level (not Starlette BaseHTTPMiddleware) so it
    wraps the complete request-response cycle with zero overhead on the async
    I/O path.

    Non-HTTP scopes (websocket, lifespan) pass through unchanged.
    When disabled via ``HP_NO_CACHE_ENABLED=false`` the middleware is a
    transparent no-op.
    """

    def __init__(self, app: Callable) -> None:
        self.app = app
        self._enabled = _is_enabled()
        self._skip_static = _skip_static()
        if self._enabled:
            _logger.debug(
                "no_cache: NoCacheMiddleware active (skip_static=%s)",
                self._skip_static,
            )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not self._enabled:
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if self._skip_static and path.startswith("/static/"):
            await self.app(scope, receive, send)
            return

        async def _patched_send(message: dict) -> None:
            if message.get("type") != "http.response.start":
                await send(message)
                return

            status: int = message.get("status", 200)
            raw_headers: list[tuple[bytes, bytes]] = list(
                message.get("headers") or []
            )

            # Strip headers that enable conditional / cacheable responses.
            filtered = [
                (k, v)
                for k, v in raw_headers
                if k.lower() not in _STRIP_RESPONSE_HEADERS
            ]

            # Also strip any existing Cache-Control / Pragma / Expires set by
            # the route handler so ours take precedence.
            _overridden = frozenset([b"cache-control", b"pragma", b"expires"])
            filtered = [(k, v) for k, v in filtered if k.lower() not in _overridden]

            # Append our headers.
            filtered.extend(_NO_CACHE_HEADERS)

            if status == 304:
                # 304 leaks that the response was previously cached.  Convert
                # to 200 with an empty body so no cached copy is used.
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": filtered,
                    }
                )
                await send({"type": "http.response.body", "body": b""})
                # Swallow the original body messages from the inner app.
                return

            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": filtered,
                }
            )

        await self.app(scope, receive, _patched_send)
