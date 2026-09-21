"""Thread-safe in-memory sliding-window rate limiter.

Per (client_ip, bucket) with buckets `auth` (login/refresh — strict) and
`api` (general). Suitable for the single-node Hostinger VPS deployment this
system targets; swap for Redis when scaling horizontally.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("silentsos.rate_limit")


@dataclass
class _Window:
    hits: deque = field(default_factory=lambda: deque(maxlen=512))


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, _Window] = defaultdict(_Window)
        self._lock = threading.Lock()
        self._last_gc = 0.0

    def allow(self, key: str, limit_per_min: int, *, window_s: float = 60.0) -> tuple[bool, int]:
        """Return (allowed, seconds_until_retry)."""
        now = time.monotonic()
        with self._lock:
            self._gc(now)
            win = self._buckets[key]
            cutoff = now - window_s
            while win.hits and win.hits[0] < cutoff:
                win.hits.popleft()
            if len(win.hits) >= limit_per_min:
                retry_after = int(max(1.0, window_s - (now - win.hits[0])))
                logger.warning("Rate limit exceeded for key=%s limit=%d retry_after=%d", key, limit_per_min, retry_after)
                return False, retry_after
            win.hits.append(now)
            return True, 0

    def _gc(self, now: float) -> None:
        # Every 5 minutes drop idle buckets to bound memory.
        if now - self._last_gc < 300.0:
            return
        self._last_gc = now
        stale = [k for k, w in self._buckets.items() if not w.hits or now - w.hits[-1] > 600.0]
        for k in stale:
            self._buckets.pop(k, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    @property
    def active_buckets(self) -> int:
        """Number of active rate-limit buckets (for monitoring)."""
        with self._lock:
            return len(self._buckets)


limiter = RateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """General per-IP throttle for API routes.

    Auth endpoints perform their own stricter, user-visible limiting inside
    the route handlers; this middleware additionally throttles webhooks and
    the whole API surface.
    """

    def __init__(
        self,
        app,  # type: ignore[no-untyped-def]
        limiter_: RateLimiter,
        *,
        api_limit_per_min: int,
        webhook_limit_per_min: int,
        webhook_prefixes: tuple[str, ...] = ("/api/v1/webhooks",),
    ) -> None:
        super().__init__(app)
        self.limiter = limiter_
        self.api_limit = api_limit_per_min
        self.webhook_limit = webhook_limit_per_min
        self.webhook_prefixes = webhook_prefixes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if path.startswith("/api") and path != "/api/v1/health":
            ip = _client_ip(request)
            bucket = "webhook" if path.startswith(self.webhook_prefixes) else "api"
            limit = self.webhook_limit if bucket == "webhook" else self.api_limit
            allowed, retry_after = self.limiter.allow(f"{ip}:{bucket}", limit)
            if not allowed:
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                    },
                )
        return await call_next(request)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""
