"""Response hardening middleware.

Every API response carries restrictive security headers. The dashboard's own
CSP is delivered by nginx (see deploy/nginx) — here we lock down the API
surface itself.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

API_CSP = "default-src 'none'; frame-ancestors 'none'; sandbox"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Core security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-XSS-Protection", "0")

        # Cross-origin isolation
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

        # API-specific headers
        if request.url.path.startswith("/api"):
            response.headers.setdefault("Content-Security-Policy", API_CSP)
            response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, private")
            response.headers.setdefault("Pragma", "no-cache")
            response.headers.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")

        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies early (DoS guard)."""

    def __init__(self, app, max_bytes: int) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length is not None and content_length.isdigit():
                if int(content_length) > self.max_bytes:
                    return Response(
                        '{"detail":"request body too large"}',
                        status_code=413,
                        media_type="application/json",
                        headers={"X-Robots-Tag": "noindex"},
                    )
        return await call_next(request)
