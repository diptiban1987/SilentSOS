"""SilentSOS API — application factory.

Security stack (outermost first):
  1. CORSMiddleware            — strict origin allowlist, credentials enabled
  2. SecurityHeadersMiddleware — nosniff / DENY / no-referrer / CSP for API
  3. BodySizeLimitMiddleware   — 413 on oversized bodies (DoS guard)
  4. RateLimitMiddleware       — per-IP sliding window (webhooks stricter)
Endpoint-level: JWT RBAC, per-device keys, HMAC webhooks, lockout, audit.
"""

from __future__ import annotations

import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.security import hash_password
from app.db.session import db_ping, engine
from app.middleware.rate_limit import RateLimitMiddleware, limiter
from app.middleware.security_headers import (
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.models.models import ROLE_ADMIN, Base, User
from app.services.audit import record

configure_logging()
logger = logging.getLogger("silentsos.main")
settings = get_settings()

_start_time = time.monotonic()


def _seed_bootstrap_admin() -> None:
    """Create the first admin only when the users table is empty."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        email = settings.SEED_ADMIN_EMAIL.strip().lower()
        password = settings.SEED_ADMIN_PASSWORD
        generated = False
        if not password:
            password = secrets.token_urlsafe(18)
            generated = True
        admin = User(
            email=email,
            full_name="Administrator",
            hashed_password=hash_password(password),
            role=ROLE_ADMIN,
        )
        db.add(admin)
        db.commit()
        if generated:
            logger.warning(
                "BOOTSTRAP ADMIN CREATED: %s / %s  — LOG IN AND CHANGE THIS PASSWORD IMMEDIATELY",
                email,
                password,
            )
        else:
            logger.info("Bootstrap admin created: %s", email)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _seed_bootstrap_admin()
    if settings.MQTT_ENABLED:
        from app.services.mqtt import start_bridge

        start_bridge()
    yield
    if settings.MQTT_ENABLED:
        from app.services.mqtt import stop_bridge

        stop_bridge()


def create_app() -> FastAPI:
    is_prod = settings.is_prod
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None if is_prod else "/redoc",
        openapi_url=None if is_prod else "/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Device-Key"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.MAX_BODY_BYTES)
    app.add_middleware(
        RateLimitMiddleware,
        limiter_=limiter,
        api_limit_per_min=settings.RATE_LIMIT_API_PER_MIN,
        webhook_limit_per_min=max(5, settings.RATE_LIMIT_AUTH_PER_MIN),
    )

    @app.get("/health", tags=["ops"])
    def health(request: Request) -> dict:
        """Unauthenticated liveness probe (also used by Docker/uptime monitors)."""
        uptime = time.monotonic() - _start_time
        return {
            "status": "ok",
            "version": settings.APP_VERSION,
            "env": settings.ENV,
            "database": "ok" if db_ping() else "degraded",
            "uptime_seconds": round(uptime, 1),
            "rate_limit_buckets": limiter.active_buckets,
            "request_id": request.headers.get("x-request-id") or uuid.uuid4().hex,
        }

    app.include_router(api_router, prefix="/api/v1")
    _mount_dashboard(app)
    return app


def _mount_dashboard(app: FastAPI) -> None:
    """Serve the built dashboard (dashboard/dist) at / when it exists.

    - One-server mode: after `npm run build`, start_server.bat serves the whole
      product from a single URL (http://127.0.0.1:8000).
    - Hot-reload UI work still uses Vite: start_dashboard.bat (port 5173).
    - Production: nginx serves dist directly (docker-compose); the API image
      does not ship dist/, so this is a no-op there.
    """
    dist = (Path(__file__).resolve().parents[2] / "dashboard" / "dist").resolve()
    index = dist / "index.html"

    if not index.is_file():
        # No built console available — land newcomers on the API docs.
        @app.get("/", include_in_schema=False)
        def root_redirect() -> RedirectResponse:
            return RedirectResponse(url="/docs")

        return

    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="spa-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        # Unknown API endpoints must remain JSON 404s, never the SPA shell.
        if full_path.startswith("api/") or full_path in {
            "docs",
            "redoc",
            "openapi.json",
            "health",
        }:
            raise HTTPException(status_code=404, detail="Not Found")
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(dist):
            return FileResponse(candidate)
        return FileResponse(index)


app = create_app()
