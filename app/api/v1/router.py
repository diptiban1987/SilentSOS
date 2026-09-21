"""Aggregated /api/v1 router."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import alerts, audit_routes, auth, contacts, devices, ingest, telemetry, users, webhooks

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(devices.router)
api_router.include_router(ingest.router)
api_router.include_router(alerts.router)
api_router.include_router(telemetry.router)
api_router.include_router(contacts.router)
api_router.include_router(webhooks.router)
api_router.include_router(audit_routes.router)
