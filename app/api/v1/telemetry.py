"""Telemetry query endpoints (authenticated operators)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import Device, Telemetry, User
from app.core.deps import require_any

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


class TelemetryPoint(BaseModel):
    ts: object
    lat: float | None = None
    lng: float | None = None
    speed_kmh: float | None = None
    battery_pct: float | None = None
    signal_dbm: int | None = None
    extra: dict | None = None


class TelemetryRecentResponse(BaseModel):
    device_public_id: str
    points: list[TelemetryPoint]


@router.get("/recent", response_model=TelemetryRecentResponse)
def recent_telemetry(
    device_public_id: str = Query(max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    _user: User = Depends(require_any),
    db: Session = Depends(get_db),
) -> TelemetryRecentResponse:
    device = db.query(Device).filter(Device.public_id == device_public_id).first()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    rows = (
        db.query(Telemetry)
        .filter(Telemetry.device_id == device.id)
        .order_by(Telemetry.ts.desc())
        .limit(limit)
        .all()
    )
    rows.reverse()  # oldest -> newest for charting
    return TelemetryRecentResponse(
        device_public_id=device.public_id,
        points=[
            TelemetryPoint(
                ts=r.ts,
                lat=r.lat,
                lng=r.lng,
                speed_kmh=r.speed_kmh,
                battery_pct=r.battery_pct,
                signal_dbm=r.signal_dbm,
                extra=r.extra,
            )
            for r in rows
        ],
    )
