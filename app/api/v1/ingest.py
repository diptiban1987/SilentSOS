"""Device ingest endpoints — authenticated by per-device API keys.

* POST /ingest/telemetry — periodic GPS/battery/heartbeat updates.
* POST /ingest/sos       — SOS trigger: creates an alert and dispatches SMS
                           to all active emergency contacts.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import (
    ALERT_TRIGGERED,
    Device,
    Telemetry,
)
from app.schemas.schemas import (
    IngestAcceptedResponse,
    SosAcceptedResponse,
    SosIngestRequest,
    TelemetryIngestRequest,
)
from app.services.audit import record
from app.services.sms import dispatch_alert_sms

router = APIRouter(prefix="/ingest", tags=["ingest"])

_DOCS_NOTE = "Device-key authenticated endpoint (X-Device-Key header)"


def get_device_by_key(
    x_device_key: str | None = Header(default=None, alias="X-Device-Key"),
    db: Session = Depends(get_db),
) -> Device:
    if not x_device_key or len(x_device_key) > 256:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing device key")
    key_hash = hashlib.sha256(x_device_key.encode("utf-8")).hexdigest()
    device = db.query(Device).filter(Device.device_key_hash == key_hash).first()
    if device is None or not device.is_active:
        # Unknown key: no timing side-channel worth equalising — the hash lookup
        # is constant-time over the index and no user enumeration exists here.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid device key")
    return device


@router.post("/telemetry", response_model=IngestAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_telemetry(
    body: TelemetryIngestRequest,
    request: Request,
    device: Device = Depends(get_device_by_key),
    db: Session = Depends(get_db),
) -> IngestAcceptedResponse:
    now = datetime.now(timezone.utc)
    device.last_seen_at = now
    if body.battery_pct is not None:
        device.battery_pct = body.battery_pct
    if body.signal_dbm is not None:
        device.signal_dbm = body.signal_dbm
    if body.fw_version:
        device.fw_version = body.fw_version[:32]
    if body.lat is not None and body.lng is not None:
        device.last_lat = body.lat
        device.last_lng = body.lng
    db.add(
        Telemetry(
            device_id=device.id,
            ts=now,
            lat=body.lat,
            lng=body.lng,
            speed_kmh=body.speed_kmh,
            battery_pct=body.battery_pct,
            signal_dbm=body.signal_dbm,
            extra=body.extra,
        )
    )
    db.commit()
    return IngestAcceptedResponse()


@router.post("/sos", response_model=SosAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_sos(
    body: SosIngestRequest,
    request: Request,
    device: Device = Depends(get_device_by_key),
    db: Session = Depends(get_db),
) -> SosAcceptedResponse:
    from app.models.models import Alert

    now = datetime.now(timezone.utc)
    device.last_seen_at = now
    if body.lat is not None and body.lng is not None:
        device.last_lat = body.lat
        device.last_lng = body.lng

    alert = Alert(
        device_id=device.id,
        status=ALERT_TRIGGERED,
        event_type=body.event_type,
        lat=body.lat,
        lng=body.lng,
        accuracy_m=body.accuracy_m,
        message=(body.message or "").strip(),
        triggered_at=now,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Dispatch happens inline (bounded by contact count); the device gets an
    # immediate 202 and monitoring can reconcile SMS status asynchronously.
    sms_requested = dispatch_alert_sms(db, alert, device.name)

    record(
        db,
        action="alert.sos_ingested",
        actor_user_id=None,
        actor_ip=request.client.host if request.client else "",
        object_type="alert",
        object_id=alert.public_id,
        detail={"device": device.public_id, "event_type": body.event_type},
    )
    return SosAcceptedResponse(
        alert_public_id=alert.public_id,
        sms_requested=sms_requested,
        event_type=body.event_type,
    )
