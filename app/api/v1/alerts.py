"""Incident centre — SOS alert lifecycle.

Lifecycle: triggered -> acknowledged -> resolved (forward-only transitions,
every transition audited).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_any, require_operator
from app.db.session import get_db
from app.models.models import (
    ALERT_ACKNOWLEDGED,
    ALERT_RESOLVED,
    ALERT_TRIGGERED,
    Alert,
    Device,
    SmsMessage,
    User,
)
from app.schemas.schemas import (
    AlertActionResponse,
    AlertListResponse,
    AlertOut,
    MessageResponse,
)
from app.services.audit import record

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _alert_to_out(db: Session, alert: Alert) -> AlertOut:
    device = db.get(Device, alert.device_id)
    ack_by = db.get(User, alert.acknowledged_by_id) if alert.acknowledged_by_id else None
    res_by = db.get(User, alert.resolved_by_id) if alert.resolved_by_id else None
    sms_rows = (
        db.query(SmsMessage).filter(SmsMessage.alert_id == alert.id).all()
    )
    sms_summary: dict = {"total": len(sms_rows), "sent": 0, "failed": 0, "simulated": 0, "pending": 0}
    for m in sms_rows:
        if m.status in ("sent", "dispatched"):
            sms_summary["sent"] += 1
        elif m.status == "failed":
            sms_summary["failed"] += 1
        elif m.status == "simulated":
            sms_summary["simulated"] += 1
        else:
            sms_summary["pending"] += 1
    return AlertOut(
        public_id=alert.public_id,
        device_public_id=device.public_id if device else "",
        device_name=device.name if device else "unknown",
        status=alert.status,
        event_type=alert.event_type,
        lat=alert.lat,
        lng=alert.lng,
        accuracy_m=alert.accuracy_m,
        message=alert.message,
        triggered_at=alert.triggered_at,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by_public_id=ack_by.public_id if ack_by else None,
        resolved_at=alert.resolved_at,
        resolved_by_public_id=res_by.public_id if res_by else None,
        sms_summary=sms_summary,
    )


@router.get("", response_model=AlertListResponse)
def list_alerts(
    status_filter: str | None = Query(default=None, alias="status", pattern="^(triggered|acknowledged|resolved)$"),
    device_public_id: str | None = Query(default=None, max_length=32),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    _user: User = Depends(require_any),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if device_public_id:
        device = db.query(Device).filter(Device.public_id == device_public_id).first()
        if device is None:
            return AlertListResponse(items=[], total=0, page=page, page_size=page_size)
        query = query.filter(Alert.device_id == device.id)
    total = query.count()
    rows = (
        query.order_by(Alert.triggered_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AlertListResponse(
        items=[_alert_to_out(db, a) for a in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{public_id}", response_model=AlertOut)
def get_alert(
    public_id: str,
    _user: User = Depends(require_any),
    db: Session = Depends(get_db),
) -> AlertOut:
    alert = db.query(Alert).filter(Alert.public_id == public_id).first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return _alert_to_out(db, alert)


@router.post("/{public_id}/acknowledge", response_model=AlertActionResponse)
def acknowledge_alert(
    public_id: str,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> AlertActionResponse:
    alert = db.query(Alert).filter(Alert.public_id == public_id).first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if alert.status != ALERT_TRIGGERED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only triggered alerts can be acknowledged (current: {alert.status})",
        )
    alert.status = ALERT_ACKNOWLEDGED
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by_id = operator.id
    db.commit()
    record(
        db,
        action="alert.acknowledged",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="alert",
        object_id=alert.public_id,
    )
    return AlertActionResponse(public_id=alert.public_id, status=alert.status)


@router.post("/{public_id}/resolve", response_model=AlertActionResponse)
def resolve_alert(
    public_id: str,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> AlertActionResponse:
    alert = db.query(Alert).filter(Alert.public_id == public_id).first()
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if alert.status == ALERT_RESOLVED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Alert already resolved")
    if alert.status == ALERT_TRIGGERED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Alert must be acknowledged before it can be resolved",
        )
    alert.status = ALERT_RESOLVED
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by_id = operator.id
    db.commit()
    record(
        db,
        action="alert.resolved",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="alert",
        object_id=alert.public_id,
    )
    return AlertActionResponse(public_id=alert.public_id, status=alert.status)

