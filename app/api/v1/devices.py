"""Device registry — enrol wearables, rotate API keys.

Device keys authenticate telemetry/SOS ingest. Keys are shown exactly once at
creation/rotation and stored only as SHA-256.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_admin, require_any, require_operator
from app.core.security import hash_device_key, new_device_key
from app.db.session import get_db
from app.models.models import Device, User
from app.schemas.schemas import (
    DeviceCreatedResponse,
    DeviceCreateRequest,
    DeviceKeyRotatedResponse,
    DeviceListResponse,
    DeviceOut,
    DeviceUpdateRequest,
    MessageResponse,
)
from app.services.audit import record

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=DeviceListResponse)
def list_devices(
    include_inactive: bool = False,
    _user: User = Depends(require_any),
    db: Session = Depends(get_db),
) -> DeviceListResponse:
    query = db.query(Device)
    if not include_inactive:
        query = query.filter(Device.is_active.is_(True))
    rows = query.order_by(Device.created_at.desc()).all()
    return DeviceListResponse(
        items=[DeviceOut.model_validate(d) for d in rows],
        total=len(rows),
    )


@router.post("", response_model=DeviceCreatedResponse, status_code=status.HTTP_201_CREATED)
def register_device(
    body: DeviceCreateRequest,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> DeviceCreatedResponse:
    raw_key = new_device_key()
    device = Device(name=body.name.strip(), device_key_hash=hash_device_key(raw_key))
    db.add(device)
    db.commit()
    db.refresh(device)
    record(
        db,
        action="device.registered",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="device",
        object_id=device.public_id,
        detail={"name": device.name},
    )
    out = DeviceOut.model_validate(device).model_dump()
    return DeviceCreatedResponse(**out, device_key=raw_key)


@router.patch("/{public_id}", response_model=DeviceOut)
def update_device(
    public_id: str,
    body: DeviceUpdateRequest,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> DeviceOut:
    device = db.query(Device).filter(Device.public_id == public_id).first()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    if body.name is not None:
        device.name = body.name.strip()
    if body.is_active is not None:
        device.is_active = body.is_active
    db.commit()
    db.refresh(device)
    record(
        db,
        action="device.updated",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="device",
        object_id=device.public_id,
        detail=body.model_dump(exclude_none=True),
    )
    return DeviceOut.model_validate(device)


@router.post("/{public_id}/rotate-key", response_model=DeviceKeyRotatedResponse)
def rotate_device_key(
    public_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> DeviceKeyRotatedResponse:
    device = db.query(Device).filter(Device.public_id == public_id).first()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    raw_key = new_device_key()
    device.device_key_hash = hash_device_key(raw_key)
    db.commit()
    record(
        db,
        action="device.key_rotated",
        actor_user_id=admin.id,
        actor_ip=get_client_ip(request),
        object_type="device",
        object_id=device.public_id,
    )
    return DeviceKeyRotatedResponse(public_id=device.public_id, device_key=raw_key)


@router.delete("/{public_id}", response_model=MessageResponse)
def deactivate_device(
    public_id: str,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> MessageResponse:
    device = db.query(Device).filter(Device.public_id == public_id).first()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")
    device.is_active = False
    db.commit()
    record(
        db,
        action="device.deactivated",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="device",
        object_id=device.public_id,
    )
    return MessageResponse(message="Device deactivated")
