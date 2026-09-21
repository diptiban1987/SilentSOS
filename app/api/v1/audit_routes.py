"""Audit trail viewer (admin-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import require_admin
from app.db.session import get_db
from app.models.models import AuditLog, User

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEntry(BaseModel):
    ts: object
    actor_user_public_id: str | None = None
    actor_ip: str
    action: str
    object_type: str
    object_id: str
    detail: dict | None = None


class AuditListResponse(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int
    page_size: int


@router.get("", response_model=AuditListResponse)
def list_audit(
    action: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AuditListResponse:
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    total = query.count()
    rows = (
        query.order_by(AuditLog.ts.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = []
    for r in rows:
        actor_pid = None
        if r.actor_user_id is not None:
            actor = db.get(User, r.actor_user_id)
            actor_pid = actor.public_id if actor else None
        items.append(
            AuditEntry(
                ts=r.ts,
                actor_user_public_id=actor_pid,
                actor_ip=r.actor_ip,
                action=r.action,
                object_type=r.object_type,
                object_id=r.object_id,
                detail=r.detail,
            )
        )
    return AuditListResponse(items=items, total=total, page=page, page_size=page_size)
