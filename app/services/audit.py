"""Immutable audit trail helper."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import AuditLog

logger = logging.getLogger("silentsos.audit")


def record(
    db: Session,
    *,
    action: str,
    actor_user_id: int | None = None,
    actor_ip: str = "",
    object_type: str = "",
    object_id: str = "",
    detail: dict[str, Any] | None = None,
) -> None:
    """Persist an audit row. Never raises — audit failures must not break the API."""
    try:
        entry = AuditLog(
            action=action,
            actor_user_id=actor_user_id,
            actor_ip=(actor_ip or "")[:64],
            object_type=object_type[:32],
            object_id=str(object_id)[:64],
            detail=detail,
        )
        db.add(entry)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("audit write failed action=%s", action)
