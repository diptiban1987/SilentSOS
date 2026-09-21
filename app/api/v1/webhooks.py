"""Provider webhooks — HMAC-SHA256 signed, constant-time verified.

SMS delivery callbacks reconcile SmsMessage.status. The signature is computed
over the raw request body with the shared SMS_WEBHOOK_SECRET.
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.models.models import SMS_FAILED, SMS_SENT, SmsMessage
from app.services.audit import record

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
_settings = get_settings()


class SmsDeliveryCallback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=128)  # our SmsMessage id or provider_ref
    status: str = Field(pattern="^(sent|failed)$")
    error: str | None = Field(default=None, max_length=500)


class CallbackAck(BaseModel):
    received: bool = True


def _verify_signature(raw_body: bytes, presented: str | None) -> bool:
    if not presented:
        return False
    expected = hmac.new(
        _settings.SMS_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, presented.strip().lower())


@router.post("/sms/delivery", response_model=CallbackAck)
async def sms_delivery(
    request: Request,
    db: Session = Depends(get_db),
) -> CallbackAck:
    raw = await request.body()
    if len(raw) > 4096:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large")
    presented = request.headers.get("X-SilentSOS-Signature")
    if not _verify_signature(raw, presented):
        record(
            db,
            action="webhook.sms_bad_signature",
            actor_ip=request.client.host if request.client else "",
            object_type="webhook",
            object_id="sms/delivery",
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")

    try:
        callback = SmsDeliveryCallback.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid payload: {exc}") from exc

    msg: SmsMessage | None = None
    if callback.message_id.isdigit():
        msg = db.get(SmsMessage, int(callback.message_id))
    if msg is None:
        msg = (
            db.query(SmsMessage)
            .filter(SmsMessage.provider_ref == callback.message_id)
            .first()
        )
    if msg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown message id")

    msg.status = SMS_SENT if callback.status == "sent" else SMS_FAILED
    if callback.status == "failed":
        msg.error = callback.error or "provider reported failure"
    else:
        msg.error = None
    db.commit()
    record(
        db,
        action="webhook.sms_delivery",
        actor_ip=request.client.host if request.client else "",
        object_type="sms",
        object_id=str(msg.id),
        detail={"status": msg.status},
    )
    return CallbackAck()
