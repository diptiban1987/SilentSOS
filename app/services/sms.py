"""SMS dispatch abstraction.

Providers:
* sim       — default; marks messages `simulated` and logs (safe for dev/tests).
* fast2sms  — Indian bulk SMS gateway used for SOS dispatch (doc-specified).
* twilio    — global SMS gateway.

Every dispatch writes a SmsMessage row first (status=pending) and mutates its
status afterwards, so delivery state is always queryable and the delivery
webhook can reconcile provider callbacks.
"""

from __future__ import annotations

import logging
from typing import Protocol

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import (
    SMS_DISPATCHED,
    SMS_FAILED,
    SMS_PENDING,
    SMS_SIMULATED,
    SMS_SENT,
    Alert,
    EmergencyContact,
    SmsMessage,
)

logger = logging.getLogger("silentsos.sms")
_settings = get_settings()


class SmsProvider(Protocol):
    name: str

    def send(self, to_number: str, body: str) -> tuple[str, str | None]:
        """Return (status, provider_ref_or_none)."""
        ...  # pragma: no cover


class SimProvider:
    name = "sim"

    def send(self, to_number: str, body: str) -> tuple[str, str | None]:
        logger.info("[SIM SMS] to=%s body=%r", to_number, body[:120])
        return SMS_SIMULATED, None


class Fast2SmsProvider:
    name = "fast2sms"

    def send(self, to_number: str, body: str) -> tuple[str, str | None]:
        # Strip leading + — Fast2SMS expects domestic 10-digit numbers.
        numbers = to_number.lstrip("+")[-10:]
        resp = httpx.post(
            "https://www.fast2sms.com/dev/bulkV2",
            headers={"authorization": _settings.FAST2SMS_API_KEY},
            data={"route": "q", "message": body, "language": "english", "numbers": numbers},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("return") is True:
            return SMS_DISPATCHED, (data.get("request_id") or None)
        raise RuntimeError(f"fast2sms rejected: {data}")


class TwilioProvider:
    name = "twilio"

    def send(self, to_number: str, body: str) -> tuple[str, str | None]:
        resp = httpx.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{_settings.TWILIO_ACCOUNT_SID}/Messages.json",
            auth=(_settings.TWILIO_ACCOUNT_SID, _settings.TWILIO_AUTH_TOKEN),
            data={"To": to_number, "From": _settings.TWILIO_FROM_NUMBER, "Body": body},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
        status = SMS_DISPATCHED if data.get("status") in ("queued", "accepted") else SMS_SENT
        return status, data.get("sid")


def get_provider() -> SmsProvider:
    if _settings.SMS_PROVIDER == "fast2sms" and _settings.FAST2SMS_API_KEY:
        return Fast2SmsProvider()
    if (
        _settings.SMS_PROVIDER == "twilio"
        and _settings.TWILIO_ACCOUNT_SID
        and _settings.TWILIO_AUTH_TOKEN
    ):
        return TwilioProvider()
    return SimProvider()


def sos_body(alert: Alert, device_name: str, contact_name: str) -> str:
    loc = ""
    if alert.lat is not None and alert.lng is not None:
        loc = f" Location: https://maps.google.com/?q={alert.lat:.6f},{alert.lng:.6f}"
    return (
        f"SILENT SOS ALERT from {device_name} ({contact_name}). "
        f"Event: {alert.event_type.upper()}.{loc}"
    )[:480]


def dispatch_alert_sms(db: Session, alert: Alert, device_name: str) -> int:
    """Create + send one SMS per active emergency contact. Returns count attempted."""
    contacts = (
        db.query(EmergencyContact)
        .filter(EmergencyContact.is_active.is_(True))
        .order_by(EmergencyContact.priority.asc(), EmergencyContact.id.asc())
        .all()
    )
    provider = get_provider()
    attempted = 0
    for contact in contacts:
        attempted += 1
        msg = SmsMessage(
            alert_id=alert.id,
            provider=provider.name,
            to_number=contact.phone,
            body=sos_body(alert, device_name, contact.name),
            status=SMS_PENDING,
        )
        db.add(msg)
        db.commit()
        db.refresh(msg)
        try:
            status, ref = provider.send(contact.phone, msg.body)
            msg.status = status
            msg.provider_ref = ref
            msg.error = None
        except Exception as exc:  # noqa: BLE001 — provider failures must not break ingest
            logger.exception("sms dispatch failed alert=%s", alert.public_id)
            msg.status = SMS_FAILED
            msg.error = str(exc)[:500]
        db.commit()
    return attempted
