"""Optional MQTT bridge (Eclipse Mosquitto).

Subscribes to:
    silentsos/<device_public_id>/telemetry
    silentsos/<device_public_id>/sos

Only started when MQTT_ENABLED=true. DB work happens on the Paho network
thread using short-lived sessions — keep handlers fast and exception-safe.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid

from app.core.config import get_settings

logger = logging.getLogger("silentsos.mqtt")
_settings = get_settings()

TOPIC_TELEMETRY = "silentsos/+/telemetry"
TOPIC_SOS = "silentsos/+/sos"

_client = None  # paho client when running
_lock = threading.Lock()


def start_bridge() -> None:
    global _client
    with _lock:
        if _client is not None:
            return
        try:
            import paho.mqtt.client as mqtt
        except ImportError:  # pragma: no cover
            logger.warning("paho-mqtt unavailable; MQTT bridge disabled")
            return

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"silentsos-api-{uuid.uuid4().hex[:12]}",
            protocol=mqtt.MQTTv311,
        )
        if _settings.MQTT_USERNAME:
            client.username_pw_set(_settings.MQTT_USERNAME, _settings.MQTT_PASSWORD or None)
        client.on_connect = _on_connect
        client.on_message = _on_message
        try:
            client.connect_async(_settings.MQTT_HOST, _settings.MQTT_PORT, keepalive=30)
            client.loop_start()
        except Exception:  # noqa: BLE001
            logger.exception("MQTT connect failed (host=%s)", _settings.MQTT_HOST)
            return
        _client = client
        logger.info("MQTT bridge started -> %s:%s", _settings.MQTT_HOST, _settings.MQTT_PORT)


def stop_bridge() -> None:
    global _client
    with _lock:
        if _client is not None:
            try:
                _client.loop_stop()
                _client.disconnect()
            except Exception:  # noqa: BLE001
                pass
            _client = None
            logger.info("MQTT bridge stopped")


def _on_connect(client, userdata, flags, reason_code, properties) -> None:  # type: ignore[no-untyped-def]
    logger.info("MQTT connected (rc=%s)", reason_code)
    client.subscribe([(TOPIC_TELEMETRY, 1), (TOPIC_SOS, 1)])


def _on_message(client, userdata, msg) -> None:  # type: ignore[no-untyped-def]
    from app.db.session import SessionLocal
    from app.models.models import ALERT_TRIGGERED, Alert, Device, Telemetry
    from app.schemas.schemas import SosIngestRequest, TelemetryIngestRequest
    from app.services.sms import dispatch_alert_sms

    parts = msg.topic.split("/")
    if len(parts) != 3:
        return
    device_public_id, kind = parts[1], parts[2]
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Malformed JSON on %s", msg.topic)
        return

    db = SessionLocal()
    try:
        device = (
            db.query(Device)
            .filter(Device.public_id == device_public_id, Device.is_active.is_(True))
            .first()
        )
        if device is None:
            logger.warning("MQTT message for unknown/inactive device %s", device_public_id)
            return

        if kind == "telemetry":
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            device.last_seen_at = now
            if data.battery_pct is not None:
                device.battery_pct = data.battery_pct
            if data.signal_dbm is not None:
                device.signal_dbm = data.signal_dbm
            if data.lat is not None and data.lng is not None:
                device.last_lat, device.last_lng = data.lat, data.lng
            db.add(
                Telemetry(
                    device_id=device.id,
                    ts=now,
                    lat=data.lat,
                    lng=data.lng,
                    speed_kmh=data.speed_kmh,
                    battery_pct=data.battery_pct,
                    signal_dbm=data.signal_dbm,
                    extra=data.extra,
                )
            )
            db.commit()
        elif kind == "sos":
            try:
                data = SosIngestRequest.model_validate(payload)
            except ValueError:
                logger.warning("Invalid SOS payload from %s", device_public_id)
                return
            from datetime import datetime, timezone

            alert = Alert(
                device_id=device.id,
                status=ALERT_TRIGGERED,
                event_type=data.event_type,
                lat=data.lat,
                lng=data.lng,
                accuracy_m=data.accuracy_m,
                message=(data.message or "").strip(),
                triggered_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            dispatch_alert_sms(db, alert, device.name)
    except Exception:  # noqa: BLE001 — the bridge must never die
        db.rollback()
        logger.exception("MQTT handler failure on %s", msg.topic)
    finally:
        db.close()
