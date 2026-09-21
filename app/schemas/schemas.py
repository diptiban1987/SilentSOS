"""Request/response contracts (Pydantic v2, strict validation)."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.models import ROLES, EVENT_TYPES

PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")  # E.164-ish


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

    model_config = ConfigDict(extra="forbid")


class UserOut(ORMModel):
    public_id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class MeResponse(UserOut):
    pass


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)

    model_config = ConfigDict(extra="forbid")


class MessageResponse(BaseModel):
    message: str


# --------------------------------------------------------------------------- #
# Users (admin)
# --------------------------------------------------------------------------- #
class UserCreateRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(pattern="^(admin|operator|viewer)$")

    model_config = ConfigDict(extra="forbid")

    @field_validator("email")
    @classmethod
    def _lower_email(cls, v: str) -> str:
        return v.strip().lower()


class UserUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: str | None = Field(default=None, pattern="^(admin|operator|viewer)$")
    is_active: bool | None = None

    model_config = ConfigDict(extra="forbid")


class UserListResponse(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------- #
# Devices
# --------------------------------------------------------------------------- #
class DeviceCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    model_config = ConfigDict(extra="forbid")


class DeviceUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    is_active: bool | None = None

    model_config = ConfigDict(extra="forbid")


class DeviceOut(ORMModel):
    public_id: str
    name: str
    is_active: bool
    last_seen_at: datetime | None = None
    battery_pct: float | None = None
    signal_dbm: int | None = None
    fw_version: str
    last_lat: float | None = None
    last_lng: float | None = None
    created_at: datetime


class DeviceCreatedResponse(DeviceOut):
    device_key: str  # shown exactly once


class DeviceListResponse(BaseModel):
    items: list[DeviceOut]
    total: int


class DeviceKeyRotatedResponse(BaseModel):
    public_id: str
    device_key: str


# --------------------------------------------------------------------------- #
# Ingest (device-key authenticated)
# --------------------------------------------------------------------------- #
class TelemetryIngestRequest(BaseModel):
    lat: float | None = Field(default=None, ge=-90, le=90)
    lng: float | None = Field(default=None, ge=-180, le=180)
    speed_kmh: float | None = Field(default=None, ge=0, le=400)
    battery_pct: float | None = Field(default=None, ge=0, le=100)
    signal_dbm: int | None = Field(default=None, ge=-150, le=0)
    fw_version: str | None = Field(default=None, max_length=32)
    extra: dict | None = Field(default=None, max_length=64)

    model_config = ConfigDict(extra="forbid")


class SosIngestRequest(BaseModel):
    lat: float | None = Field(default=None, ge=-90, le=90)
    lng: float | None = Field(default=None, ge=-180, le=180)
    accuracy_m: float | None = Field(default=None, ge=0, le=100_000)
    event_type: str = Field(default="sos", pattern="^(sos|panic_test|battery_low|geofence)$")
    message: str | None = Field(default=None, max_length=500)

    model_config = ConfigDict(extra="forbid")


class IngestAcceptedResponse(BaseModel):
    accepted: bool = True


class SosAcceptedResponse(BaseModel):
    alert_public_id: str
    sms_requested: int
    event_type: str = "sos"


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
class AlertOut(ORMModel):
    public_id: str
    device_public_id: str
    device_name: str
    status: str
    event_type: str
    lat: float | None = None
    lng: float | None = None
    accuracy_m: float | None = None
    message: str
    triggered_at: datetime
    acknowledged_at: datetime | None = None
    acknowledged_by_public_id: str | None = None
    resolved_at: datetime | None = None
    resolved_by_public_id: str | None = None
    sms_summary: dict


class AlertListResponse(BaseModel):
    items: list[AlertOut]
    total: int
    page: int
    page_size: int


class AlertActionResponse(BaseModel):
    public_id: str
    status: str


VALID_EVENT_TYPES = EVENT_TYPES
VALID_ROLES = ROLES
