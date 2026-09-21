"""Emergency contact management (who gets the SMS when SOS fires)."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_admin, require_any, require_operator
from app.db.session import get_db
from app.models.models import EmergencyContact, User
from app.services.audit import record

router = APIRouter(prefix="/contacts", tags=["contacts"])

_PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")


class ContactIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    phone: str = Field(min_length=8, max_length=20)
    priority: int = Field(default=1, ge=1, le=99)
    is_active: bool = True

    @field_validator("phone")
    @classmethod
    def _valid_phone(cls, v: str) -> str:
        v = v.strip()
        if not _PHONE_RE.match(v):
            raise ValueError("phone must be E.164-like, e.g. +919876543210")
        return v


class ContactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    phone: str
    priority: int
    is_active: bool


@router.get("", response_model=list[ContactOut])
def list_contacts(
    _user: User = Depends(require_any),
    db: Session = Depends(get_db),
) -> list[ContactOut]:
    rows = (
        db.query(EmergencyContact)
        .order_by(EmergencyContact.priority.asc(), EmergencyContact.id.asc())
        .all()
    )
    return [ContactOut.model_validate(c) for c in rows]


@router.post("", response_model=ContactOut, status_code=status.HTTP_201_CREATED)
def create_contact(
    body: ContactIn,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> ContactOut:
    if db.query(EmergencyContact).filter(EmergencyContact.phone == body.phone).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Phone already registered")
    contact = EmergencyContact(**body.model_dump())
    db.add(contact)
    db.commit()
    db.refresh(contact)
    record(
        db,
        action="contact.created",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="contact",
        object_id=str(contact.id),
        detail={"phone": contact.phone},
    )
    return ContactOut.model_validate(contact)


@router.patch("/{contact_id}", response_model=ContactOut)
def update_contact(
    contact_id: int,
    body: ContactIn,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> ContactOut:
    contact = db.get(EmergencyContact, contact_id)
    if contact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Contact not found")
    existing = (
        db.query(EmergencyContact)
        .filter(EmergencyContact.phone == body.phone, EmergencyContact.id != contact_id)
        .first()
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Phone already registered")
    for field, value in body.model_dump().items():
        setattr(contact, field, value)
    db.commit()
    db.refresh(contact)
    record(
        db,
        action="contact.updated",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="contact",
        object_id=str(contact.id),
    )
    return ContactOut.model_validate(contact)


@router.delete("/{contact_id}", response_model=ContactOut)
def delete_contact(
    contact_id: int,
    request: Request,
    operator: User = Depends(require_operator),
    db: Session = Depends(get_db),
) -> ContactOut:
    contact = db.get(EmergencyContact, contact_id)
    if contact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Contact not found")
    contact.is_active = False
    db.commit()
    record(
        db,
        action="contact.deactivated",
        actor_user_id=operator.id,
        actor_ip=get_client_ip(request),
        object_type="contact",
        object_id=str(contact.id),
    )
    return ContactOut.model_validate(contact)


_UNUSED = Query  # keep import if validators change
