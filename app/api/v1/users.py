"""User administration (admin-only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_admin
from app.core.security import hash_password, password_entropy_ok
from app.db.session import get_db
from app.models.models import ROLE_ADMIN, User
from app.schemas.schemas import (
    MessageResponse,
    UserCreateRequest,
    UserListResponse,
    UserOut,
    UserUpdateRequest,
)
from app.services.audit import record

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=UserListResponse)
def list_users(
    q: str | None = Query(default=None, max_length=120),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserListResponse:
    query = db.query(User)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(User.email.ilike(like) | User.full_name.ilike(like))
    total = query.count()
    rows = (
        query.order_by(User.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return UserListResponse(
        items=[UserOut.model_validate(u) for u in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    if not password_entropy_ok(body.password):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Password must be 12+ chars with upper, lower and digit",
        )
    if db.query(User).filter(User.email == body.email).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=body.email,
        full_name=body.full_name.strip(),
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record(
        db,
        action="user.created",
        actor_user_id=admin.id,
        actor_ip=get_client_ip(request),
        object_type="user",
        object_id=user.public_id,
        detail={"role": user.role},
    )
    return UserOut.model_validate(user)


@router.patch("/{public_id}", response_model=UserOut)
def update_user(
    public_id: str,
    body: UserUpdateRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    user = db.query(User).filter(User.public_id == public_id).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    if body.role is not None and body.role != user.role:
        if user.id == admin.id:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Cannot change your own role"
            )
        if user.role == ROLE_ADMIN:
            _ensure_other_admin_exists(db, exclude_user_id=user.id)
        user.role = body.role

    if body.is_active is not None and body.is_active != user.is_active:
        if user.id == admin.id:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Cannot deactivate your own account"
            )
        if user.is_active and user.role == ROLE_ADMIN:
            _ensure_other_admin_exists(db, exclude_user_id=user.id)
        user.is_active = body.is_active

    if body.full_name is not None:
        user.full_name = body.full_name.strip()

    db.commit()
    db.refresh(user)
    record(
        db,
        action="user.updated",
        actor_user_id=admin.id,
        actor_ip=get_client_ip(request),
        object_type="user",
        object_id=user.public_id,
        detail=body.model_dump(exclude_none=True),
    )
    return UserOut.model_validate(user)


def _ensure_other_admin_exists(db: Session, *, exclude_user_id: int) -> None:
    others = (
        db.query(User)
        .filter(
            User.role == ROLE_ADMIN,
            User.is_active.is_(True),
            User.id != exclude_user_id,
        )
        .count()
    )
    if others == 0:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Operation would leave no active admin",
        )


@router.delete("/{public_id}", response_model=MessageResponse)
def deactivate_user(
    public_id: str,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> MessageResponse:
    """Soft-delete (audit-preserving). Hard deletes are not exposed."""
    user = db.query(User).filter(User.public_id == public_id).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot deactivate your own account")
    user.is_active = False
    db.commit()
    record(
        db,
        action="user.deactivated",
        actor_user_id=admin.id,
        actor_ip=get_client_ip(request),
        object_type="user",
        object_id=user.public_id,
    )
    return MessageResponse(message="User deactivated")
