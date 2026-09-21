"""Authentication endpoints.

* POST /login    — Argon2id verify, lockout, rate limit, audit; issues access
                   JWT + rotating refresh cookie (httpOnly, SameSite=Lax).
* POST /refresh  — single-use rotation; reuse of a revoked token is audited.
* POST /logout   — revokes the presented refresh token, clears cookie.
* GET  /me       — current identity.
* POST /change-password — policy-checked; revokes ALL refresh tokens.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_client_ip, get_current_user
from app.core.security import (
    REFRESH_COOKIE_NAME,
    clear_refresh_cookie_kwargs,
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    password_entropy_ok,
    refresh_cookie_kwargs,
    refresh_expiry,
    verify_password,
)
from app.db.session import get_db
from app.middleware.rate_limit import limiter
from app.models.models import RefreshToken, User, ensure_aware
from app.schemas.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MeResponse,
    MessageResponse,
)
from app.services.audit import record

router = APIRouter(prefix="/auth", tags=["auth"])
_settings = get_settings()

# Used to equalise timing when the email does not exist (anti-enumeration).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


def _fail_login(db: Session, user: User, ip: str) -> None:
    user.failed_attempts += 1
    if user.failed_attempts >= _settings.LOCKOUT_THRESHOLD:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=_settings.LOCKOUT_MINUTES
        )
        user.failed_attempts = 0
    db.commit()
    record(
        db,
        action="auth.login_failed",
        actor_user_id=user.id,
        actor_ip=ip,
        object_type="user",
        object_id=user.public_id,
        detail={"locked": user.locked_until is not None},
    )


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = get_client_ip(request)
    allowed, retry_after = limiter.allow(f"{ip}:auth", _settings.RATE_LIMIT_AUTH_PER_MIN)
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many login attempts; slow down",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.query(User).filter(User.email == body.email.strip().lower()).first()
    now = datetime.now(timezone.utc)
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    if user is None:
        verify_password(body.password, _DUMMY_HASH)  # timing equalisation
        raise invalid
    if not user.is_active:
        raise invalid
    if user.locked_until is not None and ensure_aware(user.locked_until) > now:
        retry_after = max(1, int((ensure_aware(user.locked_until) - now).total_seconds()))
        raise HTTPException(
            status.HTTP_423_LOCKED,
            "Account temporarily locked",
            headers={"Retry-After": str(retry_after)},
        )
    if not verify_password(body.password, user.hashed_password):
        _fail_login(db, user, ip)
        raise invalid

    # Success — reset counters, issue tokens.
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()

    access, _exp = create_access_token(user.id, user.role)
    refresh = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(refresh),
            expires_at=refresh_expiry(),
            created_ip=ip,
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    db.commit()
    response.set_cookie(**refresh_cookie_kwargs(), value=refresh)

    record(
        db,
        action="auth.login",
        actor_user_id=user.id,
        actor_ip=ip,
        object_type="user",
        object_id=user.public_id,
    )
    return LoginResponse(
        access_token=access,
        expires_in=_settings.ACCESS_TOKEN_MINUTES * 60,
        user=MeResponse.model_validate(user),
    )


@router.post("/refresh", response_model=LoginResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    ip = get_client_ip(request)
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")

    rt = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == hash_refresh_token(token))
        .first()
    )
    now = datetime.now(timezone.utc)
    if rt is None or rt.revoked or ensure_aware(rt.expires_at) < now:
        if rt is not None:  # reuse of revoked/expired token — suspicious
            record(
                db,
                action="auth.refresh_reuse",
                actor_user_id=rt.user_id,
                actor_ip=ip,
                object_type="refresh_token",
                object_id=str(rt.id),
            )
            # Reuse of a rotated token may indicate theft: kill the family.
            db.query(RefreshToken).filter(RefreshToken.user_id == rt.user_id).update(
                {"revoked": True}
            )
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    user = db.get(User, rt.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    # Rotate: revoke presented token, issue a fresh one.
    rt.revoked = True
    new_token = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(new_token),
            expires_at=refresh_expiry(),
            created_ip=ip,
            user_agent=(request.headers.get("user-agent") or "")[:255],
        )
    )
    db.commit()

    access, _exp = create_access_token(user.id, user.role)
    response.set_cookie(**refresh_cookie_kwargs(), value=new_token)
    return LoginResponse(
        access_token=access,
        expires_in=_settings.ACCESS_TOKEN_MINUTES * 60,
        user=MeResponse.model_validate(user),
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> MessageResponse:
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if token:
        rt = (
            db.query(RefreshToken)
            .filter(RefreshToken.token_hash == hash_refresh_token(token))
            .first()
        )
        if rt is not None and not rt.revoked:
            rt.revoked = True
            db.commit()
            record(
                db,
                action="auth.logout",
                actor_user_id=rt.user_id,
                actor_ip=get_client_ip(request),
                object_type="refresh_token",
                object_id=str(rt.id),
            )
    response.set_cookie(**clear_refresh_cookie_kwargs(), value="")
    return MessageResponse(message="Logged out")


@router.get("/me", response_model=MeResponse)
def me(user: User = Depends(get_current_user)) -> MeResponse:
    return MeResponse.model_validate(user)


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    if not verify_password(body.current_password, user.hashed_password):
        record(
            db,
            action="auth.password_change_failed",
            actor_user_id=user.id,
            actor_ip=get_client_ip(request),
            object_type="user",
            object_id=user.public_id,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Current password is incorrect")
    if not password_entropy_ok(body.new_password):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Password must be 12+ chars with upper, lower and digit",
        )
    user.hashed_password = hash_password(body.new_password)
    # Force re-login everywhere: revoke all refresh tokens for this user.
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update(
        {"revoked": True}
    )
    db.commit()
    record(
        db,
        action="auth.password_changed",
        actor_user_id=user.id,
        actor_ip=get_client_ip(request),
        object_type="user",
        object_id=user.public_id,
    )
    return MessageResponse(message="Password updated; all sessions revoked")

