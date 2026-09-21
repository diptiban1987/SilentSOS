"""Shared FastAPI dependencies: current user, RBAC, client IP."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import TokenError, decode_access_token
from app.db.session import get_db
from app.models.models import ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER, User

bearer_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str:
    """Client IP — behind nginx, trust the first X-Forwarded-For hop."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return request.client.host if request.client else ""


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized
    try:
        payload = decode_access_token(credentials.credentials)
    except TokenError:
        raise unauthorized from None
    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError):
        raise unauthorized from None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_roles(*allowed_roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


require_admin = require_roles(ROLE_ADMIN)
require_operator = require_roles(ROLE_ADMIN, ROLE_OPERATOR)
require_any = get_current_user  # viewer included
