from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from app.config import get_settings
from app.security.audit import AuditService
from app.security.rate_limit import LoginRateLimiter
from app.storage.factory import get_config_storage, get_metrics_storage
from app.storage.repository import Repository

__all__ = [
    "config_db",
    "metrics_db",
    "audit_service",
    "login_limiter",
    "client_ip",
    "current_user",
    "require_admin",
]


def config_db() -> Repository:
    return get_config_storage()


def metrics_db():
    return get_metrics_storage()


def audit_service(repository: Repository = Depends(config_db)) -> AuditService:
    return AuditService(repository)


def login_limiter(request: Request) -> LoginRateLimiter:
    limiter = getattr(request.app.state, "login_limiter", None)
    if limiter is None:                                  
        settings = get_settings()
        limiter = LoginRateLimiter(
            max_attempts=settings.login_max_attempts,
            window_seconds=settings.login_window_seconds,
            lockout_seconds=settings.login_lockout_seconds,
        )
        request.app.state.login_limiter = limiter
    return limiter


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def current_user(
    request: Request, repository: Repository = Depends(config_db)
) -> dict:
    session_user = request.session.get("user")
    if not session_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется авторизация",
            headers={"WWW-Authenticate": "Session"},
        )

    user_id: Optional[int] = session_user.get("id")
    if user_id is None:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия недействительна",
        )

    row = repository.fetch_one("users", "id=?", (user_id,))
    if row is None:
        request.session.clear()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден",
        )

    return {
        "id": row["id"],
        "login": row["login"],
        "is_admin": bool(row["is_admin"]),
    }


def require_admin(user: dict = Depends(current_user)) -> dict:
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав",
        )
    return user
