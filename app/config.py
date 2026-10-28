from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

__all__ = ["Settings", "get_settings", "load_dotenv", "PROJECT_ROOT"]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

log = logging.getLogger("netshield.config")


def load_dotenv(path: Optional[Path] = None) -> None:
                                                                    
    env_path = path or (PROJECT_ROOT / ".env")
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("Некорректное значение %s, используется %s", name, default)
        return default


@dataclass(frozen=True)
class Settings:
    app_name: str = "NetShield"
    debug: bool = False
    secret_key: str = ""
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    session_max_age: int = 3600
    csrf_enabled: bool = True
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    login_lockout_seconds: int = 900
    trust_proxy_headers: bool = False
    admin_login: str = "admin"
    admin_password: str = ""
    static_dir: str = str(PROJECT_ROOT / "web" / "static")
    frontend_dist: str = str(PROJECT_ROOT / "web" / "static" / "dist")
    allowed_content_types: tuple[str, ...] = field(
        default=("application/json", "application/x-www-form-urlencoded")
    )


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is not None:
        return _settings

    load_dotenv()

    secret_key = os.getenv("NETSHIELD_SECRET_KEY") or os.getenv("SECRET_KEY") or ""
    if not secret_key:
                                                                         
        secret_key = secrets.token_urlsafe(48)
        log.warning(
            "NETSHIELD_SECRET_KEY не задан, сгенерирован временный ключ сессий. "
            "Задайте ключ в .env для продакшена."
        )

    samesite = os.getenv("COOKIE_SAMESITE", "lax").strip().lower()
    if samesite not in ("lax", "strict", "none"):
        samesite = "lax"

    _settings = Settings(
        app_name=os.getenv("NETSHIELD_APP_NAME", "NetShield"),
        debug=_bool("NETSHIELD_DEBUG", False),
        secret_key=secret_key,
        cookie_secure=_bool("COOKIE_SECURE", False),
        cookie_samesite=samesite,
        session_max_age=_int("SESSION_MAX_AGE", 3600),
        csrf_enabled=_bool("CSRF_ENABLED", True),
        login_max_attempts=_int("LOGIN_MAX_ATTEMPTS", 5),
        login_window_seconds=_int("LOGIN_WINDOW_SECONDS", 300),
        login_lockout_seconds=_int("LOGIN_LOCKOUT_SECONDS", 900),
        trust_proxy_headers=_bool("TRUST_PROXY_HEADERS", False),
        admin_login=os.getenv("NETSHIELD_ADMIN_LOGIN", "admin"),
        admin_password=os.getenv("NETSHIELD_ADMIN_PASSWORD", ""),
        static_dir=os.getenv(
            "NETSHIELD_STATIC_DIR", str(PROJECT_ROOT / "web" / "static")
        ),
        frontend_dist=os.getenv(
            "NETSHIELD_FRONTEND_DIST", str(PROJECT_ROOT / "web" / "static" / "dist")
        ),
    )
    return _settings


def reset_settings_cache() -> None:
    global _settings
    _settings = None
