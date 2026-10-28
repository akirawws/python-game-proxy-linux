from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import audit, auth, events, health, metrics, rules, security, servers, settings as settings_api, stats
from app.config import get_settings
from app.security.passwords import hash_password
from app.security.sessions import setup_session_middleware
from app.storage.factory import get_config_storage, get_metrics_storage
from app.storage.repository import utcnow

__all__ = ["app", "create_app"]

log = logging.getLogger("netshield")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    ),
}


def _configure_logging() -> None:
    level = logging.DEBUG if get_settings().debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _bootstrap_admin() -> None:
    config = get_settings()
    repository = get_config_storage()
    existing = repository.fetch_all("users")
    if existing:
        return
    if not config.admin_password:
        log.warning(
            "Нет ни одного администратора. Создайте его командой "
            "`python -m app.cli create-admin` или задайте NETSHIELD_ADMIN_PASSWORD."
        )
        repository.set_system_status(
            "auth",
            "error",
            "нет учётных записей администратора",
        )
        return
    repository.insert_row(
        "users",
        {
            "login": config.admin_login,
            "password_hash": hash_password(config.admin_password),
            "is_admin": 1,
            "created_at": utcnow().isoformat(),
        },
    )
    log.info("Администратор %s создан из окружения", config.admin_login)
    repository.set_system_status("auth", "ok", "администратор создан")


class SecurityHeadersMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for name, value in SECURITY_HEADERS.items():
                    headers[name.lower().encode()] = value.encode()
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_wrapper)


def create_app() -> FastAPI:
    _configure_logging()
    config = get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        _bootstrap_admin()
        get_metrics_storage()
        log.info("NetShield API запущен")
        yield
        log.info("NetShield API остановлен")

    application = FastAPI(
        title=f"{config.app_name} API",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    application.add_middleware(SecurityHeadersMiddleware)
    setup_session_middleware(application)

    @application.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("Необработанная ошибка request_id=%s path=%s", request_id, request.url.path)
            return JSONResponse(
                status_code=500,
                content={"detail": "Внутренняя ошибка сервера", "request_id": request_id},
            )
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        log.info(
            "%s %s -> %s %.1fms",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response

    @application.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    application.include_router(health.router, prefix="/api/health", tags=["Health"])
    application.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
    application.include_router(servers.router, prefix="/api/servers", tags=["Servers"])
    application.include_router(metrics.router, prefix="/api/metrics", tags=["Metrics"])
    application.include_router(events.router, prefix="/api/events", tags=["Events"])
    application.include_router(rules.router, prefix="/api/rules", tags=["Rules"])
    application.include_router(stats.router, prefix="/api/stats", tags=["Statistics"])
    application.include_router(
        settings_api.router, prefix="/api/settings", tags=["Settings"]
    )
    application.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
    application.include_router(
        security.router, prefix="/api/security", tags=["Security"]
    )

    _mount_frontend(application, config)
    return application


def _mount_frontend(application: FastAPI, config) -> None:
    static_dir = Path(config.static_dir)
    static_dir.mkdir(parents=True, exist_ok=True)
    application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    dist_dir = Path(config.frontend_dist)
    index_file = dist_dir / "index.html"

    @application.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "Не найдено"})
        if index_file.is_file():
            return FileResponse(str(index_file))
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Фронтенд не собран. Выполните: cd web/frontend && npm install && npm run build"
            },
        )


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.getenv("NETSHIELD_HOST", "127.0.0.1"),
        port=int(os.getenv("NETSHIELD_PORT", "8000")),
        reload=get_settings().debug,
    )
