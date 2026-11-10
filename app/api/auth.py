from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from app.dependencies import config_db, audit_service, login_limiter, client_ip, current_user
from app.security.audit import AuditService
from app.security.passwords import verify_password
import secrets
from pydantic import BaseModel, ConfigDict

router = APIRouter()

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    login: str
    password: str

@router.get("/csrf")
def csrf(request: Request):
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return {"csrf_token": token}

@router.post("/login")
def login(
    request: Request,
    data: LoginRequest,
    db=Depends(config_db),
    audit: AuditService = Depends(audit_service),
    limiter=Depends(login_limiter),
    ip: str = Depends(client_ip),
):
    csrf_token = request.headers.get("x-csrf-token")
    session_token = request.session.get("csrf_token")
    if not csrf_token or csrf_token != session_token:
        return JSONResponse(status_code=403, content={"code": "csrf_failed"})

    if not data.login or not data.password:
        raise HTTPException(status_code=422, detail="логин и пароль обязательны")

    locked = limiter.is_locked(ip)
    if locked:
        raise HTTPException(status_code=429, detail="заблокировано", headers={"Retry-After": str(int(locked))})

    user = db.fetch_one("users", "login=?", (data.login,))
    if not user or not verify_password(data.password, user["password_hash"]):
        limiter.record_failure(ip)
        audit.log("auth.login", details=f"failed login for {data.login}", result="fail")
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    limiter.record_success(ip)
    request.session["user"] = {"id": user["id"], "login": user["login"], "is_admin": bool(user["is_admin"])}
    request.session["csrf_token"] = secrets.token_urlsafe(32)
    audit.log("auth.login", details=f"success login for {data.login}", user_id=user["id"], result="ok")
    return {"user": {"id": user["id"], "login": user["login"], "is_admin": bool(user["is_admin"])}, "csrf_token": request.session["csrf_token"]}

@router.get("/me")
def me(user=Depends(current_user)):
    return {"user": user}

@router.post("/logout")
def logout(
    request: Request,
    db=Depends(config_db),
    audit: AuditService = Depends(audit_service),
    user=Depends(current_user),
):
    csrf_token = request.headers.get("x-csrf-token")
    session_token = request.session.get("csrf_token")
    if not csrf_token or csrf_token != session_token:
        return JSONResponse(status_code=403, content={"code": "csrf_failed"})

    request.session.clear()
    audit.log("auth.logout", details=f"logout for {user['login']}", user_id=user["id"])
    from fastapi.responses import Response
    return Response(status_code=204)