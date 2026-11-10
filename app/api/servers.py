from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from typing import List
from app.dependencies import config_db, audit_service, current_user
from app.storage.models import ProtectedServer, ProtectedPort
from app.api.schemas import ServerCreate, ServerUpdate, PortItem

router = APIRouter()

def _check_csrf(request: Request) -> None:
    csrf_token = request.headers.get("x-csrf-token")
    session_token = request.session.get("csrf_token")
    if not csrf_token or csrf_token != session_token:
        raise HTTPException(status_code=403, detail="csrf_failed")

@router.get("")
def list_servers(db=Depends(config_db), user=Depends(current_user)):
    items = db.list_servers()
    return {"total": len(items), "items": items}

@router.post("", status_code=201)
def create_server(
    request: Request,
    data: ServerCreate,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    try:
        server_id = db.create_server(data.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if data.ports:
        db.replace_ports(server_id, data.ports)
    audit.log("server.create", details=f"server {server_id}", user_id=user["id"])
    return {"id": server_id, **data.model_dump(exclude={"ports"}), "ports": data.ports}

@router.get("/{server_id}")
def get_server(server_id: int, db=Depends(config_db), user=Depends(current_user)):
    server = db.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="сервер не найден")
    return server

@router.patch("/{server_id}")
def update_server(
    request: Request,
    server_id: int,
    data: ServerUpdate,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    server = db.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="сервер не найден")
    updates = {k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None}
    if not updates:
        return server
    db.update_server(server_id, updates)
    audit.log("server.update", details=f"server {server_id}: {updates}", user_id=user["id"])
    return db.get_server(server_id)

@router.put("/{server_id}/ports")
def replace_ports(
    request: Request,
    server_id: int,
    ports: List[PortItem],
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    server = db.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="сервер не найден")
    db.replace_ports(server_id, [p.model_dump() for p in ports])
    audit.log("server.ports", details=f"server {server_id} ports updated", user_id=user["id"])
    return db.get_server(server_id)

@router.delete("/{server_id}", status_code=204)
def delete_server(
    request: Request,
    server_id: int,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    server = db.get_server(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="сервер не найден")
    db.delete_server(server_id)
    audit.log("server.delete", details=f"server {server_id}", user_id=user["id"])