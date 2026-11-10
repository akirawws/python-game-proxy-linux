from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from app.dependencies import config_db, audit_service, current_user
from app.api.schemas import RuleCreate
from app.storage.repository import utcnow
from datetime import datetime, timedelta, timezone

router = APIRouter()

def _check_csrf(request: Request) -> None:
    csrf_token = request.headers.get("x-csrf-token")
    session_token = request.session.get("csrf_token")
    if not csrf_token or csrf_token != session_token:
        raise HTTPException(status_code=403, detail="csrf_failed")

@router.get("")
def list_rules(
    server_id: int | None = Query(None),
    status_filter: str = Query("all", alias="status"),
    db=Depends(config_db),
    user=Depends(current_user),
):
    rules = db.list_rules(server_id=server_id, status=status_filter)
    return {"total": len(rules), "items": rules}

@router.post("", status_code=201)
def create_rule(
    request: Request,
    data: RuleCreate,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    server = db.fetch_one("protected_servers", "id=?", (data.server_id,))
    if not server:
        raise HTTPException(status_code=400, detail="сервер не найден")

    if data.port is not None:
        ports = db.list_ports(data.server_id)
        protected = any(
            int(p["port"]) == data.port and p["protocol"] in (data.protocol, "both")
            for p in ports
        )
        if not protected:
            raise HTTPException(status_code=400, detail="Порт не принадлежит серверу")

    expires_at = None
    rule_type = "temporary"
    if data.ttl_seconds is not None and data.ttl_seconds > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=data.ttl_seconds)
    elif data.ttl_seconds == 0:
        rule_type = "permanent"

    rule_data = {
        "server_id": data.server_id,
        "ip": data.ip,
        "port": data.port or 0,
        "protocol": data.protocol,
        "action": data.action,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "is_active": 1,
        "rule_type": rule_type,
        "reason": data.reason,
        "created_at": utcnow().isoformat(),
    }
    rule_id = db.insert_row("firewall_rules", rule_data)
    audit.log("rule.apply", details=f"rule {rule_id} {data.action} for {data.ip}", user_id=user["id"])
    return {"status": "pending", "rule_id": rule_id}

@router.delete("/{rule_id}")
def cancel_rule(
    request: Request,
    rule_id: int,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    rule = db.fetch_one("firewall_rules", "id=?", (rule_id,))
    if not rule:
        raise HTTPException(status_code=404, detail="правило не найдено")
    db.update("firewall_rules", rule_id, is_active=0)
    audit.log("rule.cancel", details=f"rule {rule_id} cancelled", user_id=user["id"])
    return {"status": "cancelled"}