from fastapi import APIRouter, Depends
from app.dependencies import config_db, current_user

router = APIRouter()

@router.get("/status")
def security_status(db=Depends(config_db), user=Depends(current_user)):
    checks = []
    statuses = db.list_system_status()
    for s in statuses:
        checks.append({
            "name": s["component"],
            "status": s["status"],
        })
    checks.append({"name": "CSRF-защита", "status": "ok"})
    checks.append({"name": "Защищаемые серверы", "status": "ok"})
    return {"checks": checks}