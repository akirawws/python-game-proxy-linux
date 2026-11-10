from fastapi import APIRouter, Depends, Query
from app.dependencies import config_db, audit_service, current_user

router = APIRouter()

@router.get("")
def list_audit(
    action: str | None = Query(None),
    result: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    items, total = db.list_audit(
        action=action,
        result=result,
        page=page,
        page_size=page_size,
    )
    return {"total": total, "items": items, "page": page, "page_size": page_size}