from fastapi import APIRouter, Depends, Query, HTTPException
from app.dependencies import config_db, metrics_db, current_user
from app.storage.repository import utcnow
from datetime import timedelta

router = APIRouter()

VALID_SEVERITIES = {"info", "low", "medium", "high"}
VALID_EVENT_TYPES = {"udp_flood", "syn_flood", "icmp_flood", "port_scan", "anomaly"}
VALID_ACTION_STATUSES = {"proposed", "applied", "cancelled"}
VALID_PROTOCOLS = {"tcp", "udp", "both"}
VALID_GROUP_BY = {"severity", "event_type", "protocol", "action_status"}

@router.get("")
def list_events(
    server_id: int | None = Query(None),
    severity: str | None = Query(None),
    event_type: str | None = Query(None),
    protocol: str | None = Query(None),
    action_status: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db=Depends(config_db),
    metrics=Depends(metrics_db),
    user=Depends(current_user),
):
    if severity and severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=422, detail="недопустимая важность")

    df = None
    dt = None
    if date_from:
        df = utcnow().fromisoformat(date_from)
    if date_to:
        dt = utcnow().fromisoformat(date_to)

    items, total = metrics.list_events(
        server_id=server_id,
        severity=severity,
        event_type=event_type,
        protocol=protocol,
        action_status=action_status,
        date_from=df,
        date_to=dt,
        page=page,
        page_size=page_size,
    )
    return {"total": total, "items": items, "has_data": total > 0, "message": "" if total > 0 else "нет данных"}

@router.get("/stats")
def events_stats(
    group_by: str = Query("severity"),
    db=Depends(config_db),
    metrics=Depends(metrics_db),
    user=Depends(current_user),
):
    if group_by not in VALID_GROUP_BY:
        raise HTTPException(status_code=422, detail="недопустимая группировка")
    try:
        items = metrics.event_stats(group_by=group_by)
    except Exception:
        items = []
    return {"group_by": group_by, "items": items, "total": sum(i.get("count", 0) for i in items)}