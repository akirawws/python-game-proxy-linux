from fastapi import APIRouter, Depends, Query, HTTPException
from app.dependencies import config_db, metrics_db, current_user
from app.storage.repository import utcnow
from datetime import timedelta

router = APIRouter()

def _parse_range(range_value: str):
    units = {"m": "minutes", "h": "hours", "d": "days"}
    if len(range_value) < 2:
        raise ValueError("неверный диапазон")
    num = int(range_value[:-1])
    unit = units.get(range_value[-1])
    if not unit:
        raise ValueError("неверный диапазон")
    return num, unit

@router.get("/traffic")
def traffic(
    range: str = Query("5m"),
    server_id: int | None = Query(None),
    db=Depends(config_db),
    metrics=Depends(metrics_db),
    user=Depends(current_user),
):
    try:
        num, unit = _parse_range(range)
    except ValueError:
        raise HTTPException(status_code=422, detail="неверный диапазон")
    date_to = utcnow()
    date_from = date_to - timedelta(**{unit: num})
    series = metrics.query_traffic_series(
        server_id=server_id,
        date_from=date_from,
        date_to=date_to,
        bucket_seconds=60,
    )
    points = []
    for s in series:
        s["ts"] = s.pop("bucket", None)
        points.append(s)
    has_data = len(points) > 0
    return {
        "has_data": has_data,
        "stale": False,
        "points": points,
        "message": "нет данных" if not has_data else "",
    }

@router.get("/connections")
def connections(
    range: str = Query("5m"),
    server_id: int | None = Query(None),
    db=Depends(config_db),
    metrics=Depends(metrics_db),
    user=Depends(current_user),
):
    num, unit = _parse_range(range)
    date_to = utcnow()
    date_from = date_to - timedelta(**{unit: num})
    series = metrics.query_connection_series(
        server_id=server_id,
        date_from=date_from,
        date_to=date_to,
        bucket_seconds=60,
    )
    has_data = len(series) > 0
    return {
        "has_data": has_data,
        "points": series,
        "message": "нет данных" if not has_data else "",
    }

@router.get("/overview")
def overview(db=Depends(config_db), metrics=Depends(metrics_db), user=Depends(current_user)):
    servers = db.list_servers()
    items = []
    for s in servers:
        latest = metrics.latest_metric(s["id"])
        conntrack = 0
        conn_series = metrics.query_connection_series(
            server_id=s["id"],
            date_from=utcnow() - timedelta(minutes=5),
            date_to=utcnow(),
            bucket_seconds=60,
        )
        if conn_series:
            conntrack = int(conn_series[-1].get("conntrack_count", 0))
        items.append({
            "id": s["id"],
            "name": s["name"],
            "ip": s["ip"],
            "has_data": latest is not None,
            "conntrack_count": conntrack,
        })
    auto_actions = db.get_setting("auto_actions_enabled", "false")
    if auto_actions in ("true", "True", "1"):
        auto_actions = True
    elif auto_actions in ("false", "False", "0"):
        auto_actions = False
    return {
        "gateway": {
            "servers_total": len(servers),
            "detection_mode": db.get_setting("detection_mode", "observation"),
            "auto_actions_enabled": auto_actions,
        },
        "items": items,
    }