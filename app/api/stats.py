from fastapi import APIRouter, Depends, Query, HTTPException
from datetime import timedelta
from app.dependencies import config_db, metrics_db, current_user
from app.storage.repository import utcnow

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

@router.get("")
def stats(
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

    events, total = metrics.list_events(
        server_id=server_id,
        date_from=date_from,
        date_to=date_to,
        page=1,
        page_size=1000,
    )

    traffic = metrics.query_traffic_series(
        server_id=server_id,
        date_from=date_from,
        date_to=date_to,
        bucket_seconds=60,
    )

    peak_in_pps = 0.0
    for t in traffic:
        if t.get("in_pps", 0) > peak_in_pps:
            peak_in_pps = t["in_pps"]

    all_rules = metrics.list_rules(server_id=server_id) if hasattr(metrics, "list_rules") else []

    by_severity = {}
    by_protocol = {}
    by_type = {}
    by_status = {}
    for e in events:
        sev = e.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        proto = e.get("protocol", "unknown")
        by_protocol[proto] = by_protocol.get(proto, 0) + 1
        etype = e.get("event_type", "unknown")
        by_type[etype] = by_type.get(etype, 0) + 1
        st = e.get("action_status", "unknown")
        by_status[st] = by_status.get(st, 0) + 1

    temporary = 0
    permanent = 0
    expired = 0
    created_in_period = 0
    by_action = {}
    now = utcnow()
    for r in all_rules:
        rt = r.get("rule_type", "temporary")
        if rt == "temporary":
            temporary += 1
        elif rt == "permanent":
            permanent += 1
        if r.get("expires_at") and r["expires_at"] <= now.isoformat():
            expired += 1
        if r.get("created_at") and r["created_at"] >= date_from.isoformat():
            created_in_period += 1
        action = r.get("action", "unknown")
        by_action[action] = by_action.get(action, 0) + 1

    return {
        "range": range,
        "server_id": server_id,
        "has_data": len(traffic) > 0 or len(events) > 0,
        "message": "" if (len(traffic) > 0 or len(events) > 0) else "нет данных",
        "traffic": {
            "series": traffic,
            "has_data": len(traffic) > 0,
            "peak_in_pps": peak_in_pps,
        },
        "events": {
            "total": total,
            "items": events,
            "by_severity": [{"severity": k, "count": v} for k, v in sorted(by_severity.items())],
            "by_protocol": [{"protocol": k, "count": v} for k, v in sorted(by_protocol.items())],
            "by_type": [{"event_type": k, "count": v} for k, v in sorted(by_type.items())],
            "by_status": [{"action_status": k, "count": v} for k, v in sorted(by_status.items())],
        },
        "rules": {
            "active": len(all_rules),
            "temporary": temporary,
            "permanent": permanent,
            "expired": expired,
            "created_in_period": created_in_period,
            "by_action": [{"action": k, "count": v} for k, v in sorted(by_action.items())],
            "items": all_rules,
        },
    }