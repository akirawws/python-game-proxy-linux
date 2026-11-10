from fastapi import APIRouter, Depends, HTTPException, Request
from app.dependencies import config_db, audit_service, current_user
from pydantic import BaseModel, field_validator
from typing import Optional

router = APIRouter()

class SettingsUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    detection_mode: Optional[str] = None
    auto_actions_enabled: Optional[bool] = None
    collection_interval_sec: Optional[int] = None
    confirmation_intervals: Optional[int] = None
    cooldown_seconds: Optional[int] = None
    max_concurrent_blocks: Optional[int] = None
    metrics_retention_days: Optional[int] = None
    event_retention_days: Optional[int] = None

    @field_validator("detection_mode")
    @classmethod
    def _validate_mode(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in ("observation", "auto"):
            raise ValueError("недопустимый режим обнаружения")
        return value

def _convert_settings(raw: dict) -> dict:
    result = {}
    for k, v in raw.items():
        if isinstance(v, bool):
            result[k] = v
        elif v in ("true", "True", "1"):
            result[k] = True
        elif v in ("false", "False", "0"):
            result[k] = False
        else:
            try:
                result[k] = int(v)
            except ValueError:
                result[k] = v
    return result

@router.get("")
def get_settings(db=Depends(config_db), user=Depends(current_user)):
    raw = db.get_settings()
    return _convert_settings(raw)

@router.put("")
def update_settings(
    request: Request,
    data: SettingsUpdate,
    db=Depends(config_db),
    audit=Depends(audit_service),
    user=Depends(current_user),
):
    _check_csrf(request)
    values = {k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None}
    str_values = {k: str(v) for k, v in values.items()}
    if "detection_mode" in str_values and str_values["detection_mode"] == "auto":
        str_values["auto_actions_enabled"] = "true"
    db.update_settings(str_values)
    audit.log("settings.update", details=str(values), user_id=user["id"])
    return _convert_settings(db.get_settings())

def _check_csrf(request: Request) -> None:
    csrf_token = request.headers.get("x-csrf-token")
    session_token = request.session.get("csrf_token")
    if not csrf_token or csrf_token != session_token:
        raise HTTPException(status_code=403, detail="csrf_failed")