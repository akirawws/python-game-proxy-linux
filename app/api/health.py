from fastapi import APIRouter, Depends
from app.dependencies import config_db, metrics_db

router = APIRouter()

@router.get("")
def health(db=Depends(config_db), metrics=Depends(metrics_db)):
    return {
        "status": "ok",
        "config_db": db.health_check(),
        "metrics_db": metrics.health_check() if hasattr(metrics, "health_check") else True,
    }