from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import List
from app.api.auth import get_current_user
import datetime

router = APIRouter()

# --- ВРЕМЕННАЯ ЗАГЛУШКА (In-memory) ---
# Когда Денис сделает ClickHouse, мы заменим это на запрос к БД
events_db = [
    {
        "id": 1,
        "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=5)).isoformat(),
        "server": "Мой Web-сервер",
        "type": "Рост частоты UDP-пакетов",
        "severity": "Средний", # Низкий, Средний, Высокий
        "status": "Применено ограничение",
        "details": "Превышен порог UDP PPS в 5000"
    },
    {
        "id": 2,
        "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
        "server": "Игровой сервер",
        "type": "Резкий всплеск новых TCP-соединений",
        "severity": "Высокий",
        "status": "Заблокирован источник",
        "details": "IP 10.0.0.5 превысил лимит SYN пакетов"
    },
    {
        "id": 3,
        "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=3)).isoformat(),
        "server": "Мой Web-сервер",
        "type": "Кратковременный легитимный пик",
        "severity": "Низкий",
        "status": "Только запись в лог",
        "details": "Аномалия не подтверждена, действие не применено"
    }
]

@router.get("/")
async def get_events(user: str = Depends(get_current_user)):
    """Получить список событий (в будущем - с фильтрацией по времени и серверу)"""
    # Сортируем по времени (сначала новые)
    sorted_events = sorted(events_db, key=lambda x: x["timestamp"], reverse=True)
    return {"events": sorted_events}