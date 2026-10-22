from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.api.auth import get_current_user

# --- ВОТ ЭТА СТРОКА ДОЛЖНА БЫТЬ ОБЯЗАТЕЛЬНО ---
router = APIRouter()
# -----------------------------------------------

# Временное хранилище (в памяти)
servers_db = [
    {
        "id": 1,
        "name": "Мой Web-сервер",
        "ip": "192.168.1.10",
        "ports": "80, 443",
        "protocol": "TCP",
        "status": "active"
    }
]

class ServerCreate(BaseModel):
    name: str
    ip: str
    ports: str
    protocol: str

@router.get("/")
async def get_servers(user: str = Depends(get_current_user)):
    """Получить список всех серверов"""
    return {"servers": servers_db}

@router.post("/")
async def create_server(server: ServerCreate, user: str = Depends(get_current_user)):
    """Добавить новый сервер"""
    new_id = max([s["id"] for s in servers_db], default=0) + 1
    
    new_server = {
        "id": new_id,
        "name": server.name,
        "ip": server.ip,
        "ports": server.ports,
        "protocol": server.protocol,
        "status": "active"
    }
    servers_db.append(new_server)
    return {"message": "Сервер добавлен", "server": new_server}