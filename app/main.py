from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.security.sessions import setup_session_middleware
from app.api.auth import get_current_user
from app.api import auth, servers, events

app = FastAPI(title="NetShield API")

# 1. Подключаем сессии и статику
setup_session_middleware(app)
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# 2. Подключаем API роутеры
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(servers.router, prefix="/api/servers", tags=["Servers"])
app.include_router(events.router, prefix="/api/events", tags=["Events"])

# 3. Настраиваем шаблоны
templates = Jinja2Templates(directory="web/templates")

# 4. Страницы (HTML)
@app.get("/", response_class=HTMLResponse)
async def dashboard_root(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(request=request, name="servers.html")

@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(request=request, name="events.html")