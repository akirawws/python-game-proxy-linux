from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.security.sessions import setup_session_middleware
from app.api import auth
from app.api.auth import get_current_user

app = FastAPI(title="NetShield API")

setup_session_middleware(app)
app.mount("/static", StaticFiles(directory="web/static"), name="static")
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])

templates = Jinja2Templates(directory="web/templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard_root(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(request=request, name="dashboard.html")