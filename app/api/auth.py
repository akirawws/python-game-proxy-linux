from fastapi import APIRouter, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext

router = APIRouter()
templates = Jinja2Templates(directory="web/templates")

# Настраиваем bcrypt для хеширования
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- ЗАГЛУШКА БАЗЫ ДАННЫХ ---
FAKE_DB_USER = {
    "username": "admin",
    # Хеш для пароля "admin123"
    "password_hash": "$2b$12$kUqF19gIt/GqVIwukvi0SejPaKaUcmHMPgD7IbHR6iPmWGRfUWc2G" 
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# 1. Страница входа
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="login.html")

# 2. Обработка формы входа
@router.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if username != FAKE_DB_USER["username"] or not verify_password(password, FAKE_DB_USER["password_hash"]):
        return templates.TemplateResponse(
            request=request, 
            name="login.html", 
            context={"error": "Неверный логин или пароль"}
        )
    
    request.session["user"] = username
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

# 3. Выход
@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/api/auth/login", status_code=status.HTTP_302_FOUND)

# 4. Зависимость для защиты роутов
async def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, 
            headers={"Location": "/api/auth/login"}
        )
    return user