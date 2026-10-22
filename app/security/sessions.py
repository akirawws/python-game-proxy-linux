from starlette.middleware.sessions import SessionMiddleware
import os

# Берем секретный ключ из переменных окружения (файл .env), 
# если его нет - используем дефолтный (только для разработки!)
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-dev-key-change-in-prod")

def setup_session_middleware(app):
    """
    Подключает middleware для работы с безопасными куки-сессиями.
    """
    app.add_middleware(
        SessionMiddleware,
        secret_key=SECRET_KEY,
        session_cookie="netshield_session",
        max_age=3600, # Сессия живет 1 час
        same_site="lax", # Защита от CSRF
        https_only=False # В продакшене (с HTTPS) поставить True!
    )