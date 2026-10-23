from starlette.middleware.sessions import SessionMiddleware
import os

                                                            
                                                              
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-dev-key-change-in-prod")

def setup_session_middleware(app):
    pass
    app.add_middleware(
        SessionMiddleware,
        secret_key=SECRET_KEY,
        session_cookie="netshield_session",
        max_age=3600,                     
        same_site="lax",                 
        https_only=False                                         
    )