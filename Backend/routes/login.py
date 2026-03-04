from fastapi import APIRouter, Response, Cookie
from pydantic import BaseModel

from services.auth_service import is_logged_in
from services.login_service import login_user_logic, login_user_expired_logic, logout_logic

router = APIRouter()

class LoginUser(BaseModel):
    username: str
    password: str

class SmsCode(BaseModel):
    sms: str
    password: str

@router.post("/login")
async def login_user(credentials: LoginUser, response: Response):
    """Endpoint primario per l'autenticazione. Decifra il vault e ripristina la sessione."""
    # Delega la logica complessa (hash username, inizializzazione client Telegram e cache) al login_service
    return await login_user_logic(credentials.username, credentials.password, response)

@router.post("/login/expired")
async def login_user_expired(credentials: SmsCode, login_session: str = Cookie(None)):
    """Gestisce il login fallback con codice SMS per sessioni scadute."""
    # Invia il codice SMS a Telegram per ristabilire la sessione obsoleta
    return await login_user_expired_logic(credentials.sms, credentials.password, login_session)

@router.get("/login/check")
async def login_check(login_session: str = Cookie(None)):
    """Determina rapidamente l'esito base dell'is_logged_in middleware."""
    # Funge da pre-flight auth check per il frontend
    is_logged_in(login_session)
    return {"status": "ok"}

@router.post("/logout")
async def logout(response: Response, login_session: str = Cookie(None)):
    """Effettua il logout rimuovendo cache volatile e cookie, mantenendo la sessione DB."""
    # Disconnette l'istanza Telethon e invalida i token per sicurezza
    return await logout_logic(response, login_session)