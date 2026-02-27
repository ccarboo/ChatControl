from fastapi import APIRouter, Response, Cookie
from pydantic import BaseModel

from services.signup_service import (
    create_user_logic, sign_up_verify_logic, sign_up_verify_password_logic
)

router = APIRouter()

class UserData(BaseModel):
    api_id: str
    api_hash: str
    phone: str
    username: str
    password: str

class SignupCode(BaseModel):
    sms_code: str

class Signup2FA(BaseModel):
    password: str

@router.post("/signup/step1")
async def create_user(credentials: UserData, response: Response):
    """Fase 1 Signup: invia codice SMS tramite Telegram e inizializza cache."""
    # Inizia la procedura instanziando un client vuoto TelegramClient e memorizza i secret crittografici
    return await create_user_logic(
        credentials.api_id, credentials.api_hash, credentials.phone, 
        credentials.username, credentials.password, response
    )
     
@router.post("/signup/step2")
async def sign_up_verify(credentials: SignupCode, signup_session: str = Cookie(None), response: Response = None):
    """Fase 2 Signup: valida codice SMS e finalizza se non serve 2FA."""
    # Raccoglie l'OTP SMS dell'utente e cerca di instaurare la sessione effettiva
    return await sign_up_verify_logic(credentials.sms_code, signup_session, response)

@router.post("/signup/step3")
async def sign_up_verify_password(credentials: Signup2FA, signup_session: str = Cookie(None), response: Response = None):
    """Fase 3 Signup: completa la registrazione tramite cloud password 2FA."""
    # Se il Sign-in di fase 2 ha sollevato un errore di SessionPasswordNeeded (2FA abilitata), usa questo fallback
    return await sign_up_verify_password_logic(credentials.password, signup_session, response)
