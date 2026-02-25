from fastapi import APIRouter, Response, Cookie, HTTPException
from pydantic import BaseModel
import secrets
import time
import hashlib
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from database.sqlite import get_connection
from config import pepper
from services.auth_service import cipher, login_cache, is_logged_in
from services.crypto_service import cifra_vault
from realtime import register_telethon_handlers
from databaseInteractions import get_user_informations, set_user_vault

router = APIRouter()

class LoginUser(BaseModel):
    username: str
    password: str

class SmsCode(BaseModel):
    sms: str

@router.post("/login")
async def login_user(credentials: LoginUser, response: Response):
    """Endpoint primario per l'autenticazione. Decifra il vault e ripristina la sessione."""
    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()
    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    vault_decyphered = get_user_informations(username, credentials.password)
    
    # Inizializza il campo chats in caso di account legacy o vuoto
    if 'chats' not in vault_decyphered:
        vault_decyphered['chats'] = {}
    
    client = TelegramClient(
        StringSession(vault_decyphered['session']), 
        vault_decyphered['api_id'], 
        vault_decyphered['api_hash']
    )

    global login_cache
    login_cache[temp_id] = {
        "data": vault_decyphered,
        "time": time.time(),
        "client": client
    }

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )

    await client.connect()

    if await client.is_user_authorized():
        return {"status": "logged in"}
    else:
        # Se la sessione Telegram risulta revocata o scaduta, invia un nuovo SMS
        try:
            await client.disconnect()
            client = TelegramClient(StringSession(), vault_decyphered['api_id'], vault_decyphered['api_hash'])
            await client.connect()

            sent_code = await client.send_code_request(vault_decyphered['phone'])
            login_cache[temp_id] = {
                "data": vault_decyphered,
                "time": time.time(),
                "client": client,
                "sent_code": sent_code
            }
            return {"status": "session expired"}
        except Exception as e:
            await client.disconnect()
            raise HTTPException(status_code=500, detail=f"Errore invio SMS: {str(e)}")

@router.post("/login/expired")
async def login_user_expired(credentials: SmsCode, login_session: str = Cookie(None)):
    """Gestisce il login fallback con codice SMS per sessioni scadute."""
    if not login_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(login_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    global login_cache
    temp_data = login_cache.get(temp_id)
    if not temp_data:
        raise HTTPException(status_code=400, detail="Cache login non trovata")

    client = temp_data['client']
    
    try: 
        await client.sign_in(
            temp_data['data']['phone'], 
            credentials.sms, 
            phone_code_hash=temp_data['sent_code'].phone_code_hash
        )
        session_str = client.session.save()
    except SessionPasswordNeededError:
        try:
            await client.sign_in(password=temp_data['data']['password'])
            session_str = client.session.save()
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
            
    temp_data['data']['session'] = session_str
    vault_ciphered = cifra_vault(temp_data['data'], temp_data['data']['masterkey'])
    username = hashlib.sha256(pepper.encode() + temp_data['data']['username'].encode()).hexdigest()
    
    set_user_vault(username, vault_ciphered)
    return {"status": "logged in"}

@router.get("/login/check")
async def login_check(login_session: str = Cookie(None)):
    """Determina rapidamente l'esito base dell'is_logged_in middleware."""
    is_logged_in(login_session)
    return {"status": "ok"}

@router.post("/logout")
async def logout(response: Response, login_session: str = Cookie(None)):
    """Effettua il logout rimuovendo cache volatile e cookie, mantenendo la sessione DB."""
    if login_session:
        try:
            temp_id = cipher.decrypt(login_session.encode()).decode()
            temp_data = login_cache.pop(temp_id, None)
            client = temp_data.get("client") if temp_data else None
            if client:
                try:
                    await client.disconnect()
                except Exception:
                    pass
        except Exception:
            pass

    response.delete_cookie(
        key="login_session",
        httponly=True,
        secure=True,
        samesite="none",
    )
    return {"status": "logged out"}