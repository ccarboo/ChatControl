from fastapi import APIRouter, Response, Cookie, HTTPException
from pydantic import BaseModel
import sqlite3
import secrets
import hashlib
import time

from cryptography.fernet import Fernet
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from database.sqlite import get_connection
from config import pepper, secret_key
from utils import deriva_master_key, cifra_vault, login_cache
from realtime import register_telethon_handlers
from databaseInteractions import check_username_unicity

router = APIRouter()

cipher = Fernet(secret_key.encode())
signup_cache = {}

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

def _build_and_store_vault(temp_data: dict, session_str: str, response: Response, client: TelegramClient, password_2fa: str | None = None):
    """
    Helper interno per consolidare i dati raccolti durante la Signup.
    Crea la struttura da cifrare (Master Vault), la inserisce nel database e
    popola la login_cache preparandosi a switchare cookie da `signup` a `login`.
    """
    masterkey_str = temp_data['masterkey_derived'].decode() if isinstance(temp_data['masterkey_derived'], bytes) else temp_data['masterkey_derived']
    
    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "masterkey": masterkey_str,
        "password": password_2fa,
        "session": session_str
    }
    
    vault_cifrato = cifra_vault(da_cifrare, temp_data['masterkey_derived'])

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_cifrato),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    response.delete_cookie("signup_session")

    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()

    login_cache[temp_id] = {
        "data": da_cifrare,
        "time": time.time(),
        "client": client
    }
    register_telethon_handlers(client, temp_id)

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )

@router.post("/signup/step1")
async def create_user(credentials: UserData, response: Response):
    """
    Fase 1 del Signup: Contatta Telegram invocando l'SMS e alloca un token TLS RAM provvisorio
    contenente i metadati (API credenziali, derive hash masterkey).
    """
    client = TelegramClient(StringSession(), credentials.api_id, credentials.api_hash)
    await client.connect()
    
    try:
        sent_code = await client.send_code_request(credentials.phone)
    except Exception as e:
        print(f"ERRORE TELEGRAM: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Errore Telegram: {str(e)}")
        
    temp_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()

    check_username_unicity(username)

    global signup_cache
    signup_cache[temp_id] = {
        "client": client,
        "phone": credentials.phone,
        "phone_code_hash": sent_code.phone_code_hash,
        "salt": salt,
        "masterkey_derived": deriva_master_key(credentials.password, salt),
        "api_id": credentials.api_id,
        "api_hash": credentials.api_hash,
        "username": username,
        "username_not_cyphered": credentials.username
    }
    
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    response.set_cookie(
        key="signup_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=300,
    )
    
    return {"status": "SMS inviato"}
     
@router.post("/signup/step2")
async def sign_up_verify(credentials: SignupCode, signup_session: str = Cookie(None), response: Response = None):
    """
    Fase 2 del Signup: Valida il codice SMS. Se manca la 2FA finalizza istantaneamente 
    (delegando il salvataggio a `_build_and_store_vault`), altrimenti informa il front-end per step 3.
    """
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
    
    client = temp_data['client']
    try: 
        await client.sign_in(temp_data['phone'], credentials.sms_code, phone_code_hash=temp_data['phone_code_hash'])
        session_str = client.session.save()
    except SessionPasswordNeededError:
        return {"status": "need_2fa_password"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Errore durante la verifica: {str(e)}")
    
    _build_and_store_vault(temp_data, session_str, response, client, password_2fa=None)
    return {"status": "Account creato!"}

@router.post("/signup/step3")
async def sign_up_verify_password(credentials: Signup2FA, signup_session: str = Cookie(None), response: Response = None):
    """
    Fase 3 opzionale del Signup: Risolve le istanze coperte da Cloud Password (2FA) di Telegram e finalizza.
    """
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=400, detail="Sessione invalida")

    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
        
    client = temp_data['client']
    try: 
        await client.sign_in(password=credentials.password)
        session_str = client.session.save()
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    _build_and_store_vault(temp_data, session_str, response, client, password_2fa=credentials.password)
    return {"status": "Account creato!"}
