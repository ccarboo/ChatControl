from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError
import secrets
from cryptography.fernet import Fernet
from config import pepper
from config import secret_key
import hashlib
import time
from utils import deriva_master_key, cifra_vault, login_cache

router = APIRouter()

SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)

class UserData(BaseModel):
    api_id: str
    api_hash: str
    phone: str
    username: str
    password: str

class signupped(BaseModel):
    sms_code: str

class signupped_2fa(BaseModel):
    password: str

signup_cache = {}

@router.post("/signup/step1")
async def create_user(credentials: UserData, response: Response):
    client = TelegramClient(StringSession(), credentials.api_id, credentials.api_hash)
    await client.connect()

    sent_code = await client.send_code_request(credentials.phone)
    temp_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati != None:
                raise HTTPException(status_code=409,detail='username already exists')
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    


    global signup_cache
    signup_cache[temp_id] = {
        "client":client,
        "phone":credentials.phone,
        "phone_code_hash": sent_code.phone_code_hash,
        "salt": salt,
        "masterkey_derived":deriva_master_key(credentials.password, salt),
        "api_id":credentials.api_id,
        "api_hash":credentials.api_hash,
        "username":username,
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
async def sign_up_verify(credentials: signupped, signup_session: str = Cookie(None), response: Response=None):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
    
    client = temp_data['client']
    try: 
        await client.sign_in(temp_data['phone'],credentials.sms_code,phone_code_hash=temp_data['phone_code_hash'])
        session_str = client.session.save()

    except SessionPasswordNeededError:
        return {"status": "need_2fa_password"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Errore durante la verifica: {str(e)}")
    
    


    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "masterkey": temp_data['masterkey_derived'].decode() if isinstance(temp_data['masterkey_derived'], bytes) else temp_data['masterkey_derived'],
        "password": None,
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
        "data" : da_cifrare,
        "time" : time.time(),
        "client" : client
    }

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )

    return {"status": "Account creato!"}

@router.post("/signup/step3")
async def sign_up_verify_password(credentials: signupped_2fa, signup_session: str = Cookie(None), response: Response = None):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except:
        raise HTTPException(status_code=400, detail="Sessione invalida")

    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
    client = temp_data['client']
    try: 
        await client.sign_in(password= credentials.password)
        session_str = client.session.save()

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))



    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "masterkey": temp_data['masterkey_derived'].decode() if isinstance(temp_data['masterkey_derived'], bytes) else temp_data['masterkey_derived'],
        "password": credentials.password,
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
        "data" : da_cifrare,
        "time" : time.time(),
        "client" : client
    }

    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )
    
    return {"status": "Account creato!"}
