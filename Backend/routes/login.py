from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
import secrets
from config import pepper
import time
import hashlib
from utils import deriva_master_key, decifra_vault, cipher, login_cache, cifra_vault, resolve_login_session
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError
from realtime import register_telethon_handlers


router = APIRouter()

class login_user(BaseModel):
    username: str
    password: str

class code(BaseModel):
    sms: str


@router.post("/login")
async def login_user(credentials: login_user, response: Response):


    

    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()
    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)
            cursor.execute(
                "SELECT salt, vault FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is None:
                raise HTTPException(status_code=404, detail='username does not exist')
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    salt_db = risultati[0]
    
    if isinstance(salt_db, str):
        salt_bytes = salt_db.encode()
    else:
        salt_bytes = salt_db

    master_key = deriva_master_key(credentials.password, salt_bytes)

    try:
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Inizializza il campo chats se non esiste
    if 'chats' not in vault_decyphered:
        vault_decyphered['chats'] = {}
    
    client = TelegramClient(StringSession(vault_decyphered['session']), vault_decyphered['api_id'], vault_decyphered['api_hash'])

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
        register_telethon_handlers(client, temp_id)
        pass
    else:
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
            return {"status":"session expired"}
        except Exception as e:
            await client.disconnect()
            raise HTTPException(status_code=500, detail=f"Errore invio SMS: {str(e)}")

    return {"status":"logged in"}

@router.post("/login/expired")
async def login_user_expired(credentials: code, login_session: str = Cookie(None)):
    
    if not login_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(login_session.encode()).decode()
    except:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    global login_cache

    temp_data = login_cache.get(temp_id)
    client = temp_data['client']

    try: 
        await client.sign_in(temp_data['data']['phone'], credentials.sms, phone_code_hash = temp_data['sent_code'].phone_code_hash)
        session_str = client.session.save()

    except SessionPasswordNeededError:
        try:
            await client.sign_in(password= temp_data['data']['password'])
            session_str = client.session.save()
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
    temp_data['data']['session'] = session_str
    register_telethon_handlers(client, temp_id)

    vault_ciphered = cifra_vault(temp_data['data'], temp_data['data']['masterkey'])
    username = hashlib.sha256(pepper.encode() + temp_data['data']['username'].encode()).hexdigest()
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utenti SET vault = ? WHERE username = ?",
                (vault_ciphered, username),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    return {"status":"logged in"}

@router.get("/login/check")
async def login_check(login_session: str = Cookie(None)):
    resolve_login_session(login_session)
    return {"status": "ok"}

@router.post("/logout")
async def logout(response: Response, login_session: str = Cookie(None)):
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