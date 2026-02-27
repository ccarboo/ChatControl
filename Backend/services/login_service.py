import secrets
import time
import hashlib
from fastapi import Response, HTTPException
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from core.config import pepper
from services.auth_service import cipher, login_cache
from services.crypto_service import cifra_vault
from services.realtime_service import register_telethon_handlers
from services.user_service import get_user_informations, set_user_vault

async def login_user_logic(username_raw: str, password_raw: str, response: Response):
    """
    Gestisce l'autenticazione dell'utente:
    1. Calcola l'hash dello username.
    2. Decifra il master vault usando la password fornita.
    3. Inizializza un'istanza TelegramClient da Telethon per usare l'API del protocollo MTProto.
    """
    username = hashlib.sha256(pepper.encode() + username_raw.encode()).hexdigest()
    # Genera un ID temporaneo di sessione e lo cifra per inviarlo in totale sicurezza al Frontend
    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    # Recupera i parametri dal vault locale dell'utente
    vault_decyphered = get_user_informations(username, password_raw)
    
    if 'chats' not in vault_decyphered:
        vault_decyphered['chats'] = {}
    
    # Istanzia il client Telegram collegando la stringa di sessione salvata
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

async def login_user_expired_logic(sms: str, login_session: str):
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
            sms, 
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

async def logout_logic(response: Response, login_session: str):
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
