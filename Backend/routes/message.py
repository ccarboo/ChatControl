from fastapi import APIRouter, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
from config import pepper
import time
import hashlib
from utils import  is_logged_in, genera_chiave_simmetrica, cifra_messaggio_k, decifra_vault, cifra_con_age, genera_chiavi, cifra_vault
import json

router = APIRouter()

class message (BaseModel):
    text: str
    chat_id: int
    cryph: bool
    group: bool

class iniz (BaseModel):
    chat_id: int
    

@router.post("/messages/send")
async def s_message( credentials: message, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not credentials.cryph:
        try:
            await client.send_message(credentials.chat_id, credentials.text)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    else:
        key = genera_chiave_simmetrica()
        text_cyp = cifra_messaggio_k(credentials.text, key)
        username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
        chat_id = hashlib.sha256(pepper.encode() + str(credentials.chat_id).encode()).hexdigest()
        if credentials.group:
            try:
                with get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                        (username, chat_id)
                    )
                    risultato = cursor.fetchone()
            except sqlite3.Error as error:
                raise HTTPException(status_code=500, detail=str(error))

            recipient_keys = []
            if risultato and risultato[0]:
                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
                all_keys = []
                if 'partecipanti' in vault_deciphered:
                    for participant_data in vault_deciphered['partecipanti'].values():
                        # Aggiungi chiave corrente
                        current_key = participant_data.get('chiave', {})
                        if current_key and current_key.get('chiave'):
                            all_keys.append(current_key)
                        # Aggiungi chiavi storiche
                        if 'chiavi' in participant_data:
                            all_keys.extend(participant_data['chiavi'])
                for k in all_keys[:]:
                    if k.get('fine') is not None:
                        all_keys.remove(k)
                recipient_keys = [k['chiave'] for k in all_keys if k.get('chiave')]

            if 'chats' in data['data'] and chat_id in data['data']['chats']:
                chat_data = data['data']['chats'][chat_id]
                if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
                    user_pubblica = chat_data['chiave']['pubblica']
                    if user_pubblica and user_pubblica not in recipient_keys:
                        recipient_keys.append(user_pubblica)
                        
            if not recipient_keys:
                raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")

            key_ciphered = cifra_con_age(key.decode(), recipient_keys)
            
            if key_ciphered is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
            
            da_hashare ={
                "cif" : "on",
                "text" : text_cyp,
                "key" : key_ciphered
            }
            json_da_hashare = json.dumps(da_hashare, sort_keys=True)
            mac = hashlib.sha256(json_da_hashare.encode()).hexdigest()
            finale = {
                "cif" : "on",
                "text" : text_cyp,
                "key" : key_ciphered,
                "mac" : mac
            }
            
            try:
                await client.send_message(credentials.chat_id, json.dumps(finale))
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        else:
            try:
                with get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                        (username, chat_id)
                    )
                    risultato = cursor.fetchone()
            except sqlite3.Error as error:
                raise HTTPException(status_code=500, detail=str(error))

            recipient_keys = []
            if risultato and risultato[0]:
                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
                all_keys = []
                if 'chiavi' in vault_deciphered:
                    all_keys.extend(vault_deciphered['chiavi'])
                for k in all_keys[:]:
                    if k.get('fine') is not None:
                        all_keys.remove(k)
                recipient_keys = [k['chiave'] for k in all_keys if k.get('chiave')]

            if 'chats' in data['data'] and chat_id in data['data']['chats']:
                chat_data = data['data']['chats'][chat_id]
                if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
                    user_pubblica = chat_data['chiave']['pubblica']
                    if user_pubblica and user_pubblica not in recipient_keys:
                        recipient_keys.append(user_pubblica)
            
            if not recipient_keys:
                raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")

            key_ciphered = cifra_con_age(key.decode(), recipient_keys)
            
            if key_ciphered is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
            
            da_hashare ={
                "cif" : "on",
                "text" : text_cyp,
                "key" : key_ciphered
            }

            json_da_hashare = json.dumps(da_hashare, sort_keys=True)
            mac = hashlib.sha256(json_da_hashare.encode()).hexdigest()
            finale = {
                "cif" : "on",
                "text" : text_cyp,
                "key" : key_ciphered,
                "mac" : mac
            }
            
            try:
                await client.send_message(credentials.chat_id, json.dumps(finale))
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
    return {"status":"ok"}

@router.post("/messages/initializing")
async def send_public_key(credentials: iniz, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    chat_id_hash = hashlib.sha256(pepper.encode() + str(credentials.chat_id).encode()).hexdigest()
    
    if 'chats' not in data['data']:
        data['data']['chats'] = {}
    
    chat_data = data['data']['chats'].get(chat_id_hash, {})
    chiave_corrente_chat = chat_data.get('chiave', {})
    
    if chiave_corrente_chat and chiave_corrente_chat.get('inizio'):
        inizio_corrente = chiave_corrente_chat.get('inizio', 0)
        if time.time() - inizio_corrente < 10:
            raise HTTPException(status_code=409, detail="Aspetta più tempo per generare un'altra chiave per questa chat")

    pubblica, privata = genera_chiavi()
    chiave_nuova = {
        "pubblica": pubblica,
        "privata": privata,
        "inizio": time.time(),
    }

    chiavi_lista = []
    
    if chiave_corrente_chat and chiave_corrente_chat.get('pubblica'):
        chiave_corrente_chat['fine'] = time.time() - 1
        chiavi_lista.append(chiave_corrente_chat)
    
    chiavi_precedenti = chat_data.get('chiavi', [])
    chiavi_lista.extend(chiavi_precedenti)
    
    data['data']['chats'][chat_id_hash] = {
        'chiave': chiave_nuova,
        'chiavi': chiavi_lista
    }

    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    vault_cifrato = cifra_vault(data['data'], data['data']['masterkey'])
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE utenti SET vault = ? WHERE username = ?""",
                (vault_cifrato, username)
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    message_payload = {
        "cif":"in",
        "public":pubblica
    }
    
    try:
        await client.send_message(credentials.chat_id, json.dumps(message_payload))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
    
    return {"status": "ok"}

