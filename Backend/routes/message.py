from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
import secrets
from config import pepper
import time
import hashlib
from utils import  is_logged_in, genera_chiave_simmetrica, cifra_messaggio_k, decifra_vault, cifra_con_age
import json
from datetime import datetime

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
        chat_id = hashlib.sha256(pepper.encode() + credentials.chat_id.encode()).hexdigest()
        if credentials.group:
            #partecipants = await client.get_partecipants(credentials.chat_id)
            #user_ids = [ hashlib.sha256(pepper.encode() + user.id.encode()).hexdigest() for user in partecipants]
            
            try:
                with get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute(
                        """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND group_id = ?""",
                        (username,chat_id)
                    )
                    risultato = cursor.fetchone()
                        
            except sqlite3.Error as error:
                raise HTTPException(status_code=500, detail=str(error))

            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            vault_json = json.dumps(vault_deciphered)
            
            # Estrai tutte le chiavi in una lista
            all_keys = []
            if 'participants' in vault_deciphered:
                for participant_id, participant_data in vault_deciphered['participants'].items():
                    if 'chiavi' in participant_data:
                        for chiave_info in participant_data['chiavi']:
                            all_keys.append(chiave_info)

            for key in all_keys[:]:
                if key['fine'] is not None:
                    all_keys.remove(key)
            

            key_ciphered = cifra_con_age(key.decode(), [k['chiave'] for k in all_keys if k.get('chiave')])
            da_hashare ={
                "CIF" : "on",
                "text" : text_cyp,
                "key" : key_ciphered
            }
            # Calcola hash SHA-256 del JSON
            json_da_hashare = json.dumps(da_hashare, sort_keys=True)
            mac = hashlib.sha256(json_da_hashare.encode()).hexdigest()
            finale = {
                "CIF" : "on",
                "text" : text_cyp,
                "key" : key_ciphered,
                "MAC" : mac
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
                        (username,chat_id)
                    )
                    risultato = cursor.fetchone()
                        
            except sqlite3.Error as error:
                raise HTTPException(status_code=500, detail=str(error))

            vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
            
            # Estrai tutte le chiavi dalla struttura {user_id: {chiavi: [...]}}
            all_keys = []
            for user_id, user_data in vault_deciphered.items():
                if isinstance(user_data, dict) and 'chiavi' in user_data:
                    for chiave_info in user_data['chiavi']:
                        all_keys.append(chiave_info)
            
            # Rimuovi chiavi scadute (fine != None)
            for key in all_keys[:]:
                if key.get('fine') is not None:
                    all_keys.remove(key)
            

            key_ciphered = cifra_con_age(key.decode(), [k['chiave'] for k in all_keys if k.get('chiave')])
            da_hashare ={
                "CIF" : "on",
                "text" : text_cyp,
                "key" : key_ciphered
            }
            # Calcola hash SHA-256 del JSON
            json_da_hashare = json.dumps(da_hashare, sort_keys=True)
            mac = hashlib.sha256(json_da_hashare.encode()).hexdigest()
            finale = {
                "CIF" : "on",
                "text" : text_cyp,
                "key" : key_ciphered,
                "MAC" : mac
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
    
    # Controlla che la chiave pubblica esista
    if 'pubblica' not in data['data']:
        raise HTTPException(status_code=400, detail="Chiave pubblica non trovata nei dati utente")

    message_payload = {
        "cif": "in",
        "public": data['data']['pubblica']
    }
    
    try:
        await client.send_message(credentials.chat_id, json.dumps(message_payload))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
    
    return {"status": "ok"}
