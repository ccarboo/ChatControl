from fastapi import APIRouter, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
from config import pepper
import time
import hashlib
from utils import  is_logged_in, decifra_vault, cifra_con_age, genera_chiavi, cifra_vault, get_chat_chyper_keys, get_group_chyper_keys
import json
from fastapi import UploadFile, File, Form
import subprocess
import tempfile
import shutil
from telethon.tl.types import DocumentAttributeFilename
import os


router = APIRouter()

class message (BaseModel):
    text: str
    chat_id: int
    cryph: bool
    group: bool

class iniz (BaseModel):
    chat_id: int
    



@router.post("/messages/send/file")
async def s_file(chat_id: int = Form(...), text: str = Form(""), cryph: bool = Form(False),group: bool = Form(False), file: UploadFile = File(...),login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not cryph:
        try:
            from telethon.tl.types import DocumentAttributeFilename
            import os
            ext = os.path.splitext(file.filename)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                shutil.copyfileobj(file.file, tmp)
                tmp_path = tmp.name

            await client.send_file(
                chat_id,
                tmp_path,
                caption=text,
                force_document=True,
                attributes=[DocumentAttributeFilename(file.filename)]
            )
            os.remove(tmp_path)

            return {"status":"ok"}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")

    else:
        
        if group:
            recipient_keys = get_group_chyper_keys(data, chat_id)

            

        else:
            recipient_keys = get_chat_chyper_keys(data, chat_id)
            

        '''encrypted_path = f"/dev/shm/{file.filename}.age"

        
        process = subprocess.Popen(
            ["age", "-r", user['target_pub_key'], "-o", encrypted_path],
            stdin=subprocess.PIPE
        )

        while chunk := await file.read(65536): # Legge 64KB alla volta
            process.stdin.write(chunk)
        
        process.stdin.close()
        process.wait()'''
    
    
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
        if credentials.group:
            
            recipient_keys = get_group_chyper_keys(data, credentials.chat_id)

            da_cifrare ={
                "cif" : "on",
                "text" : credentials.text,
            }

            json_da_cifrare = json.dumps(da_cifrare, sort_keys= True)

            text_cyp = cifra_con_age(json_da_cifrare, recipient_keys)
            
            if text_cyp is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")

            
            finale = {
                "cif" : "on",
                "text" : text_cyp,
            }
            
            try:
                await client.send_message(credentials.chat_id, json.dumps(finale))
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        else:
            
            recipient_keys = get_chat_chyper_keys(data, credentials.chat_id)

            da_cifrare ={
                "cif" : "on",
                "text" : credentials.text,
            }

            json_da_cifrare = json.dumps(da_cifrare, sort_keys= True)

            text_cyp = cifra_con_age(json_da_cifrare, recipient_keys)
            
            if text_cyp is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
            
            finale = {
                "cif" : "on",
                "text" : text_cyp,
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

