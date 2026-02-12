from fastapi import APIRouter, Cookie
import asyncio
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
from config import pepper
import time
import hashlib
from utils import  is_logged_in, decifra_vault, cifra_con_age, genera_chiavi, cifra_vault, get_chat_chyper_keys, get_group_chyper_keys, split_message
import json
from fastapi import UploadFile, File, Form
import subprocess
import tempfile
import shutil
from telethon.tl.types import DocumentAttributeFilename
import os
import secrets
import mimetypes
import io

router = APIRouter()

CAPTION_LIMIT = 1024
MESSAGE_LIMIT = 4096
MIN_UPLOAD_BPS = 32 * 1024

class message (BaseModel):
    text: str
    chat_id: int
    cryph: bool
    group: bool

class delete_m(BaseModel):
    chat_id: int
    message_id: int

class iniz (BaseModel):
    chat_id: int

async def wait_for_public_key_message(client, chat_id: int, public_key: str, timeout: float = 2.0, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            messages = await client.get_messages(chat_id, limit=10)
        except Exception:
            messages = []
        for msg in messages or []:
            text = getattr(msg, "message", None) or getattr(msg, "text", None) or ""
            if '"cif"' in text and '"in"' in text and public_key in text:
                return True
        await asyncio.sleep(interval)
    return False
    
@router.post("/messages/delete")
async def delete(message: delete_m, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()
    try:
        await client.delete_messages(message.chat_id, [message.message_id], revoke=True)
        fetched = await client.get_messages(message.chat_id, ids=message.message_id)
        if fetched is None or getattr(fetched, "deleted", False):
            return {"status": "ok"}
        return {"status": "not_deleted"}
    except Exception:
        raise HTTPException(status_code=502, detail="Non hai il permesso di cancellare questo messaggio")

@router.post("/messages/send/file")
async def s_file(chat_id: int = Form(...), text: str = Form(""), cryph: bool = Form(False),group: bool = Form(False), file: UploadFile = File(...),login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']


    if not client.is_connected():
        await client.connect()

    if not cryph:
        try:
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
        id_messagge = secrets.token_hex(16)

        token = secrets.token_hex(8)
        nome_file = token + ".dat"
        
        if group:
            recipient_keys = get_group_chyper_keys(data, chat_id)
        else:
            recipient_keys = get_chat_chyper_keys(data, chat_id)
        
        try:
            file_content = await file.read()
            
            guessed_mime, _ = mimetypes.guess_type(file.filename)
            mime_type = guessed_mime or file.content_type or "application/octet-stream"

            metadata = {
                "filename": file.filename,
                "cif": "file",
                "text": text,
                "mime": mime_type,
                "size": len(file_content),
                "timestamp": time.time(),
                "id":id_messagge
            }

            json_metadata = json.dumps(metadata, sort_keys=True)
            metadata_bytes = json_metadata.encode('utf-8')
            metadata_size = len(metadata_bytes)

            encrypted_metadata = cifra_con_age(metadata_bytes, recipient_keys)
            if encrypted_metadata is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")

            body_plain = metadata_size.to_bytes(4, byteorder='big') + metadata_bytes + file_content
            encrypted_body = cifra_con_age(body_plain, recipient_keys)
            if encrypted_body is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")

            if isinstance(encrypted_metadata, str):
                encrypted_metadata = encrypted_metadata.encode('utf-8')
            if isinstance(encrypted_body, str):
                encrypted_body = encrypted_body.encode('utf-8')

            payload = (
                metadata_size.to_bytes(4, byteorder='big')
                + len(encrypted_metadata).to_bytes(4, byteorder='big')
                + encrypted_metadata
                + encrypted_body
            )

            encrypted_payload = payload
            
            testo = {
                "cif":"file",
            }

            # Salva il file cifrato con nome = token
            with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tmp:
                if isinstance(encrypted_payload, str):
                    tmp.write(encrypted_payload.encode('utf-8'))
                else:
                    tmp.write(encrypted_payload)
                tmp_path = tmp.name
            
            # Invia il file tramite Telethon

            testo_str = json.dumps(testo)

            if len(testo_str) <= CAPTION_LIMIT:
                start_time = time.monotonic()

                async def progress_cb(current, total):
                    elapsed = time.monotonic() - start_time
                    if elapsed >= 1.0 and (current / max(elapsed, 0.001)) < MIN_UPLOAD_BPS:
                        raise Exception("Connessione troppo lenta")

                try:
                    await client.send_file(
                        chat_id,
                        tmp_path,
                        caption=testo_str,
                        force_document=True,
                        attributes=[DocumentAttributeFilename(nome_file)],
                        progress_callback=progress_cb
                    )
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

                return {"status": "ok"}
            else:
                raise HTTPException(
                    status_code=413,
                    detail=f"caption troppo lunga ({len(testo_str)}>{CAPTION_LIMIT})"
                )
        except HTTPException:
            raise
        except Exception as e:
            print(e)
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
@router.post("/messages/send")
async def s_message( credentials: message, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    if not credentials.cryph:
        try:
            if len(credentials.text)>4096:
                splitted_text = split_message(credentials.text)
                for text in splitted_text:
                    await client.send_message(credentials.chat_id, text)
            else:
                await client.send_message(credentials.chat_id, credentials.text)

        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
        
    else:
        id_messagge = secrets.token_hex(16)
        chat_id_hash = hashlib.sha256(pepper.encode() + str(credentials.chat_id).encode()).hexdigest()
        chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
        chiave_corrente_chat = chat_data.get('chiave', {})

        if not chiave_corrente_chat or not chiave_corrente_chat.get('pubblica'):
            key_response = await send_public_key(iniz(chat_id=credentials.chat_id), login_session)
            public_key = key_response.get("public") if isinstance(key_response, dict) else None
            if public_key:
                key_visible = await wait_for_public_key_message(client, credentials.chat_id, public_key)
                if not key_visible:
                    raise HTTPException(status_code=503, detail="Chiave non visibile in chat, riprova")
            chat_data = data.get('data', {}).get('chats', {}).get(chat_id_hash, {})
            chiave_corrente_chat = chat_data.get('chiave', {})

        inizio_corrente = chiave_corrente_chat.get('inizio') if chiave_corrente_chat else None
        if inizio_corrente:
            elapsed = time.time() - inizio_corrente
            if elapsed < 2.5:
                await asyncio.sleep(2.5 - elapsed)

        if credentials.group:
            
            recipient_keys = get_group_chyper_keys(data, credentials.chat_id)

            
        else:
            
            recipient_keys = get_chat_chyper_keys(data, credentials.chat_id)

        da_cifrare ={
            "cif" : "on",
            "text" : credentials.text,
            "timestamp": time.time(),
            "id": id_messagge,
        }

        json_da_cifrare = json.dumps(da_cifrare, sort_keys= True)


        text_cyp = cifra_con_age(json_da_cifrare, recipient_keys)

        encrypted_id = cifra_con_age(id_messagge, recipient_keys)
        
        if text_cyp is None:
            raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")
        
        
        if len(text_cyp) + len(encrypted_id) + 11 > MESSAGE_LIMIT:
            token = secrets.token_hex(8)
            nome_file = token + ".dat"
            message_bytes = credentials.text.encode("utf-8")
            message_metadata = {
                "cif": "message",
                "timestamp": time.time(),
                "id":id_messagge,
            }
            json_metadata = json.dumps(message_metadata, sort_keys=True)
            metadata_bytes = json_metadata.encode("utf-8")
            metadata_size = len(metadata_bytes)
            payload = metadata_size.to_bytes(4, byteorder="big") + metadata_bytes + message_bytes
            encrypted_payload = cifra_con_age(payload, recipient_keys)
            if encrypted_payload is None:
                raise HTTPException(status_code=500, detail="Errore durante la cifratura con age")

            if isinstance(encrypted_payload, str):
                encrypted_payload = encrypted_payload.encode("utf-8")

            file_in_ram = io.BytesIO(encrypted_payload)
            file_in_ram.name = nome_file

            caption = {
                "cif":"message",
            }

            try:
                file_in_ram.seek(0)
                await client.send_file(
                    credentials.chat_id,
                    file_in_ram,
                    caption=json.dumps(caption),
                    force_document=True,
                    attributes=[DocumentAttributeFilename(nome_file)]
                )
                return {"status": "ok"}
            except Exception as e:
                raise HTTPException(status_code=502, detail=f"Invio fallito: {e}")
            
        finale = {
            "cif" : "on",
            "text" : text_cyp,
            "id" : encrypted_id,
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
    
    return {"status": "ok", "public": pubblica}
