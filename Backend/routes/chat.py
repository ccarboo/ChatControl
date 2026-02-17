from fastapi import APIRouter, Cookie, WebSocket, WebSocketDisconnect
import sqlite3
from fastapi import HTTPException
from database.sqlite import get_connection
from config import pepper
import hashlib
from utils import cifra_vault, is_logged_in, is_valid_age_public_key, store_public_key_in_vault, is_group_chat_id, decifra_file_con_age, build_candidate_privates, set_media
from realtime import connect_socket, disconnect_socket, register_telethon_handlers, index_messages
from telethon.tl.types import MessageService, MessageActionChatCreate, MessageActionChatDeleteUser, MessageActionChatAddUser, MessageActionPinMessage
from datetime import datetime, timedelta
import json
import base64
import subprocess
import tempfile
from databaseInteractions import get_gruppo_vault, get_chat_vault
from fastapi.responses import StreamingResponse
import io
import os
import mimetypes

router = APIRouter()

#questa funzione inizializza la WebSocket per l'aggiornamento in tempo reali dei messaggi
@router.websocket("/ws/chats/{chat_id}")
async def chat_events(websocket: WebSocket, chat_id: int):
    login_session = websocket.cookies.get("login_session")
    try:
        temp_id, data = is_logged_in(login_session, False)
    except HTTPException:
        await websocket.close(code=1008)
        return

    client = data["client"]
    if not client.is_connected():
        await client.connect()

    register_telethon_handlers(client, temp_id, login_session)
    await connect_socket(temp_id, chat_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        data['ids_'] = set()
        data['active_chat_id'] = None
        await disconnect_socket(temp_id, chat_id, websocket)

@router.get("/chats")
async def get_chats(login_session: str = Cookie(None), offset_date: str = None):
    
    _, data = is_logged_in(login_session, False)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    dt = datetime.fromisoformat(offset_date) if offset_date else None

    chats = []

    async for dialog in client.iter_dialogs(limit=20, offset_date=dt):
        chat_info = {
            'id': dialog.id,
            'name': dialog.name,
            'unread_count': dialog.unread_count,
            'is_user': dialog.is_user,
            'is_group': dialog.is_group,
            'is_channel': dialog.is_channel,
        }
        
        if dialog.message:
            chat_info['last_message'] = {
                'text': dialog.message.text or '',
                'date': dialog.date if dialog.message else None,
                'sender_id': dialog.message.sender_id
            }
        
        chats.append(chat_info)
        
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    #la parte di codice sottostante serve per capire se la chat contiene gia' delle chiavi pubbliche 
    # inizializzate dal nostro dispositivo, oppure no
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                """SELECT contatto_id FROM contatti WHERE proprietario = ?
                
                    UNION
                    
                    SELECT gruppo_id FROM contatti_gruppo WHERE proprietario = ?""",
                (username,username)
            )
            risultati = cursor.fetchall()
            
            encrypted_ids = {row[0] for row in risultati}

            chats_data = data.get('data', {}).get('chats', {})

            for chat in chats:
                chat_id_hash = hashlib.sha256(pepper.encode() + str(chat['id']).encode()).hexdigest()
                has_remote_key = chat_id_hash in encrypted_ids
                chat_data = chats_data.get(chat_id_hash, {})
                has_own_key = bool(chat_data.get('chiave', {}).get('pubblica'))
                chat['cyphered'] = has_remote_key or has_own_key
                
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    


    return {"chats": chats}

@router.get("/chats/{chat_id}/limit/{limit}/start/{start}")
async def get_chat_messages(chat_id: int, limit: int, start: int, login_session: str = Cookie(None)):
    temp_id, data = is_logged_in(login_session, False)
    if data.get('active_chat_id') != chat_id:
        data['ids_'] = set()
        data['active_chat_id'] = chat_id
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    if "ids_" not in data:
        data['ids_'] = set()

    client = data['client']
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    messages = []
    add_offset = start if start and start > 0 else 0
    iter_kwargs = {"limit": limit}
    if add_offset:
        iter_kwargs["add_offset"] = add_offset
    async for msg in client.iter_messages(entity, **iter_kwargs):
        sender = await msg.get_sender()
        system_message = None
        if isinstance(msg, MessageService):
            action = msg.action
            if isinstance(action, MessageActionChatCreate):
                system_message = f"Gruppo creato: {action.title}"
            elif isinstance(action, MessageActionChatDeleteUser):
                left_user = getattr(action, 'user_id', None)
                left_user_name = None
                if left_user:
                    try:
                        left_user_entity = await client.get_entity(left_user)
                        left_user_name = getattr(left_user_entity, 'username', None) or getattr(left_user_entity, 'first_name', None) or str(left_user)
                    except Exception:
                        left_user_name = str(left_user)
                if left_user_name:
                    system_message = f"{left_user_name} ha lasciato il gruppo"
                else:
                    system_message = "Un utente ha lasciato il gruppo"
            elif isinstance(action, MessageActionChatAddUser):
                added_users = getattr(action, 'users', None)
                if added_users and isinstance(added_users, list):
                    names = []
                    for user_id in added_users:
                        try:
                            user_entity = await client.get_entity(user_id)
                            name = getattr(user_entity, 'username', None) or getattr(user_entity, 'first_name', None) or str(user_id)
                        except Exception:
                            name = str(user_id)
                        names.append(name)
                    users_str = ", ".join(names)
                    system_message = f"{users_str} è entrato nel gruppo"
                else:
                    system_message = "Un utente è entrato nel gruppo"
            elif isinstance(action, MessageActionPinMessage):
                system_message = f"Un messaggio è stato pinnato nella chat(id: {msg.id})"

            else:
                system_message = "Notifica di sistema"

        message_data = {
            'id': msg.id,
            'chat_id': chat_id,
            'text': msg.message or '',
            'date': msg.date if msg.date else None,
            'sender_id': msg.sender_id,
            'sender_username': getattr(sender, 'username', None) if sender else None,
            'out': msg.out,
            'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
            'system_type': system_message,
        }
        
        # Estrai dati del media se presente
        if msg.media:
            set_media(msg, message_data)
        
        messages.append(message_data)

    await index_messages(temp_id, chat_id, [m.get("id") for m in messages if m.get("id") is not None])

    # Calcola la "window" in funzione del tempo di download
    # dei file cifrati presenti nella pagina, partendo dal
    # messaggio più nuovo e andando indietro fino al punto in
    # cui un messaggio "apre" maggiormente la finestra.
    # Assumiamo una banda di 32 KiB/s. In assenza di file cifrati
    # la finestra temporale minima è di 10 secondi.

    # window sarà una coppia di date (inizio, fine)
    window_start = None
    window_end = None
    # Trova il timestamp del messaggio più recente (fine finestra)
    for m in messages:
        dt = m.get('date')
        if dt and (window_end is None or dt < window_end):
            window_end = dt

    for message in messages:
        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                message['json'] = parsed
                message['is_json'] = True
            else:
                message['is_json'] = False
        except Exception:
            message['is_json'] = False
        
        if message['is_json'] and window_end is not None:
            cif_flag = message['json'].get('CIF') or message['json'].get('cif')
            if cif_flag in ("file", "message") and message.get('file') and message.get('size') is not None:
                try:
                    size_bytes = float(message.get('size') or 0)
                except (TypeError, ValueError):
                    size_bytes = 0

                if size_bytes > 0 and message.get('date'):
                    # Tempo stimato di download del file su 32 KiB/s
                    download_time = size_bytes / (32 * 1024)
                    # "Finestra" che questo messaggio richiede:
                    # si parte dal suo timestamp e si torna indietro
                    candidate_start = message['date'] - timedelta(seconds=download_time)
                    if window_start is None or candidate_start < window_start:
                        window_start = candidate_start
            if cif_flag in ("on") and (message['date']<window_start if window_start is not None else True or window_start == None ):
                window_start = message['date']
                
    # Se non abbiamo trovato messaggi cifrati o date valide,
    # impostiamo una finestra di default di 10 secondi che
    # termina al messaggio più recente (se esiste).
    if window_end is not None:
        if window_start is None:
            window_start = window_end - timedelta(seconds=10)
        # Se la finestra è più corta di 10 secondi, estendila
        # all'indietro in modo da avere sempre almeno 10 secondi.
        min_delta = timedelta(seconds=10)
        current_delta = window_end - window_start
        if current_delta < min_delta:
            window_start = window_end - min_delta

    # Se abbiamo una finestra temporale valida, carichiamo tramite Telethon
    # tutti i messaggi compresi tra window_start e window_end.
    messages_in_window = []
    if window_start is not None and window_end is not None and window_start < window_end:
        # Partiamo da window_end e andiamo indietro nel tempo
        # finché non scendiamo sotto window_start.
        async for msg in client.iter_messages(entity, offset_date=window_end):
            # Se il messaggio non ha data, salta
            if not msg.date:
                continue
            # Se (per qualche motivo) è oltre il limite superiore, salta
            if msg.date >= window_end:
                continue
            # Una volta superato il limite inferiore, possiamo interrompere
            if msg.date < window_start:
                break

            sender = await msg.get_sender()
            message_data = {
                'id': msg.id,
                'chat_id': chat_id,
                'text': msg.message or '',
                'date': msg.date if msg.date else None,
                'sender_id': msg.sender_id,
                'sender_username': getattr(sender, 'username', None) if sender else None,
                'out': msg.out,
                'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
            }

            if msg.media:
                set_media(msg, message_data)

            messages_in_window.append(message_data)

    chats_data = data['data'].get('chats', {})
    chat_keys = chats_data.get(chat_id_cif, {})
    for message in messages_in_window:
        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
        except Exception:
            continue

        if not isinstance(parsed, dict):
            continue

        cif_flag = parsed.get('CIF') or parsed.get('cif')
        if cif_flag not in ("on", "file", "message"):
            continue

        id_message = parsed.get('id')
        if not id_message:
            continue

        candidate_privates = build_candidate_privates(chat_keys, message.get('date'))
        if not candidate_privates:
            continue

        id_message_decifrato_caption = None
        for privata in candidate_privates:
            try:
                try:
                    text_bytes = base64.b64decode(id_message)
                except Exception:
                    text_bytes = str(id_message).encode()

                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                    keyfile.write(privata)
                    keyfile_path = keyfile.name
                try:
                    result = subprocess.run(
                        ['age', '-d', '-i', keyfile_path],
                        input=text_bytes,
                        capture_output=True,
                        check=True
                    )
                    id_message_decifrato_caption = result.stdout.decode()
                    break
                finally:
                    import os
                    os.unlink(keyfile_path)
            except Exception:
                continue

        if id_message_decifrato_caption:
            data['ids_'].add(id_message_decifrato_caption)


    for message in messages:
        if message['system_type']:
            continue

        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                message['json'] = parsed
                message['is_json'] = True
            else:
                message['is_json'] = False
        except Exception:
            message['is_json'] = False
        
        if message['is_json'] == True:
            cif_flag = message['json'].get('CIF') or message['json'].get('cif')
            if cif_flag == "in":            
                if my_id and message.get('sender_id') == my_id:
                    message['is_json'] = False
                    message['text'] = None
                    message['chiave'] = "Questo messaggio e' uno scambio di chiave"
                    message['is_system'] = True
                    continue
                pubblic = message['json'].get('public')
                if pubblic is None or not is_valid_age_public_key(pubblic):
                    
                    continue
                store_public_key_in_vault(
                    data,
                    chat_id,
                    message.get('sender_id'),
                    pubblic,
                    msg_date=message.get('date'),
                    is_group=is_group_chat_id(chat_id),
                    group_title=getattr(entity, 'title', 'Gruppo')
                )
                message['text'] = None
                message['chiave'] = "Questo messaggio e' uno scambio di chiave"
                message['is_system'] = True
                
            if cif_flag == "on":
                text = message['json'].get('text')
                timestamp = message.get('date')
                id_message = message['json'].get('id')


                timestamp_unix = timestamp.timestamp() if timestamp else None
                chats_data = data['data'].get('chats', {})
                chat_keys = chats_data.get(chat_id_cif, {})

                candidate_privates = []
                
                chiave_corrente = chat_keys.get('chiave', {})
                chiavi_storiche = chat_keys.get('chiavi', [])
                chiavi_storiche_sorted = sorted(
                    [c for c in chiavi_storiche if c.get('privata')],
                    key=lambda c: c.get('inizio', 0),
                    reverse=True
                )

                if timestamp_unix:
                    inizio_corrente = chiave_corrente.get('inizio', 0)
                    if timestamp_unix >= inizio_corrente:
                        chiave_stimata = chiave_corrente
                    else:
                        chiave_stimata = None
                        for chiave_storica in chiavi_storiche_sorted:
                            inizio = chiave_storica.get('inizio', 0)
                            fine = chiave_storica.get('fine')
                            if fine is None and timestamp_unix >= inizio:
                                chiave_stimata = chiave_storica
                                break
                            elif fine is not None and inizio <= timestamp_unix <= fine:
                                chiave_stimata = chiave_storica
                                break
                    
                    if chiave_stimata and chiave_stimata.get('privata'):
                        candidate_privates.append(chiave_stimata.get('privata'))
                    
                    if chiavi_storiche_sorted:
                        chiave_precedente = chiavi_storiche_sorted[0]
                        if chiave_precedente.get('privata') and chiave_precedente.get('privata') != (chiave_stimata.get('privata') if chiave_stimata else None):
                            candidate_privates.append(chiave_precedente.get('privata'))
                else:
                    if chiave_corrente.get('privata'):
                        candidate_privates.append(chiave_corrente.get('privata'))
                    if chiavi_storiche_sorted and chiavi_storiche_sorted[0].get('privata'):
                        candidate_privates.append(chiavi_storiche_sorted[0].get('privata'))

                text_decifrato = None
                

                for privata in candidate_privates:
                    try:
                        
                        try:
                            text_bytes = base64.b64decode(text)
                        except:
                            text_bytes = text.encode()
                        
                        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                            keyfile.write(privata)
                            keyfile_path = keyfile.name
                        try:
                            result = subprocess.run(
                                ['age', '-d', '-i', keyfile_path],
                                input=text_bytes,
                                capture_output=True,
                                check=True
                            )
                            text_decifrato = result.stdout.decode()
                            break
                        finally:
                            import os
                            os.unlink(keyfile_path)
                    except Exception as e:
                        
                        continue
                id_message_decifrato_caption = None
                for privata in candidate_privates:
                    try:
                        
                        try:
                            text_bytes = base64.b64decode(id_message)
                        except:
                            text_bytes = text.encode()
                        
                        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                            keyfile.write(privata)
                            keyfile_path = keyfile.name
                        try:
                            result = subprocess.run(
                                ['age', '-d', '-i', keyfile_path],
                                input=text_bytes,
                                capture_output=True,
                                check=True
                            )
                            id_message_decifrato_caption = result.stdout.decode()
                            break
                        finally:
                            import os
                            os.unlink(keyfile_path)
                    except Exception as e:
                        
                        continue
                if text_decifrato:
                    try:
                        dizionario = json.loads(text_decifrato)
                        
                        if dizionario['cif'] == "on":
                            tempo_decifrato = dizionario.get('timestamp')
                            id_message_decifrato = dizionario.get('id')
                            timestamp = message.get('date')
                            diff_seconds = None
                            if timestamp and tempo_decifrato is not None:
                                try:
                                    diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                                except (TypeError, ValueError):
                                    diff_seconds = None

                            if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato_caption in data['ids_']):
                                message['error'] = "questo messaggio e' frutto di un replay attack"
                                if 'json' in message:
                                    del message['json']
                                message['is_json'] = False
                                continue
                           
                            elif  id_message_decifrato_caption != id_message_decifrato :
                                message['error'] = "questo messaggio e' stato modificato"
                                if 'json' in message:
                                    del message['json']
                                message['is_json'] = False
                                continue
                            message['text'] = dizionario['text']
                            message['secure'] = True
                            data['ids_'].add(id_message_decifrato_caption)

                            
                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                        else:
                            message['error'] = "questo messaggio e' stato modificato"
                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                    except Exception as e:
                        import traceback
                        traceback.print_exc()

            if cif_flag == "file":

                message_id = message.get('id')
                if message_id:
                    full_message = await client.get_messages(entity, ids=message_id)
                    if full_message and full_message.media:
                        import io
                        file_bytes = io.BytesIO()
                        max_bytes = 64 * 1024
                        downloaded = 0
                        async for chunk in client.iter_download(full_message, offset=0, limit=max_bytes):
                            if not chunk:
                                break
                            file_bytes.write(chunk)
                            downloaded += len(chunk)
                            if downloaded >= max_bytes:
                                break
                        file_bytes.seek(0)
                        file_head_bytes = file_bytes.getvalue()
                        message['file_head'] = base64.b64encode(file_head_bytes).decode()
                        message['file_head_size'] = len(file_head_bytes)

                        header_metadata_size = None
                        header_encrypted_metadata = None
                        if len(file_head_bytes) >= 8:
                            header_metadata_size = int.from_bytes(file_head_bytes[:4], byteorder='big')
                            header_encrypted_size = int.from_bytes(file_head_bytes[4:8], byteorder='big')
                            if 0 < header_encrypted_size <= len(file_head_bytes) - 8:
                                header_encrypted_metadata = file_head_bytes[8:8 + header_encrypted_size]
    

                timestamp = message.get('date')

                timestamp_unix = timestamp.timestamp() if timestamp else None
                chats_data = data['data'].get('chats', {})
                chat_keys = chats_data.get(chat_id_cif, {})

                candidate_privates = []
                
                chiave_corrente = chat_keys.get('chiave', {})
                chiavi_storiche = chat_keys.get('chiavi', [])
                chiavi_storiche_sorted = sorted(
                    [c for c in chiavi_storiche if c.get('privata')],
                    key=lambda c: c.get('inizio', 0),
                    reverse=True
                )

                if timestamp_unix:
                    inizio_corrente = chiave_corrente.get('inizio', 0)
                    if timestamp_unix >= inizio_corrente:
                        chiave_stimata = chiave_corrente
                    else:
                        chiave_stimata = None
                        for chiave_storica in chiavi_storiche_sorted:
                            inizio = chiave_storica.get('inizio', 0)
                            fine = chiave_storica.get('fine')
                            if fine is None and timestamp_unix >= inizio:
                                chiave_stimata = chiave_storica
                                break
                            elif fine is not None and inizio <= timestamp_unix <= fine:
                                chiave_stimata = chiave_storica
                                break

                    if chiave_stimata and chiave_stimata.get('privata'):
                        candidate_privates.append(chiave_stimata.get('privata'))

                    if chiavi_storiche_sorted:
                        chiave_precedente = chiavi_storiche_sorted[0]
                        if chiave_precedente.get('privata') and chiave_precedente.get('privata') != (chiave_stimata.get('privata') if chiave_stimata else None):
                            candidate_privates.append(chiave_precedente.get('privata'))
                else:
                    if chiave_corrente.get('privata'):
                        candidate_privates.append(chiave_corrente.get('privata'))
                    if chiavi_storiche_sorted and chiavi_storiche_sorted[0].get('privata'):
                        candidate_privates.append(chiavi_storiche_sorted[0].get('privata'))

                text_decifrato = None
                if header_encrypted_metadata:
                    for privata in candidate_privates:
                        try:
                            try:
                                input_bytes = base64.b64decode(header_encrypted_metadata)
                            except Exception:
                                input_bytes = header_encrypted_metadata
                            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                                keyfile.write(privata)
                                keyfile_path = keyfile.name
                            try:
                                result = subprocess.run(
                                    ['age', '-d', '-i', keyfile_path],
                                    input=input_bytes,
                                    capture_output=True,
                                    check=True
                                )
                                text_decifrato = result.stdout.decode()
                                break
                            finally:
                                import os
                                os.unlink(keyfile_path)
                        except Exception:
                            continue

                if text_decifrato:
                    try:
                        dizionario = json.loads(text_decifrato)
                        if dizionario['cif'] == "file":
                            tempo_decifrato = dizionario.get('timestamp')
                            timestamp = message.get('date')
                            id_message_decifrato = dizionario.get('id')
                            diff_seconds = None
                            if timestamp and tempo_decifrato is not None:
                                try:
                                    diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                                except (TypeError, ValueError):
                                    diff_seconds = None
                            allowed_seconds = 30
                            file_size = dizionario.get('size')
                            if file_size is not None:
                                try:
                                    file_size = float(file_size)
                                    # Allow more time for larger files on slow networks.
                                    allowed_seconds = max(30, file_size / (32 * 1024))
                                except (TypeError, ValueError):
                                    allowed_seconds = 30

                            if (diff_seconds is not None and diff_seconds > allowed_seconds) or (id_message_decifrato in data['ids_']):
                                message['error'] = "questo messaggio e' frutto di un replay attack"
                                if 'json' in message:
                                    del message['json']
                                message['is_json'] = False
                                continue
                            
                            message['file'] = True
                            message['filename'] = dizionario['filename']
                            message['text'] = dizionario['text']
                            message['mime'] = dizionario['mime']
                            message['size'] = dizionario['size']
                            message['secure'] = True

                            data['ids_'].add(id_message_decifrato)

                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                        else:
                            message['error'] = "questo messaggio e' stato modificato"
                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                    except Exception as e:
                        import traceback
                        traceback.print_exc()
            
            if cif_flag == "message":
                try:
                    message_id = message.get('id')
                    if not message_id:
                        continue

                    full_message = await client.get_messages(entity, ids=message_id)
                    if not full_message or not full_message.media or not full_message.document:
                        continue

                    import io
                    file_bytes = io.BytesIO()
                    await client.download_media(full_message, file=file_bytes)
                    file_bytes.seek(0)
                    encrypted_payload = file_bytes.getvalue()

                    timestamp = message.get('date')
                    timestamp_unix = timestamp.timestamp() if timestamp else None
                    chats_data = data['data'].get('chats', {})
                    chat_keys = chats_data.get(chat_id_cif, {})

                    candidate_privates = []
                    chiave_corrente = chat_keys.get('chiave', {})
                    chiavi_storiche = chat_keys.get('chiavi', [])
                    chiavi_storiche_sorted = sorted(
                        [c for c in chiavi_storiche if c.get('privata')],
                        key=lambda c: c.get('inizio', 0),
                        reverse=True
                    )

                    if timestamp_unix:
                        inizio_corrente = chiave_corrente.get('inizio', 0)
                        if timestamp_unix >= inizio_corrente:
                            chiave_stimata = chiave_corrente
                        else:
                            chiave_stimata = None
                            for chiave_storica in chiavi_storiche_sorted:
                                inizio = chiave_storica.get('inizio', 0)
                                fine = chiave_storica.get('fine')
                                if fine is None and timestamp_unix >= inizio:
                                    chiave_stimata = chiave_storica
                                    break
                                elif fine is not None and inizio <= timestamp_unix <= fine:
                                    chiave_stimata = chiave_storica
                                    break

                        if chiave_stimata and chiave_stimata.get('privata'):
                            candidate_privates.append(chiave_stimata.get('privata'))

                        if chiavi_storiche_sorted:
                            chiave_precedente = chiavi_storiche_sorted[0]
                            if chiave_precedente.get('privata') and chiave_precedente.get('privata') != (chiave_stimata.get('privata') if chiave_stimata else None):
                                candidate_privates.append(chiave_precedente.get('privata'))
                    else:
                        if chiave_corrente.get('privata'):
                            candidate_privates.append(chiave_corrente.get('privata'))
                        if chiavi_storiche_sorted and chiavi_storiche_sorted[0].get('privata'):
                            candidate_privates.append(chiavi_storiche_sorted[0].get('privata'))

                    decrypted_payload = None
                    for privata in candidate_privates:
                        try:
                            try:
                                input_bytes = base64.b64decode(encrypted_payload)
                            except Exception:
                                input_bytes = encrypted_payload
                            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                                keyfile.write(privata)
                                keyfile_path = keyfile.name
                            try:
                                result = subprocess.run(
                                    ['age', '-d', '-i', keyfile_path],
                                    input=input_bytes,
                                    capture_output=True,
                                    check=True
                                )
                                decrypted_payload = result.stdout
                                break
                            finally:
                                import os
                                os.unlink(keyfile_path)
                        except Exception:
                            continue
                    

                    if decrypted_payload and len(decrypted_payload) >= 4:
                        metadata_size = int.from_bytes(decrypted_payload[:4], byteorder='big')
                        if 0 < metadata_size <= len(decrypted_payload) - 4:
                            inner_metadata_bytes = decrypted_payload[4:4 + metadata_size]
                            message_bytes = decrypted_payload[4 + metadata_size:]
                            try:
                                inner_metadata_str = inner_metadata_bytes.decode('utf-8')
                                inner_metadata = json.loads(inner_metadata_str)
                            except Exception:
                                inner_metadata = None

                            if inner_metadata and inner_metadata.get('cif') == 'message':

                                tempo_decifrato = inner_metadata.get('timestamp')
                                id_message_decifrato = inner_metadata.get('id')
                                timestamp = message.get('date')
                                diff_seconds = None
                                if timestamp and tempo_decifrato is not None:
                                    try:
                                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                                    except (TypeError, ValueError):
                                        diff_seconds = None

                                if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato in data['ids_']):
                                    message['error'] = "questo messaggio e' frutto di un replay attack"
                                    if 'json' in message:
                                        del message['json']
                                    message['is_json'] = False
                                    continue

                                message['text'] = message_bytes.decode('utf-8', errors='replace')
                                data['ids_'].add(id_message_decifrato)

                                if 'json' in message:
                                    del message['json']
                                message['is_json'] = False
                                message['secure'] = True
                                message['file'] = False
                                message.pop('media_type', None)
                                message.pop('filename', None)
                                message.pop('mime', None)
                                message.pop('size', None)
                except Exception:
                    import traceback
                    traceback.print_exc()
    messages.reverse() 
    return {"chat_id": chat_id, "messages": messages}

@router.get("/chats/{chat_id}/inits")
async def get_init_messages(chat_id: int, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)

    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    init_messages = []
    
    async for msg in client.iter_messages(entity, search='"cif": "in"', limit=None):
        if my_id and msg.sender_id == my_id:
            continue

        text = msg.message or ''
        try:
            parsed = json.loads(text)
            cif_flag = parsed.get('CIF') or parsed.get('cif')
            pubblic = parsed.get('public')

            

            if cif_flag == "in" and pubblic is not None and is_valid_age_public_key(pubblic):
                init_messages.append({
                    'id': msg.id,
                    'date': msg.date,
                    'public_key': pubblic,
                    'sender_id': msg.sender_id
                })
        except Exception:
            continue

    is_group = is_group_chat_id(chat_id)
    vault_deciphered = None
    insert_new_vault = False
    
    try:
        if is_group:
            insert_new_vault, vault_deciphered = get_gruppo_vault(username, chat_id, entity, data)
        else:
            insert_new_vault, vault_deciphered = await get_chat_vault(username, chat_id, client, data)

    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    vault_dirty = False
    if is_group:
        ids = set()
        async for user in client.iter_participants(chat_id):
            ids.add(str(user.id))

        if 'partecipanti' in vault_deciphered:
            stale_ids = [pid for pid in vault_deciphered['partecipanti'].keys() if pid not in ids]
            if stale_ids:
                print(f"get_init_messages: removing participants not in group: {stale_ids}")
            for pid in stale_ids:
                del vault_deciphered['partecipanti'][pid]
            if stale_ids:
                vault_dirty = True

    all_keys = []
    if is_group and 'partecipanti' in vault_deciphered:
        for participant_data in vault_deciphered['partecipanti'].values():
            # Aggiungi chiave corrente
            current_key = participant_data.get('chiave', {})
            if current_key and current_key.get('chiave'):
                all_keys.append(current_key)
            # Aggiungi chiavi storiche
            if 'chiavi' in participant_data:
                all_keys.extend(participant_data['chiavi'])
    elif not is_group and 'chiavi' in vault_deciphered:
        all_keys.extend(vault_deciphered['chiavi'])

    existing_keys = {k['chiave'] for k in all_keys}
    keys_added = 0

    for init_msg in init_messages:
        pubblic = init_msg['public_key']
        if pubblic not in existing_keys:
            new_key_timestamp = init_msg['date'].timestamp()
            new_key = {
                'chiave': pubblic,
                'inizio': new_key_timestamp,
                'fine': None
            }
            
            if is_group:
                sender_id = str(init_msg['sender_id'])
                if sender_id not in vault_deciphered['partecipanti']:
                    vault_deciphered['partecipanti'][sender_id] = {'chiave': {}, 'chiavi': []}
                
                # Sposta la chiave corrente nello storico
                current_key = vault_deciphered['partecipanti'][sender_id].get('chiave', {})
                if current_key and current_key.get('chiave'):
                    current_key['fine'] = new_key_timestamp - 1
                    if 'chiavi' not in vault_deciphered['partecipanti'][sender_id]:
                        vault_deciphered['partecipanti'][sender_id]['chiavi'] = []
                    vault_deciphered['partecipanti'][sender_id]['chiavi'].append(current_key)
                
                # Imposta la nuova chiave come corrente
                vault_deciphered['partecipanti'][sender_id]['chiave'] = new_key
            else:
                if vault_deciphered['chiavi']:
                    vault_deciphered['chiavi'][-1]['fine'] = new_key_timestamp - 1
                
                vault_deciphered['chiavi'].append(new_key)
            
            existing_keys.add(pubblic)
            keys_added += 1
            vault_dirty = True

    if vault_dirty:
        vault_cifrato = cifra_vault(vault_deciphered, data['data']['masterkey'])
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                if is_group:
                    if insert_new_vault:
                        cursor.execute(
                            """INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""",
                            (username, chat_id_cif, vault_cifrato)
                        )
                    else:
                        cursor.execute(
                            """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                            (vault_cifrato, username, chat_id_cif)
                        )
                else:
                    if insert_new_vault:
                        cursor.execute(
                            """INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""",
                            (username, chat_id_cif, vault_cifrato)
                        )
                    else:
                        cursor.execute(
                            """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                            (vault_cifrato, username, chat_id_cif)
                        )
                conn.commit()
        except sqlite3.Error as error:
            raise HTTPException(status_code=500, detail=str(error))

    return {
        "chat_id": chat_id,
        "init_messages_found": len(init_messages),
        "keys_added": keys_added,
        "total_keys": len(existing_keys)
    }

@router.get("/media/download/{chat_id}/{message_id}")
async def download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    
    
    _, data = is_logged_in(login_session, False)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)
        
        if not message:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio non trovato (chat_id={chat_id}, message_id={message_id})"
            )
        if not message.media:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio senza media (chat_id={chat_id}, message_id={message_id})"
            )
        
        file_bytes = io.BytesIO()
        await client.download_media(message, file=file_bytes)
        file_bytes.seek(0)
        
        mime_type = 'application/octet-stream'
        
        if message.sticker:
            mime_type = message.sticker.mime_type or 'image/webp'
        elif message.gif:
            mime_type = message.gif.mime_type or 'video/mp4'
        elif message.photo:
            mime_type = 'image/jpeg'
        elif message.video:
            mime_type = message.video.mime_type or 'video/mp4'
        elif message.document:
            mime_type = message.document.mime_type or 'application/octet-stream'

        
        return StreamingResponse(
            iter([file_bytes.getvalue()]),
            media_type=mime_type,
            headers={
                'Cache-Control': 'public, max-age=31536000',
                'ETag': f'"{chat_id}-{message_id}"'
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR download_media: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
    
@router.get("/media/cifrato/download/{chat_id}/{message_id}")
async def download_encrypt_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    _, data = is_logged_in(login_session, True)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    try:
        entity = await client.get_entity(chat_id)
        message = await client.get_messages(entity, ids=message_id)

        if not message:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio non trovato (chat_id={chat_id}, message_id={message_id})"
            )
        if not message.media or not message.document:
            raise HTTPException(
                status_code=404,
                detail=f"Messaggio senza documento (chat_id={chat_id}, message_id={message_id})"
            )

        filename = None
        for attr in (message.document.attributes or []):
            if hasattr(attr, 'file_name'):
                filename = attr.file_name
                break

        if not filename or not filename.endswith('.dat'):
            raise HTTPException(status_code=400, detail="Documento non cifrato")

        caption_text = message.message or ""
        try:
            caption_json = json.loads(caption_text)
        except Exception:
            raise HTTPException(status_code=400, detail="Caption non valida")

        cif_flag = caption_json.get('CIF') or caption_json.get('cif')
        if cif_flag != "file":
            raise HTTPException(status_code=400, detail="Caption non cifrata")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        chats_data = data['data'].get('chats', {})
        chat_keys = chats_data.get(chat_id_cif, {})
        candidate_privates = build_candidate_privates(chat_keys, message.date)
        if not candidate_privates:
            raise HTTPException(status_code=400, detail="Nessuna chiave disponibile")

        file_bytes = io.BytesIO()
        await client.download_media(message, file=file_bytes)
        file_bytes.seek(0)

        encrypted_payload_bytes = file_bytes.getvalue()
        if len(encrypted_payload_bytes) < 8:
            raise HTTPException(status_code=400, detail="Payload non valido")

        header_metadata_size = int.from_bytes(encrypted_payload_bytes[:4], byteorder='big')
        header_encrypted_size = int.from_bytes(encrypted_payload_bytes[4:8], byteorder='big')
        if header_encrypted_size <= 0 or header_encrypted_size > len(encrypted_payload_bytes) - 8:
            raise HTTPException(status_code=400, detail="Header metadata non valido")

        header_encrypted_metadata = encrypted_payload_bytes[8:8 + header_encrypted_size]
        decrypted_metadata_bytes = decifra_file_con_age(header_encrypted_metadata, candidate_privates)
        if not decrypted_metadata_bytes:
            raise HTTPException(status_code=400, detail="Impossibile decifrare i metadata")

        if header_metadata_size != len(decrypted_metadata_bytes):
            raise HTTPException(status_code=400, detail="Dimensione metadata non valida")

        try:
            outer_metadata_str = decrypted_metadata_bytes.decode('utf-8')
            outer_metadata = json.loads(outer_metadata_str)
        except Exception:
            raise HTTPException(status_code=400, detail="Metadata esterni non validi")

        if outer_metadata.get('cif') != 'file':
            raise HTTPException(status_code=400, detail="Metadata esterni non cifrati")

        encrypted_body = encrypted_payload_bytes[8 + header_encrypted_size:]
        decrypted_payload = decifra_file_con_age(encrypted_body, candidate_privates)
        if not decrypted_payload:
            raise HTTPException(status_code=400, detail="Impossibile decifrare il file")

        if len(decrypted_payload) < 4:
            raise HTTPException(status_code=400, detail="Payload non valido")

        metadata_size = int.from_bytes(decrypted_payload[:4], byteorder='big')
        if metadata_size <= 0 or metadata_size > len(decrypted_payload) - 4:
            raise HTTPException(status_code=400, detail="Dimensione metadata non valida")

        inner_metadata_bytes = decrypted_payload[4:4 + metadata_size]
        file_content = decrypted_payload[4 + metadata_size:]

        try:
            inner_metadata_str = inner_metadata_bytes.decode('utf-8')
            inner_metadata = json.loads(inner_metadata_str)
        except Exception:
            raise HTTPException(status_code=400, detail="Metadata interni non validi")

        if inner_metadata != outer_metadata:
            raise HTTPException(status_code=409, detail="Metadata non corrispondenti")

        out_filename = os.path.basename(inner_metadata.get('filename') or 'file.bin')
        mime_type = inner_metadata.get('mime') or mimetypes.guess_type(out_filename)[0] or 'application/octet-stream'

        return StreamingResponse(
            iter([file_content]),
            media_type=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{out_filename}"',
                'Cache-Control': 'no-store'
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR download_encrypt_media: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Errore download: {str(e)}")
