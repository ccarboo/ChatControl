import asyncio
import base64
import subprocess
import tempfile
import hashlib
import sqlite3
import json
from fastapi import WebSocket
from telethon import events, utils
from telethon.tl.types import (
    PeerChannel,
    UpdateDeleteChannelMessages,
    UpdateDeleteMessages,
)
from config import pepper
from database.sqlite import get_connection
from utils import cifra_vault, decifra_vault, get_user_data_by_temp_id, is_valid_age_public_key, store_public_key_in_vault, set_media, is_logged_in

# temp_id -> chat_id -> set[WebSocket]
_active_connections = {}
_connections_lock = asyncio.Lock()

# temp_id -> chat_id -> {"ids": set[int], "order": list[int]}
_message_index = {}
_message_index_lock = asyncio.Lock()
_MAX_INDEX_PER_CHAT = 3000


def _is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False


async def _remove_user_from_vault(temp_id: str, chat_id: int, user_id: int | None):
    user_data = get_user_data_by_temp_id(temp_id)
    if not user_data:
        return

    if user_id is not None and not _is_group_chat_id(chat_id):
        if str(user_id) != str(chat_id):
            return

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    is_group = _is_group_chat_id(chat_id)

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    return
                vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
                partecipanti = vault_deciphered.get('partecipanti')
                if not partecipanti or str(user_id) not in partecipanti:
                    return
                del partecipanti[str(user_id)]
                vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                    (vault_cifrato, username, chat_id_cif)
                )
                conn.commit()
            else:
                cursor.execute(
                    """DELETE FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                conn.commit()
    except sqlite3.Error as error:
        print(f"ERROR remove_user_from_vault: {error}")

#crea una struttura con al suo interno l'id utente, connesso ad ogni chat con un set ed una lista di id dei messaggi con eventi (la lista e' ordinata)
#serve solo per alcuni raw update eliminazioni in chat singole per esempio
async def index_messages(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.setdefault(temp_id, {})
        chat_map = user_map.setdefault(chat_id, {"ids": set(), "order": []})
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            if mid is None:
                continue
            if mid in ids_set:
                continue
            ids_set.add(mid)
            order.append(mid)
        if len(order) > _MAX_INDEX_PER_CHAT:
            overflow = len(order) - _MAX_INDEX_PER_CHAT
            for _ in range(overflow):
                old = order.pop(0)
                ids_set.discard(old)


async def drop_message_ids(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return
        chat_map = user_map.get(chat_id)
        if not chat_map:
            return
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            ids_set.discard(mid)
        if order:
            chat_map["order"] = [mid for mid in order if mid in ids_set]


async def resolve_chat_id_for_deleted(temp_id: str, message_ids: list[int]) -> int | None:
    if not message_ids:
        return None
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return None
        ids = set(mid for mid in message_ids if mid is not None)
        if not ids:
            return None
        candidates = []
        for chat_id, chat_map in user_map.items():
            if ids.issubset(chat_map["ids"]):
                candidates.append(chat_id)
        if len(candidates) == 1:
            return candidates[0]
        return None


def _serialize_message(msg):
    message_data = {
        "id": msg.id,
        "chat_id": msg.chat_id,
        "text": msg.message or "",
        "date": msg.date if msg.date else None,
        "sender_id": msg.sender_id,
        "out": msg.out,
        "reply_to": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
    }
    if msg.media:
        set_media(msg, message_data)

    return message_data


async def connect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    await websocket.accept()
    async with _connections_lock:
        user_map = _active_connections.setdefault(temp_id, {})
        sockets = user_map.setdefault(chat_id, set())
        sockets.add(websocket)


async def disconnect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    async with _connections_lock:
        user_map = _active_connections.get(temp_id)
        if not user_map:
            return
        sockets = user_map.get(chat_id)
        if not sockets:
            return
        sockets.discard(websocket)
        if not sockets:
            user_map.pop(chat_id, None)
        if not user_map:
            _active_connections.pop(temp_id, None)


async def broadcast_event(temp_id: str, chat_id: int, payload: dict):
    async with _connections_lock:
        sockets = list(_active_connections.get(temp_id, {}).get(chat_id, set()))

    if not sockets:
        return

    dead = []
    for ws in sockets:
        try:
     
            if payload.get('message') and payload.get('message').get('date'):
                payload['message']['date']= payload['message']['date'].isoformat()
        
                
            await ws.send_json(payload)
        except Exception as e:
            dead.append(ws)

    for ws in dead:
        await disconnect_socket(temp_id, chat_id, ws)


def register_telethon_handlers(client, temp_id: str, login_session: str):
    if getattr(client, "_cc_handlers_added", False):
        return

    async def handle_new_message(event):
        try:
            entity = await client.get_entity(event.chat_id)
        except:
            return 
        temp_id, data = is_logged_in(login_session, False)
        me = await client.get_me()
        my_id = me.id if me else None
        message_data = _serialize_message(event.message)

        sender = await event.message.get_sender()
        message_data['sender_username'] = getattr(sender, 'username', None) if sender else None
        chat_id_cif = hashlib.sha256(pepper.encode() + str(event.chat_id).encode()).hexdigest()

        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        if event.message and not getattr(event.message, "out", False):
            
            

            text = event.message.message or ""
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    message_data['json'] = parsed
                    message_data['is_json'] = True
                else:
                    message_data['is_json'] = False
            except Exception:
                message_data['is_json'] = False
                parsed = None

            if message_data['is_json'] == True:
                cif_flag = parsed.get("CIF") or parsed.get("cif")
                if cif_flag == "in":
                    if my_id and message_data.get('sender_id') == my_id:
                        message_data['is_json'] = False
                        message_data['text'] = None
                        message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
                        message_data['is_system'] = True
                        payload = {
                            "event_type": "new",
                            "chat_id": event.chat_id,
                            "message": message_data,
                        }
                        await broadcast_event(temp_id, event.chat_id, payload)
                        return

                    pubblic = parsed.get("public")
                    if pubblic and is_valid_age_public_key(pubblic):
                        user_data = get_user_data_by_temp_id(temp_id)
                        if user_data:
                            store_public_key_in_vault(
                                user_data,
                                event.chat_id,
                                event.message.sender_id,
                                pubblic,
                                msg_date=getattr(message_data, "date", None),
                                is_group=_is_group_chat_id(event.chat_id),
                                group_title=getattr(event.chat, "title", "Gruppo")
                            )
                    message_data['text'] = None
                    message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
                    message_data['is_system'] = True
                
                if cif_flag == "on":
                    text = message_data['json'].get('text')
                    timestamp = message_data.get('date')
                    id_message = message_data['json'].get('id')


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
                                timestamp = message_data.get('date')
                                diff_seconds = None
                                if timestamp and tempo_decifrato is not None:
                                    try:
                                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                                    except (TypeError, ValueError):
                                        diff_seconds = None

                                if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato_caption in data['ids_']):
                                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                                    if 'json' in message_data:
                                        del message_data['json']
                                    message_data['is_json'] = False
                                    payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": message_data,
                                    }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return
                            
                                elif  id_message_decifrato_caption != id_message_decifrato :
                                    message_data['error'] = "questo messaggio e' stato modificato"
                                    if 'json' in message_data:
                                        del message_data['json']
                                    message_data['is_json'] = False
                                    payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": message_data,
                                    }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return
                                message_data['text'] = dizionario['text']
                                message_data['secure'] = True
                                data['ids_'].add(id_message_decifrato_caption)

                                
                                if 'json' in message_data:
                                    del message_data['json']
                                message_data['is_json'] = False
                            else:
                                message_data['error'] = "questo messaggio e' stato modificato"
                                if 'json' in message_data:
                                    del message_data['json']
                                message_data['is_json'] = False
                        except Exception as e:
                            import traceback
                            traceback.print_exc()

                if cif_flag == "message":
                    try:
                        message_id = message_data.get('id')
                        if not message_id:
                            message_data['error'] = "nessun message id presente"
                            payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": message_data,
                                    }
                            await broadcast_event(temp_id, event.chat_id, payload)
                            return

                        full_message = await client.get_messages(entity, ids=message_id)
                        if not full_message or not full_message.media or not full_message.document:
                            message_data['error'] = "il messaggio dovrebbe contenere un documento, ma non e' presente"
                            payload = {
                                        "event_type": "new",
                                        "chat_id": event.chat_id,
                                        "message": message_data,
                                    }
                            await broadcast_event(temp_id, event.chat_id, payload)
                            return

                        import io
                        file_bytes = io.BytesIO()
                        await client.download_media(full_message, file=file_bytes)
                        file_bytes.seek(0)
                        encrypted_payload = file_bytes.getvalue()

                        timestamp = message_data.get('date')
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
                                    timestamp = message_data.get('date')
                                    diff_seconds = None
                                    if timestamp and tempo_decifrato is not None:
                                        try:
                                            diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                                        except (TypeError, ValueError):
                                            diff_seconds = None

                                    if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato in data['ids_']):
                                        message_data['error'] = "questo messaggio e' frutto di un replay attack"
                                        if 'json' in message_data:
                                            del message_data['json']
                                        message_data['is_json'] = False
                                        payload = {
                                                    "event_type": "new",
                                                    "chat_id": event.chat_id,
                                                    "message": message_data,
                                                }
                                        await broadcast_event(temp_id, event.chat_id, payload)
                                        return

                                    message_data['text'] = message_bytes.decode('utf-8', errors='replace')
                                    data['ids_'].add(id_message_decifrato)

                                    if 'json' in message_data:
                                        del message_data['json']
                                    message_data['is_json'] = False
                                    message_data['secure'] = True
                                    message_data['file'] = False
                                    message_data.pop('media_type', None)
                                    message_data.pop('filename', None)
                                    message_data.pop('mime', None)
                                    message_data.pop('size', None)
                    except Exception:
                        import traceback
                        traceback.print_exc()
        
                if cif_flag == "file":
                    message_id = message_data.get('id')
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
                            message_data['file_head'] = base64.b64encode(file_head_bytes).decode()
                            message_data['file_head_size'] = len(file_head_bytes)

                            header_metadata_size = None
                            header_encrypted_metadata = None
                            if len(file_head_bytes) >= 8:
                                header_metadata_size = int.from_bytes(file_head_bytes[:4], byteorder='big')
                                header_encrypted_size = int.from_bytes(file_head_bytes[4:8], byteorder='big')
                                if 0 < header_encrypted_size <= len(file_head_bytes) - 8:
                                    header_encrypted_metadata = file_head_bytes[8:8 + header_encrypted_size]
        
                    timestamp = message_data.get('date')

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
                                timestamp = message_data.get('date')
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
                                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                                    if 'json' in message_data:
                                        del message_data['json']
                                    message_data['is_json'] = False
                                    payload = {
                                                    "event_type": "new",
                                                    "chat_id": event.chat_id,
                                                    "message": message_data,
                                                }
                                    await broadcast_event(temp_id, event.chat_id, payload)
                                    return
                                
                                message_data['file'] = True
                                message_data['filename'] = dizionario['filename']
                                message_data['text'] = dizionario['text']
                                message_data['mime'] = dizionario['mime']
                                message_data['size'] = dizionario['size']
                                message_data['secure'] = True

                                data['ids_'].add(id_message_decifrato)

                                if 'json' in message_data:
                                    del message_data['json']
                                message_data['is_json'] = False
                            else:
                                message_data['error'] = "questo messaggio e' stato modificato"
                                if 'json' in message_data:
                                    del message_data['json']
                                message_data['is_json'] = False
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
        payload = {
            "event_type": "new",
            "chat_id": event.chat_id,
            "message": message_data,
        }
        await broadcast_event(temp_id, event.chat_id, payload)
        return

    async def handle_edited_message(event):
        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        message_data=_serialize_message(event.message)
        payload = {
            "event_type": "edited",
            "chat_id": event.chat_id,
            "message": message_data,
        }
        await broadcast_event(temp_id, event.chat_id, payload)

    async def handle_deleted_message(event):
        print("deleted handled")
        message_ids = list(event.deleted_ids or [])
        if not message_ids:
            return
        chat_id = getattr(event, "chat_id", None)
        if not chat_id:
            peer = getattr(event, "peer_id", None)
            if peer is not None:
                try:
                    chat_id = utils.get_peer_id(peer)
                except Exception:
                    chat_id = None
        if not chat_id:
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
        if not chat_id:
            return
        await drop_message_ids(temp_id, chat_id, message_ids)
        
        payload = {
            "event_type": "deleted",
            "chat_id": chat_id,
            "message_ids": message_ids,
        }
        print(payload)
        await broadcast_event(temp_id, chat_id, payload)

    async def handle_raw_update(event):
        update = getattr(event, "update", event)
        if isinstance(update, UpdateDeleteChannelMessages):
            chat_id = utils.get_peer_id(PeerChannel(update.channel_id))
            message_ids = list(update.messages or [])
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)
        elif isinstance(update, UpdateDeleteMessages):
            message_ids = list(update.messages or [])
            if not message_ids:
                return
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
            if not chat_id:
                return
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)

    async def handle_chat_action(event):
        if not event.chat_id:
            return
        if not (getattr(event, "user_left", False) or getattr(event, "user_kicked", False)):
            return
        user_ids = []
        if getattr(event, "user_id", None):
            user_ids.append(event.user_id)
        elif getattr(event, "user_ids", None):
            user_ids.extend(list(event.user_ids))

        for uid in user_ids:
            await _remove_user_from_vault(temp_id, event.chat_id, uid)

    client.add_event_handler(handle_new_message, events.NewMessage())
    client.add_event_handler(handle_edited_message, events.MessageEdited())
    client.add_event_handler(handle_deleted_message, events.MessageDeleted())
    client.add_event_handler(handle_raw_update, events.Raw())
    client.add_event_handler(handle_chat_action, events.ChatAction())
    client._cc_handlers_added = True
