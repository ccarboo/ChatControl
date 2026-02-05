from fastapi import APIRouter, Cookie, Depends
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
from config import pepper
import time
import hashlib
from utils import decifra_vault, cifra_vault, is_logged_in, is_valid_age_public_key
from telethon.tl.types import DocumentAttributeAnimated
from datetime import datetime
import json
import base64
import subprocess
import tempfile
                                
router = APIRouter()


def is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False


@router.get("/chats")
async def get_chats(login_session: str = Cookie(None), offset_date: str = None):
    
    data = is_logged_in(login_session)
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
           
            for chat in chats:
                chat_id_hash = hashlib.sha256(pepper.encode() + str(chat['id']).encode()).hexdigest()
                chat['cyphered'] = chat_id_hash in encrypted_ids
                
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    


    return {"chats": chats}

@router.get("/chats/{chat_id}/limit/{limit}")
async def get_chat_messages(chat_id: int, limit: int, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    
    client = data['client']
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    messages = []
    async for msg in client.iter_messages(entity, limit=limit):
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
        
        # Estrai dati del media se presente
        if msg.media:
            message_data['file'] = True
            
            # Controlla PRIMA sticker e gif (altrimenti finiscono come documenti)
            if msg.sticker:
                document = msg.sticker
                is_animated = any(
                    isinstance(attr, DocumentAttributeAnimated)
                    for attr in (document.attributes or [])
                )
                mime = document.mime_type or 'image/webp'
                if is_animated or mime in ('application/x-tgsticker', 'video/webm'):
                    message_data['media_type'] = 'sticker_animated'
                else:
                    message_data['media_type'] = 'sticker'
                message_data['size'] = document.size
                message_data['mime'] = mime
            
            elif msg.gif:
                message_data['media_type'] = 'gif'
                message_data['size'] = msg.gif.size
                message_data['mime'] = msg.gif.mime_type or 'video/mp4'
            
            # Documenti generici
            elif msg.document:
                document = msg.document
                message_data['media_type'] = 'document'
                message_data['filename'] = None
                message_data['mime'] = document.mime_type or 'application/octet-stream'
                message_data['size'] = document.size or 0
                
                for attr in (document.attributes or []):
                    if hasattr(attr, 'file_name'):
                        message_data['filename'] = attr.file_name
                        break
            
            # Foto
            elif msg.photo:
                message_data['media_type'] = 'photo'
                message_data['size'] = msg.photo.size if hasattr(msg.photo, 'size') else 0
            
            # Video
            elif msg.video:
                message_data['media_type'] = 'video'
                message_data['size'] = msg.video.size if hasattr(msg.video, 'size') else 0
                message_data['mime'] = msg.video.mime_type if hasattr(msg.video, 'mime_type') else 'video/mp4'
        
        messages.append(message_data)

    messages.reverse()  

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
        
        if message['is_json'] == True:
            cif_flag = message['json'].get('CIF') or message['json'].get('cif')
            if cif_flag == "in":
                if my_id and message.get('sender_id') == my_id:
                    message['is_json'] = False
                    continue
                pubblic = message['json'].get('public')
                if pubblic is None or not is_valid_age_public_key(pubblic):
                    continue
                vault_deciphered = None
                all_keys = []
                insert_new_vault = False
                is_group = is_group_chat_id(chat_id)
                try:
                    if is_group:
                        with get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                                (username, chat_id_cif)
                            )
                            risultato = cursor.fetchone()
                            if not risultato or not risultato[0]:
                                vault_deciphered = {
                                    'gruppo_id': chat_id,
                                    'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                                    'partecipanti': {}
                                }
                                insert_new_vault = True
                            else:
                                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])

                            if 'partecipanti' in vault_deciphered:
                                for participant_id, participant_data in vault_deciphered['partecipanti'].items():
                                    # Aggiungi chiave corrente
                                    current_key = participant_data.get('chiave', {})
                                    if current_key and current_key.get('chiave'):
                                        all_keys.append(current_key)
                                    # Aggiungi chiavi storiche
                                    if 'chiavi' in participant_data:
                                        for chiave_info in participant_data['chiavi']:
                                            all_keys.append(chiave_info)

                            for key in all_keys[:]:
                                if key.get('fine') is not None:
                                    all_keys.remove(key)
                    else:
                        with get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                                (username, chat_id_cif)
                            )
                            risultato = cursor.fetchone()
                            if not risultato or not risultato[0]:
                                sender = await msg.get_sender()
                                vault_deciphered = {
                                    'user_id': chat_id,
                                    'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                                    'chiavi': []
                                }
                                insert_new_vault = True
                            else:
                                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])

                            if 'chiavi' in vault_deciphered:
                                for chiave_info in vault_deciphered['chiavi']:
                                    all_keys.append(chiave_info)

                            for key in all_keys[:]:
                                if key.get('fine') is not None:
                                    all_keys.remove(key)
                except sqlite3.Error as error:
                    raise HTTPException(status_code=500, detail=str(error))

                if pubblic not in [k['chiave'] for k in all_keys]:
                    new_key_timestamp = time.time()
                    new_key = {
                        'chiave': pubblic,
                        'inizio': new_key_timestamp,
                        'fine': None
                    }

                    if is_group:
                        sender_id = str(message.get('sender_id'))
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
                        chiavi_list = vault_deciphered.get('chiavi', [])
                        for chiave_info in chiavi_list:
                            if chiave_info.get('fine') is None:
                                chiave_info['fine'] = new_key_timestamp - 1
                        chiavi_list.append(new_key)

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
                    
            if cif_flag == "on":
                text = message['json'].get('text')
   
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

                if text_decifrato:
                    try:
                        dizionario = json.loads(text_decifrato)
                        if dizionario['cif'] == "on":
                            message['text'] = dizionario['text']
                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                        else:
                            message['error'] = "on"
                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                    except Exception as e:
                        import traceback
                        traceback.print_exc()

            if cif_flag == "file":
                text = message['json'].get('text')
   
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

                if text_decifrato:
                    try:
                        dizionario = json.loads(text_decifrato)
                        if dizionario['cif'] == "file":
                            message['file'] = True
                            message['filename'] = dizionario['filename']
                            message['text'] = dizionario['text']
                            message['mime'] = dizionario['mime']
                            message['size'] = dizionario['size']

                            if 'json' in message:
                                del message['json']
                            message['is_json'] = False
                        else:
                            message['error'] = "on"
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
                                message['text'] = message_bytes.decode('utf-8', errors='replace')
                                if 'json' in message:
                                    del message['json']
                                message['is_json'] = False
                                message['file'] = False
                except Exception:
                    import traceback
                    traceback.print_exc()
    return {"chat_id": chat_id, "messages": messages}

@router.get("/chats/{chat_id}/inits")
async def get_init_messages(chat_id: int, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
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
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    vault_deciphered = {
                        'gruppo_id': chat_id,
                        'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                        'partecipanti': {}
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        else:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    sender = await client.get_entity(chat_id)
                    vault_deciphered = {
                        'user_id': chat_id,
                        'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                        'chiavi': []
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

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

    if keys_added > 0:
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
    from fastapi.responses import StreamingResponse
    import io
    
    data = is_logged_in(login_session)
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
    data = is_logged_in(login_session)
    client = data['client']
    
    if not client.is_connected():
        await client.connect()
    
    from fastapi.responses import StreamingResponse
    import io
    import os
    import mimetypes
    
    def build_candidate_privates(chat_id_hash: str, timestamp):
        timestamp_unix = timestamp.timestamp() if timestamp else None
        chats_data = data['data'].get('chats', {})
        chat_keys = chats_data.get(chat_id_hash, {})

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

        return candidate_privates

    def decrypt_with_age(ciphertext, candidate_privates):
        for privata in candidate_privates:
            try:
                try:
                    input_bytes = base64.b64decode(ciphertext)
                except Exception:
                    input_bytes = ciphertext if isinstance(ciphertext, (bytes, bytearray)) else str(ciphertext).encode()

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
                    return result.stdout
                finally:
                    os.unlink(keyfile_path)
            except Exception:
                continue
        return None

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

        encrypted_metadata = caption_json.get('text')
        if not encrypted_metadata:
            raise HTTPException(status_code=400, detail="Caption mancante")

        chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
        candidate_privates = build_candidate_privates(chat_id_cif, message.date)
        if not candidate_privates:
            raise HTTPException(status_code=400, detail="Nessuna chiave disponibile")

        decrypted_metadata_bytes = decrypt_with_age(encrypted_metadata, candidate_privates)
        if not decrypted_metadata_bytes:
            raise HTTPException(status_code=400, detail="Impossibile decifrare la caption")

        try:
            outer_metadata_str = decrypted_metadata_bytes.decode()
            outer_metadata = json.loads(outer_metadata_str)
        except Exception:
            raise HTTPException(status_code=400, detail="Metadata esterni non validi")

        if outer_metadata.get('cif') != 'file':
            raise HTTPException(status_code=400, detail="Metadata esterni non cifrati")

        file_bytes = io.BytesIO()
        await client.download_media(message, file=file_bytes)
        file_bytes.seek(0)

        encrypted_payload_bytes = file_bytes.getvalue()
        decrypted_payload = decrypt_with_age(encrypted_payload_bytes, candidate_privates)
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
    