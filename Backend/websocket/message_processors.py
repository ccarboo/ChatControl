import json
import base64
import traceback
import hashlib
import io
from config import pepper
from services.auth_service import get_user_data_by_temp_id
from services.telegram_service import is_group_chat_id
from services.crypto_service import (
    is_valid_age_public_key, store_public_key_in_vault, build_candidate_privates, decifra_file_con_age
)

async def _process_key_exchange(temp_id, event, message_data, parsed):
    my_id = message_data.get('my_id')
    if my_id and message_data.get('sender_id') == my_id:
        message_data['is_json'] = False
        message_data['text'] = None
        message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
        message_data['is_system'] = True
        return message_data
    
    pubblica = parsed.get("public")
    if pubblica and is_valid_age_public_key(pubblica):
        user_data = get_user_data_by_temp_id(temp_id)
        if user_data:
            store_public_key_in_vault(
                user_data,
                event.chat_id,
                event.message.sender_id,
                pubblica,
                msg_date=getattr(message_data, "date", None),
                is_group=is_group_chat_id(event.chat_id),
                group_title=getattr(event.chat, "title", "Gruppo")
            )
    message_data['text'] = None
    message_data['chiave'] = "Questo messaggio e' uno scambio di chiave"
    message_data['is_system'] = True
    return message_data

async def _process_text_message(event, message_data, parsed, chat_keys, data):
    text_encrypted = message_data['json'].get('text')
    id_message_encrypted = message_data['json'].get('id')
    timestamp = message_data.get('date')

    candidate_privates = build_candidate_privates(chat_keys, timestamp)

    text_decifrato = decifra_file_con_age(text_encrypted, candidate_privates)
    if text_decifrato:
        text_decifrato = text_decifrato.decode() if isinstance(text_decifrato, bytes) else text_decifrato

    id_message_decifrato_caption = decifra_file_con_age(id_message_encrypted, candidate_privates)
    if id_message_decifrato_caption:
        id_message_decifrato_caption = id_message_decifrato_caption.decode() if isinstance(id_message_decifrato_caption, bytes) else id_message_decifrato_caption

    if text_decifrato:
        try:
            dizionario = json.loads(text_decifrato)
            if dizionario.get('cif') == "on":
                tempo_decifrato = dizionario.get('timestamp')
                id_message_decifrato = dizionario.get('id')
                diff_seconds = None
                if timestamp and tempo_decifrato is not None:
                    try:
                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                    except (TypeError, ValueError):
                        diff_seconds = None

                if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato_caption in data['ids_']):
                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                elif id_message_decifrato_caption != id_message_decifrato:
                    message_data['error'] = "questo messaggio e' stato modificato"
                else:
                    message_data['text'] = dizionario['text']
                    message_data['secure'] = True
                    data['ids_'].add(id_message_decifrato_caption)
            else:
                message_data['error'] = "questo messaggio e' stato modificato"
        except Exception:
            traceback.print_exc()

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data

async def _process_document_payload(client, entity, event, message_data, parsed, chat_keys, data):
    message_id = message_data.get('id')
    if not message_id:
        message_data['error'] = "nessun message id presente"
        return message_data

    full_message = await client.get_messages(entity, ids=message_id)
    if not full_message or not full_message.media or not full_message.document:
        message_data['error'] = "il messaggio dovrebbe contenere un documento, ma non e' presente"
        return message_data

    file_bytes = io.BytesIO()
    await client.download_media(full_message, file=file_bytes)
    file_bytes.seek(0)
    encrypted_payload = file_bytes.getvalue()

    timestamp = message_data.get('date')
    candidate_privates = build_candidate_privates(chat_keys, timestamp)

    decrypted_payload = decifra_file_con_age(encrypted_payload, candidate_privates)
   
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
                diff_seconds = None
                if timestamp and tempo_decifrato is not None:
                    try:
                        diff_seconds = abs(timestamp.timestamp() - float(tempo_decifrato))
                    except (TypeError, ValueError):
                        diff_seconds = None

                if (diff_seconds is not None and diff_seconds > 10) or (id_message_decifrato in data['ids_']):
                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                else:
                    message_data['text'] = message_bytes.decode('utf-8', errors='replace')
                    data['ids_'].add(id_message_decifrato)
                    message_data['secure'] = True
                    message_data['file'] = False
                    
                    message_data.pop('media_type', None)
                    message_data.pop('filename', None)
                    message_data.pop('mime', None)
                    message_data.pop('size', None)

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data

async def _process_encrypted_file(client, entity, event, message_data, parsed, chat_keys, data):
    message_id = message_data.get('id')
    header_encrypted_metadata = None
    
    if message_id:
        full_message = await client.get_messages(entity, ids=message_id)
        if full_message and full_message.media:
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

            if len(file_head_bytes) >= 8:
                header_encrypted_size = int.from_bytes(file_head_bytes[4:8], byteorder='big')
                if 0 < header_encrypted_size <= len(file_head_bytes) - 8:
                    header_encrypted_metadata = file_head_bytes[8:8 + header_encrypted_size]

    timestamp = message_data.get('date')
    candidate_privates = build_candidate_privates(chat_keys, timestamp)

    text_decifrato = None
    if header_encrypted_metadata:
        text_decifrato = decifra_file_con_age(header_encrypted_metadata, candidate_privates)
        if text_decifrato:
            text_decifrato = text_decifrato.decode() if isinstance(text_decifrato, bytes) else text_decifrato

    if text_decifrato:
        try:
            dizionario = json.loads(text_decifrato)
            if dizionario.get('cif') == "file":
                tempo_decifrato = dizionario.get('timestamp')
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
                        allowed_seconds = max(30, file_size / (32 * 1024))
                    except (TypeError, ValueError):
                        pass

                if (diff_seconds is not None and diff_seconds > allowed_seconds) or (id_message_decifrato in data['ids_']):
                    message_data['error'] = "questo messaggio e' frutto di un replay attack"
                else:
                    message_data['file'] = True
                    message_data['filename'] = dizionario.get('filename')
                    message_data['text'] = dizionario.get('text')
                    message_data['mime'] = dizionario.get('mime')
                    message_data['size'] = dizionario.get('size')
                    message_data['secure'] = True
                    data['ids_'].add(id_message_decifrato)
            else:
                message_data['error'] = "questo messaggio e' stato modificato"
        except Exception:
            traceback.print_exc()

    if 'json' in message_data:
        del message_data['json']
    message_data['is_json'] = False
    return message_data
