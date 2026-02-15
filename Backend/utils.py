import subprocess
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import json
from cryptography.fernet import Fernet
from config import secret_key
from fastapi import Cookie, HTTPException
import time
import re
import sqlite3
from database.sqlite import get_connection
import hashlib
from config import pepper
import os
import tempfile
from telethon.tl.types import DocumentAttributeAnimated

SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)
MESSAGE_LIMIT = 4096

login_cache = {}

def get_user_data_by_temp_id(temp_id: str):
    return login_cache.get(temp_id)

def split_message(text: str, limit: int = MESSAGE_LIMIT) -> list[str]:
    if limit <= 0:
        raise ValueError("limit must be > 0")
    return [text[i:i + limit] for i in range(0, len(text), limit)]

def deriva_master_key(passphrase: str, salt: bytes):
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    master_key_base64 = base64.urlsafe_b64encode(raw_key)
    return master_key_base64

def cifra_vault(dinizionario, master_key):
    json_data = json.dumps(dinizionario)
    f = Fernet(master_key)
    blob_cifrato = f.encrypt(json_data.encode())
    return blob_cifrato

def decifra_vault(blob_cifrato, master_key):
    try:
        f = Fernet(master_key)
        json_data = f.decrypt(blob_cifrato).decode()
        return json.loads(json_data)
    except Exception as e:
        raise ValueError(f"Errore nella decifrazione del vault: {str(e)}")

def cifra_con_age(plaintext: str | bytes, public_keys: list):
    
    try:
        # Costruisci argomenti age: -r for each recipient
        args = ['age']
        for key in public_keys:
            args.extend(['-r', key])
        
        # Esegui age con input/output binario
        if isinstance(plaintext, bytes):
            input_data = plaintext
        else:
            input_data = plaintext.encode()
        
        result = subprocess.run(args, input=input_data, capture_output=True, check=True)
        ciphertext = result.stdout
        
        # Converti in base64 per trasmissione sicura
        return base64.b64encode(ciphertext).decode()
    except subprocess.CalledProcessError as e:
        print(f"Errore cifratura age: {e.stderr}")
        return None

def decifra_file_con_age(ciphertext, candidate_privates):
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

def genera_chiavi():
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        output = risultato.stdout
        linee = output.splitlines()
        pubblica = ""
        privata = ""
        for linea in linee:
            if linea.startswith("# public key:"):
                pubblica = linea.split(":")[1].strip()
            elif linea.startswith("AGE-SECRET-KEY-1"):
                privata = linea.strip()
        return pubblica, privata
    except subprocess.CalledProcessError:
        print("Errore: age-keygen non è installato. Usa 'sudo apt install age'")
        return None, None
    
def is_logged_in( login_session: str = Cookie(None), set_time: bool = False):
    global login_cache
    if not login_session:
        raise HTTPException(status_code=401, detail="Sessione mancante. Effettua il login.")
    try:
        temp_id = cipher.decrypt(login_session.encode()).decode()
    except Exception:
        raise HTTPException(status_code=401, detail="Sessione non valida. Riesegui il login.")

    user_data = login_cache.get(temp_id)
    if not user_data:
        raise HTTPException(status_code=401, detail="Sessione scaduta. Riesegui il login.")
    
    current_time = time.time()

    if current_time - user_data['time'] > 1200:
        del login_cache[temp_id]
        raise HTTPException(status_code=401, detail="Sessione scaduta. Riesegui il login.")
    
    if set_time:
        user_data['time'] = current_time
    return temp_id, user_data    

def is_valid_age_public_key(key: str):
    pattern = r"^age1[0-9a-z]{58}$"
    if re.match(pattern, key):
        return True
    return False

def store_public_key_in_vault(
    user_data,
    chat_id: int,
    sender_id,
    public_key: str,
    msg_date=None,
    is_group: bool | None = None,
    group_title: str | None = None,
    sender_username: str | None = None,
):
    if not user_data or not public_key:
        return False

    if is_group is None:
        try:
            is_group = int(chat_id) < 0
        except Exception:
            is_group = False

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    vault_deciphered = None
    insert_new_vault = False

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
                    vault_deciphered = {
                        'gruppo_id': chat_id,
                        'gruppo_nome': group_title or 'Gruppo',
                        'partecipanti': {}
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
            else:
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    vault_deciphered = {
                        'user_id': chat_id,
                        'username': sender_username or str(chat_id),
                        'chiavi': []
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
    except sqlite3.Error:
        return False

    existing_keys = set()
    if is_group:
        partecipanti = vault_deciphered.get('partecipanti', {})
        for participant_data in partecipanti.values():
            current_key = participant_data.get('chiave', {})
            if current_key and current_key.get('chiave'):
                existing_keys.add(current_key.get('chiave'))
            for chiave_info in participant_data.get('chiavi', []) or []:
                if chiave_info.get('chiave'):
                    existing_keys.add(chiave_info.get('chiave'))
    else:
        for chiave_info in vault_deciphered.get('chiavi', []) or []:
            if chiave_info.get('chiave'):
                existing_keys.add(chiave_info.get('chiave'))

    if public_key in existing_keys:
        return False

    new_key_timestamp = msg_date.timestamp() if msg_date else time.time()
    new_key = {
        'chiave': public_key,
        'inizio': new_key_timestamp,
        'fine': None
    }

    if is_group:
        sender_id_str = str(sender_id) if sender_id is not None else ''
        partecipanti = vault_deciphered.setdefault('partecipanti', {})
        if sender_id_str not in partecipanti:
            partecipanti[sender_id_str] = {'chiave': {}, 'chiavi': []}

        current_key = partecipanti[sender_id_str].get('chiave', {})
        if current_key and current_key.get('chiave'):
            current_key['fine'] = new_key_timestamp - 1
            partecipanti[sender_id_str].setdefault('chiavi', []).append(current_key)

        partecipanti[sender_id_str]['chiave'] = new_key
    else:
        chiavi_list = vault_deciphered.get('chiavi', [])
        for chiave_info in chiavi_list:
            if chiave_info.get('fine') is None:
                chiave_info['fine'] = new_key_timestamp - 1
        chiavi_list.append(new_key)
        vault_deciphered['chiavi'] = chiavi_list

    vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
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
    except sqlite3.Error:
        return False

    return True

def get_group_chyper_keys(data, chat_id1):
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()
    
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
    else:
        return recipient_keys
    
def get_chat_chyper_keys(data, chat_id1):
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()

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

    else:
        return recipient_keys

def build_candidate_privates(chat_keys: str, timestamp):
    timestamp_unix = timestamp.timestamp() if timestamp else None
    

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

#questa funzione ritorna se la chat e' un gruppo oppure no
def is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False
    
#questa funzione mi gestisce i media per renderli comprensibili al frontend
def set_media(msg, message_data):
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