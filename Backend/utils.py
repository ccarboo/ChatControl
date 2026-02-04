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


SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)

login_cache = {}

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
    
def is_logged_in(login_session: str = Cookie(None)):
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
        del login_cache[login_session]
        raise HTTPException(status_code=401, detail="Sessione scaduta. riesegui il login")

    user_data['time'] = time.time()
    return user_data    

def is_valid_age_public_key(key: str):
    pattern = r"^age1[0-9a-z]{58}$"
    if re.match(pattern, key):
        return True
    return False

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