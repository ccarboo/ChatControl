from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import DATABASE_PATH
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError
import secrets
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from config import pepper
from config import secret_key
import time
import hashlib
import subprocess

router = APIRouter()

SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)

class UserData(BaseModel):
    api_id: str
    api_hash: str
    phone: str
    username: str
    password: str

class signupped(BaseModel):
    sms_code: str

class signupped_2fa(BaseModel):
    password: str

class login_user(BaseModel):
    username: str
    password: str

signup_cache = {}
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

@router.post("/login")
async def login_user(credentials: login_user, response: Response):

    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()
    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            params = (username,)
            cursor.execute(
                "SELECT salt, vault FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is None:
                raise HTTPException(status_code=404, detail='username does not exist')
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    salt_db = risultati[0]
    
    if isinstance(salt_db, str):
        salt_bytes = salt_db.encode()
    else:
        salt_bytes = salt_db

    master_key = deriva_master_key(credentials.password, salt_bytes)

    try:
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    login_cache[temp_id] = {
        "data": vault_decyphered,
        "time": time.time(),
    }
    print(login_cache[temp_id])
    response.set_cookie(
        key="login_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
    )
    
    return {"status":"logged in"}

@router.post("/signup/step1")
async def create_user(credentials: UserData, response: Response):
    client = TelegramClient(StringSession(), credentials.api_id, credentials.api_hash)
    await client.connect()

    sent_code = await client.send_code_request(credentials.phone)
    temp_id = secrets.token_hex(16)
    salt = secrets.token_bytes(16)
    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati != None:
                raise HTTPException(status_code=409,detail='username already exists')
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    


    global signup_cache
    signup_cache[temp_id] = {
        "client":client,
        "phone":credentials.phone,
        "phone_code_hash": sent_code.phone_code_hash,
        "salt": salt,
        "masterkey_derived":deriva_master_key(credentials.password, salt),
        "api_id":credentials.api_id,
        "api_hash":credentials.api_hash,
        "username":username,
        "username_not_cyphered": credentials.username
    }
    
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    response.set_cookie(
        key="signup_session",
        value=temp_id_encrypted,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=300,
    )
    
    return {"status": "SMS inviato"}
     

@router.post("/signup/step2")
async def sign_up_verify(credentials: signupped, signup_session: str = Cookie(None), response: Response=None):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except:
        raise HTTPException(status_code=400, detail="Sessione invalida")
    
    temp_data = signup_cache.get(temp_id)
    client = temp_data['client']
    try: 
        await client.sign_in(temp_data['phone'],credentials.sms_code,phone_code_hash=temp_data['phone_code_hash'])
        session_str = client.session.save()

    except SessionPasswordNeededError:
        return {"status": "need_2fa_password"}
    
    pubblica, privata = genera_chiavi()


    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "pubblica": pubblica,
        "privata": privata,
        "password": None,
        "session": session_str
    }
    vault_cifrato = cifra_vault(da_cifrare, temp_data['masterkey_derived'])

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_cifrato),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    response.delete_cookie("signup_session")
    return {"status": "Account creato!"}

@router.post("/signup/step3")
async def sign_up_verify_password(credentials: signupped_2fa, signup_session: str = Cookie(None), response: Response = None):
    if not signup_session:
        raise HTTPException(status_code=400, detail="Sessione non trovata")
    
    try:
        temp_id = cipher.decrypt(signup_session.encode()).decode()
    except:
        raise HTTPException(status_code=400, detail="Sessione invalida")

    temp_data = signup_cache.get(temp_id)
    if temp_data is None:
        raise HTTPException(status_code=400, detail="Sessione scaduta o non valida")
    client = temp_data['client']
    try: 
        await client.sign_in(password= credentials.password)
        session_str = client.session.save()

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
    
    pubblica, privata = genera_chiavi()


    da_cifrare = {
        "phone": temp_data['phone'],
        "api_id": temp_data['api_id'],
        "api_hash": temp_data['api_hash'],
        "username": temp_data['username_not_cyphered'],
        "pubblica": pubblica,
        "privata": privata,
        "password": credentials.password,
        "session": session_str
    }
    vault_cifrato = cifra_vault(da_cifrare, temp_data['masterkey_derived'])

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utenti (username, salt, vault) VALUES (?, ?, ?)",
                (temp_data['username'], temp_data['salt'], vault_cifrato),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    
    response.delete_cookie("signup_session")
    
    return {"status": "Account creato!"}
