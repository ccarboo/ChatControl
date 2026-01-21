from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
import secrets
from cryptography.fernet import Fernet
from config import pepper
from config import secret_key
import time
import hashlib
from utils import deriva_master_key, decifra_vault

router = APIRouter()

SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)


class login_user(BaseModel):
    username: str
    password: str

login_cache = {}


@router.post("/login")
async def login_user(credentials: login_user, response: Response):

    username = hashlib.sha256(pepper.encode() + credentials.username.encode()).hexdigest()
    temp_id = secrets.token_hex(16)
    temp_id_encrypted = cipher.encrypt(temp_id.encode()).decode()
    
    try:
        with get_connection() as conn:
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
    
    global login_cache
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

