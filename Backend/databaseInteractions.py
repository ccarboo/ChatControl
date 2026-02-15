from database.sqlite import get_connection
from fastapi import HTTPException
import sqlite3
from utils import deriva_master_key, decifra_vault

#questa funzione prende i dati dell'utente (vault e salt) e li decifra prendendo in input lo 
#username dell'utente passato in una funzione di hash e la sua password(in versione passphrase)
def get_user_informations(username: str, password: str):
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
    
    salt_bytes = salt_db

    master_key = deriva_master_key(password, salt_bytes)

    try:
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return vault_decyphered

#la funzione che si occupa di modificare il vault di un utente dato in input
def set_user_vault(username: str, vault_cyphered: bytes):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE utenti SET vault = ? WHERE username = ?",
                (vault_cyphered, username),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
