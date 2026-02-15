from database.sqlite import get_connection
from fastapi import HTTPException
import sqlite3
from utils import deriva_master_key, decifra_vault
import hashlib
from config import pepper


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

#verifica l'unicita' dello username
def check_username_unicity(username: str):
    try:
        with get_connection() as conn:
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

#prende il vault dei partecipanti al gruppo
def get_gruppo_vault(username: str, chat_id: str, entity, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

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
            insert_new_vault = False
    return insert_new_vault, vault_deciphered
                
#prende il vault di una chat
async def get_chat_vault(username: str, chat_id: str, client, data):
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

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
            insert_new_vault = False
    return insert_new_vault, vault_deciphered

