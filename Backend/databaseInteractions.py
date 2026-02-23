from database.sqlite import get_connection
from fastapi import HTTPException
import sqlite3
from utils import deriva_master_key, decifra_vault
import hashlib
from config import pepper

def get_user_informations(username: str, password: str) -> dict:
    """
    Recupera le credenziali utente (salt e vault cifrato) dal DB tramite lo username pre-hashato.
    Deriva la master key dalla password in input per decifrare il Master Vault ritornandolo come dictionary.
    """
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
    master_key = deriva_master_key(password, salt_db)

    try:
        vault_decyphered = decifra_vault(risultati[1], master_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return vault_decyphered

def set_user_vault(username: str, vault_cyphered: bytes) -> None:
    """
    Sovrascrive o aggiorna in modo atomico il Master Vault cifrato di un utente nel DB SQLite.
    """
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

def check_username_unicity(username: str) -> None:
    """
    Si assicura che in fase di registrazione lo username (già hashato) non sia duplicato.
    Lancia un'eccezione col codice 409 in caso di collisione.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            params = (username,)  
            cursor.execute(
                "SELECT * FROM utenti WHERE username = ? LIMIT 1",
                params,
            )
            risultati = cursor.fetchone()
            if risultati is not None:
                raise HTTPException(status_code=409, detail='username already exists')
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

def get_gruppo_vault(username: str, chat_id: str, entity, data: dict) -> tuple[bool, dict]:
    """
    Estrapola il sub-vault specifico di un gruppo dal DB. Ritorna una tupla:
    (insert_new_vault_flag, vault_deciphered_dict). Se non esiste lo innesca a vuoto.
    """
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
                
async def get_chat_vault(username: str, chat_id: str, client, data: dict) -> tuple[bool, dict]:
    """
    Estrapola il sub-vault specifico di una chat (1a1) dal DB. Ritorna una tupla:
    (insert_new_vault_flag, vault_deciphered_dict). Se non esiste lo innesca a vuoto.
    """
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
