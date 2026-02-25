import time
from fastapi import Cookie, HTTPException
from cryptography.fernet import Fernet
from config import secret_key

SECRET_KEY = secret_key.encode()
cipher = Fernet(SECRET_KEY)

login_cache = {}

def get_user_data_by_temp_id(temp_id: str):
    """Restituisce i dati utente associati a un ID di sessione temporaneo."""
    return login_cache.get(temp_id)

def is_logged_in( login_session: str = Cookie(None), set_time: bool = False):
    """Verifica la validità della sessione utente e ne aggiorna eventualmente l'ultimo accesso."""
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
