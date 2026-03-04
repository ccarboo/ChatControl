import os, base64
from dotenv import load_dotenv

# Carica le variabili d'ambiente dal file .env nella directory corrente
load_dotenv()

# Pepper crittografico: utilizzato per salare e anonimizzare identificativi (es. chat_id o username) prima dell'inserimento a DB
pepper = os.getenv("SECRET_PEPPER")

# Chiave segreta: utilizzata per la cifratura simmetrica locale (tramite Fernet) di dati sensibili (es. master vault) e token di sessione
secret_key = base64.urlsafe_b64encode(os.urandom(32))