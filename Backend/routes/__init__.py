from fastapi import APIRouter
from routes.login import router as r_login
from routes.signup import router as r_signup
from routes.chat import router as r_chats
from routes.message import router as r_messages

# Router unificato API: raccoglie tutti i sotto-router specifici in un unico punto di ingresso
router = APIRouter()
router.include_router(r_login, tags=["login"])       # Rotte per l'autenticazione / sessioni
router.include_router(r_signup, tags=["signup"])     # Rotte per la creazione di nuovi account/vault
router.include_router(r_chats, tags=["chats"])       # Rotte per la gestione delle chat e download media (anche in realtime)
router.include_router(r_messages, tags=["messages"]) # Rotte per invio di messaggi (testo e file, in chiaro o crittografati)
