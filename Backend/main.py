from fastapi import FastAPI
from database import sqlite as db_setup
from routes import router as api_router
from routes.media import router as media_router
from fastapi.middleware.cors import CORSMiddleware





# Istanzia l'applicazione FastAPI principale per il backend di ChatControl
app = FastAPI()

# Configurazione del middleware CORS per abilitare le richieste cross-origin
# Limita l'accesso solo agli URL del frontend di sviluppo (locale) e di produzione
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:5173",
        "https://127.0.0.1:5173",
        "https://192.168.1.228:5173",
        "https://server.apernici.it",
        "https://apernici.it",
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Permetti tutti i metodi HTTP (GET, POST, ecc.)
    allow_headers=["*"],  # Permetti tutti gli header
)

# Registra il router principale (raccoglie tutti i sotto-router da routes/)
app.include_router(api_router)
app.include_router(media_router)
# Initialize database on backend startup
@app.on_event("startup")
async def startup_event():
	"""Inizializza il DB all'avvio del backend."""
	db_setup.initDB()  # This executes the setup code in sqlite.py



	
