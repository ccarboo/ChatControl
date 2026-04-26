import sqlite3
import os

DATABASE_NAME = "database.db"
# Assicuriamoci che la cartella database esista
DATABASE_FOLDER = "database"
DATABASE_PATH = os.path.join(DATABASE_FOLDER, DATABASE_NAME)

def initDB():
    """Inizializza la base dati creando le tabelle necessarie."""
    if not os.path.exists(DATABASE_FOLDER):
        os.makedirs(DATABASE_FOLDER)
        
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    c = conn.cursor()

    # Tabelle esistenti (Utenti, Contatti, Gruppi)
    c.execute("""CREATE TABLE IF NOT EXISTS utenti (
                username TEXT PRIMARY KEY, 
                salt TEXT, 
                vault BLOB)""")

    c.execute("""CREATE TABLE IF NOT EXISTS contatti (
                proprietario TEXT,
                contatto_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti(username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, contatto_id))""")

    c.execute("""CREATE TABLE IF NOT EXISTS contatti_gruppo (
                proprietario TEXT,
                gruppo_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti (username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, gruppo_id))""")

    # --- NUOVA TABELLA MESSAGGI ---
    # Qui salviamo i dati necessari per le anteprime
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                chat_id INTEGER,
                text TEXT,
                media_type TEXT, -- 'photo', 'document', 'sticker', ecc.
                mime TEXT,       -- 'image/jpeg', 'video/mp4', ecc.
                filename TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")

    conn.commit()
    conn.close()

def get_connection():
    """Restituisce una connessione SQLite con chiavi esterne attive."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row # Questo permette di accedere ai dati come dizionari: row['mime']
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# --- NUOVE FUNZIONI PER IL MEDIA ROUTER ---

def get_message_by_id(message_id):
    """Recupera i metadati di un messaggio specifico per il download media."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT mime, filename, media_type FROM messages WHERE id = ?", (message_id,))
        row = cursor.fetchone()
        if row:
            return dict(row) # Converte sqlite3.Row in un dizionario Python
        return None
    finally:
        conn.close()

def save_message(message_id, chat_id, text, media_type=None, mime=None, filename=None):
    """Salva o aggiorna un messaggio nel DB (chiamata da telegram_service)."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO messages (id, chat_id, text, media_type, mime, filename)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (message_id, chat_id, text, media_type, mime, filename))
        conn.commit()
    finally:
        conn.close()