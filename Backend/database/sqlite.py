import sqlite3

DATABASE_NAME = "database.db"
DATABASE_PATH = "database/"+ DATABASE_NAME

def initDB():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS utenti (
                username TEXT PRIMARY KEY, 
                salt TEXT, 
                vault BLOB)"""
              )

    #il contatto_id e' l'id telegram del contatto
    c.execute("""CREATE TABLE IF NOT EXISTS contatti (
                proprietario TEXT,
                contatto_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti(username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, contatto_id))"""
              )
    #il gruppo_id e' l'id telegram del gruppo

    c.execute("""CREATE TABLE IF NOT EXISTS contatti_gruppo (
                proprietario TEXT,
                gruppo_id TEXT,
                vault BLOB,
                FOREIGN KEY (proprietario) REFERENCES utenti (username) ON DELETE CASCADE ON UPDATE CASCADE,
                PRIMARY KEY (proprietario, gruppo_id))"""
              )

    conn.commit()

    conn.close()


def get_connection():
    """Open SQLite connection with foreign keys enforced."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
