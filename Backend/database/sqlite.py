import sqlite3

DATABASE_NAME = "database.db"
DATABASE_PATH = "database/"+ DATABASE_NAME

def initDB():
    conn = sqlite3.connect(DATABASE_PATH)

    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS utenti (username TEXT PRIMARY KEY, salt TEXT, vault BLOB)""")

    conn.commit()

    conn.close()
