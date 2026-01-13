from fastapi import APIRouter
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import DATABASE_PATH

router = APIRouter()

class UserCredentials(BaseModel):
	username: str
	password: str

@router.put("/Login")
def create_user(credentials: UserCredentials):
    print(credentials)

    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO utente (username, password) VALUES (?, ?)",
                (credentials.username, credentials.password),
            )
            conn.commit()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))