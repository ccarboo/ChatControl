from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
import secrets
from config import pepper
import time
import hashlib
from utils import deriva_master_key, decifra_vault, cipher, login_cache, cifra_vault, is_logged_in
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

router = APIRouter()


@router.get("/chats")
async def get_chats(login_session: str = Cookie(None)):
    
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    chats = 
       