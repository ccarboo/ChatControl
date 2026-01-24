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
from datetime import datetime

router = APIRouter()


@router.get("/chats")
async def get_chats(login_session: str = Cookie(None), offset_date: str = None):
    
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    dt = datetime.fromisoformat(offset_date) if offset_date else None

    chats = []

    async for dialog in client.iter_dialogs(limit=20, offset_date=dt):
        chat_info = {
            'id': dialog.id,
            'name': dialog.name,
            'unread_count': dialog.unread_count,
            'is_user': dialog.is_user,
            'is_group': dialog.is_group,
            'is_channel': dialog.is_channel,
        }
        
        if dialog.message:
            chat_info['last_message'] = {
                'text': dialog.message.text or '',
                'date': dialog.date if dialog.message else None,
                'sender_id': dialog.message.sender_id
            }
        
        chats.append(chat_info)
    
    return {"chats": chats}

@router.get("/chats/{chat_id}")
async def get_chat_messages(chat_id: int, limit: int = 50, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']

    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    messages = []
    async for msg in client.iter_messages(entity, limit=limit):
        sender = await msg.get_sender()
        messages.append({
            'id': msg.id,
            'text': msg.message or '',
            'date': msg.date if msg.date else None,
            'sender_id': msg.sender_id,
            'sender_username': getattr(sender, 'username', None) if sender else None,
            'out': msg.out,
            'reply_to': msg.reply_to.reply_to_msg_id if msg.reply_to else None,
        })

    messages.reverse()  
    return {"chat_id": chat_id, "messages": messages}