from fastapi import APIRouter, Cookie, HTTPException
from fastapi.responses import StreamingResponse
import io
from services import message_service
from database import sqlite as db

router = APIRouter()

@router.get("/media/download/{chat_id}/{message_id}")
async def download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    if not login_session:
        raise HTTPException(status_code=401, detail="Sessione mancante")

    # 1. Recupera i metadati dal DB (MIME salvato da telegram_service.py)
    msg_data = db.get_message_by_id(message_id) 
    if not msg_data:
        raise HTTPException(status_code=404, detail="Messaggio non trovato nel DB")

    # 2. Ottieni i byte da Telegram
    file_bytes = await message_service.get_media_logic(chat_id, message_id, login_session)
    
    if not file_bytes:
        raise HTTPException(status_code=404, detail="File non trovato su Telegram")

    # 3. FORZA IL MIME TYPE (fondamentale per l'anteprima)
    mime_type = msg_data.get('mime', 'application/octet-stream')
    filename = msg_data.get('filename', 'file')

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type=mime_type, # Se è image/jpeg, il browser attiva l'anteprima
        headers={
            "Content-Disposition": f"inline; filename={filename}"
        }
    )