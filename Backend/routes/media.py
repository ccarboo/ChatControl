from fastapi import APIRouter, Cookie, HTTPException
from fastapi.responses import StreamingResponse
import io
import json

from services import message_service
from services.crypto_service import decifra_payload_stream  # <-- IMPORTIAMO QUELLA GIUSTA!
from services.auth_service import is_logged_in

router = APIRouter()

@router.get("/media/download/{chat_id}/{message_id}")
async def download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    if not login_session:
        raise HTTPException(status_code=401, detail="Sessione mancante")

    from database import sqlite as db
    msg_data = db.get_message_by_id(message_id) 
    if not msg_data:
        raise HTTPException(status_code=404, detail="Messaggio non trovato nel DB")

    file_bytes = await message_service.get_media_logic(chat_id, message_id, login_session)
    if not file_bytes:
        raise HTTPException(status_code=404, detail="File non trovato su Telegram")

    mime_type = msg_data.get('mime', 'application/octet-stream')
    filename = msg_data.get('filename', 'file')

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type=mime_type,
        headers={
            "Content-Disposition": f'inline; filename="{filename}"'
        }
    )


@router.get("/media/secure-download/{chat_id}/{message_id}")
async def secure_download_media(chat_id: int, message_id: int, login_session: str = Cookie(None)):
    if not login_session:
        raise HTTPException(status_code=401, detail="Sessione mancante")

    # 1. Scarica la busta cifrata da Telegram
    encrypted_bytes = await message_service.get_media_logic(chat_id, message_id, login_session)
    if not encrypted_bytes:
        raise HTTPException(status_code=404, detail="File non trovato su Telegram")

    try:
        _, session_data = is_logged_in(login_session, True)
    except Exception:
        raise HTTPException(status_code=401, detail="Sessione non valida o scaduta")

    # 2. Cerca tutte le chiavi private nel Vault dell'utente
    candidate_privates = []
    data_vault = session_data.get('data', {})
    
    for category in ['chats', 'groups']:
        for _, item_data in data_vault.get(category, {}).items():
            if 'chiave' in item_data and 'privata' in item_data['chiave']:
                candidate_privates.append(item_data['chiave']['privata'])
            for old_key in item_data.get('chiavi', []):
                if 'privata' in old_key:
                    candidate_privates.append(old_key['privata'])

    if not candidate_privates:
        raise HTTPException(status_code=401, detail="Nessuna chiave privata nel vault")

    # 3. Funzione di supporto per trasformare i bytes in un iteratore asincrono (richiesto da CCV3)
    async def bytes_to_async_iterable(b: bytes):
        yield b

    # 4. Decifra lo stream binario CCV3
    try:
        decrypted_chunks = []
        
        # Passiamo i byte alla TUA bellissima funzione decifra_payload_stream
        async for chunk in decifra_payload_stream(bytes_to_async_iterable(encrypted_bytes), candidate_privates):
            decrypted_chunks.append(chunk)
            
        if not decrypted_chunks:
            raise ValueError("Decifratura fallita: chiavi errate o file vuoto")
            
        # Ricostruiamo il blocco decifrato in memoria
        decrypted_raw = b"".join(decrypted_chunks)

        # 5. Estraiamo il tuo formato personalizzato: [4B Size] [JSON] [File Bytes]
        metadata_size = int.from_bytes(decrypted_raw[:4], byteorder='big')
        
        metadata_bytes = decrypted_raw[4:4+metadata_size]
        dizionario = json.loads(metadata_bytes.decode('utf-8'))
        
        # I byte restanti sono l'immagine/video reale!
        decrypted_file_bytes = decrypted_raw[4+metadata_size:]
        mime_type = dizionario.get('mime', 'application/octet-stream')
        filename = dizionario.get('filename', 'secure_file')

        # 6. Invio magico al Frontend
        return StreamingResponse(
            io.BytesIO(decrypted_file_bytes),
            media_type=mime_type,
            headers={
                "Content-Disposition": f'inline; filename="{filename}"'
            }
        )

    except ValueError as ve:
        raise HTTPException(status_code=500, detail=f"Errore CCV3: {str(ve)}")
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Errore interno durante l'estrazione: {str(e)}")