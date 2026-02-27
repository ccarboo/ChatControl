from telethon.tl.types import DocumentAttributeAnimated

MESSAGE_LIMIT = 4096

def split_message(text: str, limit: int = MESSAGE_LIMIT) -> list[str]:
    """Divide un messaggio in frammenti più piccoli rispettando il limite rigoroso di caratteri imposto dalle API Telegram (standard 4096)."""
    if limit <= 0:
        raise ValueError("limit must be > 0")
    return [text[i:i + limit] for i in range(0, len(text), limit)]

def is_group_chat_id(chat_id: int) -> bool:
    """Verifica se un ID chat appartiene a un gruppo (valore negativo)."""
    try:
        return int(chat_id) < 0
    except Exception:
        return False

def set_media(msg, message_data):
    """Estrae e normalizza in un dizionario custom le info sui file multimediali nativi (foto, video, document, sticker, gif) pescati dai messaggi Telegram."""
    message_data['file'] = True
            
    # Controlla PRIMA sticker e gif (altrimenti finiscono come documenti)
    if msg.sticker:
        document = msg.sticker
        is_animated = any(
            isinstance(attr, DocumentAttributeAnimated)
            for attr in (document.attributes or [])
        )
        mime = document.mime_type or 'image/webp'
        if is_animated or mime in ('application/x-tgsticker', 'video/webm'):
            message_data['media_type'] = 'sticker_animated'
        else:
            message_data['media_type'] = 'sticker'
        message_data['size'] = document.size
        message_data['mime'] = mime
    
    elif msg.gif:
        message_data['media_type'] = 'gif'
        message_data['size'] = msg.gif.size
        message_data['mime'] = msg.gif.mime_type or 'video/mp4'
    
    # Documenti generici
    elif msg.document:
        document = msg.document
        message_data['media_type'] = 'document'
        message_data['filename'] = None
        message_data['mime'] = document.mime_type or 'application/octet-stream'
        message_data['size'] = document.size or 0
        
        for attr in (document.attributes or []):
            if hasattr(attr, 'file_name'):
                message_data['filename'] = attr.file_name
                break
    
    # Foto
    elif msg.photo:
        message_data['media_type'] = 'photo'
        message_data['size'] = msg.photo.size if hasattr(msg.photo, 'size') else 0
    
    # Video
    elif msg.video:
        message_data['media_type'] = 'video'
        message_data['size'] = msg.video.size if hasattr(msg.video, 'size') else 0
        message_data['mime'] = msg.video.mime_type if hasattr(msg.video, 'mime_type') else 'video/mp4'
