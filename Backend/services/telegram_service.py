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

# Modifica in Backend/services/telegram_service.py

def set_media(msg, message_data):
    if message_data is None:
        return # Evita il crash se message_data è None
        
    message_data['file'] = True
    
    # Se è una foto o un documento, gestiamo i casi
    if hasattr(msg, 'photo') and msg.photo:
        message_data['media_type'] = 'photo'
        message_data['mime'] = 'image/jpeg'
    elif hasattr(msg, 'document') and msg.document:
        mime = msg.document.mime_type or ''
        # Se è crittografato, potremmo non avere il MIME subito
        if mime.startswith('image/'):
            message_data['media_type'] = 'photo'
        else:
            message_data['media_type'] = 'document'
        message_data['mime'] = mime
    else:
        # Fallback per messaggi crittografati o strani
        message_data['media_type'] = 'document'
        message_data['mime'] = 'application/octet-stream'