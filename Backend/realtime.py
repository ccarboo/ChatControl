import asyncio
import hashlib
import sqlite3
from fastapi import WebSocket
from telethon import events, utils
from telethon.tl.types import (
    DocumentAttributeAnimated,
    PeerChannel,
    UpdateDeleteChannelMessages,
    UpdateDeleteMessages,
)
from config import pepper
from database.sqlite import get_connection
from utils import cifra_vault, decifra_vault, get_user_data_by_temp_id

# temp_id -> chat_id -> set[WebSocket]
_active_connections = {}
_connections_lock = asyncio.Lock()

# temp_id -> chat_id -> {"ids": set[int], "order": list[int]}
_message_index = {}
_message_index_lock = asyncio.Lock()
_MAX_INDEX_PER_CHAT = 3000


def _is_group_chat_id(chat_id: int) -> bool:
    try:
        return int(chat_id) < 0
    except Exception:
        return False


async def _remove_user_from_vault(temp_id: str, chat_id: int, user_id: int | None):
    user_data = get_user_data_by_temp_id(temp_id)
    if not user_data:
        return

    if user_id is not None and not _is_group_chat_id(chat_id):
        if str(user_id) != str(chat_id):
            return

    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    is_group = _is_group_chat_id(chat_id)

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if is_group:
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    return
                vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
                partecipanti = vault_deciphered.get('partecipanti')
                if not partecipanti or str(user_id) not in partecipanti:
                    return
                del partecipanti[str(user_id)]
                vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
                cursor.execute(
                    """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                    (vault_cifrato, username, chat_id_cif)
                )
                conn.commit()
            else:
                cursor.execute(
                    """DELETE FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                conn.commit()
    except sqlite3.Error as error:
        print(f"ERROR remove_user_from_vault: {error}")

#crea una struttura con al suo interno l'id utente, connesso ad ogni chat con un set ed una lista di id dei messaggi con eventi (la lista e' ordinata)
#serve solo per alcuni raw update eliminazioni in chat singole per esempio
async def index_messages(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.setdefault(temp_id, {})
        chat_map = user_map.setdefault(chat_id, {"ids": set(), "order": []})
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            if mid is None:
                continue
            if mid in ids_set:
                continue
            ids_set.add(mid)
            order.append(mid)
        if len(order) > _MAX_INDEX_PER_CHAT:
            overflow = len(order) - _MAX_INDEX_PER_CHAT
            for _ in range(overflow):
                old = order.pop(0)
                ids_set.discard(old)


async def drop_message_ids(temp_id: str, chat_id: int, message_ids: list[int]):
    if not message_ids:
        return
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return
        chat_map = user_map.get(chat_id)
        if not chat_map:
            return
        ids_set = chat_map["ids"]
        order = chat_map["order"]
        for mid in message_ids:
            ids_set.discard(mid)
        if order:
            chat_map["order"] = [mid for mid in order if mid in ids_set]


async def resolve_chat_id_for_deleted(temp_id: str, message_ids: list[int]) -> int | None:
    if not message_ids:
        return None
    async with _message_index_lock:
        user_map = _message_index.get(temp_id)
        if not user_map:
            return None
        ids = set(mid for mid in message_ids if mid is not None)
        if not ids:
            return None
        candidates = []
        for chat_id, chat_map in user_map.items():
            if ids.issubset(chat_map["ids"]):
                candidates.append(chat_id)
        if len(candidates) == 1:
            return candidates[0]
        return None


def _serialize_message(msg):
    data = {
        "id": msg.id,
        "chat_id": msg.chat_id,
        "text": msg.message or "",
        "date": msg.date.isoformat() if msg.date else None,
        "sender_id": msg.sender_id,
        "out": msg.out,
        "reply_to": msg.reply_to.reply_to_msg_id if msg.reply_to else None,
    }

    if msg.media:
        data["file"] = True

        if msg.sticker:
            document = msg.sticker
            is_animated = any(
                isinstance(attr, DocumentAttributeAnimated)
                for attr in (document.attributes or [])
            )
            mime = document.mime_type or "image/webp"
            if is_animated or mime in ("application/x-tgsticker", "video/webm"):
                data["media_type"] = "sticker_animated"
            else:
                data["media_type"] = "sticker"
            data["size"] = document.size
            data["mime"] = mime
        elif msg.gif:
            data["media_type"] = "gif"
            data["size"] = msg.gif.size
            data["mime"] = msg.gif.mime_type or "video/mp4"
        elif msg.document:
            document = msg.document
            data["media_type"] = "document"
            data["filename"] = None
            data["mime"] = document.mime_type or "application/octet-stream"
            data["size"] = document.size or 0
            for attr in (document.attributes or []):
                if hasattr(attr, "file_name"):
                    data["filename"] = attr.file_name
                    break
        elif msg.photo:
            data["media_type"] = "photo"
            data["size"] = msg.photo.size if hasattr(msg.photo, "size") else 0
        elif msg.video:
            data["media_type"] = "video"
            data["size"] = msg.video.size if hasattr(msg.video, "size") else 0
            data["mime"] = msg.video.mime_type if hasattr(msg.video, "mime_type") else "video/mp4"

    return data


async def connect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    await websocket.accept()
    async with _connections_lock:
        user_map = _active_connections.setdefault(temp_id, {})
        sockets = user_map.setdefault(chat_id, set())
        sockets.add(websocket)


async def disconnect_socket(temp_id: str, chat_id: int, websocket: WebSocket):
    async with _connections_lock:
        user_map = _active_connections.get(temp_id)
        if not user_map:
            return
        sockets = user_map.get(chat_id)
        if not sockets:
            return
        sockets.discard(websocket)
        if not sockets:
            user_map.pop(chat_id, None)
        if not user_map:
            _active_connections.pop(temp_id, None)


async def broadcast_event(temp_id: str, chat_id: int, payload: dict):
    async with _connections_lock:
        sockets = list(_active_connections.get(temp_id, {}).get(chat_id, set()))

    if not sockets:
        return

    dead = []
    for ws in sockets:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)

    for ws in dead:
        await disconnect_socket(temp_id, chat_id, ws)


def register_telethon_handlers(client, temp_id: str):
    if getattr(client, "_cc_handlers_added", False):
        return

    async def handle_new_message(event):
        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        payload = {
            "event_type": "new",
            "chat_id": event.chat_id,
            "message": _serialize_message(event.message),
        }
        await broadcast_event(temp_id, event.chat_id, payload)

    async def handle_edited_message(event):
        if not event.chat_id:
            return
        if event.message and event.message.id:
            await index_messages(temp_id, event.chat_id, [event.message.id])
        payload = {
            "event_type": "edited",
            "chat_id": event.chat_id,
            "message": _serialize_message(event.message),
        }
        await broadcast_event(temp_id, event.chat_id, payload)

    async def handle_deleted_message(event):
        message_ids = list(event.deleted_ids or [])
        if not message_ids:
            return
        chat_id = getattr(event, "chat_id", None)
        if not chat_id:
            peer = getattr(event, "peer_id", None)
            if peer is not None:
                try:
                    chat_id = utils.get_peer_id(peer)
                except Exception:
                    chat_id = None
        if not chat_id:
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
        if not chat_id:
            return
        await drop_message_ids(temp_id, chat_id, message_ids)
        payload = {
            "event_type": "deleted",
            "chat_id": chat_id,
            "message_ids": message_ids,
        }
        await broadcast_event(temp_id, chat_id, payload)

    async def handle_raw_update(event):
        update = getattr(event, "update", event)
        if isinstance(update, UpdateDeleteChannelMessages):
            chat_id = utils.get_peer_id(PeerChannel(update.channel_id))
            message_ids = list(update.messages or [])
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)
        elif isinstance(update, UpdateDeleteMessages):
            message_ids = list(update.messages or [])
            if not message_ids:
                return
            chat_id = await resolve_chat_id_for_deleted(temp_id, message_ids)
            if not chat_id:
                return
            await drop_message_ids(temp_id, chat_id, message_ids)
            payload = {
                "event_type": "deleted",
                "chat_id": chat_id,
                "message_ids": message_ids,
            }
            await broadcast_event(temp_id, chat_id, payload)

    async def handle_chat_action(event):
        if not event.chat_id:
            return
        if not (getattr(event, "user_left", False) or getattr(event, "user_kicked", False)):
            return
        user_ids = []
        if getattr(event, "user_id", None):
            user_ids.append(event.user_id)
        elif getattr(event, "user_ids", None):
            user_ids.extend(list(event.user_ids))

        for uid in user_ids:
            await _remove_user_from_vault(temp_id, event.chat_id, uid)

    client.add_event_handler(handle_new_message, events.NewMessage())
    client.add_event_handler(handle_edited_message, events.MessageEdited())
    client.add_event_handler(handle_deleted_message, events.MessageDeleted())
    client.add_event_handler(handle_raw_update, events.Raw())
    client.add_event_handler(handle_chat_action, events.ChatAction())
    client._cc_handlers_added = True
