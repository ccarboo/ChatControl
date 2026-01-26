from fastapi import APIRouter, Response, Cookie
import sqlite3
from fastapi import HTTPException
from pydantic import BaseModel
from database.sqlite import get_connection
import secrets
from config import pepper
import time
import hashlib
from utils import deriva_master_key, decifra_vault, cipher, login_cache, cifra_vault, is_logged_in, is_valid_age_public_key
from datetime import datetime
import json

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
        
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                """SELECT contatto_id FROM contatti WHERE proprietario = ?
                
                    UNION
                    
                    SELECT gruppo_id FROM contatti_gruppo WHERE proprietario = ?""",
                (username,username)
            )
            risultati = cursor.fetchall()
            
            encrypted_ids = {row[0] for row in risultati}
           
            for chat in chats:
                chat_id_hash = hashlib.sha256(pepper.encode() + str(chat['id']).encode()).hexdigest()
                chat['cyphered'] = chat_id_hash in encrypted_ids
                
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))
    


    return {"chats": chats}

@router.get("/chats/{chat_id}")
async def get_chat_messages(chat_id: int, limit: int = 50, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    client = data['client']
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

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

    # Try to interpret message text as JSON payload without breaking UI
    for message in messages:
        # Evita di processare messaggi inviati dall'utente loggato
        if my_id and message.get('sender_id') == my_id:
            message['is_json'] = False
            continue

        text = message.get('text') or ''
        try:
            parsed = json.loads(text)
            message['json'] = parsed
            message['is_json'] = True
            
        except Exception:
            message['is_json'] = False
        
        if message['is_json'] == True:
            cif_flag = message['json'].get('CIF') or message['json'].get('cif')
            if cif_flag == "in":
                pubblic = message['json'].get('public')
                if pubblic is None or not is_valid_age_public_key(pubblic):
                    continue
                vault_deciphered = None
                all_keys = []
                insert_new_vault = False
                # Telethon User non espone is_group: calcola in modo sicuro
                is_group = bool(
                    getattr(entity, 'is_group', False)
                    or getattr(entity, 'megagroup', False)
                    or getattr(entity, 'gigagroup', False)
                )
                try:
                    if is_group:
                        with get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                                (username, chat_id_cif)
                            )
                            risultato = cursor.fetchone()
                            if not risultato or not risultato[0]:
                                # Crea struttura per gruppo nuovo con i campi richiesti
                                vault_deciphered = {
                                    'gruppo_id': chat_id,
                                    'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                                    'partecipanti': {}
                                }
                                insert_new_vault = True
                            else:
                                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])

                            # Estrai tutte le chiavi in una lista
                            if 'partecipanti' in vault_deciphered:
                                for participant_id, participant_data in vault_deciphered['partecipanti'].items():
                                    if 'chiavi' in participant_data:
                                        for chiave_info in participant_data['chiavi']:
                                            all_keys.append(chiave_info)

                            for key in all_keys[:]:
                                if key['fine'] is not None:
                                    all_keys.remove(key)
                    else:
                        with get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute(
                                """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                                (username, chat_id_cif)
                            )
                            risultato = cursor.fetchone()
                            if not risultato or not risultato[0]:
                                # Crea struttura per contatto nuovo con i campi richiesti
                                sender = await msg.get_sender()
                                vault_deciphered = {
                                    'user_id': chat_id,
                                    'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                                    'chiavi': []
                                }
                                insert_new_vault = True
                            else:
                                vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])

                            # Estrai tutte le chiavi dalla struttura con i campi richiesti
                            if 'chiavi' in vault_deciphered:
                                for chiave_info in vault_deciphered['chiavi']:
                                    all_keys.append(chiave_info)

                            # Rimuovi chiavi scadute (fine != None)
                            for key in all_keys[:]:
                                if key.get('fine') is not None:
                                    all_keys.remove(key)
                except sqlite3.Error as error:
                    raise HTTPException(status_code=500, detail=str(error))

                if pubblic not in [k['chiave'] for k in all_keys]:
                    # Scade eventuali chiavi attive (fine == None) e aggiunge la nuova chiave
                    expire_ts = time.time() - 1
                    new_key = {
                        'chiave': pubblic,
                        'inizio': time.time(),
                        'fine': None
                    }

                    if is_group:
                        for participant_data in vault_deciphered.get('partecipanti', {}).values():
                            chiavi_list = participant_data.get('chiavi', [])
                            for chiave_info in chiavi_list:
                                if chiave_info.get('fine') is None:
                                    chiave_info['fine'] = expire_ts
                            chiavi_list.append(new_key)
                    else:
                        # Aggiorna la chiave nel contatto (struttura piatta)
                        chiavi_list = vault_deciphered.get('chiavi', [])
                        for chiave_info in chiavi_list:
                            if chiave_info.get('fine') is None:
                                chiave_info['fine'] = expire_ts
                        chiavi_list.append(new_key)

                    # Salva il vault aggiornato
                    vault_cifrato = cifra_vault(vault_deciphered, data['data']['masterkey'])
                    try:
                        with get_connection() as conn:
                            cursor = conn.cursor()
                            if is_group:
                                if insert_new_vault:
                                    cursor.execute(
                                        """INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""",
                                        (username, chat_id_cif, vault_cifrato)
                                    )
                                else:
                                    cursor.execute(
                                        """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                                        (vault_cifrato, username, chat_id_cif)
                                    )
                            else:
                                if insert_new_vault:
                                    cursor.execute(
                                        """INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""",
                                        (username, chat_id_cif, vault_cifrato)
                                    )
                                else:
                                    cursor.execute(
                                        """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                                        (vault_cifrato, username, chat_id_cif)
                                    )
                            conn.commit()
                    except sqlite3.Error as error:
                        raise HTTPException(status_code=500, detail=str(error))
                    

                

    return {"chat_id": chat_id, "messages": messages}

@router.get("/chats/{chat_id}/inits")
async def get_init_messages(chat_id: int, login_session: str = Cookie(None)):
    data = is_logged_in(login_session)
    client = data['client']
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    
    if not client.is_connected():
        await client.connect()

    try:
        entity = await client.get_entity(chat_id)

    except Exception:
        raise HTTPException(status_code=404, detail="Chat non trovata.")

    me = await client.get_me()
    my_id = me.id if me else None

    init_messages = []
    async for msg in client.iter_messages(entity, search='"cif":"in"'):
        if my_id and msg.sender_id == my_id:
            continue

        text = msg.message or ''
        try:
            parsed = json.loads(text)
            cif_flag = parsed.get('CIF') or parsed.get('cif')
            pubblic = parsed.get('public')

            if cif_flag == "in" and pubblic is not None and is_valid_age_public_key(pubblic):
                init_messages.append({
                    'id': msg.id,
                    'date': msg.date,
                    'public_key': pubblic,
                    'sender_id': msg.sender_id
                })
        except Exception:
            continue

    is_group = bool(
        getattr(entity, 'is_group', False)
        or getattr(entity, 'megagroup', False)
        or getattr(entity, 'gigagroup', False)
    )

    vault_deciphered = None
    insert_new_vault = False
    
    try:
        if is_group:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    vault_deciphered = {
                        'gruppo_id': chat_id,
                        'gruppo_nome': getattr(entity, 'title', 'Gruppo'),
                        'partecipanti': {}
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        else:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                    (username, chat_id_cif)
                )
                risultato = cursor.fetchone()
                if not risultato or not risultato[0]:
                    sender = await client.get_entity(chat_id)
                    vault_deciphered = {
                        'user_id': chat_id,
                        'username': getattr(sender, 'username', str(chat_id)) if sender else str(chat_id),
                        'chiavi': []
                    }
                    insert_new_vault = True
                else:
                    vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    all_keys = []
    if is_group and 'partecipanti' in vault_deciphered:
        for participant_data in vault_deciphered['partecipanti'].values():
            if 'chiavi' in participant_data:
                all_keys.extend(participant_data['chiavi'])
    elif not is_group and 'chiavi' in vault_deciphered:
        all_keys.extend(vault_deciphered['chiavi'])

    existing_keys = {k['chiave'] for k in all_keys}
    keys_added = 0

    for init_msg in init_messages:
        pubblic = init_msg['public_key']
        if pubblic not in existing_keys:
            new_key_timestamp = init_msg['date'].timestamp()
            new_key = {
                'chiave': pubblic,
                'inizio': new_key_timestamp,
                'fine': None
            }
            
            if is_group:
                sender_id = str(init_msg['sender_id'])
                if sender_id not in vault_deciphered['partecipanti']:
                    vault_deciphered['partecipanti'][sender_id] = {'chiavi': []}
                
                # Aggiorna la fine della chiave precedente
                if vault_deciphered['partecipanti'][sender_id]['chiavi']:
                    vault_deciphered['partecipanti'][sender_id]['chiavi'][-1]['fine'] = new_key_timestamp - 1
                
                vault_deciphered['partecipanti'][sender_id]['chiavi'].append(new_key)
            else:
                # Aggiorna la fine della chiave precedente
                if vault_deciphered['chiavi']:
                    vault_deciphered['chiavi'][-1]['fine'] = new_key_timestamp - 1
                
                vault_deciphered['chiavi'].append(new_key)
            
            existing_keys.add(pubblic)
            keys_added += 1

    if keys_added > 0:
        vault_cifrato = cifra_vault(vault_deciphered, data['data']['masterkey'])
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                if is_group:
                    if insert_new_vault:
                        cursor.execute(
                            """INSERT INTO contatti_gruppo (proprietario, gruppo_id, vault) VALUES (?, ?, ?)""",
                            (username, chat_id_cif, vault_cifrato)
                        )
                    else:
                        cursor.execute(
                            """UPDATE contatti_gruppo SET vault = ? WHERE proprietario = ? AND gruppo_id = ?""",
                            (vault_cifrato, username, chat_id_cif)
                        )
                else:
                    if insert_new_vault:
                        cursor.execute(
                            """INSERT INTO contatti (proprietario, contatto_id, vault) VALUES (?, ?, ?)""",
                            (username, chat_id_cif, vault_cifrato)
                        )
                    else:
                        cursor.execute(
                            """UPDATE contatti SET vault = ? WHERE proprietario = ? AND contatto_id = ?""",
                            (vault_cifrato, username, chat_id_cif)
                        )
                conn.commit()
        except sqlite3.Error as error:
            raise HTTPException(status_code=500, detail=str(error))

    return {
        "chat_id": chat_id,
        "init_messages_found": len(init_messages),
        "keys_added": keys_added,
        "total_keys": len(existing_keys)
    }
    