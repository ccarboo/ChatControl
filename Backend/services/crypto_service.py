import base64
import nacl.public
import nacl.secret
import nacl.utils
import nacl.exceptions
import subprocess
import json
import re
import time
import os
import tempfile
import sqlite3
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fastapi import HTTPException
from core.config import secret_key, pepper
from database.sqlite import get_connection

# Inizializzazione della chiave segreta per Fernet utilizzando la secret_key dalla configurazione
SECRET_KEY = secret_key.decode()
cipher = Fernet(SECRET_KEY)

def deriva_master_key(passphrase: str, salt: bytes):
    """
    Deriva una master key crittografica a partire da una passphrase e un salt utilizzando l'algoritmo Argon2id.
    """
    # Configurazione di Argon2id con parametri di sicurezza (iterazioni, memoria, parallelismo)
    kdf = Argon2id(salt=salt, length=32, iterations=2, memory_cost=65536, lanes=4)
    raw_key = kdf.derive(passphrase.encode())
    # Codifica la chiave in un formato base64 compatibile con la libreria crittografica
    master_key_base64 = base64.urlsafe_b64encode(raw_key)
    return master_key_base64

def cifra_vault(dinizionario, master_key):
    """
    Cifra un dizionario Python (rappresentante un vault di chiavi/dati) in un blob crittografato
    utilizzando PyNaCl SecretBox (XSalsa20-Poly1305) per maggiore sicurezza rispetto a AES-CBC (Fernet).
    """
    json_data = json.dumps(dinizionario).encode('utf-8')
    
    # Extract the raw 32 bytes from the urlsafe base64 encoded master_key (Argon2id output)
    raw_key = base64.urlsafe_b64decode(master_key)
    
    box = nacl.secret.SecretBox(raw_key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    
    encrypted = box.encrypt(json_data, nonce)
    
    # Restituiamo il formato unificato nonce + ciphertext codificato base64 per storage in SQLite
    return base64.b64encode(nonce + encrypted.ciphertext).decode('utf-8')

def decifra_vault(blob_cifrato, master_key):
    """
    Decifra un blob crittografato restituendo il dizionario (vault) originale.
    Supporta il nuovo standard PyNaCl e implementa un fallback trasparente per legacy Vault `Fernet`.
    """
    # 1. Tenta la decrittazione con PyNaCl (Nuovo Standard)
    try:
        raw_key = base64.urlsafe_b64decode(master_key)
        box = nacl.secret.SecretBox(raw_key)
        
        raw_blob = base64.b64decode(blob_cifrato.encode() if isinstance(blob_cifrato, str) else blob_cifrato)
        
        # Estrai il nonce (primi 24 byte) e il testo cifrato
        nonce = raw_blob[:nacl.secret.SecretBox.NONCE_SIZE]
        ciphertext = raw_blob[nacl.secret.SecretBox.NONCE_SIZE:]
        
        decrypted_bytes = box.decrypt(ciphertext, nonce)
        return json.loads(decrypted_bytes.decode('utf-8'))
        
    except (nacl.exceptions.CryptoError, ValueError, TypeError) as e:
        # 2. Fallback alla decrittazione legacy Fernet (AES-CBC) per retrocompatibilità coi vecchi DB
        try:
            f = Fernet(master_key)
            # Decifra e converte nuovamente da bytes a stringa
            json_data = f.decrypt(blob_cifrato).decode('utf-8')
            return json.loads(json_data)
        except Exception as fallback_err:
            raise ValueError(f"Errore critico nella decifrazione del vault (Sia PyNaCl che Fallback Fernet falliti)")

def cifra_payload(plaintext: str | bytes, public_keys: list, force_no_chunking=False):
    """
    Cifra un testo o dei dati binari utilizzando lo scambio di chiavi ECDH (Curve25519) e la derivazione matematica tramite HKDF per generare le DEK in Envelope Encryption.
    """
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import os
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        
        # Generiamo una chiave privata effimera per il sender senza chiamare il bloccante generate() in C su pyNaCl
        ephemeral_sender_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        ephemeral_sender_pub_bytes = ephemeral_sender_priv.public_key().public_bytes_raw()
        ephemeral_sender_pub_b64 = base64.b64encode(ephemeral_sender_pub_bytes).decode('utf-8')

        encrypted_deks = []
                
        # 1. Genera una Master Message Key casuale per il payload effettivo
        mmk = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        
        # 2. Cifra la MMK per ogni destinatario usando la sua "DEK Derivata via ECDH"
        for pk_b64 in public_keys:
             try:
                pk_bytes = base64.b64decode(pk_b64)
                # Costruisce la chiave pubblica dalla stringa 32byte di nacl
                pub_key = X25519PublicKey.from_public_bytes(pk_bytes)
                
                # Calcolo ECDH sicuro
                shared_key = ephemeral_sender_priv.exchange(pub_key)
                
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=nacl.secret.SecretBox.KEY_SIZE,
                    salt=None,
                    info=b"ChatControl Message DEK HKDF"
                )
                derived_dek = hkdf.derive(shared_key)
                
                # cifratura simmetrica della MMK con la derived_dek
                # usiamo un nonce statico O random ma serializzato (es. tutti i 0) dato che 
                # la derivata DEK è unica per (chiave pubblica eph, chiave pubblica dest)
                dek_box = nacl.secret.SecretBox(derived_dek)
                nonce_dek = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                enc_mmk = dek_box.encrypt(mmk, nonce_dek)
                
                # Aggiungiamo il nonce ai dati inviati per permettere la decifratura
                full_enc_mmk = nonce_dek + enc_mmk.ciphertext
                encrypted_deks.append(base64.b64encode(full_enc_mmk).decode('utf-8'))
             except Exception:
                 continue
                 
        if not encrypted_deks:
             # Failsafe: age fallback
             import subprocess
             args = ['age']
             for pk in public_keys:
                 args.extend(['-r', str(pk)])
             input_data = plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext
             try:
                 res = subprocess.run(args, input=input_data, capture_output=True, check=True)
                 return base64.b64encode(res.stdout).decode()
             except Exception as ex:
                 print(f"Errore fallback age cifratura: {ex}")
                 return None

        if isinstance(plaintext, str):
             plaintext = plaintext.encode('utf-8')
             
        # Cifratura finale del payload con la Master Message Key
        payload_box = nacl.secret.SecretBox(mmk)
        
        # LIGHTWEIGHT CHUNKING
        CHUNK_SIZE = 1024 * 1024 # 1MB
        
        if len(plaintext) > CHUNK_SIZE and not force_no_chunking:
            chunks = []
            for i in range(0, len(plaintext), CHUNK_SIZE):
                chunk_data = plaintext[i:i + CHUNK_SIZE]
                nonce_payload = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                encrypted_chunk = payload_box.encrypt(chunk_data, nonce_payload)
                chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
                
            envelope = {
                "v": 3, # Version 3 HKDF-ECDH PyNaCl
                "ephemeral_pub": ephemeral_sender_pub_b64,
                "deks": encrypted_deks,
                "chunked": True,
                "data": chunks
            }
        else:
            nonce_payload = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            encrypted_payload = payload_box.encrypt(plaintext, nonce_payload)
            
            # Build Envelope compatibile 
            envelope = {
                "v": 3, # Version 3 HKDF-ECDH PyNaCl
                "ephemeral_pub": ephemeral_sender_pub_b64,
                "deks": encrypted_deks,
                "chunked": False,
                "data": base64.b64encode(encrypted_payload).decode('utf-8')
            }
        
        return base64.b64encode(json.dumps(envelope).encode()).decode()
    except Exception:
        # Rimossa print() esplicita per prevenire Side-Channel Logs delle eccezioni crittografiche
        return None



def decifra_payload(ciphertext, candidate_privates):
    """
    Tenta di decifrare un testo cifrato con PyNaCl. Con fallback su 'age' per legacy messages.
    """
    try:
        raw_bytes = ciphertext.encode() if isinstance(ciphertext, str) else ciphertext
        try:
            input_bytes = base64.b64decode(raw_bytes, validate=True)
        except Exception:
            input_bytes = raw_bytes
            
        try: # Prova JSON Envelope (PyNaCl)
            envelope = json.loads(input_bytes.decode('utf-8'))
            if envelope.get("v") == 3:
                encrypted_deks = envelope.get("deks", [])
                ephemeral_pub_b64 = envelope.get("ephemeral_pub")
                
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                from cryptography.hazmat.primitives import hashes
                import os
                
                if not ephemeral_pub_b64:
                    pass # Fallback successivi
                else:
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
                    
                    # Convertiamo l'ephemeral string in un oggetto PublicKey
                    ephemeral_pub_bytes = base64.b64decode(ephemeral_pub_b64)
                    ephemeral_pub_key = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
                    
                    for priv_b64 in candidate_privates:
                        try:
                            priv_bytes = base64.b64decode(priv_b64)
                            # Convertiamo i byte nacl della chiave privata candidata in oggetto Python Cryptography
                            priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
                            
                            # Calcolo Secret Condiviso (lato ricevente) senza bloccarsi in C extension
                            shared_key = priv_key.exchange(ephemeral_pub_key)
                            
                            hkdf = HKDF(
                                algorithm=hashes.SHA256(),
                                length=nacl.secret.SecretBox.KEY_SIZE,
                                salt=None,
                                info=b"ChatControl Message DEK HKDF"
                            )
                            derived_dek = hkdf.derive(shared_key)
                            dek_box = nacl.secret.SecretBox(derived_dek)
                            
                            mmk = None
                            for enc_mmk_b64 in encrypted_deks:
                                try:
                                    full_enc_mmk = base64.b64decode(enc_mmk_b64)
                                    nonce_dek = full_enc_mmk[:nacl.secret.SecretBox.NONCE_SIZE]
                                    ciphertext_mmk = full_enc_mmk[nacl.secret.SecretBox.NONCE_SIZE:]
                                    
                                    # decifriamo la Master Message Key
                                    mmk = dek_box.decrypt(ciphertext_mmk, nonce_dek)
                                    break
                                except nacl.exceptions.CryptoError:
                                    continue
                                    
                            if mmk:
                                payload_box = nacl.secret.SecretBox(mmk)
                                
                                # Re-assembly of chunks
                                is_chunked = envelope.get("chunked", False)
                                if is_chunked:
                                    chunks = envelope.get("data", [])
                                    decrypted_full_bytes = b""
                                    for enc_chunk_b64 in chunks:
                                        enc_chunk_bytes = base64.b64decode(enc_chunk_b64)
                                        decrypted_full_bytes += payload_box.decrypt(enc_chunk_bytes)
                                    return decrypted_full_bytes
                                else:
                                    # Fallback standard legacy string / old v3 implementations
                                    encrypted_data = base64.b64decode(envelope.get("data", ""))
                                    return payload_box.decrypt(encrypted_data)
                        except Exception:
                            continue
            
            elif envelope.get("v") == 2:
                encrypted_deks = envelope.get("deks", [])
                encrypted_data = base64.b64decode(envelope.get("data", ""))
                
                for priv_b64 in candidate_privates:
                    try:
                        priv_bytes = base64.b64decode(priv_b64)
                        priv_key = nacl.public.PrivateKey(priv_bytes)
                        sealed_box = nacl.public.SealedBox(priv_key)
                        
                        dek = None
                        for enc_dek_b64 in encrypted_deks:
                            try:
                                enc_dek_bytes = base64.b64decode(enc_dek_b64)
                                dek = sealed_box.decrypt(enc_dek_bytes)
                                break
                            except nacl.exceptions.CryptoError:
                                continue
                                
                        if dek:
                            box = nacl.secret.SecretBox(dek)
                            return box.decrypt(encrypted_data)
                    except Exception:
                        continue
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass
            
        # Fallback ad 'age' se non è un JSON PyNaCl valido
        for privata in candidate_privates:
            try:
                import os, tempfile, subprocess
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
                    keyfile.write(privata)
                    keyfile_path = keyfile.name
                try:
                    res = subprocess.run(['age', '-d', '-i', keyfile_path], input=input_bytes, capture_output=True, check=True)
                    return res.stdout
                finally:
                    os.unlink(keyfile_path)
            except Exception:
                continue
    except Exception:
        pass
    return None

def genera_chiavi():
    """
    Genera una coppia di chiavi `PyNaCl`/Curve25519 pubblica e privata bypassando il generatore bloccato C.
    """
    try:
        import os
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        private_key = X25519PrivateKey.from_private_bytes(os.urandom(32))
        public_key_bytes = private_key.public_key().public_bytes_raw()
        private_key_bytes = private_key.private_bytes_raw()
        
        pubblica = base64.b64encode(public_key_bytes).decode('utf-8')
        privata = base64.b64encode(private_key_bytes).decode('utf-8')
        return pubblica, privata
    except Exception as e:
        print(f"Errore genera_chiavi PyNaCl: {e}")
        return None, None



def is_valid_public_key(key: str):
    """
    Verifica se una stringa è una chiave pubblica PyNaCl valida.
    Supporta anche fallback alle chiavi legacy 'age1...'
    """
    if str(key).startswith("age1") and len(str(key)) == 62:
        return True
    try:
        decoded = base64.b64decode(key, validate=True)
        return len(decoded) == nacl.public.PublicKey.SIZE
    except Exception:
        return False


def store_public_key_in_vault(
    user_data,
    chat_id: int,
    sender_id,
    public_key: str,
    msg_date=None,
    is_group: bool | None = None,
    group_title: str | None = None,
    sender_username: str | None = None,
):
    """
    Salva la chiave pubblica (ricevuta da un altro utente/gruppo) all'interno del vault crittografato
    dell'utente locale, tracciando le rotazioni delle chiavi (data inizio/fine di validità).
    """
    if not user_data or not public_key:
        return False

    # Se non è specificato esplicitamente, assume che gli ID negativi siano gruppi (standard Telegram/simili)
    if is_group is None:
        try:
            is_group = int(chat_id) < 0
        except Exception:
            is_group = False

    # Hashing per identificare in modo anonimo proprietario e chat all'interno del DB
    username = hashlib.sha256(pepper.encode() + user_data['data']['username'].encode()).hexdigest()
    chat_id_cif = hashlib.sha256(pepper.encode() + str(chat_id).encode()).hexdigest()

    vault_deciphered = None
    insert_new_vault = False

    # Fase 1: Recupero e decifratura del vault dal database
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            table = 'contatti_gruppo' if is_group else 'contatti'
            id_col = 'gruppo_id' if is_group else 'contatto_id'
            
            cursor.execute(f"SELECT vault FROM {table} WHERE proprietario = ? AND {id_col} = ?", (username, chat_id_cif))
            risultato = cursor.fetchone()
            
            if not risultato or not risultato[0]:
                insert_new_vault = True
                if is_group:
                    vault_deciphered = {'gruppo_id': chat_id, 'gruppo_nome': group_title or 'Gruppo', 'partecipanti': {}}
                else:
                    vault_deciphered = {'user_id': chat_id, 'username': sender_username or str(chat_id), 'chiavi': []}
            else:
                vault_deciphered = decifra_vault(risultato[0], user_data['data']['masterkey'])
    except sqlite3.Error:
        return False

    # Fase 2: Verifica della presenza della chiave (evita di re-inserire la stessa chiave)
    existing_keys = set()
    if is_group:
        for p in vault_deciphered.get('partecipanti', {}).values():
            if p.get('chiave', {}).get('chiave'): 
                existing_keys.add(p['chiave']['chiave'])
            existing_keys.update(k['chiave'] for k in p.get('chiavi', []) if k.get('chiave'))
    else:
        existing_keys.update(k['chiave'] for k in vault_deciphered.get('chiavi', []) if k.get('chiave'))

    # Se la chiave è già conosciuta, si interrompe l'operazione
    if public_key in existing_keys:
        return False

    # Fase 3: Aggiunta della nuova chiave e rotazione della precedente
    new_key_timestamp = msg_date.timestamp() if msg_date else time.time()
    new_key = {
        'chiave': public_key,
        'inizio': new_key_timestamp,
        'fine': None
    }

    if is_group:
        sender_id_str = str(sender_id) if sender_id is not None else ''
        partecipanti = vault_deciphered.setdefault('partecipanti', {})
        # Assicura la struttura per questo partecipante
        if sender_id_str not in partecipanti:
            partecipanti[sender_id_str] = {'chiave': {}, 'chiavi': []}

        current_key = partecipanti[sender_id_str].get('chiave', {})
        # Ruota la chiave vecchia impostandole una data di fine e mettendola nello storico
        if current_key and current_key.get('chiave'):
            current_key['fine'] = new_key_timestamp - 1
            partecipanti[sender_id_str].setdefault('chiavi', []).append(current_key)

        partecipanti[sender_id_str]['chiave'] = new_key
    else:
        chiavi_list = vault_deciphered.get('chiavi', [])
        # Chiude le chiavi correnti (senza una data di 'fine')
        for chiave_info in chiavi_list:
            if chiave_info.get('fine') is None:
                chiave_info['fine'] = new_key_timestamp - 1
        chiavi_list.append(new_key)
        vault_deciphered['chiavi'] = chiavi_list

    # Fase 4: Ricifratura e persistenza del vault aggiornato
    vault_cifrato = cifra_vault(vault_deciphered, user_data['data']['masterkey'])
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            table = 'contatti_gruppo' if is_group else 'contatti'
            id_col = 'gruppo_id' if is_group else 'contatto_id'
            
            if insert_new_vault:
                cursor.execute(f"INSERT INTO {table} (proprietario, {id_col}, vault) VALUES (?, ?, ?)", (username, chat_id_cif, vault_cifrato))
            else:
                cursor.execute(f"UPDATE {table} SET vault = ? WHERE proprietario = ? AND {id_col} = ?", (vault_cifrato, username, chat_id_cif))
            conn.commit()
    except sqlite3.Error:
        return False

    return True

def get_group_chyper_keys(data, chat_id1):
    """
    Recupera tutte le chiavi pubbliche associate ai partecipanti attuali di un determinato gruppo, 
    inclusa la propria chiave pubblica. Permette al mittente di cifrare un messaggio destinato al gruppo.
    """
    # Hashing in base al sistema per recuperare i record sicuri nel DB
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()
    
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT vault FROM contatti_gruppo WHERE proprietario = ? AND gruppo_id = ?""",
                (username, chat_id)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = []
    if risultato and risultato[0]:
        # Decifra il vault del gruppo
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        all_keys = []
        for p in vault_deciphered.get('partecipanti', {}).values():
            if p.get('chiave', {}).get('chiave'): all_keys.append(p['chiave'])
            all_keys.extend(p.get('chiavi', []))
        
        # Filtra ed estrae direttamente le chiavi pubbliche valide (senza 'fine')
        recipient_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]

    # Assicurati di includere la propria chiave pubblica, se disponibile in memoria
    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
            user_pubblica = chat_data['chiave']['pubblica']
            if user_pubblica and user_pubblica not in recipient_keys:
                recipient_keys.append(user_pubblica)
                
    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")
    else:
        return recipient_keys

def get_chat_chyper_keys(data, chat_id1):
    """
    Recupera la chiave pubblica attiva del destinatario di una chat (1 a 1), insieme 
    alla chiave pubblica del mittente stesso, per consentire la corretta cifratura del messaggio asimmetrico.
    """
    username = hashlib.sha256(pepper.encode() + data['data']['username'].encode()).hexdigest()
    chat_id = hashlib.sha256(pepper.encode() + str(chat_id1).encode()).hexdigest()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT vault FROM contatti WHERE proprietario = ? AND contatto_id = ?""",
                (username, chat_id)
            )
            risultato = cursor.fetchone()
    except sqlite3.Error as error:
        raise HTTPException(status_code=500, detail=str(error))

    recipient_keys = []
    if risultato and risultato[0]:
        vault_deciphered = decifra_vault(risultato[0], data['data']['masterkey'])
        all_keys = vault_deciphered.get('chiavi', [])
        # Estrae le stringhe attuali delle chiavi pubbliche
        recipient_keys = [k['chiave'] for k in all_keys if k.get('fine') is None and k.get('chiave')]

    # Includi la propria chiave associata a questa chat, essenziale affinché il mittente possa rileggere i propri messaggi
    if 'chats' in data['data'] and chat_id in data['data']['chats']:
        chat_data = data['data']['chats'][chat_id]
        if 'chiave' in chat_data and 'pubblica' in chat_data['chiave']:
            user_pubblica = chat_data['chiave']['pubblica']
            if user_pubblica and user_pubblica not in recipient_keys:
                recipient_keys.append(user_pubblica)
    
    if not recipient_keys:
        raise HTTPException(status_code=400, detail="Nessuna chiave disponibile per cifrare")
    else:
        return recipient_keys

def build_candidate_privates(chat_keys: dict, timestamp):
    """
    Determina quale (o quali) chiavi private `age` potrebbero essere state usate per decifrare 
    un vecchio messaggio, posizionandosi cronologicamente con il timestamp di invio del messaggio.

    Per messaggi arrivati in momenti di transizione/rotazione delle chiavi, considera come valide 
    sia la chiave stimata in quel dato momento che la chiave immediatamente precedente, per coprire 
    probabili scarti temporali (race conditions) ai margini della rotazione.
    """
    timestamp_unix = timestamp.timestamp() if timestamp else None
    
    candidate_privates = []
    chiave_corrente = chat_keys.get('chiave', {})
    chiavi_storiche = chat_keys.get('chiavi', [])
    
    # Ordina cronologicamente le chiavi storiche disponibili (dal più al meno recente)
    chiavi_storiche_sorted = sorted(
        [c for c in chiavi_storiche if c.get('privata')],
        key=lambda c: c.get('inizio', 0),
        reverse=True
    )

    if timestamp_unix:
        inizio_corrente = chiave_corrente.get('inizio', 0)
        
        # Se il msg ha un timestamp successivo all'introduzione della chiave corrente, proviamo con quest'ultima
        if timestamp_unix >= inizio_corrente:
            chiave_stimata = chiave_corrente
        else:
            chiave_stimata = None
            # Altrimenti cerchiamo un intervallo di tempo storico idoneo per quel timestamp
            for chiave_storica in chiavi_storiche_sorted:
                inizio = chiave_storica.get('inizio', 0)
                fine = chiave_storica.get('fine')
                if fine is None and timestamp_unix >= inizio:
                    chiave_stimata = chiave_storica
                    break
                elif fine is not None and inizio <= timestamp_unix <= fine:
                    chiave_stimata = chiave_storica
                    break

        if chiave_stimata and chiave_stimata.get('privata'):
            candidate_privates.append(chiave_stimata.get('privata'))

        # Per messaggi molto vicini al confine temporale, proviamo anche la chiave usata precedentemente (utile in ritardi di rete)
        if chiavi_storiche_sorted:
            chiave_precedente = chiavi_storiche_sorted[0]
            if chiave_precedente.get('privata') and chiave_precedente.get('privata') != (chiave_stimata.get('privata') if chiave_stimata else None):
                candidate_privates.append(chiave_precedente.get('privata'))
    else:
        # Se manca del tutto il riferimento temporale, inseriamo i candidati principali come fallback
        if chiave_corrente.get('privata'):
            candidate_privates.append(chiave_corrente.get('privata'))
        if chiavi_storiche_sorted and chiavi_storiche_sorted[0].get('privata'):
            candidate_privates.append(chiavi_storiche_sorted[0].get('privata'))

    return candidate_privates

def cifra_payload_stream(input_generator, public_keys: list):
    """
    Cifra in streaming usando blocchi binari ed Envelope Encryption. (V1)
    L'input deve essere un generatore che produce chunks (bytes).
    Ritorna un generatore che produce l'header (con busta cifrata) e i vari chunk cifrati.
    """
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import os
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        
        ephemeral_sender_priv = X25519PrivateKey.from_private_bytes(os.urandom(32))
        ephemeral_sender_pub_bytes = ephemeral_sender_priv.public_key().public_bytes_raw()
        ephemeral_sender_pub_b64 = base64.b64encode(ephemeral_sender_pub_bytes).decode('utf-8')

        encrypted_deks = []
        mmk = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        
        for pk_b64 in public_keys:
             try:
                pk_bytes = base64.b64decode(pk_b64)
                pub_key = X25519PublicKey.from_public_bytes(pk_bytes)
                shared_key = ephemeral_sender_priv.exchange(pub_key)
                hkdf = HKDF(algorithm=hashes.SHA256(), length=nacl.secret.SecretBox.KEY_SIZE, salt=None, info=b"ChatControl Message DEK HKDF")
                derived_dek = hkdf.derive(shared_key)
                dek_box = nacl.secret.SecretBox(derived_dek)
                nonce_dek = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                enc_mmk = dek_box.encrypt(mmk, nonce_dek)
                full_enc_mmk = nonce_dek + enc_mmk.ciphertext
                encrypted_deks.append(base64.b64encode(full_enc_mmk).decode('utf-8'))
             except Exception:
                 continue
                 
        if not encrypted_deks:
             raise ValueError("Nessuna chiave pubblica valida per la cifratura.")

        envelope = {
            "v": 1,
            "ephemeral_pub": ephemeral_sender_pub_b64,
            "deks": encrypted_deks
        }
        envelope_bytes = json.dumps(envelope).encode('utf-8')
        
        header = b"CCV1" + len(envelope_bytes).to_bytes(4, byteorder='big') + envelope_bytes
        yield header

        payload_box = nacl.secret.SecretBox(mmk)
        for chunk_data in input_generator:
            if not chunk_data:
                continue
            nonce_payload = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            encrypted_chunk = payload_box.encrypt(chunk_data, nonce_payload)
            chunk_len = len(encrypted_chunk)
            yield chunk_len.to_bytes(4, byteorder='big') + encrypted_chunk
    except Exception as e:
        print(f"Errore nella cifratura stream: {e}")
        return

async def _read_exact(iterator, n: int, buffer: bytearray):
    is_async = hasattr(iterator, "__anext__")
    while len(buffer) < n:
        try:
            if is_async:
                chunk = await iterator.__anext__()
            else:
                chunk = next(iterator)
            if not chunk:
                break
            buffer.extend(chunk)
        except (StopAsyncIteration, StopIteration):
            break
    if len(buffer) < n:
        return None
    res = bytes(buffer[:n])
    del buffer[:n]
    return res

async def decifra_payload_stream(async_iterator, candidate_privates: list):
    """
    Decifra uno stream crittografato formattato come V1.
    Accetta in input un Async Generator (come iter_download di Telethon) o iteratore compatibile.
    Ritorna un generatore asincrono (async yield) per i chunk in chiaro.
    """
    buffer = bytearray()
    
    magic = await _read_exact(async_iterator, 4, buffer)
    if magic != b"CCV1":
        raise ValueError("Il file non rispetta il formato V1 binario supportato per lo stream, o e' corrotto")
        
    env_len_bytes = await _read_exact(async_iterator, 4, buffer)
    if not env_len_bytes:
        raise ValueError("Stream terminato improvvisamente prima dell'envelope")
    env_len = int.from_bytes(env_len_bytes, byteorder='big')
    
    envelope_bytes = await _read_exact(async_iterator, env_len, buffer)
    if not envelope_bytes:
        raise ValueError("Stream interrotto leggendo l'envelope")
        
    envelope = json.loads(envelope_bytes.decode('utf-8'))
    encrypted_deks = envelope.get("deks", [])
    ephemeral_pub_b64 = envelope.get("ephemeral_pub")
    
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    
    ephemeral_pub_bytes = base64.b64decode(ephemeral_pub_b64)
    ephemeral_pub_key = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    
    mmk = None
    for priv_b64 in candidate_privates:
        try:
            priv_bytes = base64.b64decode(priv_b64)
            priv_key = X25519PrivateKey.from_private_bytes(priv_bytes)
            shared_key = priv_key.exchange(ephemeral_pub_key)
            hkdf = HKDF(algorithm=hashes.SHA256(), length=nacl.secret.SecretBox.KEY_SIZE, salt=None, info=b"ChatControl Message DEK HKDF")
            derived_dek = hkdf.derive(shared_key)
            dek_box = nacl.secret.SecretBox(derived_dek)
            
            for enc_mmk_b64 in encrypted_deks:
                try:
                    full_enc_mmk = base64.b64decode(enc_mmk_b64)
                    nonce_dek = full_enc_mmk[:nacl.secret.SecretBox.NONCE_SIZE]
                    ciphertext_mmk = full_enc_mmk[nacl.secret.SecretBox.NONCE_SIZE:]
                    mmk = dek_box.decrypt(ciphertext_mmk, nonce_dek)
                    break
                except nacl.exceptions.CryptoError:
                    continue
            if mmk: break
        except Exception:
            continue
            
    if not mmk:
        raise ValueError("Impossibile decifrare il layer dell'envelope con le tue chiavi")
        
    payload_box = nacl.secret.SecretBox(mmk)
    
    while True:
        chunk_len_bytes = await _read_exact(async_iterator, 4, buffer)
        if not chunk_len_bytes:
            break
        chunk_len = int.from_bytes(chunk_len_bytes, byteorder='big')
        
        encrypted_chunk = await _read_exact(async_iterator, chunk_len, buffer)
        if not encrypted_chunk:
            break
            
        decrypted_chunk = payload_box.decrypt(encrypted_chunk)
        yield decrypted_chunk

async def estrai_metadata_da_stream_v1(async_iterator, candidate_privates: list):
    """
    Legge la prima parte di uno stream V1 per decifrare l'envelope ed estrarre il primo chunk
    che contiene metadata_size (4 bytes) seguito dai metadata json in utf-8.
    """
    try:
        decrypted_stream = decifra_payload_stream(async_iterator, candidate_privates)
        first_chunk = await decrypted_stream.__anext__()
        
        if first_chunk and len(first_chunk) >= 4:
            metadata_size = int.from_bytes(first_chunk[:4], byteorder='big')
            if 0 < metadata_size <= len(first_chunk) - 4:
                metadata_bytes = first_chunk[4:4 + metadata_size]
                return metadata_bytes.decode('utf-8')
    except Exception:
        pass
    return None
