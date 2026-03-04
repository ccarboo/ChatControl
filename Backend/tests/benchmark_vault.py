import sys
import os
import tracemalloc
import time
import base64
import json
from cryptography.fernet import Fernet
import nacl.secret
import nacl.utils

# Aggiungi il path della root del Backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import cifra_vault, decifra_vault, deriva_master_key

# Re-implementazione dummy locale del VECCHIO cifra_vault per fare il confronto
def old_cifra_vault(dinizionario, master_key):
    json_data = json.dumps(dinizionario)
    f = Fernet(master_key)
    return f.encrypt(json_data.encode())

def old_decifra_vault(blob, master_key):
    f = Fernet(master_key)
    return json.loads(f.decrypt(blob).decode())

def run_vault_benchmark():
    print("=" * 60)
    print("🛡️ BENCHMARK VAULT: PYNACL (Nuovo) vs FERNET (Vecchio) 🛡️")
    print("=" * 60)

    # Genera Master Key realistica
    passphrase = "password_super_sicura_123!"
    salt = os.urandom(16)
    master_key_b64 = deriva_master_key(passphrase, salt)

    # Finto Vault (Dizionario molto grande per stress test)
    vault_data = {
        "user_id": 999123,
        "username": "utente_test",
        "chiavi": [{"chiave": f"chiave_pubblica_finta_lunga_{i}", "inizio": time.time(), "fine": None} for i in range(1000)]
    }

    # --- TEST 1: VECCHIO FERNET ---
    print("\n--- TEST FERNET (AES-CBC) ---")
    tracemalloc.start()
    start_t = time.perf_counter()
    old_blob = old_cifra_vault(vault_data, master_key_b64)
    old_time_enc = (time.perf_counter() - start_t) * 1000
    _, peak_enc_old = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    start_t = time.perf_counter()
    _ = old_decifra_vault(old_blob, master_key_b64)
    old_time_dec = (time.perf_counter() - start_t) * 1000
    _, peak_dec_old = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    old_size = len(old_blob)
    print(f"Cifratura   : {old_time_enc:.2f} ms | Picco RAM: {peak_enc_old/1024:.2f} KB | Size Output: {old_size/1024:.2f} KB")
    print(f"Decifratura : {old_time_dec:.2f} ms | Picco RAM: {peak_dec_old/1024:.2f} KB")

    # --- TEST 2: NUOVO PYNACL ---
    print("\n--- TEST PYNACL (SecretBox XSalsa20) ---")
    tracemalloc.start()
    start_t = time.perf_counter()
    new_blob = cifra_vault(vault_data, master_key_b64)
    new_time_enc = (time.perf_counter() - start_t) * 1000
    _, peak_enc_new = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    start_t = time.perf_counter()
    _ = decifra_vault(new_blob, master_key_b64)
    new_time_dec = (time.perf_counter() - start_t) * 1000
    _, peak_dec_new = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    new_size = len(new_blob)
    print(f"Cifratura   : {new_time_enc:.2f} ms | Picco RAM: {peak_enc_new/1024:.2f} KB | Size Output: {new_size/1024:.2f} KB")
    print(f"Decifratura : {new_time_dec:.2f} ms | Picco RAM: {peak_dec_new/1024:.2f} KB")

    # --- TEST 3: COMPATIBILITÀ RETROATTIVA ---
    print("\n--- TEST FALLBACK RETROATTIVITÀ ---")
    start_t = time.perf_counter()
    risultato_fallback = decifra_vault(old_blob, master_key_b64)
    t_fallback = (time.perf_counter() - start_t) * 1000
    if risultato_fallback.get('user_id') == 999123:
        print(f"✅ Passato: Il nuovo sistema decifra correttamente i vecchi salvataggi AES! ({t_fallback:.2f} ms)")
    else:
        print("❌ Errore critico nel fallback retroattivo.")

if __name__ == "__main__":
    run_vault_benchmark()
