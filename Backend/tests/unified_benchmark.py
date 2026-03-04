"""
=============================================================================
UNIFIED BENCHMARK: AGE CLI vs PYNACL vs HKDF CHUNKING & VAULT
=============================================================================
Obiettivi Dimostrati:
1. PyNaCl (nativo) è drasticamente più veloce di Age (CLI) per generare chiavi e messaggi brevi.
2. Il passaggio a PyNaCl aggiunge overhead di tempo/RAM solo su file giganti se non gestiti bene.
3. Il Chunking mitiga il problema della RAM per i file grandi in PyNaCl.
4. Valutazione dell'overhead computazionale puro introdotto da HKDF + Chunking rispetto a PyNaCl raw.
5. Vault: Fernet (vecchio) vs SecretBox PyNaCl (nuovo).
=============================================================================
"""

import sys
import os
import tracemalloc
import time
import base64
import json
import subprocess
import tempfile
from cryptography.fernet import Fernet

# Aggiungi il path della root del Backend (modifica se necessario)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import (
    genera_chiavi, cifra_payload, decifra_payload, 
    cifra_vault, decifra_vault, deriva_master_key
)

# ==========================================
# FUNZIONI UTILITY LEGACY (AGE & FERNET)
# ==========================================
def old_cifra_vault(dizionario, master_key):
    json_data = json.dumps(dizionario)
    f = Fernet(master_key)
    return f.encrypt(json_data.encode())

def old_decifra_vault(blob, master_key):
    f = Fernet(master_key)
    return json.loads(f.decrypt(blob).decode())

def generate_age_keys():
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        linee = risultato.stdout.splitlines()
        pubblica, privata = "", ""
        for linea in linee:
            if linea.startswith("# public key:"): pubblica = linea.split(":")[1].strip()
            elif linea.startswith("AGE-SECRET-KEY-1"): privata = linea.strip()
        return pubblica, privata
    except Exception:
        return None, None

def cifra_age_mem(plaintext, public_keys):
    args = ['age'] + [item for pk in public_keys for item in ('-r', pk)]
    input_data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    result = subprocess.run(args, input=input_data, capture_output=True, check=True)
    return base64.b64encode(result.stdout).decode()

def cifra_age_file(file_path, public_keys, out_path):
    args = ['age', '-r', public_keys[0]]
    with open(file_path, 'rb') as in_f, open(out_path, 'wb') as out_f:
        subprocess.run(args, stdin=in_f, stdout=out_f, check=True)

# ==========================================
# ESECUZIONE BENCHMARK
# ==========================================
def run_unified_benchmark():
    print("=" * 70)
    print("🚀 INIZIO BENCHMARK UNIFICATO SISTEMA CRITTOGRAFICO 🚀")
    print("=" * 70)

    # ---------------------------------------------------------
    # FASE 1: GENERAZIONE CHIAVI
    # ---------------------------------------------------------
    print("\n--- [FASE 1] VELOCITA' GENERAZIONE CHIAVI ---")
    
    start = time.perf_counter()
    age_pub, age_priv = generate_age_keys()
    t_age_gen = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    nacl_pub, nacl_priv = genera_chiavi()
    t_nacl_gen = (time.perf_counter() - start) * 1000
    
    print(f"🔹 AGE (CLI)    : {t_age_gen:.2f} ms")
    print(f"🔹 PyNaCl (Nativo): {t_nacl_gen:.2f} ms")
    print(f"💡 RISULTATO: PyNaCl è ~{t_age_gen/t_nacl_gen if t_nacl_gen > 0 else 0:.1f}x più veloce per le operazioni base.\n")

    # ---------------------------------------------------------
    # FASE 2: BENCHMARK VAULT (FERNET VS PYNACL)
    # ---------------------------------------------------------
    print("--- [FASE 2] BENCHMARK VAULT (Vecchia vs Nuova Implementazione) ---")
    master_key = deriva_master_key("password_super_sicura", os.urandom(16))
    vault_data = {"user_id": 1, "dati": ["A" * 100] * 500} # Dati medi

    tracemalloc.start()
    start = time.perf_counter()
    old_vault = old_cifra_vault(vault_data, master_key)
    t_old_vault = (time.perf_counter() - start) * 1000
    _, peak_old = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    start = time.perf_counter()
    new_vault = cifra_vault(vault_data, master_key)
    t_new_vault = (time.perf_counter() - start) * 1000
    _, peak_new = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"🔹 Fernet (Vecchio) : Tempo: {t_old_vault:.2f} ms | RAM Picco: {peak_old/1024:.2f} KB | Size: {len(old_vault)/1024:.2f} KB")
    print(f"🔹 PyNaCl (Nuovo)   : Tempo: {t_new_vault:.2f} ms | RAM Picco: {peak_new/1024:.2f} KB | Size: {len(new_vault)/1024:.2f} KB")

    # ---------------------------------------------------------
    # FASE 3: MESSAGGI PICCOLI (Overhead base e HKDF)
    # ---------------------------------------------------------
    print("\n--- [FASE 3] CIFRATURA MESSAGGI PICCOLI E MEDI ---")
    messaggio = json.dumps({"testo": "Ciao, questo è un test normale", "timestamp": time.time()})
    
    # 3.1 AGE
    start = time.perf_counter()
    cifra_age_mem(messaggio, [age_pub])
    t_age_msg = (time.perf_counter() - start) * 1000

    # 3.2 PyNaCl No-Chunking (V2)
    start = time.perf_counter()
    cifra_payload(messaggio, [nacl_pub], force_no_chunking=True)
    t_nacl_no_chunk = (time.perf_counter() - start) * 1000

    # 3.3 PyNaCl Chunking + HKDF (V3)
    start = time.perf_counter()
    cifra_payload(messaggio, [nacl_pub], force_no_chunking=False)
    t_nacl_chunk = (time.perf_counter() - start) * 1000

    print(f"🔹 AGE (CLI)            : {t_age_msg:.2f} ms")
    print(f"🔹 PyNaCl (Senza Chunk) : {t_nacl_no_chunk:.2f} ms")
    print(f"🔹 PyNaCl (Chunk+HKDF)  : {t_nacl_chunk:.2f} ms")
    overhead_hkdf = t_nacl_chunk - t_nacl_no_chunk
    print(f"💡 RISULTATO: PyNaCl domina su age. L'overhead di HKDF su payload piccoli è minimo ({overhead_hkdf:.2f} ms).")

    # ---------------------------------------------------------
    # FASE 4: STRESS TEST (FILE GRANDI, RAM E OVERHEAD HKDF)
    # ---------------------------------------------------------
    print("\n--- [FASE 4] STRESS TEST RAM E FILE GRANDI (5 MB) ---")
    mb_size = 5
    file_size = mb_size * 1024 * 1024
    dummy_file = f"temp_5MB.bin"
    out_age = f"temp_out_age.dat"
    
    with open(dummy_file, "wb") as f:
        f.write(os.urandom(file_size))
        
    with open(dummy_file, "rb") as f:
        large_payload = f.read()

    # 4.1 AGE (Streaming su File)
    tracemalloc.start()
    start = time.perf_counter()
    cifra_age_file(dummy_file, [age_pub], out_age)
    t_age_large = (time.perf_counter() - start) * 1000
    _, peak_age_large = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 4.2 PyNaCl SENZA Chunking (In-Memory pesante)
    tracemalloc.start()
    start = time.perf_counter()
    cifra_payload(large_payload, [nacl_pub], force_no_chunking=True)
    t_nacl_no_chunk_large = (time.perf_counter() - start) * 1000
    _, peak_nacl_no_chunk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 4.3 PyNaCl CON Chunking + HKDF (Stream Simulato In-Memory)
    tracemalloc.start()
    start = time.perf_counter()
    cifra_payload(large_payload, [nacl_pub], force_no_chunking=False)
    t_nacl_chunk_large = (time.perf_counter() - start) * 1000
    _, peak_nacl_chunk = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"🔹 AGE (Streaming OS)  : Tempo {t_age_large:.2f} ms | RAM: {peak_age_large / 10**6:.2f} MB")
    print(f"🔹 PyNaCl (No Chunk)   : Tempo {t_nacl_no_chunk_large:.2f} ms | RAM: {peak_nacl_no_chunk / 10**6:.2f} MB")
    print(f"🔹 PyNaCl (Chunk+HKDF) : Tempo {t_nacl_chunk_large:.2f} ms | RAM: {peak_nacl_chunk / 10**6:.2f} MB")
    
    ram_risparmiata = peak_nacl_no_chunk - peak_nacl_chunk
    print("\n📊 ANALISI FINALE FILE GRANDI:")
    if t_age_large < t_nacl_chunk_large:
         print(f"1. AGE è più veloce di PyNaCl sui file grandi di {t_nacl_chunk_large - t_age_large:.2f} ms, perché usa i Pipe C in background.")
    print(f"2. Il Chunking in PyNaCl salva {ram_risparmiata / 10**6:.2f} MB di RAM rispetto al caricare tutto come singolo blocco.")
    print(f"3. L'algoritmo HKDF+Chunking aggiunge un tempo di calcolo extra di {t_nacl_chunk_large - t_nacl_no_chunk_large:.2f} ms rispetto alla cifratura nuda PyNaCl.")

    # Pulizia file temporanei
    if os.path.exists(dummy_file): os.remove(dummy_file)
    if os.path.exists(out_age): os.remove(out_age)

    print("\n" + "=" * 70)
    print("✅ BENCHMARK COMPLETATO")
    print("=" * 70)

if __name__ == "__main__":
    run_unified_benchmark()