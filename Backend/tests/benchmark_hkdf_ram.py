import sys
import os
import tracemalloc
import time
import base64
import json

# Aggiungi il path della root del Backend
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import genera_chiavi, cifra_payload, decifra_payload

def run_ram_benchmark():
    print("=" * 60)
    print("🧠 BENCHMARK RAM E VELOCITÀ: HKDF LIGHTWEIGHT CHUNKING 🧠")
    print("=" * 60)

    # 1. Generazione chiavi
    pub_a, priv_a = genera_chiavi()
    pub_b, priv_b = genera_chiavi()

    # 2. Creazione Payload Pesante (Es. ~5MB di testo ripetuto)
    print("\nGenerazione payload da 5MB in RAM...")
    payload_gigante = "A" * (5 * 1024 * 1024)
    
    # ---------------------------------------------------------
    # TEST 1: SENZA CHUNKING (Legacy Mode)
    # ---------------------------------------------------------
    print("\n--- 🔴 TEST 1: SENZA CHUNKING (Single Block) 🔴 ---")
    tracemalloc.start()
    
    start_time_nochunk = time.perf_counter()
    cifrato_nochunk = cifra_payload(payload_gigante, [pub_b], force_no_chunking=True)
    end_time_nochunk = time.perf_counter()
    
    current_nc, peak_nc = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"Tempo di Cifratura : {(end_time_nochunk - start_time_nochunk) * 1000:.2f} ms")
    print(f"PICCO MAX RAM      : {peak_nc / 10**6:.2f} MB")
    
    env_json_nc = json.loads(base64.b64decode(cifrato_nochunk).decode('utf-8'))
    print(f"Stato Chunking JSON: {'ATTIVO' if env_json_nc.get('chunked') else 'DISATTIVO'}")

    tracemalloc.start()
    start_time_dec_nc = time.perf_counter()
    decifra_payload(cifrato_nochunk, [priv_b])
    end_time_dec_nc = time.perf_counter()
    _, peak_dec_nc = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"PICCO DECIFRATURA  : {peak_dec_nc / 10**6:.2f} MB")

    # ---------------------------------------------------------
    # TEST 2: CON CHUNKING (New Mode)
    # ---------------------------------------------------------
    print("\n--- 🟢 TEST 2: CON CHUNKING (Lightweight Stream) 🟢 ---")
    tracemalloc.start()
    
    start_time_chunk = time.perf_counter()
    cifrato_chunk = cifra_payload(payload_gigante, [pub_b], force_no_chunking=False)
    end_time_chunk = time.perf_counter()
    
    current_c, peak_c = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"Tempo di Cifratura : {(end_time_chunk - start_time_chunk) * 1000:.2f} ms")
    print(f"PICCO MAX RAM      : {peak_c / 10**6:.2f} MB")
    
    env_json_c = json.loads(base64.b64decode(cifrato_chunk).decode('utf-8'))
    chunks_count = len(env_json_c.get('data', [])) if env_json_c.get('chunked') else 1
    print(f"Stato Chunking JSON: {'ATTIVO' if env_json_c.get('chunked') else 'DISATTIVO'} ({chunks_count} frammenti)")
    
    tracemalloc.start()
    start_time_dec_c = time.perf_counter()
    decifra_payload(cifrato_chunk, [priv_b])
    end_time_dec_c = time.perf_counter()
    _, peak_dec_c = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"PICCO DECIFRATURA  : {peak_dec_c / 10**6:.2f} MB")

    # ---------------------------------------------------------
    # RISULTATI
    # ---------------------------------------------------------
    print("\n" + "=" * 60)
    print("📊 RISULTATI COMPARATI")
    print("=" * 60)
    ram_risparmiata = peak_nc - peak_c
    if ram_risparmiata > 0:
        print(f"Risparmio RAM durante cifratura: {ram_risparmiata / 10**6:.2f} MB (-{(ram_risparmiata/peak_nc)*100:.1f}%)")
    else:
        print(f"⚠️ Nessun risparmio RAM evidente o peggioramento: {(peak_c - peak_nc) / 10**6:.2f} MB extra.")
        
    ram_risparmiata_dec = peak_dec_nc - peak_dec_c
    if ram_risparmiata_dec > 0:
        print(f"Risparmio RAM durante decifratura: {ram_risparmiata_dec / 10**6:.2f} MB (-{(ram_risparmiata_dec/peak_dec_nc)*100:.1f}%)")
    
    print("\n✅ TEST COMPLETATO STABILMENTE.")


if __name__ == "__main__":
    run_ram_benchmark()
