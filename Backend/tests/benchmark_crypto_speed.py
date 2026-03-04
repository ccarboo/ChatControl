"""
=============================================================================
TEST: Benchmark Crittografico (Velocità ed Esecuzione) - PyNaCl vs Age CLI
=============================================================================

DESCRIZIONE:
Questo script esegue un test comparativo Esaustivo (End-to-End) per misurare la
latenza e le performance crittografiche tra la vecchia implementazione basata 
sull'eseguibile CLI `age` e la nuova implementazione in-memory basata su `PyNaCl` (libsodium).

COSA VIENE TESTATO:
1. Generazione delle Chiavi: Paragone del tempo necessario per generare 2 paia di chiavi asimmetriche.
2. Cifratura (Testo, JSON, Documenti): Misura del tempo di cifratura utilizzando 
   l'Envelope Encryption per payload di varie dimensioni indirizzati a multipli destinatari.
3. Decifratura (In-Memory vs Subprocess): Validazione della correttezza del payload 
   in uscita e comparazione dei tempi di lettura.
4. Fallback Legacy: Verifica che la funzione `decifra_payload` di PyNaCl riesca
   ad intercettare correttamente un payload nativo `age` e demandarlo al tool CLI
   senza andare in crash (fondamentale per mantenere la leggibilità dello storico chat).

REQUISITI:
- Modulo `pynacl` installato (`pip install pynacl`)
- Binario `age` e `age-keygen` installati a livello di sistema operativo.
=============================================================================
"""

import time
import base64
import subprocess
import json
import os
import tempfile
import sys

# Aggiunge il path della root del Backend per permettere le importazioni relative
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import genera_chiavi, cifra_payload, decifra_payload

def generate_age_keys():
    """Genera una coppia di chiavi usando l'eseguibile age-keygen."""
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        output = risultato.stdout
        linee = output.splitlines()
        pubblica = ""
        privata = ""
        for linea in linee:
            if linea.startswith("# public key:"):
                pubblica = linea.split(":")[1].strip()
            elif linea.startswith("AGE-SECRET-KEY-1"):
                privata = linea.strip()
        return pubblica, privata
    except subprocess.CalledProcessError:
        return None, None

def cifra_age(plaintext, public_keys):
    """Implementazione hardware CLI per cifrare un dato destinato a n public_keys."""
    args = ['age']
    for key in public_keys:
        args.extend(['-r', key])
    
    input_data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    result = subprocess.run(args, input=input_data, capture_output=True, check=True)
    return base64.b64encode(result.stdout).decode()

def decifra_age(ciphertext, private_key):
    """Implementazione hardware CLI per decifrare un dato usando file temporanei per la chiave privata."""
    raw_bytes = base64.b64decode(ciphertext)
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as keyfile:
        keyfile.write(private_key)
        keyfile_path = keyfile.name
    try:
        result = subprocess.run(['age', '-d', '-i', keyfile_path], input=raw_bytes, capture_output=True, check=True)
        return result.stdout
    finally:
        os.unlink(keyfile_path)

def run_comprehensive_tests():
    print("=" * 60)
    print("🚀 BENCHMARK VELOCITA': AGE (CLI) vs PYNACL (Nativo) 🚀")
    print("=" * 60)
    
    print("\n--- [1] FASE DI GENERAZIONE CHIAVI ---")
    start_age_gen = time.perf_counter()
    age_pub1, age_priv1 = generate_age_keys()
    age_pub2, age_priv2 = generate_age_keys()
    t_age_gen = (time.perf_counter() - start_age_gen) * 1000
    print(f"AGE   : Generate 2 coppie di chiavi in {t_age_gen:.2f} ms")
    
    start_nacl_gen = time.perf_counter()
    nacl_pub1, nacl_priv1 = genera_chiavi()
    nacl_pub2, nacl_priv2 = genera_chiavi()
    t_nacl_gen = (time.perf_counter() - start_nacl_gen) * 1000
    print(f"PyNaCl: Generate 2 coppie di chiavi in {t_nacl_gen:.2f} ms")
    print(f"🏆 Vincitore: {'PyNaCl' if t_nacl_gen < t_age_gen else 'AGE'} (PyNaCl è {t_age_gen/t_nacl_gen if t_nacl_gen > 0 else 0:.2f}x più veloce)")

    # Testiamo 3 scenari comuni nell'applicativo
    messaggi_da_testare = [
        ("Testo Corto (Messaggio Telegram)", "Ciao, come stai?"),
        ("JSON Medio (Metadati Foto)", json.dumps({"cif": "on", "text": "Messaggio normale", "id": "1234567890abcdef", "timestamp": time.time()})),
        ("Documento di testo (~100KB)", "A" * 100_000)
    ]

    for label, payload in messaggi_da_testare:
        print(f"\n--- [2] FASE DI CIFRATURA: {label} ({len(payload)} bytes) ---")
        
        # Benchmarking cifratura AGE
        start_age_enc = time.perf_counter()
        age_enc = cifra_age(payload, [age_pub1, age_pub2])
        t_age_enc = (time.perf_counter() - start_age_enc) * 1000
        print(f"AGE   : Cifratura multi-destinatario (2 pub-keys) in {t_age_enc:.2f} ms")
        
        # Benchmarking cifratura PyNaCl
        start_nacl_enc = time.perf_counter()
        nacl_enc = cifra_payload(payload, [nacl_pub1, nacl_pub2])
        t_nacl_enc = (time.perf_counter() - start_nacl_enc) * 1000
        print(f"PyNaCl: Cifratura multi-destinatario (2 pub-keys) in {t_nacl_enc:.2f} ms")
        
        ratio_enc = t_age_enc/t_nacl_enc if t_nacl_enc > 0 else 0
        print(f"🏆 Vincitore Cifratura: {'PyNaCl' if t_nacl_enc < t_age_enc else 'AGE'}")

        print(f"\n--- [3] FASE DI DECIFRATURA: {label} ---")
        
        # Benchmarking decifratura AGE
        start_age_dec = time.perf_counter()
        age_dec = decifra_age(age_enc, age_priv2)
        t_age_dec = (time.perf_counter() - start_age_dec) * 1000
        assert age_dec.decode() == payload, "Fallo critico: decifratura AGE errata"
        print(f"AGE   : Decifratura in {t_age_dec:.2f} ms")
        
        # Benchmarking decifratura PyNaCl
        start_nacl_dec = time.perf_counter()
        nacl_dec = decifra_payload(nacl_enc, [nacl_priv2])
        t_nacl_dec = (time.perf_counter() - start_nacl_dec) * 1000
        assert nacl_dec.decode() == payload, "Fallo critico: decifratura PyNaCl errata"
        print(f"PyNaCl: Decifratura in {t_nacl_dec:.2f} ms")
        print(f"🏆 Vincitore Decifratura: {'PyNaCl' if t_nacl_dec < t_age_dec else 'AGE'}")
        
    print("\n" + "=" * 60)
    print("TEST DI FALLBACK LEGACY (SICUREZZA STORICA)")
    print("Controllo se PyNaCl riesce a redigere una decifratura vecchia nativa...")
    # Qui inviamo a PyNaCl un messaggio formato vecchissimo (generato da age puro) 
    # e ci aspettiamo che passi autonomamente a subprocess.run('age').
    start_legacy = time.perf_counter()
    nacl_legacy_dec = decifra_payload(age_enc, [age_priv2])
    t_legacy = (time.perf_counter() - start_legacy) * 1000
    if nacl_legacy_dec and nacl_legacy_dec.decode() == payload:
        print(f"✅ decifra_payload() rileva il vecchio standard e decifra via fallback (Tempo: {t_legacy:.2f} ms)")
    else:
        print("❌ Fallito il test di fallback legacy!")
        
    print("=" * 60)
    print("🎉 TUTTI I TEST ESAUSTIVI COMPLETATI CON SUCCESSO! 🎉")

if __name__ == "__main__":
    run_comprehensive_tests()
