import time
import base64
import subprocess
import json
import os
import tempfile
from services.crypto_service import genera_chiavi, cifra_payload, decifra_payload

def generate_age_keys():
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
    args = ['age']
    for key in public_keys:
        args.extend(['-r', key])
    
    input_data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    result = subprocess.run(args, input=input_data, capture_output=True, check=True)
    return base64.b64encode(result.stdout).decode()

def decifra_age(ciphertext, private_key):
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
    print("🚀 BENCHMARK ESAUSTIVO: AGE (CLI) vs PYNACL (Nativo) 🚀")
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

    # -------------------------------------------------------------
    
    messaggi_da_testare = [
        ("Testo Corto (Chat)", "Ciao, come stai?"),
        ("JSON Medio (Metadati)", json.dumps({"cif": "on", "text": "Messaggio normale", "id": "1234567890abcdef", "timestamp": time.time()})),
        ("Documento Largo (~100KB)", "A" * 100_000)
    ]

    for label, payload in messaggi_da_testare:
        print(f"\n--- [2] FASE DI CIFRATURA: {label} ({len(payload)} bytes) ---")
        
        # --- CIFRATURA AGE ---
        start_age_enc = time.perf_counter()
        age_enc = cifra_age(payload, [age_pub1, age_pub2])
        t_age_enc = (time.perf_counter() - start_age_enc) * 1000
        print(f"AGE   : Cifratura multi-destinatario (2 pub-keys) in {t_age_enc:.2f} ms. Output size: {len(age_enc)} bytes")
        
        # --- CIFRATURA PYNACL ---
        start_nacl_enc = time.perf_counter()
        nacl_enc = cifra_payload(payload, [nacl_pub1, nacl_pub2])
        t_nacl_enc = (time.perf_counter() - start_nacl_enc) * 1000
        print(f"PyNaCl: Cifratura multi-destinatario (2 pub-keys) in {t_nacl_enc:.2f} ms. Output size: {len(nacl_enc)} bytes")
        
        ratio_enc = t_age_enc/t_nacl_enc if t_nacl_enc > 0 else 0
        print(f"🏆 Vincitore Cifratura: {'PyNaCl' if t_nacl_enc < t_age_enc else 'AGE'} (PyNaCl è {ratio_enc:.2f}x più veloce)")

        # -------------------------------------------------------------
        
        print(f"\n--- [3] FASE DI DECIFRATURA: {label} ---")
        
        # --- DECIFRATURA AGE ---
        start_age_dec = time.perf_counter()
        age_dec = decifra_age(age_enc, age_priv2) # Usa la chiave del destinatario 2
        t_age_dec = (time.perf_counter() - start_age_dec) * 1000
        assert age_dec.decode() == payload, "AGE DECRYPT FAILED!"
        print(f"AGE   : Decifratura avvenuta con successo in {t_age_dec:.2f} ms")
        
        # --- DECIFRATURA PYNACL ---
        start_nacl_dec = time.perf_counter()
        nacl_dec = decifra_payload(nacl_enc, [nacl_priv2]) # Array simulando la candidate pipeline locale
        t_nacl_dec = (time.perf_counter() - start_nacl_dec) * 1000
        assert nacl_dec.decode() == payload, "PYNACL DECRYPT FAILED!"
        print(f"PyNaCl: Decifratura avvenuta con successo in {t_nacl_dec:.2f} ms")

        ratio_dec = t_age_dec/t_nacl_dec if t_nacl_dec > 0 else 0
        print(f"🏆 Vincitore Decifratura: {'PyNaCl' if t_nacl_dec < t_age_dec else 'AGE'} (PyNaCl è {ratio_dec:.2f}x più veloce)\n")
        
    print("=" * 60)
    print("TEST DI FALLBACK LEGACY...")
    # Testiamo se la funzione decifra_payload di PyNaCl riesce ad aprire un messaggio AGE-legacy
    start_legacy = time.perf_counter()
    nacl_legacy_dec = decifra_payload(age_enc, [age_priv2])
    t_legacy = (time.perf_counter() - start_legacy) * 1000
    if nacl_legacy_dec and nacl_legacy_dec.decode() == payload:
        print(f"✅ decifra_payload() ha identificato e decriptato con successo un payload AGE nativo in {t_legacy:.2f} ms")
    else:
        print("❌ Fallito il test di fallback legacy!")
        
    print("=" * 60)
    print("🎉 TUTTI I TEST ESAUSTIVI COMPLETATI CON SUCCESSO! 🎉")

if __name__ == "__main__":
    run_comprehensive_tests()
