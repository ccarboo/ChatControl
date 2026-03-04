import sys
import os
import base64
import json

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from services.crypto_service import genera_chiavi, cifra_payload, decifra_payload

def run_test():
    print("1. Generazione chiavi Utente A (Sender) e Utente B (Receiver)...")
    pub_A, priv_A = genera_chiavi()
    pub_B, priv_B = genera_chiavi()
    
    msg_chiaro = "Test segreto con Envelope v3 (ECDH + HKDF)."
    print(f"Messaggio originale: {msg_chiaro}")
    
    print("\n2. Cifratura payload da parte di A (versione Envelope v3)...")
    try:
        payload_cifrato = cifra_payload(msg_chiaro, [pub_B])
        print("Cifratura completata senza eccezioni!")
    except Exception as e:
        print(f"ECCEZIONE durante cifratura: {e}")
        return
    
    if not payload_cifrato:
        print("ERRORE: Cifratura fallita!")
        return
        
    print(f"Payload (Base64 Envelope): {payload_cifrato[:50]}...")
    
    # Ispeziona Envelope per verificare versione v3
    envelope_raw = base64.b64decode(payload_cifrato).decode()
    envelope_json = json.loads(envelope_raw)
    print(f"Versione Envelope: {envelope_json.get('v')}")
    if envelope_json.get('v') != 3:
         print("ERRORE ARCHITETTURALE: L'envelope generato non è v3!")
    
    print("\n3. Decifratura del payload da parte di B...")
    decifrato_bytes = decifra_payload(payload_cifrato, [priv_B])
    
    if not decifrato_bytes:
         print("ERRORE: Decifrazione fallita. I byte sono None.")
         return
         
    msg_decifrato = decifrato_bytes.decode()
    print(f"Messaggio decifrato: {msg_decifrato}")
    
    if msg_decifrato == msg_chiaro:
         print("\nSUCCESSO! Il processo Envelope Encryption v3 con HKDF funziona perfettamente.")
    else:
         print("\nFALLITO! I messaggi non corrispondono.")

if __name__ == "__main__":
    run_test()
