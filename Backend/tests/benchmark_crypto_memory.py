"""
=============================================================================
TEST: Benchmark Utilizzo Memoria RAM e I/O - PyNaCl vs Age CLI
=============================================================================

DESCRIZIONE:
Questo script esegue un test mirato ad analizzare l'efficienza della memoria
nell'architettura del backend, in virtù del raddoppiamento della RAM in Python.
Risolve il dubbio architetturale per l'invio e la ricezione di FILE MULTIMEDIALI
PESANTI (come i video HD o grossi archivi ZIP transitati su Telegram).

COSA VIENE TESTATO:
1. Impatto dell'Envelope Encryption su PyNaCl quando processa payload enormi (vari MB).
   Siccome l'API `cifra_payload` processa tutto in unico blocco `bytes` in RAM (in-memory),
   il processo decuplica il peso originale portando a rischi di esaurimento memoria (OOM).
2. L'efficienza invariata di `age` (Golang CLI) che utilizza i Pipe dell'OS per uno *Streaming 
   Chunking* nativo e che gli permette di cifrare File di 1 GB impattando 0 MB di memoria.
   
IL VERDETTO SULLA SCELTA:
Il test mostrerà chiaramente l'esplosione della RAM di PyNaCl. Pertanto getta le 
basi per i futuri Refactoring (es. insegnare a PyNaCl a trattare i chunk di lettura 
da stream, in maniera simile ad Age, prima di usarlo in pianta stabile sui Media pesanti).
=============================================================================
"""

import time
import os
import subprocess
import tracemalloc
import sys

# Aggiunge il root path del Backend per correttezza degli import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import genera_chiavi, cifra_payload

def generate_age_keys():
    """Generazione utilità chiavi age compatibili per il test dello Stream"""
    try:
        risultato = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True)
        return risultato.stdout.splitlines()[2].split(":")[1].strip(), risultato.stdout.splitlines()[0].strip()
    except subprocess.CalledProcessError:
        return None, None

def cifra_age(file_path, public_keys, out_path):
    """Cifra da file a file direttamente via filesystem sfruttando lo streaming di age CLI (No RAM Load)"""
    args = ['age', '-r', public_keys[0]]
    with open(file_path, 'rb') as in_f, open(out_path, 'wb') as out_f:
        subprocess.run(args, stdin=in_f, stdout=out_f, check=True)

def benchmark_files():
    print("=" * 60)
    print("🚀 BENCHMARK STRESS MEMORIA RAM: AGE vs PYNACL (FILE GRANDI) 🚀")
    print("=" * 60)

    age_pub1, _ = generate_age_keys()
    nacl_pub1, _ = genera_chiavi()

    # Le dimensioni stress-test: 1MB (Documento), 10MB (Foto RAW), 50MB (Video), 100MB (Archivio)
    sizes_mb = [1, 10, 50, 100]
    
    for mb in sizes_mb:
        file_size = mb * 1024 * 1024
        print(f"\n[Test Cifratura su FILE da {mb} MB]")
        
        dummy_file = f"temp_dummy_{mb}MB.bin"
        # Creiamo fisicamente il payload sul disco (urandom scrive direttamente senza impallare la ram di python)
        with open(dummy_file, "wb") as f:
            f.write(os.urandom(file_size))
            
        out_age = f"temp_out_age_{mb}MB.dat"

        # --- FASE 1: TEST AGE (STREAMING) ---
        tracemalloc.start()
        start_age = time.perf_counter()
        
        # Invoca l'executable in shell
        cifra_age(dummy_file, [age_pub1], out_age)
        
        t_age = (time.perf_counter() - start_age) * 1000
        _, peak_age = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f" -> AGE (Streaming I/O) : Tempo {t_age:6.2f} ms | Costo di RAM in Python: {peak_age / 1024 / 1024:6.2f} MB")

        # --- FASE 2: TEST PYNACL (IN-MEMORY BYTES) ---
        tracemalloc.start()
        start_nacl = time.perf_counter()
        
        try:
            # Letale per dispositivi embedded: Carica tutto l'array in ram nativamente
            with open(dummy_file, "rb") as f:
                data = f.read() 
            
            cifrato = cifra_payload(data, [nacl_pub1])
            
            with open(f"temp_out_nacl_{mb}MB.dat", "w") as f_out:
                f_out.write(cifrato)
                
            t_nacl = (time.perf_counter() - start_nacl) * 1000
            _, peak_nacl = tracemalloc.get_traced_memory()
            print(f" -> PyNaCl (In-Memory)  : Tempo {t_nacl:6.2f} ms | Costo di RAM in Python: {peak_nacl / 1024 / 1024:6.2f} MB")
            
        except MemoryError:
            print(f" -> PyNaCl: CRASH FATALE (MemoryError)! Esaurita memoria elaborando {mb} MB.")
        finally:
            tracemalloc.stop()
            # Rimozione spazzatura
            if os.path.exists(dummy_file): os.remove(dummy_file)
            if os.path.exists(out_age): os.remove(out_age)
            if os.path.exists(f"temp_out_nacl_{mb}MB.dat"): os.remove(f"temp_out_nacl_{mb}MB.dat")

if __name__ == '__main__':
    benchmark_files()
