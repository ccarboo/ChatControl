import time
import os
import sys
import tracemalloc
import tempfile
import json
from base64 import b64decode, b64encode

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.crypto_service import genera_chiavi, cifra_payload, cifra_payload_stream, decifra_payload, decifra_payload_stream
from services.message_service import CAPTION_LIMIT

def generate_dummy_file(mb_size: int, filename: str):
    file_size = mb_size * 1024 * 1024
    with open(filename, "wb") as f:
        f.write(os.urandom(file_size))
    return filename

def benchmark_speed_and_memory():
    print("=" * 60)
    print("🚀 UNIFIED BENCHMARK: V1 STREAMING vs V3 MEMORY (SPEED & RAM) 🚀")
    print("=" * 60)

    pub1, priv1 = genera_chiavi()
    sizes_mb = [1, 5, 25]
    
    for mb in sizes_mb:
        print(f"\n--- [Test File from {mb} MB] ---")
        dummy_in = f"temp_in_{mb}MB.bin"
        generate_dummy_file(mb, dummy_in)
        
        # === 1. LEGACY V3 MEMORY BENCHMARK ===
        dummy_out_v3 = f"temp_out_v3_{mb}.dat"
        print(f"[{mb}MB] Testing Legacy V3 Memory Approach...")
        
        tracemalloc.start()
        start_t = time.perf_counter()
        
        try:
            with open(dummy_in, "rb") as f:
                data = f.read()
            cifrato = cifra_payload(data, [pub1])
            with open(dummy_out_v3, "w") as f_out:
                f_out.write(cifrato)
            
            t_enc_v3 = (time.perf_counter() - start_t) * 1000
            _, peak_enc_v3 = tracemalloc.get_traced_memory()
            
            # Legacy Decryption
            tracemalloc.clear_traces()
            start_t = time.perf_counter()
            with open(dummy_out_v3, "r") as f_in:
                cif_data = f_in.read()
            decifrato = decifra_payload(cif_data, [priv1])
            t_dec_v3 = (time.perf_counter() - start_t) * 1000
            _, peak_dec_v3 = tracemalloc.get_traced_memory()
            
            print(f" -> V3 Encrypt: {t_enc_v3:6.2f} ms | RAM Peak: {peak_enc_v3 / 1024 / 1024:6.2f} MB")
            print(f" -> V3 Decrypt: {t_dec_v3:6.2f} ms | RAM Peak: {peak_dec_v3 / 1024 / 1024:6.2f} MB")
            
        except MemoryError:
            print(f" -> V3: CRASH FATALE (MemoryError) elaborando {mb} MB.")
        except Exception as e:
            print(f" -> V3: ERRORE: {e}")
        finally:
            tracemalloc.stop()
            
        # === 2. NEW V1 STREAM BENCHMARK ===
        dummy_out_v1 = f"temp_out_v1_{mb}.dat"
        dummy_dec_v1 = f"temp_dec_v1_{mb}.dat"
        print(f"[{mb}MB] Testing New V1 Stream Approach...")
        
        tracemalloc.start()
        start_t = time.perf_counter()
        
        def file_chunk_generator(filepath, chunk_size=1024*1024):
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk: break
                    yield chunk

        try:
            with open(dummy_out_v1, "wb") as f_out:
                for chunk in cifra_payload_stream(file_chunk_generator(dummy_in), [pub1]):
                    f_out.write(chunk)
                    
            t_enc_v1 = (time.perf_counter() - start_t) * 1000
            _, peak_enc_v1 = tracemalloc.get_traced_memory()
            
            # Stream Decryption
            tracemalloc.clear_traces()
            start_t = time.perf_counter()
            
            # Wrap as an async generator helper for testing sync-to-async decoding
            async def test_async_wrapper(filepath):
                for chunk in file_chunk_generator(filepath):
                    yield chunk

            # Since decifra_payload_stream generates using an async_generator
            import asyncio
            async def run_decryption():
                with open(dummy_dec_v1, "wb") as fd_out:
                    async for chunk in decifra_payload_stream(test_async_wrapper(dummy_out_v1), [priv1]):
                        fd_out.write(chunk)
                        
            asyncio.run(run_decryption())
            
            t_dec_v1 = (time.perf_counter() - start_t) * 1000
            _, peak_dec_v1 = tracemalloc.get_traced_memory()
            
            print(f" -> V1 Encrypt: {t_enc_v1:6.2f} ms | RAM Peak: {peak_enc_v1 / 1024 / 1024:6.2f} MB")
            print(f" -> V1 Decrypt: {t_dec_v1:6.2f} ms | RAM Peak: {peak_dec_v1 / 1024 / 1024:6.2f} MB")
            
            # Verify integrity
            with open(dummy_in, "rb") as o, open(dummy_dec_v1, "rb") as d:
                assert o.read() == d.read(), "Integrity Check Failed! Decoded file does not match original."
                
        finally:
            tracemalloc.stop()
            for tmp in [dummy_in, dummy_out_v3, dummy_out_v1, dummy_dec_v1]:
                if os.path.exists(tmp): os.remove(tmp)

def api_convenience_test():
    print("\n" + "=" * 60)
    print("🔍 API CONVENIENCE & INTEGRITY TEST")
    print("=" * 60)
    
    pub1, priv1 = genera_chiavi()
    data = b"Hello Stream API! The quick brown fox jumps over the lazy dog."
    
    def generator(): yield data
    
    # 1. Encrypt directly from a minimal generator to memory
    enc_stream = list(cifra_payload_stream(generator(), [pub1]))
    full_encrypted = b"".join(enc_stream)
    
    print(f"Successfully encrypted {len(data)} bytes into {len(full_encrypted)} bytes using V1 Generator API")
    
    # 2. Decrypt it back
    import asyncio
    async def async_gen(): yield full_encrypted
    
    async def decrypt_test():
        decrypted_chunks = []
        async for chunk in decifra_payload_stream(async_gen(), [priv1]):
            decrypted_chunks.append(chunk)
        return b"".join(decrypted_chunks)
        
    result = asyncio.run(decrypt_test())
    
    if result == data:
        print("✅ Integration test V1 Stream: PASSED")
    else:
        print("❌ Integration test V1 Stream: FAILED")

if __name__ == '__main__':
    api_convenience_test()
    benchmark_speed_and_memory()