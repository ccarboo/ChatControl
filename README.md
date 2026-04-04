# 🔒 ChatControl

Benvenuto in **ChatControl**, una sofisticata applicazione di messaggistica proxy basata sull'API ufficiale di Telegram (tramite *Telethon*) che aggiunge un **layer di crittografia asimmetrica** inviolabile (basato su `age` e Curve25519) sopra alle tue chat.

ChatControl ti garantisce che né i server di Telegram, né eventuali intercettatori, possano leggere il vero contenuto dei tuoi messaggi criptati, salvaguardando la tua privacy in ogni momento.

---

## ✨ Caratteristiche Principali
- **Crittografia Estrema**: Usa chiavi asimmetriche (Curve25519 via `age`) per proteggere testi e file.
- **Gestione Cifrata dei Vault**: Le chiavi di cifratura non escono mai in chiaro; sono archiviate localmente in SQLite su un Vault locale protetto da chiavi AES (Fernet) e da una chiave master derivata da password tramite algoritmi memory-hard come **Argon2id**.
- **Real-Time WebSocket**: Sincronizzazione in tempo reale e bidirezionale (NewMessage, Deleted, Edited) su base asincrona senza gravare sul DB.
- **Architettura Modulare**: Backend Python a strati (Routes, Services, WebSocket, Core) manutenibile ed elegante a singola responsabilità.

---

## 🚀 Guida all'Installazione e Setup

### 1. Prerequisiti di Sistema
Assicurati di avere le dipendenze essenziali di crittografia installate a livello di OS:
```bash
sudo apt update
sudo apt install age openssl python3-pip python3-venv
```

I requisiti Python sono delineati nel file `requirements.txt` fornito nella root del progetto.

### 2. Setup dell'Ambiente e Installazione
Prima di tutto, crea l'ambiente virtuale (`.venv`), attivalo e installa tutti i pacchetti Python richiesti. Questo passaggio installerà librerie centrali per l'API (come FastAPI, uvicorn, python-dotenv) e per la logica crittografica/proxy (Telethon, Cryptography, PyNaCl):

```bash
# Crea l'ambiente virtuale (eseguire dalla root del progetto)
python3 -m venv .venv

# Attiva l'ambiente virtuale
source .venv/bin/activate

# Installa le dipendenze
pip install -r requirements.txt
```

Successivamente, crea un file `.env` nella directory `ChatControl/Backend/` configurando i segreti per l'hashing anonimizzato e la criptazione simmetrica del Data Vault SQLite:

```env
SECRET_PEPPER=9ed4ecb784384de16c2dc5be86818e0b36db355438acd616a45367f50ffca648c4e5793f4b2e3711093b91b54720fb0dc81d11dbed4ceb8c006cdadd5a8efb5d
SECRET_KEY=PgiGSC2uTj3fTcn4nURonH1CZtFhBw6B9Na1I7P7z7k=
```

### 3. Generazione dei Certificati SSL (TLS)
Affinché i cookie `Secure` del session token e le WebSocket viaggino in sicurezza, l'applicazione *DEVE* operare in HTTPS. 
Genera i file `cert.pem` e `key.pem` nella directory dei certificati del backend.

```bash
cd Backend
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 365 -nodes
```

### 4. Avvio del Backend 
Torna alla root directory, carica l'ambiente virtuale ed esegui `uvicorn` puntando al backend con il TLS abilitato:

```bash
# Esempio dalla root di progetto
source .venv/bin/activate
cd Backend
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./certs/key.pem --ssl-certfile ./certs/cert.pem
```
*(Al primo avvio, il file database `database.db` verrà istanziato con le tre tabelle necessarie: utenti, contatti e contatti_gruppo).*

### 5. Avvio del Frontend (Vue.js)
In un nuovo terminale, esegui il server di sviluppo per la UI in locale:

```bash
cd Frontend
npm install
npm run dev
```

---

### 6. Esecuzione dei Test
Il progetto include una suite di script di test e benchmark all'interno della directory `Backend/tests`. Questi strumenti sono fondamentali per verificare che gli algoritmi crittografici (KX basato su X25519, HKDF) siano integrati bene e che i vault SQLite siano robusti.

Assicurati che l'ambiente virtuale sia attivo ed esegui i moduli dalla directory del Backend in modo da accedere correttamente ai path (es. `services`, `core`):

```bash
# 1. Torna (o assicurati di essere) nel Backend e di avere .venv attivato
source .venv/bin/activate
cd Backend/tests

# 2. Lancia il benchmark unificato per crittografia payload stream e stringhe
python3 -m tests.unified_benchmark

# 3. Lancia il test e benchmark su decifratura/cifratura del vault locale
python3 -m tests.benchmark_vault
```

---


