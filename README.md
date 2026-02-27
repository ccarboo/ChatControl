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

I requisiti python verranno gestiti dall'ambiente virtuale `.venv` (es. `fastapi`, `uvicorn`, `telethon` e `cryptography`).

### 2. Setup dell'Ambiente
Crea un file `.env` nella directory `ChatControl/Backend/` configurando i segreti per l'hashing anonimizzato e la criptazione simmetrica:

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
