# VoxLibera (ChatControl)

VoxLibera è un **Crypto-Gateway** per Telegram: un server fidato, pensato per girare su hardware sotto il controllo dell'utente (ad esempio un Raspberry Pi Zero 2 W), che cifra e decifra i messaggi al posto del client Telegram. Telegram vede e trasporta solo contenuti già cifrati, anche nei **gruppi**, dove i secret chat nativi non sono disponibili.

## Requisiti

- Python **3.10 o superiore**
- Node.js **20.19+** (oppure 22.12+) e npm
- OpenSSL (per generare il certificato di sviluppo)
- Su Debian/Ubuntu/Raspberry Pi OS: `sudo apt install python3-venv python3-pip openssl`. Per Node.js usa la versione ufficiale (<https://nodejs.org>) o `nvm`, perché i pacchetti `apt` spesso sono più vecchi di quella richiesta.
- Un account Telegram con **API ID** e **API Hash** (si ottengono da <https://my.telegram.org>; la procedura è spiegata anche nella pagina *Guida* dell'app)

## Installazione

### 1. Backend

```bash
git clone <url-del-repository>
cd ChatControl

python -m venv .venv
source .venv/bin/activate          # su Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Crea il file `Backend/.env` con un *pepper* casuale:

```bash
cd Backend
echo "SECRET_PEPPER=$(python -c 'import secrets; print(secrets.token_hex(32))')" > .env
```

Serve solo `SECRET_PEPPER`. La chiave Fernet che protegge i cookie di sessione viene generata a ogni avvio del backend (non va messa nel `.env`), quindi dopo un riavvio bisogna rifare il login.

> ⚠️ **Non pubblicare mai il `.env` né esempi di pepper reali** in repository o documentazione: ognuno deve generare il proprio valore.

> ⚠️ **Conserva il pepper.** Se lo cambi o lo perdi, gli account già creati non sono più raggiungibili, perché gli identificativi nel database non corrispondono più. 

### 2. Certificato HTTPS (sviluppo)

Il frontend, il backend e i cookie di sessione (`Secure`) richiedono HTTPS. Per lo sviluppo basta un certificato autofirmato, che va copiato in **entrambe** le cartelle (`Backend/certs/` per uvicorn, `Frontend/certs/` per Vite):

```bash
mkdir -p Backend/certs Frontend/certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout Backend/certs/key.pem -out Backend/certs/cert.pem \
  -subj "/CN=localhost"
cp Backend/certs/*.pem Frontend/certs/
```


### 3. Avvio

Backend (dalla cartella `Backend/`, con il virtualenv attivo):

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./certs/key.pem --ssl-certfile ./certs/cert.pem
```

Frontend (in un altro terminale):

```bash
cd Frontend
npm install      # solo la prima volta
npm run dev
```

Apri `https://localhost:5173`. Il browser avviserà che il certificato non è attendibile: accettalo. **Apri una volta anche `https://localhost:8000` e accetta il certificato**, altrimenti la connessione WebSocket (`wss://localhost:8000`) viene bloccata.
