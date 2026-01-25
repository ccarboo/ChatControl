# installazione e setup

## 1. prerequisiti di sistema

``` bash 
sudo apt update
```
***installa le dipendenze necessarie***
```bash
sudo apt install age openssl python3-pip
```
``` bash
pip install fastapi uvicorn telethon cryptography
 ```
## 2. setup ambiente
***crea l'ambiente virtuale***
``` bash 
    python3 -m venv .venv
```
***attivare l'ambiente virtuale***
```bash
.\.venv\Scripts\Activate.ps1
```

***crea un file .env nella cartella principale del progetto come segue:***

```python
SECRET_PEPPER=una_stringa_casuale_esadecimale
TELEGRAM_API_ID=123456
TELEGRAM_API_HASH=abcdef123456...
```

***posizionare i certificati in una cartella ../frontend/certs/ ed in una cartella ../backend/certs***

## 3. generare i certificati

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes
```

## 3. lanciare il backend

***spostarsi nella cartella backend e lanciare il seguente comando***

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./key.pem --ssl-certfile ./cert.pem
```

## 4. lanciare il frontend

***spostarsi nella cartella frontend e lanciare il seguente comando:***

```bash
npm run dev
```
