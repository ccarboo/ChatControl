#installazione e setup

##1. prerequisiti di sistema

```sudo apt update
sudo apt install age openssl python3-pip```

##2. setup ambiente

```python3 -m venv .venv
pip install fastapi uvicorn telethon cryptography ```

***crea un file .env nella cartella principale del progetto come segue:***

```  SECRET_PEPPER=una_stringa_casuale_esadecimale
    TELEGRAM_API_ID=123456
    TELEGRAM_API_HASH=abcdef123456...```

***posizionare i certificati in una cartella ../frontend/certs/ ed in una cartella ../backend/certs***
##3. generare i certificati

` openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes`
##3. lanciare il backend
***spostarsi nella cartella backend e lanciare il seguente comando***
` uvicorn main:app --host 0.0.0.0 --port 8000 --ssl-keyfile ./key.pem --ssl-certfile ./cert.pem `

##4. lanciare il frontend

***spostarsi nella cartella frontend e lanciare il seguente comando:***
`npm run dev`
