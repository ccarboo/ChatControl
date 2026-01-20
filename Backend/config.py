import os
from dotenv import load_dotenv

load_dotenv()

pepper = os.getenv("SECRET_PEPPER")
secret_key = os.getenv("SECRET_KEY")