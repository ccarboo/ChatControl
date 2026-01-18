import os
from dotenv import load_dotenv

load_dotenv()

pepper = os.getenv("SECRET_PEPPER")
