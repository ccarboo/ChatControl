from routes_handler import router as r
from fastapi import FastAPI
from database import sqlite as db_setup
from routes_handler import router as api_router
import os



app = FastAPI()
app.include_router(api_router)

# Initialize database on backend startup
@app.on_event("startup")
async def startup_event():
	"""Run database setup when the backend starts."""
	db_setup.initDB()  # This executes the setup code in sqlite.py



	
