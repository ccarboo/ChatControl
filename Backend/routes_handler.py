from fastapi import APIRouter
from routes.login import router as r_login




router = APIRouter()
router.include_router(r_login, tags=["login"])


