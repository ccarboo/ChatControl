from fastapi import APIRouter
from routes.login import router as r_login
from routes.signup import router as r_signup



router = APIRouter()
router.include_router(r_login, tags=["login"])
router.include_router(r_signup, tags=["signup"])

