from fastapi import APIRouter, Depends
from app.api.v1.auth import get_current_user
from app.models.models import User

router = APIRouter()

@router.get("/health")
async def admin_health():
    return {"status": "ok", "message": "Admin — Phase 7"}
