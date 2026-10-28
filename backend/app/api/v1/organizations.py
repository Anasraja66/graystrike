"""
Stub routers — Organizations, Findings, Reports, Admin
These will be fully implemented in Phase 2-6
"""
from fastapi import APIRouter, Depends
from app.api.v1.auth import get_current_user
from app.models.models import User

# Organizations
organizations_router = APIRouter()

@organizations_router.get("/")
async def list_organizations(current_user: User = Depends(get_current_user)):
    return {"message": "Organizations endpoint — Phase 2"}

router = organizations_router
