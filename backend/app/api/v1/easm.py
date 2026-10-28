"""
EASM API — External Attack Surface Management & Shadow Asset Discovery
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import User, Project, OrganizationMember
from app.services.easm_service import EASMService

router = APIRouter()


class DiscoverRequest(BaseModel):
    target: Optional[str] = None
    project_id: Optional[str] = None


@router.post("/discover")
async def trigger_asset_discovery(
    data: DiscoverRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger real-time attack surface discovery for a domain or project.
    Discovers subdomains, shadow environments, dangling CNAME takeover risks, and cloud buckets.
    """
    target_host = None
    if data.project_id:
        result = await db.execute(select(Project).where(Project.id == data.project_id))
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        target_host = project.base_url
    elif data.target:
        target_host = data.target
    else:
        raise HTTPException(status_code=400, detail="Must provide either 'target' or 'project_id'")

    surface = await EASMService.discover_attack_surface(target_host)
    return surface


@router.get("/projects/{project_id}/assets")
async def get_project_attack_surface(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get discovered external attack surface assets for a project.
    """
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    surface = await EASMService.discover_attack_surface(project.base_url)
    return {
        "project_id": project.id,
        "project_name": project.name,
        "base_url": project.base_url,
        **surface
    }


@router.get("/workspace/assets")
async def get_workspace_attack_surface(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Aggregate discovered assets across all projects in the active organization.
    """
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="No active organization found")

    # Fetch projects
    p_res = await db.execute(
        select(Project).where(
            Project.organization_id == membership.organization_id,
            Project.is_active == True
        )
    )
    projects = p_res.scalars().all()

    if not projects:
        return {
            "organization_id": membership.organization_id,
            "total_assets_found": 0,
            "shadow_assets_count": 0,
            "takeover_risks_count": 0,
            "assets": [],
            "summary": {
                "discovered_subdomains": 0,
                "takeover_vulnerabilities": 0,
                "shadow_environments": 0,
                "status": "HEALTHY"
            }
        }

    # Discover for first 3 active projects
    all_assets = []
    total_shadow = 0
    total_takeovers = 0

    for proj in projects[:3]:
        surf = await EASMService.discover_attack_surface(proj.base_url)
        all_assets.extend(surf.get("assets", []))
        total_shadow += surf.get("shadow_assets_count", 0)
        total_takeovers += surf.get("takeover_risks_count", 0)

    # Deduplicate assets by hostname
    unique_assets = {a["hostname"]: a for a in all_assets if "hostname" in a}

    return {
        "organization_id": membership.organization_id,
        "total_assets_found": len(unique_assets),
        "shadow_assets_count": total_shadow,
        "takeover_risks_count": total_takeovers,
        "assets": list(unique_assets.values()),
        "summary": {
            "discovered_subdomains": len(unique_assets),
            "takeover_vulnerabilities": total_takeovers,
            "shadow_environments": total_shadow,
            "status": "DANGER" if total_takeovers > 0 else ("WARNING" if total_shadow > 0 else "HEALTHY")
        }
    }
