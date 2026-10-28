"""
Projects API — CRUD for websites/projects
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional, Any
from pydantic import BaseModel, HttpUrl

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import User, Project, OrganizationMember

router = APIRouter()


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    base_url: str


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    base_url: str
    is_active: bool
    scan_schedule: Optional[str] = "manual"
    last_scanned_at: Optional[Any] = None
    next_scan_at: Optional[Any] = None
    organization_id: str

    class Config:
        from_attributes = True


class ScheduleUpdateRequest(BaseModel):
    scan_schedule: str  # "manual", "daily", "weekly"


@router.get("/", response_model=List[ProjectResponse])
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all projects for user's organization."""
    # Get user's org
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        return []

    result = await db.execute(
        select(Project).where(
            Project.organization_id == membership.organization_id,
            Project.is_active == True
        )
    )
    return result.scalars().all()


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    data: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new project (website)."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="No organization found")

    project = Project(
        organization_id=membership.organization_id,
        name=data.name,
        description=data.description,
        base_url=data.base_url.rstrip("/"),
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific project."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()

    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == membership.organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Soft delete a project."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()

    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == membership.organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.is_active = False
    await db.commit()


@router.post("/{project_id}/schedule")
async def update_project_schedule(
    project_id: str,
    data: ScheduleUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update continuous recurring scan frequency for a project (manual, daily, weekly)."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()

    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.organization_id == membership.organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    sched = data.scan_schedule.lower()
    if sched not in ["manual", "daily", "weekly"]:
        raise HTTPException(status_code=400, detail="Schedule must be 'manual', 'daily', or 'weekly'")

    project.scan_schedule = sched
    await db.commit()
    return {
        "status": "success",
        "project_id": project.id,
        "scan_schedule": project.scan_schedule,
        "message": f"Continuous security audit schedule set to '{sched}'"
    }
