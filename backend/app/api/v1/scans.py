"""
Scans API — Start, monitor, cancel scans
"""
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pydantic import BaseModel
import asyncio
import json

from app.core.database import get_db, AsyncSessionLocal
from app.api.v1.auth import get_current_user
from app.models.models import User, Scan, ScanEvent, Project, Domain, OrganizationMember, ScanStatus

router = APIRouter()


class ScanCreate(BaseModel):
    project_id: str
    target_url: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    project_id: str
    status: str
    current_stage: Optional[str]
    target_url: Optional[str]
    pages_discovered: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_tokens: int
    estimated_cost_usd: float

    class Config:
        from_attributes = True


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    data: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a new security scan."""
    # Verify project ownership + domain verified
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="No organization")

    result = await db.execute(
        select(Project).where(
            Project.id == data.project_id,
            Project.organization_id == membership.organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if domain is verified (Enforced in production; permitted in development for local testing)
    result = await db.execute(
        select(Domain).where(Domain.project_id == project.id, Domain.is_verified == True)
    )
    verified_domain = result.scalar_one_or_none()
    from app.core.config import settings
    if not verified_domain and settings.ENVIRONMENT != "development":
        raise HTTPException(
            status_code=400,
            detail="Domain must be verified before scanning. Add DNS TXT record first."
        )

    # Create scan record
    scan = Scan(
        project_id=project.id,
        organization_id=membership.organization_id,
        target_url=data.target_url or project.base_url,
        status=ScanStatus.QUEUED,
        current_stage="queued"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Queue scan: In development or standalone mode, dispatch immediately via asyncio background task
    from app.worker.tasks import _run_scan_async
    asyncio.create_task(_run_scan_async(scan.id))

    return scan


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all scans for user's org."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        return []

    result = await db.execute(
        select(Scan).where(Scan.organization_id == membership.organization_id)
        .order_by(Scan.queued_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scan details."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == membership.organization_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Scan cannot be cancelled")

    scan.status = ScanStatus.CANCELLED
    await db.commit()
    return {"message": "Scan cancelled"}


@router.websocket("/ws/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint — stream live scan events to frontend."""
    await websocket.accept()
    last_event_id = None

    try:
        while True:
            async with AsyncSessionLocal() as db:
                # Get latest events
                query = select(ScanEvent).where(ScanEvent.scan_id == scan_id)
                if last_event_id:
                    query = query.where(ScanEvent.id > last_event_id)
                query = query.order_by(ScanEvent.created_at).limit(10)

                result = await db.execute(query)
                events = result.scalars().all()

                for event in events:
                    await websocket.send_json({
                        "type": event.event_type,
                        "message": event.message,
                        "data": event.data,
                        "timestamp": event.created_at.isoformat()
                    })
                    last_event_id = event.id

                # Check if scan is done
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan and scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                    await websocket.send_json({"type": "scan_complete", "status": scan.status})
                    break

            await asyncio.sleep(2)  # Poll every 2 seconds
    except WebSocketDisconnect:
        pass
