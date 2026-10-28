"""
Findings API — View, triage, and retest detected vulnerabilities
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import (
    User, Finding, OrganizationMember, FindingStatus, FindingSeverity, FindingEvidence
)
from app.services.retest_engine import RetestEngine

router = APIRouter()


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    title: str
    category: Optional[str]
    cwe_id: Optional[str]
    owasp_ref: Optional[str]
    affected_asset: str
    evidence_summary: Optional[str]
    severity: str
    confidence: float
    risk_score: float
    verification_status: str
    technical_explanation: Optional[str]
    remediation_steps: Optional[str]
    business_impact: Optional[str] = None
    ai_fix_prompt: Optional[str] = None
    status: str
    fingerprint: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    retest_status: Optional[str] = None
    retest_notes: Optional[str] = None
    last_retested_at: Optional[datetime] = None
    screenshot_url: Optional[str] = None

    class Config:
        from_attributes = True


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class RetestResponse(BaseModel):
    finding_id: str
    title: str
    affected_asset: str
    is_fixed: bool
    status: str
    retest_status: str
    previous_evidence: Optional[str] = None
    new_evidence: str
    notes: str
    http_status: Optional[int] = None
    tested_at: str


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    project_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all findings for user's organization."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        return []

    query = select(Finding).where(Finding.organization_id == membership.organization_id)

    if project_id:
        query = query.where(Finding.project_id == project_id)
    if severity:
        query = query.where(Finding.severity == severity.lower())
    if status:
        query = query.where(Finding.status == status.lower())

    query = query.order_by(Finding.discovered_at.desc()).limit(150)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get single finding detail."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == membership.organization_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    data: FindingStatusUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Triage or update lifecycle status of a finding (e.g. open -> triaged -> in_progress -> ready_retest -> resolved)."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == membership.organization_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = data.status
    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{finding_id}/retest", response_model=RetestResponse)
async def retest_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Automated Retest Engine:
    Executes a live targeted verification probe on the finding's affected asset.
    Generates before/after verification proof and automatically updates finding lifecycle status.
    """
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == membership.organization_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Run retest probe
    retest_result = await RetestEngine.retest_finding(finding)

    # Update finding in database
    finding.status = retest_result["new_status"]
    finding.retest_status = retest_result["retest_status"]
    finding.retest_notes = retest_result["notes"]
    finding.last_retested_at = datetime.now(timezone.utc)

    # Save structured verification evidence
    evidence = FindingEvidence(
        finding_id=finding.id,
        evidence_type="retest_verification",
        content=f"Before: {finding.evidence_summary}\nAfter: {retest_result['new_evidence']}\nNotes: {retest_result['notes']}"
    )
    db.add(evidence)

    await db.commit()
    await db.refresh(finding)

    return RetestResponse(
        finding_id=finding.id,
        title=finding.title,
        affected_asset=finding.affected_asset,
        is_fixed=retest_result["is_fixed"],
        status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        retest_status=finding.retest_status,
        previous_evidence=finding.evidence_summary,
        new_evidence=retest_result["new_evidence"],
        notes=retest_result["notes"],
        http_status=retest_result.get("http_status"),
        tested_at=retest_result["tested_at"]
    )


class AutoFixRequest(BaseModel):
    github_repo: Optional[str] = None
    github_token: Optional[str] = None
    base_branch: Optional[str] = "main"


@router.post("/{finding_id}/auto-fix")
async def create_auto_fix_pr(
    finding_id: str,
    data: AutoFixRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Auto-PR Agent:
    Generates code patch and automatically creates a Pull Request on GitHub to remediate the vulnerability.
    """
    from app.services.auto_fixer_service import AutoFixerService

    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == membership.organization_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    patch_diff = AutoFixerService.get_patch_diff(finding)

    # If GitHub repo and token are supplied, automatically open PR
    if data.github_repo and data.github_token:
        try:
            pr_result = await AutoFixerService.create_github_pull_request(
                finding=finding,
                github_repo=data.github_repo,
                github_token=data.github_token,
                base_branch=data.base_branch or "main"
            )
            return {
                "success": True,
                "message": "Automated Pull Request created successfully!",
                "pull_request_url": pr_result["pull_request_url"],
                "pull_request_number": pr_result["pull_request_number"],
                "branch_name": pr_result["branch_name"],
                "patch": patch_diff
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"GitHub PR creation failed: {str(e)}")

    # Otherwise return patch diff ready for manual or local git apply
    return {
        "success": True,
        "message": "Patch generated. Provide github_repo and github_token to open a Pull Request automatically.",
        "pull_request_url": None,
        "patch": patch_diff
    }


@router.get("/{finding_id}/regression-tests")
async def get_finding_regression_tests(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Automated QA & CI/CD Regression Test Generator:
    Generates ready-to-commit TypeScript (Jest/Vitest), Python (Pytest), Playwright E2E,
    and safe diagnostic verification probes for this finding.
    """
    from app.services.security_test_generator import SecurityTestGenerator

    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == membership.organization_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    tests = SecurityTestGenerator.generate_tests_for_finding(finding)
    return tests

