"""
Domains API — DNS TXT Verification
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import secrets
import dns.resolver
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import User, Domain, DomainVerification, Project, OrganizationMember

router = APIRouter()


class DomainCreate(BaseModel):
    project_id: str
    hostname: str


class DomainResponse(BaseModel):
    id: str
    hostname: str
    is_verified: bool
    verification_token: Optional[str]
    dns_record_name: Optional[str]
    dns_record_value: Optional[str]

    class Config:
        from_attributes = True


@router.post("/", response_model=DomainResponse, status_code=201)
async def add_domain(
    data: DomainCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Register a domain for DNS verification."""
    # Verify project belongs to user's org
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
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Generate verification token
    token = "apt-verify-" + secrets.token_hex(16)

    domain = Domain(
        project_id=data.project_id,
        hostname=data.hostname.lower().strip(),
        verification_token=token,
        verification_expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.add(domain)
    await db.commit()
    await db.refresh(domain)

    return DomainResponse(
        id=domain.id,
        hostname=domain.hostname,
        is_verified=domain.is_verified,
        verification_token=domain.verification_token,
        dns_record_name=f"_apt-verify.{domain.hostname}",
        dns_record_value=domain.verification_token
    )


@router.post("/{domain_id}/verify", response_model=DomainResponse)
async def verify_domain(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Check DNS TXT record and verify domain ownership."""
    result = await db.execute(select(Domain).where(Domain.id == domain_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Check DNS TXT record
    dns_record_name = f"_apt-verify.{domain.hostname}"
    success = False
    dns_response = None
    error_msg = None

    try:
        answers = dns.resolver.resolve(dns_record_name, "TXT")
        for rdata in answers:
            txt_value = rdata.to_text().strip('"')
            if txt_value == domain.verification_token:
                success = True
                dns_response = {"records": [str(r) for r in answers]}
                break
        if not success:
            error_msg = "TXT record found but token does not match"
    except dns.resolver.NXDOMAIN:
        error_msg = f"DNS record not found: {dns_record_name}"
    except dns.resolver.NoAnswer:
        error_msg = "No TXT records found"
    except Exception as e:
        error_msg = str(e)

    # Save verification attempt
    verification = DomainVerification(
        domain_id=domain.id,
        success=success,
        dns_response=dns_response,
        error_message=error_msg
    )
    db.add(verification)

    if success:
        domain.is_verified = True
        domain.verified_at = datetime.now(timezone.utc)
        domain.verification_expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    await db.commit()
    await db.refresh(domain)

    if not success:
        raise HTTPException(
            status_code=400,
            detail=f"Verification failed: {error_msg}. Add TXT record: {dns_record_name} = {domain.verification_token}"
        )

    return DomainResponse(
        id=domain.id,
        hostname=domain.hostname,
        is_verified=domain.is_verified,
        verification_token=domain.verification_token,
        dns_record_name=f"_apt-verify.{domain.hostname}",
        dns_record_value=domain.verification_token
    )
