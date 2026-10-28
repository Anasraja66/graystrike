"""
CI/CD Integration API — GitHub Actions / GitLab CI / CLI Security Gates
Provides API key management, scoped scan triggering, idempotency, baseline management,
and fail-safe automated security gate evaluations.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel
from urllib.parse import urlparse
import secrets
import hashlib
import asyncio

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import (
    User, OrganizationMember, Project, Domain, Scan, ScanStatus, 
    Finding, FindingSeverity, FindingStatus, ApiKey, ScanEvent
)
from app.services.scope_service import ScopeEnforcer, ScopeViolationError
from app.worker.tasks import _run_scan_async

router = APIRouter()


# =============================================
# SCHEMAS
# =============================================

class ApiKeyCreate(BaseModel):
    name: str = "GitHub Actions CI Key"
    project_id: Optional[str] = None
    expires_in_days: Optional[int] = 90


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    project_id: Optional[str] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    secret_key: Optional[str] = None


class CIScanRequest(BaseModel):
    project_id: str
    target_url: Optional[str] = None
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    pull_request_number: Optional[int] = None
    ci_provider: Optional[str] = "github_actions"


class CIScanResponse(BaseModel):
    scan_id: str
    project_id: str
    target_url: str
    status: str
    queued_at: datetime
    authorized_domain: str
    idempotent_reused: bool = False


class CIGateEvaluation(BaseModel):
    scan_id: str
    project_id: str
    target_url: str
    status: str
    gate_passed: bool
    fail_on_threshold: str
    reason: str
    is_initial_baseline: bool = False
    new_findings_count: int
    regression_findings_count: int
    existing_unresolved_count: int
    resolved_count: int
    findings_by_severity: Dict[str, int]
    new_findings: List[Dict[str, Any]]
    regressions: List[Dict[str, Any]]
    summary_markdown: str


# =============================================
# API KEY MANAGEMENT
# =============================================

@router.post("/keys", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate a new secure, revocable API Key for CI/CD GitHub Actions."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="User has no organization")

    # Generate token with prefix apt_live_
    raw_token = "apt_live_" + secrets.token_hex(24)
    key_prefix = raw_token[:13] + "..."
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    expires_at = None
    if data.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_in_days)

    api_key = ApiKey(
        organization_id=membership.organization_id,
        project_id=data.project_id,
        user_id=current_user.id,
        name=data.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        scopes=["ci:scan", "findings:read"],
        expires_at=expires_at
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return ApiKeyResponse(
        id=str(api_key.id),
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        project_id=str(api_key.project_id) if api_key.project_id else None,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        secret_key=raw_token  # Returned only once
    )


@router.get("/keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List active API Keys for user's organization."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        return []

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.organization_id == membership.organization_id,
            ApiKey.is_active == True
        ).order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [
        ApiKeyResponse(
            id=str(k.id),
            name=k.name,
            key_prefix=k.key_prefix,
            project_id=str(k.project_id) if k.project_id else None,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            secret_key=None
        ) for k in keys
    ]


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Revoke / deactivate an API Key immediately."""
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.organization_id == membership.organization_id
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API Key not found")

    key.is_active = False
    await db.commit()
    return None


# =============================================
# CI SCAN TRIGGER & IDEMPOTENCY
# =============================================

@router.post("/scan", response_model=CIScanResponse, status_code=status.HTTP_201_CREATED)
async def trigger_ci_scan(
    data: CIScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger an authorized CI/CD Scan.
    Features:
    - Idempotency: Reuses active scans on workflow retries for identical commit_sha.
    - Anti-SSRF: Target URLs validated against project scope; loopback and cloud metadata blocked.
    """
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized for this organization")

    # If API Key is restricted to a specific project_id, enforce it
    api_key_obj = getattr(current_user, "_api_key", None)
    if api_key_obj and api_key_obj.project_id and api_key_obj.project_id != data.project_id:
        raise HTTPException(status_code=403, detail="This API Key is scoped to a different project ID")

    result = await db.execute(
        select(Project).where(
            Project.id == data.project_id,
            Project.organization_id == membership.organization_id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Scope Safety Check: Target URL Validation
    target_url = data.target_url or project.base_url
    target_parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    target_host = (target_parsed.hostname or "").lower()

    project_parsed = urlparse(project.base_url if "://" in project.base_url else f"https://{project.base_url}")
    project_host = (project_parsed.hostname or "").lower()

    # ScopeEnforcer validation
    enforcer = ScopeEnforcer(allowed_hosts=[project_host], allow_private_ips=False)
    is_valid, err_msg = enforcer.validate_url(target_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Scope Violation: {err_msg}")

    # Check Domain Verification in production
    from app.core.config import settings
    if settings.ENVIRONMENT != "development":
        dom_res = await db.execute(
            select(Domain).where(Domain.project_id == project.id, Domain.is_verified == True)
        )
        if not dom_res.scalar_one_or_none():
            raise HTTPException(
                status_code=400,
                detail="Project domain must be verified via DNS TXT before running CI scans."
            )

    # 1. IDEMPOTENCY: Check for existing active scan on this exact commit SHA
    if data.commit_sha:
        active_res = await db.execute(
            select(Scan).where(
                Scan.project_id == project.id,
                Scan.commit_sha == data.commit_sha,
                Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
            ).order_by(Scan.queued_at.desc()).limit(1)
        )
        existing_active = active_res.scalar_one_or_none()
        if existing_active:
            print(f"🔁 [CI Idempotency] Reusing active scan {existing_active.id} for commit {data.commit_sha}")
            return CIScanResponse(
                scan_id=str(existing_active.id),
                project_id=str(project.id),
                target_url=existing_active.target_url,
                status=existing_active.status.value if hasattr(existing_active.status, "value") else str(existing_active.status),
                queued_at=existing_active.queued_at,
                authorized_domain=project_host,
                idempotent_reused=True
            )

    # Create new Scan record
    scan = Scan(
        project_id=project.id,
        organization_id=membership.organization_id,
        target_url=target_url,
        commit_sha=data.commit_sha,
        pull_request_number=data.pull_request_number,
        ci_provider=data.ci_provider,
        status=ScanStatus.QUEUED,
        current_stage="queued"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Log CI Context Event
    db.add(ScanEvent(
        scan_id=scan.id,
        event_type="ci_triggered",
        message=f"Scan triggered by {data.ci_provider} (Branch: {data.branch}, Commit: {data.commit_sha or 'N/A'}, PR: #{data.pull_request_number or 'N/A'})",
        data={
            "branch": data.branch,
            "commit_sha": data.commit_sha,
            "pr": data.pull_request_number,
            "ci_provider": data.ci_provider
        }
    ))
    await db.commit()

    # Dispatch scan worker
    asyncio.create_task(_run_scan_async(scan.id))

    return CIScanResponse(
        scan_id=str(scan.id),
        project_id=str(project.id),
        target_url=target_url,
        status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        queued_at=scan.queued_at,
        authorized_domain=project_host,
        idempotent_reused=False
    )


# =============================================
# CI STATUS & GATE EVALUATION
# =============================================

@router.get("/scans/{scan_id}/summary", response_model=CIGateEvaluation)
async def evaluate_ci_scan_summary(
    scan_id: str,
    fail_on: str = Query("high", description="Severity threshold: critical, high, medium, low, none"),
    fail_on_regression_only: bool = Query(False, description="Fail only if regressions or new findings occur"),
    allow_initial_baseline: bool = Query(True, description="If true, establishes initial baseline on first scan without failing build"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Evaluates scan findings, detects regressions, compares against baseline,
    and returns a pass/fail security gate decision with redacted Markdown summary.
    Enforces strict Fail-Safe Policy: Incomplete, failed, or timed-out scans are NEVER passed.
    """
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == membership.organization_id
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    status_str = scan.status.value if hasattr(scan.status, "value") else str(scan.status)

    # 1. FAIL-SAFE: If scan is still running or queued
    if status_str in ["queued", "running"]:
        return CIGateEvaluation(
            scan_id=str(scan.id),
            project_id=str(scan.project_id),
            target_url=scan.target_url,
            status=status_str,
            gate_passed=False,
            fail_on_threshold=fail_on,
            reason=f"Scan is currently {status_str} ({scan.current_stage or 'in progress'}).",
            new_findings_count=0,
            regression_findings_count=0,
            existing_unresolved_count=0,
            resolved_count=0,
            findings_by_severity={},
            new_findings=[],
            regressions=[],
            summary_markdown=f"### ⏳ APT Agents Scan in Progress\nStatus: `{status_str}` | Stage: `{scan.current_stage}`"
        )

    # 2. FAIL-SAFE: If scan failed or was cancelled
    if status_str in ["failed", "cancelled"]:
        return CIGateEvaluation(
            scan_id=str(scan.id),
            project_id=str(scan.project_id),
            target_url=scan.target_url,
            status=status_str,
            gate_passed=False,
            fail_on_threshold=fail_on,
            reason=f"Scan {status_str}: {scan.error_message or 'Scan halted without completing.'}",
            new_findings_count=0,
            regression_findings_count=0,
            existing_unresolved_count=0,
            resolved_count=0,
            findings_by_severity={},
            new_findings=[],
            regressions=[],
            summary_markdown=f"### ❌ APT Agents Scan Failed\nStatus: `{status_str}`\nReason: {scan.error_message or 'Scan was cancelled or encountered an error.'}"
        )

    # 3. FAIL-SAFE: Incomplete scan check (Zero pages discovered)
    if scan.pages_discovered == 0 or scan.current_stage != "completed":
        return CIGateEvaluation(
            scan_id=str(scan.id),
            project_id=str(scan.project_id),
            target_url=scan.target_url,
            status="incomplete",
            gate_passed=False,
            fail_on_threshold=fail_on,
            reason="Scan INCOMPLETE: 0 pages or endpoints were crawled. Cannot certify security posture on an empty scan.",
            new_findings_count=0,
            regression_findings_count=0,
            existing_unresolved_count=0,
            resolved_count=0,
            findings_by_severity={},
            new_findings=[],
            regressions=[],
            summary_markdown=f"### ⚠️ APT Agents Scan Incomplete\n**Target:** `{scan.target_url}`\n**Status:** Incomplete\nReason: Zero pages or endpoints were crawled. Target may be offline or blocking crawler."
        )

    # Fetch current scan findings
    f_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    current_findings = f_res.scalars().all()

    # Severity ordering
    sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold_weight = sev_weights.get(fail_on.lower(), 3)  # default high (3)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # 4. BASELINE HANDLING: Check if this is the very first completed scan for this project
    prev_scans_res = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.project_id == scan.project_id,
            Scan.id != scan.id,
            Scan.status == ScanStatus.COMPLETED
        )
    )
    prev_completed_scans = prev_scans_res.scalar() or 0
    is_initial_baseline = (prev_completed_scans == 0)

    if is_initial_baseline:
        baseline_list = []
        gate_violators = []

        for f in current_findings:
            sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            f_weight = sev_weights.get(sev, 0)

            f_dict = {
                "id": str(f.id),
                "title": f.title,
                "severity": sev.upper(),
                "affected_asset": f.affected_asset,
                "cwe_id": f.cwe_id,
                "confidence": f.confidence,
                "evidence": _redact_sensitive_data(f.evidence_summary or "")
            }
            baseline_list.append(f_dict)
            if not allow_initial_baseline and f_weight >= threshold_weight and fail_on.lower() != "none":
                gate_violators.append(f)

        gate_passed = len(gate_violators) == 0
        if allow_initial_baseline:
            gate_reason = f"Initial security baseline established: {len(baseline_list)} pre-existing findings cataloged into inventory. Subsequent PRs will be gated against regressions and new additions relative to this baseline."
        else:
            gate_reason = "All security gates passed successfully." if gate_passed else f"Initial baseline threshold '{fail_on.upper()}' violated: {len(gate_violators)} finding(s) met or exceeded severity threshold."

        md = _build_initial_baseline_markdown_summary(
            scan=scan,
            gate_passed=gate_passed,
            fail_on=fail_on,
            gate_reason=gate_reason,
            sev_counts=sev_counts,
            baseline_list=baseline_list
        )

        return CIGateEvaluation(
            scan_id=str(scan.id),
            project_id=str(scan.project_id),
            target_url=scan.target_url,
            status=status_str,
            gate_passed=gate_passed,
            fail_on_threshold=fail_on,
            reason=gate_reason,
            is_initial_baseline=True,
            new_findings_count=0,
            regression_findings_count=0,
            existing_unresolved_count=len(baseline_list),
            resolved_count=0,
            findings_by_severity=sev_counts,
            new_findings=[],
            regressions=[],
            summary_markdown=md
        )

    # 5. SUBSEQUENT SCANS: Compare against baseline fingerprints
    base_res = await db.execute(
        select(Finding).where(
            Finding.project_id == scan.project_id,
            Finding.scan_id != scan.id
        )
    )
    baseline_findings = base_res.scalars().all()
    baseline_fps = {b.fingerprint: b for b in baseline_findings if b.fingerprint}

    new_list = []
    regressions_list = []
    existing_list = []
    gate_violators = []

    for f in current_findings:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

        f_weight = sev_weights.get(sev, 0)
        is_regression = (f.status == FindingStatus.REGRESSION_DETECTED) or (
            f.fingerprint in baseline_fps and baseline_fps[f.fingerprint].status == FindingStatus.RESOLVED
        )

        redacted_evidence = _redact_sensitive_data(f.evidence_summary or "")

        f_dict = {
            "id": str(f.id),
            "title": f.title,
            "severity": sev.upper(),
            "affected_asset": f.affected_asset,
            "cwe_id": f.cwe_id,
            "confidence": f.confidence,
            "evidence": redacted_evidence
        }

        if is_regression:
            regressions_list.append(f_dict)
            if f_weight >= threshold_weight and fail_on.lower() != "none":
                gate_violators.append(f)
        elif f.fingerprint not in baseline_fps:
            new_list.append(f_dict)
            if f_weight >= threshold_weight and fail_on.lower() != "none":
                gate_violators.append(f)
        else:
            existing_list.append(f_dict)
            if not fail_on_regression_only and f_weight >= threshold_weight and fail_on.lower() != "none":
                gate_violators.append(f)

    # Resolved in this scan: was in baseline, but not in current scan findings
    current_fps = {f.fingerprint for f in current_findings if f.fingerprint}
    resolved_count = sum(1 for fp, bf in baseline_fps.items() if fp not in current_fps and bf.status != FindingStatus.RESOLVED)

    gate_passed = len(gate_violators) == 0
    gate_reason = "All security gates passed successfully." if gate_passed else f"Security gate threshold '{fail_on.upper()}' violated: {len(gate_violators)} finding(s) met or exceeded severity threshold."

    # Build Markdown Summary for GitHub Actions & PR comments
    md = _build_ci_markdown_summary(
        scan=scan,
        gate_passed=gate_passed,
        fail_on=fail_on,
        gate_reason=gate_reason,
        sev_counts=sev_counts,
        new_list=new_list,
        regressions_list=regressions_list,
        existing_list=existing_list,
        resolved_count=resolved_count
    )

    return CIGateEvaluation(
        scan_id=str(scan.id),
        project_id=str(scan.project_id),
        target_url=scan.target_url,
        status=status_str,
        gate_passed=gate_passed,
        fail_on_threshold=fail_on,
        reason=gate_reason,
        is_initial_baseline=False,
        new_findings_count=len(new_list),
        regression_findings_count=len(regressions_list),
        existing_unresolved_count=len(existing_list),
        resolved_count=resolved_count,
        findings_by_severity=sev_counts,
        new_findings=new_list,
        regressions=regressions_list,
        summary_markdown=md
    )


@router.get("/scans/{scan_id}/sarif")
async def export_scan_sarif(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export scan findings as OASIS SARIF v2.1.0 for GitHub Code Scanning."""
    from app.services.sarif_generator import SarifGenerator
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == membership.organization_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    f_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = f_res.scalars().all()

    return SarifGenerator.generate_sarif(scan, findings)


# =============================================
# HELPERS: REDACTION & MARKDOWN SUMMARY
# =============================================

def _redact_sensitive_data(text: str) -> str:
    """Masks secret tokens, API keys, and session cookies from PR comments."""
    import re
    # Mask JWTs
    text = re.sub(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', '[REDACTED_JWT]', text)
    # Mask Bearer tokens
    text = re.sub(r'(?i)bearer\s+[a-zA-Z0-9\-_]{16,}', 'Bearer [REDACTED_TOKEN]', text)
    # Mask API keys
    text = re.sub(r'(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{8,}["\']?', r'\1: [REDACTED]', text)
    # Mask Cookies
    text = re.sub(r'(?i)cookie:\s*([^;\r\n]+)', 'cookie: [REDACTED_COOKIE]', text)
    return text


def _build_initial_baseline_markdown_summary(
    scan: Scan,
    gate_passed: bool,
    fail_on: str,
    gate_reason: str,
    sev_counts: Dict[str, int],
    baseline_list: List[Dict[str, Any]]
) -> str:
    status_icon = "📦" if gate_passed else "🚨"
    title_text = "Initial Baseline Established" if gate_passed else "Initial Baseline Gate Blocked"

    lines = [
        f"## {status_icon} APT Agents: {title_text}",
        f"**Target:** `{scan.target_url}` | **Scan ID:** `{str(scan.id)[:8]}` | **Status:** Initial Project Baseline",
        f"**Outcome:** {gate_reason}\n",
        "| Severity | Total Existing |",
        "| :--- | :--- |",
        f"| 🔴 **Critical** | {sev_counts.get('critical', 0)} |",
        f"| 🟠 **High** | {sev_counts.get('high', 0)} |",
        f"| 🟡 **Medium** | {sev_counts.get('medium', 0)} |",
        f"| 🔵 **Low** | {sev_counts.get('low', 0)} |",
        f"\n**Inventory Cataloged:** `{len(baseline_list)} pre-existing findings` saved to baseline. Subsequent PRs will be gated against new additions and regressions.\n"
    ]
    lines.append("\n---\n*Report generated by [APT Agents](https://aptagents.io) — Autonomous AI Application Security Platform*")
    return "\n".join(lines)


def _build_ci_markdown_summary(
    scan: Scan,
    gate_passed: bool,
    fail_on: str,
    gate_reason: str,
    sev_counts: Dict[str, int],
    new_list: List[Dict[str, Any]],
    regressions_list: List[Dict[str, Any]],
    existing_list: List[Dict[str, Any]],
    resolved_count: int
) -> str:
    status_icon = "✅" if gate_passed else "🚨"
    title_text = "Security Gate Passed" if gate_passed else "Security Gate Failed"

    lines = [
        f"## {status_icon} APT Agents: {title_text}",
        f"**Target:** `{scan.target_url}` | **Scan ID:** `{str(scan.id)[:8]}` | **Threshold:** `{fail_on.upper()}`",
        f"**Outcome:** {gate_reason}\n",
        "| Severity | Total Found |",
        "| :--- | :--- |",
        f"| 🔴 **Critical** | {sev_counts.get('critical', 0)} |",
        f"| 🟠 **High** | {sev_counts.get('high', 0)} |",
        f"| 🟡 **Medium** | {sev_counts.get('medium', 0)} |",
        f"| 🔵 **Low** | {sev_counts.get('low', 0)} |",
        f"\n**Delta Breakdown:** 🆕 `{len(new_list)} New` | 🚨 `{len(regressions_list)} Regressions` | ⏳ `{len(existing_list)} Existing` | 🟢 `{resolved_count} Resolved`\n"
    ]

    if regressions_list:
        lines.append("### 🚨 Regressions Detected (Previously Fixed, Now Reappeared)")
        for r in regressions_list[:5]:
            lines.append(f"- **[{r['severity']}] {r['title']}** on `{r['affected_asset']}`")
            if r.get("evidence"):
                lines.append(f"  > *Evidence:* {r['evidence'][:140]}...")

    if new_list:
        lines.append("\n### 🆕 New Vulnerabilities Introduced in this PR/Commit")
        for n in new_list[:5]:
            lines.append(f"- **[{n['severity']}] {n['title']}** on `{n['affected_asset']}`")
            if n.get("evidence"):
                lines.append(f"  > *Evidence:* {n['evidence'][:140]}...")

    lines.append("\n---\n*Report generated by [APT Agents](https://aptagents.io) — Autonomous AI Application Security Platform*")
    return "\n".join(lines)
