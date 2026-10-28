"""
Reports API — Download Executive PDF & JSON Vulnerability Reports
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.models import User, Scan, Finding, Project, Organization, OrganizationMember, FindingStatus
from app.services.report_generator import ReportGenerator
from app.services.attack_path_engine import AttackPathEngine

router = APIRouter()


@router.get("/scans/{scan_id}/pdf")
async def download_pdf_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Generate and download a professional PDF audit report for a completed scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch organization
    org_res = await db.execute(select(Organization).where(Organization.id == scan.organization_id))
    org = org_res.scalar_one_or_none()
    org_name = org.name if org else "Authorized Organization"

    # Fetch findings
    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = findings_res.scalars().all()

    findings_list = [
        {
            "title": f.title,
            "category": f.category,
            "cwe_id": f.cwe_id,
            "owasp_ref": f.owasp_ref,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "affected_asset": f.affected_asset,
            "evidence_summary": f.evidence_summary,
            "remediation_steps": f.remediation_steps,
            "business_impact": getattr(f, "business_impact", ""),
            "ai_fix_prompt": getattr(f, "ai_fix_prompt", "")
        }
        for f in findings
    ]

    scan_date = scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "In Progress"

    pdf_bytes = ReportGenerator.generate_pdf(
        target_url=scan.target_url or "Unknown Target",
        org_name=org_name,
        scan_date=scan_date,
        findings=findings_list,
        pages_crawled=scan.pages_discovered
    )

    filename = f"APT_Agents_Security_Report_{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/scans/{scan_id}/json")
async def download_json_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Export raw findings and telemetry as JSON."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = findings_res.scalars().all()

    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "metrics": {
            "pages_discovered": scan.pages_discovered,
            "endpoints_found": scan.endpoints_found,
            "total_findings": scan.total_findings,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "cwe_id": f.cwe_id,
                "owasp_ref": f.owasp_ref,
                "severity": f.severity,
                "confidence": f.confidence,
                "risk_score": f.risk_score,
                "affected_asset": f.affected_asset,
                "evidence_summary": f.evidence_summary,
                "technical_explanation": f.technical_explanation,
                "remediation_steps": f.remediation_steps,
                "references": f.references
            }
            for f in findings
        ]
    }


@router.get("/scans/{scan_id}/compliance")
async def get_compliance_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Evaluate and export compliance mapping for SOC 2, ISO 27001, PCI-DSS, HIPAA, and GDPR."""
    from app.services.compliance_engine import ComplianceEngine
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = findings_res.scalars().all()

    compliance_results = ComplianceEngine.evaluate_compliance(findings)
    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "evaluated_at": scan.completed_at or scan.queued_at,
        "frameworks": compliance_results
    }


@router.get("/scans/{scan_id}/compliance-packet-pdf")
async def download_compliance_packet_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate and stream an Auditor-Ready Compliance Evidence Packet PDF for SOC 2, ISO 27001, PCI-DSS, and HIPAA.
    """
    from app.services.compliance_engine import ComplianceEngine

    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    org_res = await db.execute(select(Organization).where(Organization.id == scan.organization_id))
    org = org_res.scalar_one_or_none()
    org_name = org.name if org else "Authorized Organization"

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan.id))
    findings = findings_res.scalars().all()

    compliance_results = ComplianceEngine.evaluate_compliance(findings)
    scan_date = scan.completed_at.strftime("%Y-%m-%d %H:%M") if scan.completed_at else "In Progress"

    findings_list = [
        {"title": f.title, "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity)}
        for f in findings
    ]

    pdf_bytes = ReportGenerator.generate_compliance_packet_pdf(
        target_url=scan.target_url or "Target System",
        org_name=org_name,
        scan_date=scan_date,
        compliance_data=compliance_results,
        findings=findings_list
    )

    filename = f"Auditor_Evidence_Packet_{scan.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/scans/{scan_id}/attack-paths")
async def get_scan_attack_paths(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Correlate security findings into multi-stage attack paths (Pentera / Wiz style).
    Identifies Entry nodes, Pivots, Exploits, Crown Jewel breaches, and the Critical Choke Point.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan.id,
            Finding.status != FindingStatus.RESOLVED
        )
    )
    findings = findings_res.scalars().all()
    attack_graph = AttackPathEngine.generate_attack_graph(findings)

    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        **attack_graph
    }


@router.get("/projects/{project_id}/attack-paths")
async def get_project_attack_paths(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate aggregate attack paths across all active findings in a project.
    """
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    findings_res = await db.execute(
        select(Finding).where(
            Finding.project_id == project.id,
            Finding.status != FindingStatus.RESOLVED
        )
    )
    findings = findings_res.scalars().all()
    attack_graph = AttackPathEngine.generate_attack_graph(findings)

    return {
        "project_id": project.id,
        "project_name": project.name,
        "target_url": project.target_url,
        **attack_graph
    }


@router.get("/workspace/attack-paths")
async def get_workspace_attack_paths(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate aggregate attack paths across the entire organization workspace.
    """
    result = await db.execute(
        select(OrganizationMember).where(OrganizationMember.user_id == current_user.id).limit(1)
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="No active organization found")

    findings_res = await db.execute(
        select(Finding).where(
            Finding.organization_id == membership.organization_id,
            Finding.status != FindingStatus.RESOLVED
        )
    )
    findings = findings_res.scalars().all()
    attack_graph = AttackPathEngine.generate_attack_graph(findings)

    return {
        "organization_id": membership.organization_id,
        **attack_graph
    }
