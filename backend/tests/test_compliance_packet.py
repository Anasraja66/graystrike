"""
Tests for Compliance Engine and Auditor Evidence Packet PDF Generator
"""
import sys
import os
import uuid
from datetime import datetime, timezone
import pytest

# Ensure backend and ai_engine are in path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.models.models import Finding, FindingSeverity, FindingStatus
from app.services.compliance_engine import ComplianceEngine
from app.services.report_generator import ReportGenerator


def create_finding(title: str, category: str, cwe_id: str, severity: FindingSeverity = FindingSeverity.HIGH) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        organization_id=str(uuid.uuid4()),
        title=title,
        category=category,
        cwe_id=cwe_id,
        severity=severity,
        status=FindingStatus.OPEN,
        affected_asset="https://example.com/api",
        evidence_summary="Compliance audit verification finding",
        risk_score=80.0,
        confidence=0.9,
        discovered_at=datetime.now(timezone.utc)
    )


def test_compliance_engine_evaluation():
    findings = [
        create_finding("Missing HSTS Header", "cryptographic_failures", "CWE-319", FindingSeverity.MEDIUM),
        create_finding("SQL Injection in Query Param", "sql_injection", "CWE-89", FindingSeverity.CRITICAL),
    ]

    results = ComplianceEngine.evaluate_compliance(findings)
    assert "soc_2" in results
    assert "iso_27001" in results
    assert "pci_dss" in results
    assert "hipaa" in results
    assert "gdpr" in results

    # Check SOC 2 structure
    soc2 = results["soc_2"]
    assert soc2["framework_name"] == "SOC 2 Type II"
    assert soc2["total_controls"] >= 4
    assert isinstance(soc2["compliance_score"], int)
    assert soc2["status"] in ("PASSED", "NEEDS_REMEDIATION", "NON_COMPLIANT")


def test_compliance_packet_pdf_generation():
    findings = [
        create_finding("Missing HSTS Header", "cryptographic_failures", "CWE-319", FindingSeverity.MEDIUM),
        create_finding("Supabase Row-Level Security Disabled", "supabase_exposure", "CWE-284", FindingSeverity.CRITICAL),
    ]
    results = ComplianceEngine.evaluate_compliance(findings)
    findings_list = [{"title": f.title, "severity": f.severity.value} for f in findings]

    pdf_bytes = ReportGenerator.generate_compliance_packet_pdf(
        target_url="https://app.example.com",
        org_name="Acme Corp Ltd.",
        scan_date="2026-10-25 02:00",
        compliance_data=results,
        findings=findings_list
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
