"""
Tests for Attack Path & Business Risk Graph Engine (Pentera / Wiz style)
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
from app.services.attack_path_engine import AttackPathEngine


def create_mock_finding(
    title: str,
    category: str,
    cwe_id: str,
    severity: FindingSeverity = FindingSeverity.HIGH,
    affected_asset: str = "https://example.com/api"
) -> Finding:
    f = Finding(
        id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        organization_id=str(uuid.uuid4()),
        title=title,
        category=category,
        cwe_id=cwe_id,
        severity=severity,
        status=FindingStatus.OPEN,
        affected_asset=affected_asset,
        evidence_summary="Discovered by automated AI agent probe",
        risk_score=85.0,
        confidence=0.95,
        discovered_at=datetime.now(timezone.utc)
    )
    return f


def test_empty_findings_attack_graph():
    graph = AttackPathEngine.generate_attack_graph([])
    assert graph["paths"] == []
    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert graph["critical_choke_point"] is None
    assert graph["summary"]["total_paths"] == 0
    assert graph["summary"]["crown_jewels_at_risk"] == 0


def test_supabase_database_exfiltration_path():
    f_entry = create_mock_finding(
        title="Missing Strict Content-Security-Policy",
        category="security_headers",
        cwe_id="CWE-693",
        severity=FindingSeverity.LOW,
        affected_asset="https://myapp.lovable.app"
    )
    f_exploit = create_mock_finding(
        title="Supabase Row-Level Security (RLS) Disabled",
        category="supabase_rls_security",
        cwe_id="CWE-284",
        severity=FindingSeverity.CRITICAL,
        affected_asset="https://xyz.supabase.co/rest/v1/profiles"
    )

    graph = AttackPathEngine.generate_attack_graph([f_entry, f_exploit])
    assert len(graph["paths"]) >= 1
    
    db_path = next((p for p in graph["paths"] if p["id"] == "path_database_exfiltration"), None)
    assert db_path is not None
    assert db_path["severity"] == "critical"
    assert "Customer" in db_path["crown_jewel"]
    assert len(db_path["steps"]) >= 2

    # Check Choke Point
    assert graph["critical_choke_point"] is not None
    assert graph["critical_choke_point"]["finding_id"] == str(f_exploit.id)
    assert graph["critical_choke_point"]["risk_reduction_pct"] >= 50


def test_llm_and_webhook_chains_multi_exploit():
    f_llm = create_mock_finding(
        title="Exposed LLM Endpoint & Missing Prompt Guard",
        category="llm_prompt_injection_guard",
        cwe_id="CWE-1426",
        severity=FindingSeverity.HIGH,
        affected_asset="https://myapp.bolt.new/api/chat"
    )
    f_wh = create_mock_finding(
        title="Payment Webhook Missing Signature Verification",
        category="webhook_signature_integrity",
        cwe_id="CWE-345",
        severity=FindingSeverity.CRITICAL,
        affected_asset="https://myapp.bolt.new/api/webhooks/stripe"
    )

    graph = AttackPathEngine.generate_attack_graph([f_llm, f_wh])
    assert len(graph["paths"]) == 2
    
    path_ids = [p["id"] for p in graph["paths"]]
    assert "path_llm_exhaustion" in path_ids
    assert "path_webhook_payment_forgery" in path_ids

    # Both Crown Jewels should be identified
    assert graph["summary"]["crown_jewels_at_risk"] == 2
    assert graph["summary"]["total_paths"] == 2
    assert graph["critical_choke_point"] is not None


def test_blast_radius_and_edges():
    f_cors = create_mock_finding(
        title="Permissive CORS Wildcard",
        category="cors_misconfiguration",
        cwe_id="CWE-942",
        severity=FindingSeverity.MEDIUM,
        affected_asset="https://api.vibeapp.com"
    )
    f_sp = create_mock_finding(
        title="Supabase Public Profiles RLS Bypass",
        category="supabase_rls_security",
        cwe_id="CWE-284",
        severity=FindingSeverity.CRITICAL,
        affected_asset="https://xyz.supabase.co/rest/v1/orders"
    )
    graph = AttackPathEngine.generate_attack_graph([f_cors, f_sp])
    
    # Check edges exist and connect the nodes
    assert len(graph["edges"]) >= 2
    edge_types = [e["type"] for e in graph["edges"]]
    assert "chains_to" in edge_types
    assert "compromises" in edge_types
