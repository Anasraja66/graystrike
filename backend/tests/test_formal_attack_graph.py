"""
Unit & Integration Tests for P1 Deep-Tech Innovation:
Formal Evidence Knowledge Graph & SAT/SMT Reachability Constraint Engine
"""
import sys
import os
import uuid
from datetime import datetime, timezone
import pytest

# Ensure backend and root paths are registered
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.models.models import Finding, FindingSeverity, FindingStatus
from app.services.formal_attack_graph import (
    EvidenceKnowledgeGraph,
    EvidenceNode,
    EvidenceEdge,
    GraphNodeType,
    GraphEdgeType,
    FormalReachabilitySolver,
    FormalAttackPathEngine,
    HAS_Z3
)
from app.services.attack_path_engine import AttackPathEngine


def create_dummy_finding(
    title: str,
    category: str,
    cwe_id: str = "CWE-284",
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    affected_asset: str = "https://myapp.lovable.app/api"
) -> Finding:
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
        affected_asset=affected_asset,
        evidence_summary="Verified by active evidence probe",
        risk_score=90.0,
        confidence=0.95,
        discovered_at=datetime.now(timezone.utc)
    )


def test_evidence_knowledge_graph_construction():
    """Verify nodes, edges, provenance attributes, and graph traversal."""
    graph = EvidenceKnowledgeGraph()

    # 1. Add Identity Node
    attacker_node = EvidenceNode(
        id="attacker_1",
        node_type=GraphNodeType.IDENTITY,
        label="Anonymous Attacker",
        properties={"role": "unauthenticated"}
    )
    graph.add_node(attacker_node)

    # 2. Add Endpoint Node
    endpoint_node = EvidenceNode(
        id="endpoint_users",
        node_type=GraphNodeType.ENDPOINT,
        label="/rest/v1/users",
        properties={"method": "GET"}
    )
    graph.add_node(endpoint_node)

    # 3. Add Data Resource Node
    db_node = EvidenceNode(
        id="cj_db",
        node_type=GraphNodeType.DATA_RESOURCE,
        label="Customer PII Database",
        properties={"sensitivity": "critical"}
    )
    graph.add_node(db_node)

    # 4. Add Edges with Semantics & Preconditions
    e1 = EvidenceEdge(
        id="edge_1",
        source_id="attacker_1",
        target_id="endpoint_users",
        edge_type=GraphEdgeType.CALLS,
        technique="HTTP GET without Auth",
        confidence=0.98,
        preconditions=["InternetAccessible"],
        postconditions=["ReachedEndpoint"]
    )
    e2 = EvidenceEdge(
        id="edge_2",
        source_id="endpoint_users",
        target_id="cj_db",
        edge_type=GraphEdgeType.CAN_READ,
        technique="Disabled RLS dump",
        confidence=0.92,
        preconditions=["ReachedEndpoint"],
        postconditions=["Compromised(CustomerDB)"]
    )

    graph.add_edge(e1)
    graph.add_edge(e2)

    assert "attacker_1" in graph.nodes
    assert "endpoint_users" in graph.nodes
    assert "cj_db" in graph.nodes
    assert len(graph.get_outgoing_edges("attacker_1")) == 1
    assert graph.get_outgoing_edges("attacker_1")[0].target_id == "endpoint_users"
    assert len(graph.get_outgoing_edges("endpoint_users")) == 1
    assert graph.get_outgoing_edges("endpoint_users")[0].target_id == "cj_db"


def test_formal_reachability_solver_sat_proof():
    """Verify formal satisfiability proof: Reachable(A, D) <=> exists p : AND_{e in p} C_e."""
    graph = EvidenceKnowledgeGraph()

    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker State"))
    graph.add_node(EvidenceNode(id="E", node_type=GraphNodeType.ENDPOINT, label="Public API"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Crown Jewel"))

    graph.add_edge(EvidenceEdge(
        id="e1",
        source_id="A",
        target_id="E",
        edge_type=GraphEdgeType.CALLS,
        technique="Call API",
        confidence=0.95,
        preconditions=["InternetAccessible"],
        postconditions=["HasAPIResponse"]
    ))
    graph.add_edge(EvidenceEdge(
        id="e2",
        source_id="E",
        target_id="D",
        edge_type=GraphEdgeType.CAN_READ,
        technique="Exfiltrate Data",
        confidence=0.90,
        preconditions=["HasAPIResponse"],
        postconditions=["Compromised(CrownJewel)"]
    ))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof is not None
    assert proof.is_mathematically_proven is True
    assert proof.satisfaction_status == "SAT"
    assert "Reachable(A, D) <=>" in proof.reachability_formula
    assert "C_e1" in proof.reachability_formula
    assert "C_e2" in proof.reachability_formula
    assert proof.confidence_score == 0.90
    assert len(proof.proof_witness) == 2
    assert "UNSAT" in proof.choke_point_formula


def test_formal_reachability_solver_unsat_on_missing_precondition():
    """Verify that unsatisfied preconditions mathematically result in UNSAT."""
    graph = EvidenceKnowledgeGraph()

    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker State"))
    graph.add_node(EvidenceNode(id="E", node_type=GraphNodeType.ENDPOINT, label="Internal Admin API"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Crown Jewel"))

    # e1 requires AdminMFA which public attacker does NOT have and is not entailed
    graph.add_edge(EvidenceEdge(
        id="e1",
        source_id="A",
        target_id="E",
        edge_type=GraphEdgeType.CALLS,
        technique="Attempt Admin Call",
        confidence=0.95,
        preconditions=["AdminMFAVerified"],  # Unmet precondition!
        postconditions=["InAdminConsole"]
    ))
    graph.add_edge(EvidenceEdge(
        id="e2",
        source_id="E",
        target_id="D",
        edge_type=GraphEdgeType.CAN_WRITE,
        technique="Drop Database",
        confidence=0.95,
        preconditions=["InAdminConsole"],
        postconditions=["DatabaseDestroyed"]
    ))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    # Reachability should fail (UNSAT or None because no SAT path exists)
    assert proof is None


def test_formal_attack_path_engine_all_crown_jewels():
    """Verify end-to-end multi-path analysis across all 4 crown jewels."""
    f1 = create_dummy_finding(
        title="Supabase RLS Policy Disabled on Users Table",
        category="supabase_rls_security",
        affected_asset="https://app.example.com/rest/v1/users"
    )
    f2 = create_dummy_finding(
        title="Exposed LLM Completion Route without Authentication",
        category="llm_prompt_injection_guard",
        affected_asset="https://app.example.com/api/chat"
    )
    f3 = create_dummy_finding(
        title="Stripe Webhook Missing Signature Validation",
        category="webhook_signature_integrity",
        affected_asset="https://app.example.com/api/webhooks/stripe"
    )
    f4 = create_dummy_finding(
        title="Admin API Accessible Without Server-Side Verification",
        category="admin_portal_exposure",
        affected_asset="https://app.example.com/api/admin/users"
    )

    result = FormalAttackPathEngine.generate_attack_graph([f1, f2, f3, f4])

    assert len(result["paths"]) == 4
    assert result["summary"]["total_paths"] == 4
    assert result["summary"]["crown_jewels_at_risk"] == 4
    assert result["summary"]["max_risk_score"] == 95

    # Check that each path has a formal mathematical proof attached
    for path in result["paths"]:
        assert "formal_proof" in path
        assert path["formal_proof"]["is_mathematically_proven"] is True
        assert path["formal_proof"]["satisfaction_status"] == "SAT"
        assert len(path["steps"]) >= 2

    # Verify Critical Choke Point is identified
    assert result["critical_choke_point"] is not None
    assert "mathematical_cut_proof" in result["critical_choke_point"]
    assert "UNSAT" in result["critical_choke_point"]["mathematical_cut_proof"]


def test_attack_path_engine_backward_compatibility_with_formal_proof():
    """Verify that AttackPathEngine integrates formal proof fields while maintaining UI compatibility."""
    f_rls = create_dummy_finding(
        title="Supabase Row-Level Security (RLS) Disabled",
        category="supabase_rls_security",
        cwe_id="CWE-284",
        severity=FindingSeverity.CRITICAL,
        affected_asset="https://xyz.supabase.co/rest/v1/profiles"
    )

    graph = AttackPathEngine.generate_attack_graph([f_rls])
    assert len(graph["paths"]) >= 1

    db_path = graph["paths"][0]
    # Check existing UI fields
    assert "id" in db_path
    assert "name" in db_path
    assert "risk_score" in db_path
    assert "crown_jewel" in db_path
    assert "steps" in db_path

    # Check P1 Deep-Tech additions
    assert "formal_proof" in db_path
    assert db_path["formal_proof"]["is_mathematically_proven"] is True
    assert db_path["formal_proof"]["satisfaction_status"] == "SAT"
    assert "Reachable" in db_path["formal_proof"]["reachability_formula"]

    # Check Choke Point mathematical cut proof
    assert graph["critical_choke_point"] is not None
    assert "mathematical_cut_proof" in graph["critical_choke_point"]
    assert "UNSAT" in graph["critical_choke_point"]["mathematical_cut_proof"]
    assert graph["summary"]["reachability_proof_status"] == "SAT_PROVEN"
