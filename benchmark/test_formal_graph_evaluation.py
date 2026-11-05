"""
P2.1: Formal Graph Engine Scientific Evaluation Suite
Evaluates GrayStrike's Evidence Knowledge Graph & Constraint Reachability Engine
independently of scanner heuristic probes.

Evaluates:
1. Constraint Correctness: Are all transitions logically entailment-checked?
2. Missing Evidence Handling: Does the engine avoid hallucinating edges when evidence is missing?
3. UNSAT Interpretation: Does severing a precondition or choke point mathematically produce UNSAT?
4. False Exploit-Chain Confirmation Resistance: Disconnected or contradictory paths must be rejected.
5. Distinction: Confirms model satisfiability (SAT) is distinguished from confirmed active exploit.
"""
import sys
import os
import uuid
import pytest
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from backend.app.services.formal_attack_graph import (
    EvidenceKnowledgeGraph,
    EvidenceNode,
    EvidenceEdge,
    GraphNodeType,
    GraphEdgeType,
    FormalReachabilitySolver,
    FormalAttackPathEngine,
    FormalExploitProof
)


# =============================================================
# 1. CONSTRAINT CORRECTNESS TESTS
# =============================================================

def test_constraint_horn_clause_entailment():
    """Verify that every step's postconditions strictly become the next step's preconditions."""
    graph = EvidenceKnowledgeGraph()

    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker"))
    graph.add_node(EvidenceNode(id="B", node_type=GraphNodeType.ENDPOINT, label="Step 1 Route"))
    graph.add_node(EvidenceNode(id="C", node_type=GraphNodeType.ENDPOINT, label="Step 2 Route"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Target Database"))

    # Step 1: InternetAccessible -> HasStep1Token
    graph.add_edge(EvidenceEdge(
        id="e1", source_id="A", target_id="B",
        edge_type=GraphEdgeType.CALLS, technique="Initial Probe",
        preconditions=["InternetAccessible"],
        postconditions=["HasStep1Token"],
        confidence=0.95
    ))

    # Step 2: HasStep1Token -> HasAdminPrivilege
    graph.add_edge(EvidenceEdge(
        id="e2", source_id="B", target_id="C",
        edge_type=GraphEdgeType.CALLS, technique="Privilege Pivot",
        preconditions=["HasStep1Token"],
        postconditions=["HasAdminPrivilege"],
        confidence=0.90
    ))

    # Step 3: HasAdminPrivilege -> Target Compromise
    graph.add_edge(EvidenceEdge(
        id="e3", source_id="C", target_id="D",
        edge_type=GraphEdgeType.CAN_READ, technique="Read Crown Jewel",
        preconditions=["HasAdminPrivilege"],
        postconditions=["Compromised(TargetDB)"],
        confidence=0.92
    ))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof is not None
    assert proof.satisfaction_status == "SAT"
    assert proof.model_satisfiable is True
    assert len(proof.proof_witness) == 3
    assert len(proof.satisfied_constraints) == 3


# =============================================================
# 2. MISSING EVIDENCE / BROKEN CHAIN RESISTANCE
# =============================================================

def test_missing_evidence_breaks_chain_to_unsat():
    """
    If Step 2 requires 'HasSecretKey' but Step 1 never produced it,
    the solver MUST NOT confirm reachability (returns None / UNSAT).
    """
    graph = EvidenceKnowledgeGraph()

    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker"))
    graph.add_node(EvidenceNode(id="B", node_type=GraphNodeType.ENDPOINT, label="Public Route"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Customer DB"))

    # Step 1 produces only 'BrowsedPublicCatalog'
    graph.add_edge(EvidenceEdge(
        id="e1", source_id="A", target_id="B",
        edge_type=GraphEdgeType.CALLS, technique="Browse Catalog",
        preconditions=["InternetAccessible"],
        postconditions=["BrowsedPublicCatalog"],  # Does NOT produce database token
        confidence=0.95
    ))

    # Step 2 requires 'ExtractedAnonKey' which was NEVER observed or produced
    graph.add_edge(EvidenceEdge(
        id="e2", source_id="B", target_id="D",
        edge_type=GraphEdgeType.CAN_READ, technique="Dump Database",
        preconditions=["ExtractedAnonKey"],  # Unmet precondition!
        postconditions=["Compromised(CustomerDB)"],
        confidence=0.90
    ))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    # Reachability must be rejected
    assert proof is None


# =============================================================
# 3. UNSAT INTERPRETATION VIA CHOKE POINT CUT
# =============================================================

def test_choke_point_cut_proves_unsat():
    """
    Asserting NOT(C_choke) must mathematically break the path.
    Verify that removing the choke transition renders target unreachable.
    """
    graph = EvidenceKnowledgeGraph()

    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker"))
    graph.add_node(EvidenceNode(id="B", node_type=GraphNodeType.ENDPOINT, label="Supabase Route"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Customer DB"))

    choke_edge = EvidenceEdge(
        id="edge_choke_rls", source_id="A", target_id="B",
        edge_type=GraphEdgeType.CALLS, technique="Exploit RLS Policy",
        preconditions=["InternetAccessible"],
        postconditions=["BypassedRLS"],
        confidence=0.95
    )
    data_edge = EvidenceEdge(
        id="edge_data_dump", source_id="B", target_id="D",
        edge_type=GraphEdgeType.CAN_READ, technique="Read Data",
        preconditions=["BypassedRLS"],
        postconditions=["Compromised(CustomerDB)"],
        confidence=0.92
    )

    graph.add_edge(choke_edge)
    graph.add_edge(data_edge)

    # 1. Before remediation: Reachable (SAT)
    proof_before = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof_before is not None
    assert proof_before.satisfaction_status == "SAT"

    # 2. Simulate Remediation: Severing choke edge (simulating NOT(C_choke))
    graph.edges.pop("edge_choke_rls")
    graph.adjacency["A"] = []

    # 3. After remediation: Unreachable (UNSAT)
    proof_after = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof_after is None, "Target must be unreachable after severing choke point"


# =============================================================
# 4. FALSE EXPLOIT-CHAIN CONFIRMATION RESISTANCE
# =============================================================

def test_disconnected_subgraphs_rejected():
    """Isolated security findings must NOT form a confirmed attack path."""
    graph = EvidenceKnowledgeGraph()

    # Subgraph 1: Attacker -> Public API
    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker"))
    graph.add_node(EvidenceNode(id="B", node_type=GraphNodeType.ENDPOINT, label="Public API"))
    graph.add_edge(EvidenceEdge(
        id="e1", source_id="A", target_id="B",
        edge_type=GraphEdgeType.CALLS, technique="Ping",
        preconditions=["InternetAccessible"], postconditions=["GotPing"], confidence=0.9
    ))

    # Subgraph 2: Completely isolated internal database (no path from B to D)
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Crown Jewel"))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof is None


# =============================================================
# 5. MODEL SATISFIABILITY VS EMPIRICAL EXPLOITABILITY
# =============================================================

def test_proof_contains_scientific_disclaimer():
    """All formal proofs must explicitly distinguish model SAT from unconstrained empirical exploit."""
    graph = EvidenceKnowledgeGraph()
    graph.add_node(EvidenceNode(id="A", node_type=GraphNodeType.IDENTITY, label="Attacker"))
    graph.add_node(EvidenceNode(id="D", node_type=GraphNodeType.DATA_RESOURCE, label="Crown Jewel"))
    graph.add_edge(EvidenceEdge(
        id="e1", source_id="A", target_id="D",
        edge_type=GraphEdgeType.CAN_READ, technique="Direct Access",
        preconditions=["InternetAccessible"], postconditions=["GotData"], confidence=0.9
    ))

    proof = FormalReachabilitySolver.solve_reachability(graph, "A", "D")
    assert proof is not None
    assert hasattr(proof, "scientific_disclaimer")
    assert "Model satisfiability (SAT)" in proof.scientific_disclaimer
    assert proof.exploit_status == "model_satisfiable_hypothesis"
    assert proof.model_satisfiable is True
