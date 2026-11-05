"""
GrayAnalyze Agent — Formal Taxonomy & SMT Reachability Reasoner
Inspired by SecureAnalyze (Alve et al., SecureFlow, MDPI 2026) and GrayStrike Formal Attack Graph.

Purpose:
1. Maps candidate vulnerabilities to formal CWE and OWASP Top-10 taxonomy.
2. Formulates formal reachability logic and queries the SAT/SMT reasoner.
3. Distinguishes genuine exploitable reachability from unreachable or guarded code paths.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from backend.app.services.formal_attack_graph import (
    EvidenceKnowledgeGraph,
    EvidenceNode,
    EvidenceEdge,
    GraphNodeType,
    GraphEdgeType,
    FormalReachabilitySolver
)


@dataclass
class FormalSecurityFinding:
    finding_id: str
    cwe_id: str
    owasp_category: str
    title: str
    description: str
    severity: str
    file_path: Optional[str]
    line_number: Optional[int]
    is_satisfiable: bool  # SAT (exploitable) vs UNSAT (guarded)
    reachability_formula: str
    satisfying_assignment: Optional[Dict[str, Any]]
    preconditions: List[str] = field(default_factory=list)
    confidence: float = 0.95

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "is_satisfiable": self.is_satisfiable,
            "reachability_formula": self.reachability_formula,
            "satisfying_assignment": self.satisfying_assignment,
            "preconditions": self.preconditions,
            "confidence": self.confidence,
        }


class GrayAnalyzeAgent:
    """
    Classifies vulnerabilities into CWE/OWASP taxonomy and runs formal SMT satisfiability checks.
    """

    TAXONOMY_MAP = {
        "sql": {
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "title": "SQL Injection in Route Handler",
            "severity": "critical",
            "hint": "Sanitize and parameterize all SQL queries using prepared statements or ORM binding."
        },
        "supabase": {
            "cwe": "CWE-284",
            "owasp": "A01:2021-Broken Access Control",
            "title": "Supabase Missing Row Level Security (RLS)",
            "severity": "critical",
            "hint": "Enable RLS on table and add 'auth.uid() = user_id' security policies."
        },
        "llm": {
            "cwe": "CWE-306",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "title": "Unauthenticated AI/LLM Route Exposure",
            "severity": "high",
            "hint": "Enforce per-user authentication session tokens and rate limits on LLM inference."
        },
        "exec": {
            "cwe": "CWE-78",
            "owasp": "A03:2021-Injection",
            "title": "Command Injection in Backend Process",
            "severity": "critical",
            "hint": "Avoid shell execution; pass argument vectors and validate against a strict whitelist."
        },
        "fetch": {
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
            "title": "Unrestricted Outbound Request (SSRF)",
            "severity": "high",
            "hint": "Enforce private IP blacklisting and strict outbound destination hostname validation."
        },
        "credential": {
            "cwe": "CWE-798",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "title": "Hardcoded Sensitive API Token or Secret",
            "severity": "critical",
            "hint": "Move sensitive tokens to environment variables and inject via secure vault."
        }
    }

    @classmethod
    def analyze_candidate(
        cls,
        candidate_reason: str,
        snippet: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
        is_authenticated_route: bool = False,
        has_input_sanitizer: bool = False
    ) -> FormalSecurityFinding:
        """
        Classifies candidate and constructs formal reachability proof using SAT reasoning.
        """
        # Step 1: Map to Taxonomy
        matched_key = "sql"
        lower_reason = (candidate_reason + " " + snippet).lower()
        for key in cls.TAXONOMY_MAP.keys():
            if key in lower_reason:
                matched_key = key
                break

        tax_meta = cls.TAXONOMY_MAP[matched_key]

        # Step 2: Formulate Formal Reachability via Evidence Knowledge Graph
        graph = EvidenceKnowledgeGraph()

        # Node 1: Entry Point (Public / Internet Caller)
        node_entry = EvidenceNode(
            id="node_public_entry",
            node_type=GraphNodeType.IDENTITY,
            label="Internet Client",
            properties={"scope": "external"}
        )
        graph.add_node(node_entry)

        # Node 2: Route / Function Handler
        node_route = EvidenceNode(
            id="node_target_route",
            node_type=GraphNodeType.ENDPOINT,
            label=tax_meta["title"],
            properties={"file": file_path, "line": line_number}
        )
        graph.add_node(node_route)

        # Node 3: Target Crown Jewel (Sensitive Data Resource)
        node_jewel = EvidenceNode(
            id="node_target_jewel",
            node_type=GraphNodeType.DATA_RESOURCE,
            label="Customer PII Database",
            properties={"asset": "UserRecords"}
        )
        graph.add_node(node_jewel)

        # Edge 1: Entry -> Route
        edge1_pre = ["InternetAccessible"]
        if is_authenticated_route:
            edge1_pre.append("AuthenticatedSession")  # Unfulfilled by public anonymous caller!

        edge1 = EvidenceEdge(
            id="edge_reach_route",
            source_id="node_public_entry",
            target_id="node_target_route",
            edge_type=GraphEdgeType.CALLS,
            technique="HTTP_REQUEST",
            preconditions=edge1_pre,
            postconditions=["RouteReached"],
            constraint_formula="P_exposed ∧ P_unauth" if not is_authenticated_route else "P_exposed ∧ ¬P_unauth"
        )
        graph.add_edge(edge1)

        # Edge 2: Route -> Crown Jewel
        edge2_pre = ["RouteReached"]
        if has_input_sanitizer:
            edge2_pre.append("BypassSanitization")  # Contradicts input sanitizer!

        edge2 = EvidenceEdge(
            id="edge_exploit_sink",
            source_id="node_target_route",
            target_id="node_target_jewel",
            edge_type=GraphEdgeType.CAN_READ,
            technique="INJECTION_OR_DIRECT_ACCESS",
            preconditions=edge2_pre,
            postconditions=["CrownJewelCompromised"],
            constraint_formula="P_tainted ∧ P_no_guard" if not has_input_sanitizer else "¬P_tainted ∧ ¬P_no_guard"
        )
        graph.add_edge(edge2)

        proof = FormalReachabilitySolver.solve_reachability(
            graph=graph,
            initial_node_id="node_public_entry",
            crown_jewel_id="node_target_jewel"
        )

        is_sat = proof is not None and proof.satisfaction_status == "SAT"
        formula_repr = "P_exposed ∧ P_unauth ∧ (P_tainted ∨ P_no_guard)"

        return FormalSecurityFinding(
            finding_id=f"formal-{matched_key}-01",
            cwe_id=tax_meta["cwe"],
            owasp_category=tax_meta["owasp"],
            title=tax_meta["title"],
            description=f"Formally analyzed {tax_meta['title']} at {file_path}:{line_number}. Formula: {formula_repr}.",
            severity=tax_meta["severity"],
            file_path=file_path,
            line_number=line_number,
            is_satisfiable=is_sat,
            reachability_formula=formula_repr,
            satisfying_assignment=proof.model_dump() if hasattr(proof, "model_dump") else (proof.dict() if proof else None),
            preconditions=[
                "External public route accessible",
                "Unauthenticated HTTP request accepted",
                "Direct untrusted data reaches sensitive sink"
            ],
            confidence=0.98 if is_sat else 0.20
        )
