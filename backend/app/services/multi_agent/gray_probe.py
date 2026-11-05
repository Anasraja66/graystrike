"""
GrayProbe Agent — Fast Binary Filter & Attack Surface Scout
Inspired by SecureProbe (Alve et al., SecureFlow, MDPI 2026).

Purpose:
Performs coarse-grained binary filtering (Safe vs Candidate Vulnerable).
Acts as an early-exit filter to reject benign code/endpoints quickly,
protecting downstream reasoning solvers and LLMs from task interference
and unnecessary compute costs.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import re


@dataclass
class ProbeCandidate:
    candidate_id: str
    target_type: str  # "source_code" or "api_endpoint"
    asset: str
    line_number: Optional[int]
    suspicion_reason: str
    raw_snippet: str
    confidence_score: float  # 0.0 to 1.0


@dataclass
class ProbeResult:
    is_vulnerable_candidate: bool
    status: str  # "Safe" or "CandidateVulnerable"
    candidates: List[ProbeCandidate] = field(default_factory=list)
    total_inspected: int = 0
    safe_filtered_count: int = 0
    early_exit_applied: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_vulnerable_candidate": self.is_vulnerable_candidate,
            "status": self.status,
            "candidates": [
                {
                    "candidate_id": c.candidate_id,
                    "target_type": c.target_type,
                    "asset": c.asset,
                    "line_number": c.line_number,
                    "suspicion_reason": c.suspicion_reason,
                    "confidence_score": c.confidence_score
                }
                for c in self.candidates
            ],
            "total_inspected": self.total_inspected,
            "safe_filtered_count": self.safe_filtered_count,
            "early_exit_applied": self.early_exit_applied,
            "metadata": self.metadata
        }


class GrayProbeAgent:
    """
    Fast AST & Endpoint filter that separates safe assets from vulnerable candidates.
    """

    SUSPICIOUS_CODE_PATTERNS = [
        (r"(SELECT\s+.*?\s+FROM\s+.*?\+\s*req|SELECT\s+.*?\s+WHERE\s+.*?\$\{)", "Raw SQL string concatenation or template literal", 0.92),
        (r"(supabase\.from\(['\"].*?['\"]\)\.select\(.*?\))", "Supabase direct table query without evident RLS check", 0.85),
        (r"(exec\(|eval\(|child_process\.exec|os\.system\()", "Dangerous OS command or code evaluation", 0.95),
        (r"(fetch\(\s*req\.query|requests\.get\(\s*params\[)", "Unvalidated server-side outbound HTTP request (potential SSRF)", 0.88),
        (r"(\/api\/chat|\/api\/generate|\/api\/ai)", "Exposed AI / LLM generation route handler", 0.80),
        (r"(sk_live_[a-zA-Z0-9_\-]+|SUPABASE_SERVICE_ROLE_KEY|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})", "Hardcoded credential or private API token", 0.99)
    ]

    BENIGN_INDICATORS = [
        r"//\s*@safe",
        r"sql\.param\(",
        r"prepared_statement",
        r"auth\.require_user\(",
        r"EnterpriseSafetyGuard\.validate_target_scope"
    ]

    @classmethod
    def evaluate_code(
        cls,
        code_content: str,
        file_path: str = "app/api/route.ts"
    ) -> ProbeResult:
        """
        Scans code snippet for immediate red flags vs benign status.
        """
        lines = code_content.splitlines()
        candidates: List[ProbeCandidate] = []
        safe_filtered = 0

        # Check for immediate benign patterns
        has_benign = any(re.search(pat, code_content, re.IGNORECASE) for pat in cls.BENIGN_INDICATORS)

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "/*")):
                safe_filtered += 1
                continue

            for pattern, reason, conf in cls.SUSPICIOUS_CODE_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    # Adjust confidence if benign indicators present in file
                    effective_conf = conf * 0.5 if has_benign else conf
                    if effective_conf >= 0.70:
                        candidates.append(
                            ProbeCandidate(
                                candidate_id=f"cand-{len(candidates) + 1}",
                                target_type="source_code",
                                asset=file_path,
                                line_number=line_idx,
                                suspicion_reason=reason,
                                raw_snippet=stripped,
                                confidence_score=round(effective_conf, 2)
                            )
                        )
                    else:
                        safe_filtered += 1

        is_vuln = len(candidates) > 0
        return ProbeResult(
            is_vulnerable_candidate=is_vuln,
            status="CandidateVulnerable" if is_vuln else "Safe",
            candidates=candidates,
            total_inspected=len(lines),
            safe_filtered_count=safe_filtered,
            early_exit_applied=not is_vuln,
            metadata={"file_path": file_path, "has_benign_guard": has_benign}
        )

    @classmethod
    def evaluate_endpoint(
        cls,
        endpoint_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None
    ) -> ProbeResult:
        """
        Fast filter for API endpoints.
        """
        candidates: List[ProbeCandidate] = []
        is_candidate = False

        # Endpoint heuristics
        lower_url = endpoint_url.lower()
        if any(kw in lower_url for kw in ["/api/db/", "/users", "/admin", "/orders", "/chat", "/eval", "/query"]):
            has_auth = headers and any(k.lower() in ["authorization", "x-api-key"] for k in headers.keys())
            if not has_auth:
                is_candidate = True
                candidates.append(
                    ProbeCandidate(
                        candidate_id="cand-ep-1",
                        target_type="api_endpoint",
                        asset=endpoint_url,
                        line_number=None,
                        suspicion_reason=f"Sensitive {method} endpoint exposed without authorization header",
                        raw_snippet=f"{method} {endpoint_url}",
                        confidence_score=0.90
                    )
                )

        return ProbeResult(
            is_vulnerable_candidate=is_candidate,
            status="CandidateVulnerable" if is_candidate else "Safe",
            candidates=candidates,
            total_inspected=1,
            safe_filtered_count=0 if is_candidate else 1,
            early_exit_applied=not is_candidate,
            metadata={"endpoint": endpoint_url, "method": method}
        )
