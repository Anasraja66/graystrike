"""
P3: Code-to-Runtime Mapper
Links GitHub commit SHA → deployed DAST scan findings.
Enables security teams to trace a live vulnerability back to the exact
source code commit that introduced it.

Key capabilities:
- Commit SHA correlation with DAST findings
- Security regression detection (new vulns introduced in a commit)
- Code-path trace: File + line number → deployed endpoint → scan finding
- Security diff: Before/after commit security posture comparison
"""
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

from backend.app.services.sast.ast_analyzer import SASTFinding


# =============================================================
# DATA MODELS
# =============================================================

@dataclass
class CommitSecurityDiff:
    """Security posture change between two commits."""
    commit_sha: str
    parent_sha: str
    commit_message: str
    commit_author: str
    commit_timestamp: str
    new_findings: List[SASTFinding]            # Vulnerabilities introduced in this commit
    resolved_findings: List[SASTFinding]        # Vulnerabilities that no longer appear
    persisting_findings: List[SASTFinding]      # Still present since parent commit
    risk_delta: int                            # +ve = risk increased, -ve = risk reduced
    regression_detected: bool                  # True if critical/high vuln introduced
    regression_summary: str


@dataclass
class CodeToRuntimeLink:
    """Links a SAST finding (source code) to a DAST finding (runtime behavior)."""
    sast_finding: SASTFinding
    dast_finding_id: Optional[str]         # Finding.id from DB
    dast_finding_title: Optional[str]
    dast_scan_url: Optional[str]
    link_confidence: float                 # How confident is this code→runtime link?
    link_method: str                       # "category_match" | "endpoint_match" | "cwe_match"
    commit_sha: str
    file_path: str
    line_number: int
    deployed_endpoint: Optional[str]       # The live URL corresponding to this code path


@dataclass
class SecurityPostureReport:
    """Full security posture merging SAST + DAST results."""
    repo_url: str
    commit_sha: str
    scan_timestamp: str
    sast_findings: List[SASTFinding]
    dast_findings_raw: List[Dict[str, Any]]
    code_to_runtime_links: List[CodeToRuntimeLink]
    summary: Dict[str, Any]


# =============================================================
# CODE-TO-RUNTIME MAPPER ENGINE
# =============================================================

class CodeToRuntimeMapper:
    """
    Correlates SAST findings (GitHub source) with DAST findings (live scan).
    
    Mapping Strategy:
    1. Category Match: SAST finding.category == DAST finding.category
    2. CWE Match: SAST finding.cwe_id == DAST finding.cwe_id
    3. Endpoint Inference: Derive live endpoint URL from file path + base URL
    """

    # File path → API route pattern inference for Next.js App Router
    NEXTJS_ROUTE_PATTERNS = [
        (re.compile(r"app/(api/.+)/route\.(ts|js)$"), "/{path}"),
        (re.compile(r"app/api/(.+)/route\.(ts|js)$"), "/api/{path}"),
        (re.compile(r"pages/api/(.+)\.(ts|js)$"), "/api/{path}"),
        (re.compile(r"app/(.+)/page\.(ts|js|tsx|jsx)$"), "/{path}"),
    ]

    # File path → Flask/FastAPI route inference
    PYTHON_ROUTE_PATTERNS = [
        (re.compile(r"routes?/(.+)\.py$"), "/api/{path}"),
        (re.compile(r"api/(.+)\.py$"), "/api/{path}"),
        (re.compile(r"views?/(.+)\.py$"), "/{path}"),
    ]

    @classmethod
    def infer_endpoint_from_path(cls, file_path: str, base_url: str) -> Optional[str]:
        """
        Infer the live endpoint URL from a source file path.
        Example: app/api/chat/route.ts → https://myapp.com/api/chat
        """
        base_url = base_url.rstrip("/")
        fp = file_path.replace("\\", "/").lower()

        for pattern, template in cls.NEXTJS_ROUTE_PATTERNS:
            m = pattern.search(fp)
            if m:
                path = m.group(1).replace("/index", "").strip("/")
                return f"{base_url}/{path}"

        for pattern, template in cls.PYTHON_ROUTE_PATTERNS:
            m = pattern.search(fp)
            if m:
                path = m.group(1).replace("_", "-")
                return f"{base_url}/api/{path}"

        return None

    @classmethod
    def build_links(
        cls,
        sast_findings: List[SASTFinding],
        dast_findings: List[Dict[str, Any]],
        base_url: str,
        commit_sha: str
    ) -> List[CodeToRuntimeLink]:
        """
        Build Code→Runtime links by correlating SAST and DAST findings.
        """
        links: List[CodeToRuntimeLink] = []

        for sf in sast_findings:
            best_dast = None
            best_confidence = 0.0
            best_method = "unmatched"

            for df in dast_findings:
                dast_cat = str(df.get("category", "")).lower()
                dast_cwe = str(df.get("cwe_id", "")).lower()
                sast_cat = sf.category.lower()
                sast_cwe = sf.cwe_id.lower()

                confidence = 0.0
                method = "unmatched"

                # CWE-level exact match (strongest signal)
                if sast_cwe and dast_cwe and sast_cwe == dast_cwe:
                    confidence = 0.88
                    method = "cwe_match"

                # Category semantic match
                elif sast_cat and dast_cat and (sast_cat == dast_cat or
                        (sast_cat in dast_cat) or (dast_cat in sast_cat)):
                    confidence = 0.75
                    method = "category_match"

                # Keyword match on title
                elif cls._keyword_overlap(sf.title, str(df.get("title", ""))):
                    confidence = 0.65
                    method = "keyword_match"

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_dast = df
                    best_method = method

            # Infer deployed endpoint
            deployed_endpoint = cls.infer_endpoint_from_path(sf.file_path, base_url)

            links.append(CodeToRuntimeLink(
                sast_finding=sf,
                dast_finding_id=str(best_dast.get("id", "")) if best_dast else None,
                dast_finding_title=str(best_dast.get("title", "")) if best_dast else None,
                dast_scan_url=str(best_dast.get("affected_asset", "")) if best_dast else None,
                link_confidence=round(best_confidence, 2),
                link_method=best_method,
                commit_sha=commit_sha,
                file_path=sf.file_path,
                line_number=sf.line_number,
                deployed_endpoint=deployed_endpoint
            ))

        return links

    @classmethod
    def compute_security_diff(
        cls,
        current_findings: List[SASTFinding],
        previous_findings: List[SASTFinding],
        commit_sha: str,
        commit_message: str = "",
        commit_author: str = "",
        commit_timestamp: str = ""
    ) -> CommitSecurityDiff:
        """
        Compare two sets of SAST findings to identify regressions and improvements.
        """
        def finding_key(f: SASTFinding) -> str:
            return f"{f.rule_id}::{f.file_path}"

        current_keys = {finding_key(f): f for f in current_findings}
        previous_keys = {finding_key(f): f for f in previous_findings}

        new_findings = [f for k, f in current_keys.items() if k not in previous_keys]
        resolved_findings = [f for k, f in previous_keys.items() if k not in current_keys]
        persisting_findings = [f for k, f in current_keys.items() if k in previous_keys]

        # Risk delta: +1 per new high/critical, -1 per resolved high/critical
        severity_weights = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        risk_delta = sum(severity_weights.get(f.severity, 0) for f in new_findings)
        risk_delta -= sum(severity_weights.get(f.severity, 0) for f in resolved_findings)

        regression_detected = any(f.severity in ("critical", "high") for f in new_findings)

        if regression_detected:
            new_critical = [f for f in new_findings if f.severity == "critical"]
            new_high = [f for f in new_findings if f.severity == "high"]
            regression_summary = (
                f"SECURITY REGRESSION: Commit {commit_sha[:8]} introduced "
                f"{len(new_critical)} critical and {len(new_high)} high severity vulnerabilities. "
                f"Files affected: {', '.join(set(f.file_path for f in new_findings))}"
            )
        elif resolved_findings:
            regression_summary = (
                f"Security improvement in commit {commit_sha[:8]}: "
                f"{len(resolved_findings)} vulnerability/vulnerabilities resolved."
            )
        else:
            regression_summary = f"No security posture change in commit {commit_sha[:8]}."

        parent_sha = f"parent_of_{commit_sha[:8]}"

        return CommitSecurityDiff(
            commit_sha=commit_sha,
            parent_sha=parent_sha,
            commit_message=commit_message,
            commit_author=commit_author,
            commit_timestamp=commit_timestamp or datetime.now(timezone.utc).isoformat(),
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persisting_findings=persisting_findings,
            risk_delta=risk_delta,
            regression_detected=regression_detected,
            regression_summary=regression_summary
        )

    @classmethod
    def build_posture_report(
        cls,
        repo_url: str,
        commit_sha: str,
        sast_findings: List[SASTFinding],
        dast_findings: List[Dict[str, Any]],
        base_url: str
    ) -> SecurityPostureReport:
        """Generate a unified SAST + DAST security posture report."""
        links = cls.build_links(sast_findings, dast_findings, base_url, commit_sha)

        severity_counts = {}
        for f in sast_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        confirmed_links = [l for l in links if l.link_confidence >= 0.75]
        categories = list(set(f.category for f in sast_findings))

        return SecurityPostureReport(
            repo_url=repo_url,
            commit_sha=commit_sha,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            sast_findings=sast_findings,
            dast_findings_raw=dast_findings,
            code_to_runtime_links=links,
            summary={
                "total_sast_findings": len(sast_findings),
                "total_dast_findings": len(dast_findings),
                "code_to_runtime_links": len(confirmed_links),
                "sast_severity_breakdown": severity_counts,
                "affected_categories": categories,
                "high_confidence_links": len(confirmed_links),
                "commit_sha": commit_sha,
                "repo_url": repo_url,
            }
        )

    @staticmethod
    def _keyword_overlap(title1: str, title2: str, threshold: int = 2) -> bool:
        """Check if two finding titles share >= threshold meaningful keywords."""
        STOPWORDS = {"missing", "the", "a", "an", "of", "in", "on", "and", "or", "is", "with"}
        words1 = set(re.findall(r"\w+", title1.lower())) - STOPWORDS
        words2 = set(re.findall(r"\w+", title2.lower())) - STOPWORDS
        return len(words1 & words2) >= threshold
