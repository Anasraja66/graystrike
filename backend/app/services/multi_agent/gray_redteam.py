"""
GrayRedTeam Agent — Active Proof Verifier & Counselor
Inspired by LLM-SmartAudit Counselor (Lee et al., IEEE TSE 2025) and GrayStrike Active Verifier.

Purpose:
1. Performs targeted, safe dynamic verification (DAST) on suspected vulnerability endpoints.
2. Acts as the skeptic/counselor: refutes candidate findings if live runtime evidence fails.
3. Produces exact, reproducible cURL command traces with evidence hashes.
4. Enforces EnterpriseSafetyGuard (blocking SSRF to internal RFC1918 addresses and redacting keys).
"""
import httpx
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

from backend.app.core.safety_guard import EnterpriseSafetyGuard, ScopeValidationError


@dataclass
class RedTeamVerificationResult:
    is_confirmed: bool
    verification_status: str  # "confirmed", "refuted", "unverified_safe"
    reproduction_curl: str
    http_status_code: Optional[int]
    response_evidence_hash: str
    evidence_summary: str
    rejection_reason: Optional[str] = None
    telemetry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_confirmed": self.is_confirmed,
            "verification_status": self.verification_status,
            "reproduction_curl": self.reproduction_curl,
            "http_status_code": self.http_status_code,
            "response_evidence_hash": self.response_evidence_hash,
            "evidence_summary": self.evidence_summary,
            "rejection_reason": self.rejection_reason,
            "telemetry": self.telemetry,
        }


class GrayRedTeamAgent:
    """
    Active proof verifier agent that eliminates hallucinations through runtime probing.
    """

    @classmethod
    async def verify_endpoint(
        cls,
        target_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        expected_leak_keywords: Optional[List[str]] = None,
        allow_loopback: bool = True
    ) -> RedTeamVerificationResult:
        """
        Executes a safe HTTP probe against the target URL and verifies exploitability.
        """
        # Scope and SSRF verification via EnterpriseSafetyGuard
        try:
            EnterpriseSafetyGuard.validate_target_scope(
                target_url=target_url,
                allow_loopback_for_testing=allow_loopback
            )
        except ScopeValidationError as err:
            return RedTeamVerificationResult(
                is_confirmed=False,
                verification_status="refuted",
                reproduction_curl="",
                http_status_code=None,
                response_evidence_hash="none",
                evidence_summary=f"Probe blocked by EnterpriseSafetyGuard policy: {err}",
                rejection_reason=str(err)
            )

        # Build clean reproduction cURL
        clean_headers = headers or {}
        header_flags = " ".join([f"-H '{k}: {v}'" for k, v in clean_headers.items()])
        curl_cmd = f"curl -s -X {method} '{target_url}' {header_flags}".strip()

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                if method.upper() == "GET":
                    resp = await client.get(target_url, headers=clean_headers)
                else:
                    resp = await client.post(target_url, headers=clean_headers, json=json_body)

                body_text = resp.text
                status_code = resp.status_code
                resp_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()[:16]

                # Counselor skeptic logic: evaluate if live behavior proves vulnerability
                keywords = expected_leak_keywords or ["email", "user", "admin", "token", "error", "sql"]
                matched_keywords = [kw for kw in keywords if kw.lower() in body_text.lower()]

                if status_code in (200, 201) and matched_keywords:
                    # Verified exploit!
                    redacted_summary = EnterpriseSafetyGuard.redact_raw_text(body_text[:180])
                    return RedTeamVerificationResult(
                        is_confirmed=True,
                        verification_status="confirmed",
                        reproduction_curl=curl_cmd,
                        http_status_code=status_code,
                        response_evidence_hash=resp_hash,
                        evidence_summary=f"HTTP {status_code} returned with data matching indicators: {matched_keywords}. Sample: {redacted_summary}",
                        telemetry={"matched_indicators": matched_keywords, "bytes": len(body_text)}
                    )
                elif status_code in (401, 403):
                    # Guarded by Auth -> Refuted finding!
                    return RedTeamVerificationResult(
                        is_confirmed=False,
                        verification_status="refuted",
                        reproduction_curl=curl_cmd,
                        http_status_code=status_code,
                        response_evidence_hash=resp_hash,
                        evidence_summary=f"Endpoint properly guarded by HTTP {status_code} Access Denied.",
                        rejection_reason="Access control is active; candidate finding refuted as false positive."
                    )
                else:
                    # Ambiguous or 404 -> Unconfirmed
                    return RedTeamVerificationResult(
                        is_confirmed=False,
                        verification_status="unverified_safe",
                        reproduction_curl=curl_cmd,
                        http_status_code=status_code,
                        response_evidence_hash=resp_hash,
                        evidence_summary=f"HTTP {status_code} received without exploit payload confirmation.",
                        rejection_reason="No payload execution or data leak observed."
                    )

        except Exception as ex:
            # Connection error or offline
            return RedTeamVerificationResult(
                is_confirmed=False,
                verification_status="unverified_safe",
                reproduction_curl=curl_cmd,
                http_status_code=None,
                response_evidence_hash="error",
                evidence_summary=f"Connection failure or service unreachable: {str(ex)}",
                rejection_reason="Target service did not respond to active probe."
            )
