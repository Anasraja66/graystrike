"""
GrayStrike Swarm Orchestrator — Autonomous Multi-Agent Security Audit Engine
Synthesizes the core discoveries of:
- SecureFlow (Alve et al., MDPI 2026): Task decomposition into Probe -> Analyze -> Synthesize.
- LLM-SmartAudit (Lee et al., IEEE TSE 2025): Collaborative roles & Counselor/Challenger validation.
- HAFixAgent (Shi et al., Queen's Univ, arXiv:2511.01047, 2025): Blame-derived fl_diff historical grounding.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.app.services.multi_agent.history_miner import GitHistoryMiner, GitHistoryContext
from backend.app.services.multi_agent.gray_probe import GrayProbeAgent, ProbeResult
from backend.app.services.multi_agent.gray_analyze import GrayAnalyzeAgent, FormalSecurityFinding
from backend.app.services.multi_agent.gray_redteam import GrayRedTeamAgent, RedTeamVerificationResult
from backend.app.services.multi_agent.gray_synthesize import GraySynthesizeAgent, SynthesisResult
from backend.app.core.safety_guard import EnterpriseSafetyGuard


@dataclass
class SwarmAuditReport:
    audit_id: str
    target_asset: str
    status: str  # "AUDIT_COMPLETED", "EARLY_EXIT_SAFE", "REPAIR_VERIFIED"
    start_time: str
    duration_seconds: float
    total_findings_evaluated: int
    confirmed_findings_count: int
    early_exit_applied: bool
    stages: Dict[str, Any] = field(default_factory=dict)
    remediation_patches: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "target_asset": self.target_asset,
            "status": self.status,
            "start_time": self.start_time,
            "duration_seconds": self.duration_seconds,
            "total_findings_evaluated": self.total_findings_evaluated,
            "confirmed_findings_count": self.confirmed_findings_count,
            "early_exit_applied": self.early_exit_applied,
            "stages": self.stages,
            "remediation_patches": self.remediation_patches,
            "metadata": self.metadata,
        }


class GrayStrikeSwarmOrchestrator:
    """
    Supervisor Agent coordinating the multi-agent swarm in an end-to-end audit cycle.
    """

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path
        self.history_miner = GitHistoryMiner(repo_path=repo_path)

    async def execute_full_audit(
        self,
        source_code: str,
        file_path: str = "app/api/db/users/route.ts",
        live_endpoint_url: Optional[str] = "http://127.0.0.1:9001/api/db/users",
        allow_loopback: bool = True
    ) -> SwarmAuditReport:
        """
        Executes the complete multi-agent audit lifecycle.
        """
        start_ts = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        audit_id = f"swarm-audit-{int(t0)}"

        stages_log: Dict[str, Any] = {}
        patches: List[Dict[str, Any]] = []

        # =================================================================
        # STAGE 1: PROBE & SCOUT (Fast Binary Filter)
        # =================================================================
        probe_res = GrayProbeAgent.evaluate_code(code_content=source_code, file_path=file_path)
        stages_log["stage1_probe"] = probe_res.to_dict()

        if probe_res.early_exit_applied or not probe_res.is_vulnerable_candidate:
            duration = round(time.time() - t0, 3)
            return SwarmAuditReport(
                audit_id=audit_id,
                target_asset=file_path,
                status="EARLY_EXIT_SAFE",
                start_time=start_ts,
                duration_seconds=duration,
                total_findings_evaluated=0,
                confirmed_findings_count=0,
                early_exit_applied=True,
                stages=stages_log,
                metadata={"message": "No suspicious patterns detected; pipeline exited early at Probe stage."}
            )

        candidate = probe_res.candidates[0]

        # =================================================================
        # STAGE 2: FORMAL TAXONOMY & SMT REACHABILITY (GrayAnalyze)
        # =================================================================
        analysis_res = GrayAnalyzeAgent.analyze_candidate(
            candidate_reason=candidate.suspicion_reason,
            snippet=candidate.raw_snippet,
            file_path=file_path,
            line_number=candidate.line_number
        )
        stages_log["stage2_formal_analysis"] = analysis_res.to_dict()

        # =================================================================
        # STAGE 3: HISTORY CONTEXT MINING (HAFix Heuristic)
        # =================================================================
        line_num = candidate.line_number or 1
        history_ctx = self.history_miner.mine_line_history(file_path=file_path, line_number=line_num)
        stages_log["stage3_history_mining"] = history_ctx.to_dict()

        # =================================================================
        # STAGE 4: RED TEAM ACTIVE PROOF & COUNSELOR VERIFICATION (GrayRedTeam)
        # =================================================================
        if live_endpoint_url:
            redteam_res = await GrayRedTeamAgent.verify_endpoint(
                target_url=live_endpoint_url,
                method="GET",
                allow_loopback=allow_loopback
            )
            stages_log["stage4_redteam_verification"] = redteam_res.to_dict()
            if redteam_res.is_confirmed:
                is_confirmed = True
            elif redteam_res.verification_status == "unverified_safe" and analysis_res.is_satisfiable:
                # Target endpoint unreachable or offline in test environment:
                # Fallback to formal SMT satisfiability proof as mathematical verification
                is_confirmed = True
                stages_log["stage4_redteam_verification"]["verification_mode"] = "formal_smt_fallback"
            else:
                is_confirmed = False
        else:
            # Code-only audit: formal satisfiability serves as verification
            is_confirmed = analysis_res.is_satisfiable
            stages_log["stage4_redteam_verification"] = {
                "is_confirmed": is_confirmed,
                "verification_status": "formally_verified" if is_confirmed else "unsat_guarded",
                "evidence_summary": "Code-only verification conducted via SMT satisfiability proof."
            }

        # =================================================================
        # STAGE 5: HISTORY-AWARE MINIMAL-DIFF SYNTHESIS (GraySynthesize)
        # =================================================================
        if is_confirmed:
            synth_res = GraySynthesizeAgent.synthesize_remediation(
                cwe_id=analysis_res.cwe_id,
                target_file=file_path,
                original_code=source_code,
                line_number=candidate.line_number,
                history_context=history_ctx
            )
            stages_log["stage5_synthesis"] = synth_res.to_dict()
            patches.append(synth_res.to_dict())

        duration = round(time.time() - t0, 3)
        return SwarmAuditReport(
            audit_id=audit_id,
            target_asset=file_path,
            status="AUDIT_COMPLETED",
            start_time=start_ts,
            duration_seconds=duration,
            total_findings_evaluated=len(probe_res.candidates),
            confirmed_findings_count=1 if is_confirmed else 0,
            early_exit_applied=False,
            stages=stages_log,
            remediation_patches=patches,
            metadata={
                "cwe_id": analysis_res.cwe_id,
                "owasp": analysis_res.owasp_category,
                "is_sat": analysis_res.is_satisfiable,
                "history_mined": history_ctx.available
            }
        )
