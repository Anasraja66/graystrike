"""
Test Suite: Multi-Agent Swarm with History-Awareness
Validates the collaborative agents inspired by SecureFlow, LLM-SmartAudit, and HAFixAgent.
"""
import pytest
import os
from unittest.mock import patch, MagicMock

from backend.app.services.multi_agent.history_miner import GitHistoryMiner, GitHistoryContext
from backend.app.services.multi_agent.gray_probe import GrayProbeAgent
from backend.app.services.multi_agent.gray_analyze import GrayAnalyzeAgent
from backend.app.services.multi_agent.gray_redteam import GrayRedTeamAgent
from backend.app.services.multi_agent.gray_synthesize import GraySynthesizeAgent
from backend.app.services.multi_agent.swarm_orchestrator import GrayStrikeSwarmOrchestrator


class TestGitHistoryMiner:
    def test_history_miner_initialization(self):
        miner = GitHistoryMiner(repo_path=".")
        assert miner.repo_path is not None

    def test_history_miner_on_untracked_file_graceful_fallback(self):
        miner = GitHistoryMiner(repo_path=".")
        # Test on non-existent or untracked file
        ctx = miner.mine_line_history("non_existent_file_xyz.ts", 10)
        assert ctx.available is False
        assert ctx.heuristic_used == "none"

    def test_history_miner_blameless_fallback(self):
        miner = GitHistoryMiner(repo_path=".")
        with patch.object(miner, "_execute_blame") as mock_blame:
            # First line returns None (simulating newly inserted line)
            # Second line returns blame info
            mock_blame.side_effect = [
                None,
                {"commit_hash": "a1b2c3d", "author": "Alice", "summary": "Add users query"}
            ]
            with patch.object(miner, "_run_git", return_value="diff --git a/test b/test\n+new line"):
                ctx = miner.mine_line_history("app/api/users.ts", 15)
                assert ctx.available is True
                assert ctx.is_blameless_fallback is True
                assert ctx.commit_hash == "a1b2c3d"
                assert ctx.commit_summary == "Add users query"


class TestGrayProbeAgent:
    def test_probe_detects_raw_sql_injection(self):
        code = """
        export async function GET(req) {
            const query = "SELECT * FROM users WHERE id = " + req.query.id;
            return db.execute(query);
        }
        """
        res = GrayProbeAgent.evaluate_code(code, "app/api/users/route.ts")
        assert res.is_vulnerable_candidate is True
        assert res.status == "CandidateVulnerable"
        assert len(res.candidates) >= 1
        assert "SQL" in res.candidates[0].suspicion_reason

    def test_probe_early_exit_on_safe_code(self):
        safe_code = """
        // @safe
        export async function GET(req) {
            const id = sql.param(req.query.id);
            return db.query("SELECT * FROM users WHERE id = $1", [id]);
        }
        """
        res = GrayProbeAgent.evaluate_code(safe_code, "app/api/safe/route.ts")
        assert res.is_vulnerable_candidate is False
        assert res.status == "Safe"
        assert res.early_exit_applied is True

    def test_probe_endpoint_heuristics(self):
        res = GrayProbeAgent.evaluate_endpoint("http://127.0.0.1:8000/api/db/users")
        assert res.is_vulnerable_candidate is True
        assert res.candidates[0].target_type == "api_endpoint"


class TestGrayAnalyzeAgent:
    def test_analyze_maps_cwe_and_proves_satisfiability(self):
        finding = GrayAnalyzeAgent.analyze_candidate(
            candidate_reason="Raw SQL string concatenation",
            snippet="SELECT * FROM users WHERE id = " + "req.id",
            file_path="app/api/users/route.ts",
            line_number=5,
            is_authenticated_route=False,
            has_input_sanitizer=False
        )
        assert finding.cwe_id == "CWE-89"
        assert finding.owasp_category == "A03:2021-Injection"
        assert finding.is_satisfiable is True
        assert "P_exposed ∧ P_unauth" in finding.reachability_formula

    def test_analyze_marks_guarded_path_unsat(self):
        finding = GrayAnalyzeAgent.analyze_candidate(
            candidate_reason="Raw SQL string concatenation",
            snippet="SELECT * FROM users",
            file_path="app/api/users/route.ts",
            line_number=5,
            is_authenticated_route=True,
            has_input_sanitizer=True
        )
        # When route is authenticated and sanitized, unauth reachability fails
        assert finding.is_satisfiable is False


class TestGrayRedTeamAgent:
    @pytest.mark.asyncio
    async def test_redteam_blocks_malicious_ssrf_scope(self):
        # 169.254.169.254 is AWS metadata IP (RFC3927)
        res = await GrayRedTeamAgent.verify_endpoint("http://169.254.169.254/latest/meta-data")
        assert res.is_confirmed is False
        assert res.verification_status == "refuted"
        assert "EnterpriseSafetyGuard" in res.evidence_summary

    @pytest.mark.asyncio
    async def test_redteam_counselor_refutes_authenticated_endpoint(self):
        # Mock HTTP client returning 401
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.text = "Unauthorized Access"
            mock_get.return_value = mock_resp

            res = await GrayRedTeamAgent.verify_endpoint("http://127.0.0.1:9001/api/guarded")
            assert res.is_confirmed is False
            assert res.verification_status == "refuted"
            assert "Access control is active" in res.rejection_reason


class TestGraySynthesizeAgent:
    def test_synthesize_generates_4part_prompt_and_minimal_diff(self):
        vuln_code = (
            "export async function GET(req) {\n"
            "    const query = \"SELECT * FROM users WHERE id = \" + req.query.id;\n"
            "    return db.query(query);\n"
            "}"
        )
        history_ctx = GitHistoryContext(
            available=True,
            commit_hash="commit_hash_12345",
            commit_summary="Initial users search implementation",
            fl_diff="diff --git a/app.ts b/app.ts\n+SELECT * FROM users WHERE id ="
        )

        res = GraySynthesizeAgent.synthesize_remediation(
            cwe_id="CWE-89",
            target_file="app/api/users/route.ts",
            original_code=vuln_code,
            line_number=2,
            history_context=history_ctx
        )

        assert res.is_patch_generated is True
        assert "--- a/app/api/users/route.ts" in res.minimal_diff_patch
        assert "+++ b/app/api/users/route.ts" in res.minimal_diff_patch
        assert "Parameterized query replaces string concatenation" in res.minimal_diff_patch
        assert "Initial users search implementation" in res.root_cause_explanation
        assert "def test_regression_cwe_89" in res.regression_test_code


class TestGrayStrikeSwarmOrchestrator:
    @pytest.mark.asyncio
    async def test_swarm_full_audit_lifecycle(self):
        orchestrator = GrayStrikeSwarmOrchestrator(repo_path=".")
        vuln_code = """
        export async function GET(req: Request) {
            const users = await supabase.from('users').select('*');
            return Response.json(users);
        }
        """

        report = await orchestrator.execute_full_audit(
            source_code=vuln_code,
            file_path="app/api/db/users/route.ts",
            live_endpoint_url=None  # Formal SMT verification mode
        )

        assert report.status == "AUDIT_COMPLETED"
        assert report.total_findings_evaluated == 1
        assert report.confirmed_findings_count == 1
        assert "stage1_probe" in report.stages
        assert "stage2_formal_analysis" in report.stages
        assert "stage3_history_mining" in report.stages
        assert "stage4_redteam_verification" in report.stages
        assert "stage5_synthesis" in report.stages
        assert len(report.remediation_patches) == 1

    @pytest.mark.asyncio
    async def test_swarm_early_exit_on_benign_code(self):
        orchestrator = GrayStrikeSwarmOrchestrator(repo_path=".")
        safe_code = """
        // @safe
        export function healthCheck() {
            return { status: "healthy" };
        }
        """

        report = await orchestrator.execute_full_audit(
            source_code=safe_code,
            file_path="app/api/health.ts",
            live_endpoint_url=None
        )

        assert report.status == "EARLY_EXIT_SAFE"
        assert report.early_exit_applied is True
        assert report.confirmed_findings_count == 0
        assert "stage2_formal_analysis" not in report.stages
