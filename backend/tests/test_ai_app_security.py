"""
Unit & Integration Tests for Gap 1: AI-Generated / Vibe-Coded Apps Security Mode
"""
import sys
from pathlib import Path
base_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(base_dir))
sys.path.insert(0, str(base_dir / "backend"))
sys.path.insert(0, str(base_dir / "ai_engine"))

import pytest
from ai_engine.agents.base_agent import AgentRegistry
from ai_engine.agents.ai_app_agents import (
    SupabaseRlsAuditorAgent,
    ClientBundleSecretLeakAgent,
    PublicCloudStorageBucketAgent,
    LLMEndpointExposureAgent,
    WebhookSignatureIntegrityAgent,
    ClientSideAuthBypassAgent
)
from app.services.auto_fixer_service import AutoFixerService
from app.services.retest_engine import RetestEngine
from app.models.models import Finding, FindingStatus, FindingSeverity


class TestAIAppSecurityMode:

    def test_total_micro_agents_registration(self):
        """Verify all 44 agents including the 6 AI-app security agents are loaded."""
        import ai_engine.agents.core_agents  # noqa: F401
        import ai_engine.agents.extended_agents  # noqa: F401
        import ai_engine.agents.framework_agents  # noqa: F401
        import ai_engine.agents.easm_agents  # noqa: F401
        import ai_engine.agents.redteam_agents  # noqa: F401
        import ai_engine.agents.ai_app_agents  # noqa: F401

        agents = AgentRegistry.list_all()
        assert len(agents) >= 44
        agent_ids = [a.id for a in agents]
        assert "supabase_rls_auditor" in agent_ids
        assert "client_bundle_secret_leak" in agent_ids
        assert "cloud_storage_bucket_exposure" in agent_ids
        assert "llm_prompt_injection_guard" in agent_ids
        assert "webhook_signature_integrity" in agent_ids
        assert "client_side_auth_tampering" in agent_ids

    def test_client_bundle_secret_patterns(self):
        """Verify expanded secret patterns detect Claude, Stripe, Supabase Service Role, etc."""
        agent = ClientBundleSecretLeakAgent()
        pattern_names = [p["name"] for p in agent.SECRET_PATTERNS]
        assert "Stripe Live Secret Key" in pattern_names
        assert "OpenAI Secret API Key" in pattern_names
        assert "Anthropic Claude Secret API Key" in pattern_names
        assert "Clerk Secret API Key" in pattern_names
        assert "GitHub Personal Access Token" in pattern_names

    def test_auto_fix_patches_for_ai_apps(self):
        """Verify Auto-Fixer produces precise remediation code for modern AI app bugs."""
        # 1. LLM Endpoint exposure
        finding_llm = Finding(
            id="test-llm-1",
            title="Unauthenticated AI/LLM Endpoint Exposed: '/api/chat'",
            category="insecure_design",
            cwe_id="CWE-1426",
            affected_asset="https://example.com/api/chat"
        )
        patch_llm = AutoFixerService.get_patch_diff(finding_llm)
        assert patch_llm["target_file"] == "app/api/chat/route.ts"
        assert "sb-access-token" in patch_llm["patch_code"]
        assert "gpt-4o-mini" in patch_llm["patch_code"]

        # 2. Webhook Signature verification
        finding_webhook = Finding(
            id="test-webhook-1",
            title="Critical Unverified Webhook Endpoint: '/api/webhooks/stripe'",
            category="broken_authentication",
            cwe_id="CWE-345",
            affected_asset="https://example.com/api/webhooks/stripe"
        )
        patch_webhook = AutoFixerService.get_patch_diff(finding_webhook)
        assert patch_webhook["target_file"] == "app/api/webhooks/stripe/route.ts"
        assert "stripe.webhooks.constructEvent" in patch_webhook["patch_code"]

        # 3. Supabase RLS
        finding_rls = Finding(
            id="test-rls-1",
            title="Critical Supabase RLS Disabled on Table 'users'",
            category="broken_access_control",
            cwe_id="CWE-284",
            affected_asset="https://xyz.supabase.co/rest/v1/users"
        )
        patch_rls = AutoFixerService.get_patch_diff(finding_rls)
        assert patch_rls["target_file"] == "supabase/migrations/enable_rls_security.sql"
        assert "ENABLE ROW LEVEL SECURITY" in patch_rls["patch_code"]

        # 4. Leaked client secret
        finding_secret = Finding(
            id="test-secret-1",
            title="Critical Secret Leaked in Client Bundle: Stripe Live Secret Key",
            category="cryptographic_failures",
            cwe_id="CWE-798",
            affected_asset="https://example.com/chunk-123.js -> sk_live_..."
        )
        patch_secret = AutoFixerService.get_patch_diff(finding_secret)
        assert patch_secret["target_file"] == ".env.local.example"
        assert "NEXT_PUBLIC_" in patch_secret["patch_code"]

    @pytest.mark.asyncio
    async def test_retest_engine_ai_app_methods(self):
        """Verify retest engine handlers exist and parse target assets properly."""
        target, target_type = RetestEngine._parse_asset("https://xyz.supabase.co/rest/v1/orders?select=*")
        assert "https://xyz.supabase.co" in target
        assert target_type == "http"

        target_llm, _ = RetestEngine._parse_asset("https://example.com/api/chat")
        assert target_llm == "https://example.com/api/chat"
