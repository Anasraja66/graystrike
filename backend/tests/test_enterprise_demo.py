"""
P4: Unit & Integration Tests for Enterprise Readiness & Demo Workflow
Tests:
1. EnterpriseSafetyGuard: Target scope validation, SSRF protection, loopback gating
2. EnterpriseSafetyGuard: Secret redaction across API keys, passwords, and tokens
3. EnterpriseSafetyGuard: Multi-tenant boundary isolation
4. EnterpriseDemoOrchestrator: Complete 5-step closed-loop demo execution (SAT -> Remediation -> UNSAT)
"""
import sys
import os
import pytest
import asyncio

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from backend.app.core.safety_guard import EnterpriseSafetyGuard, ScopeValidationError
from backend.app.services.e2e_enterprise_demo import EnterpriseDemoOrchestrator


# =============================================================
# 1. SCOPE & SAFETY GUARD TESTS
# =============================================================

def test_scope_validation_allows_valid_https():
    """Valid HTTPS target with matching authorized domain must pass."""
    assert EnterpriseSafetyGuard.validate_target_scope(
        "https://myapp.company.co.uk/api",
        authorized_domains=["company.co.uk"]
    ) is True


def test_scope_validation_blocks_file_scheme():
    """file:// schemes must be strictly rejected."""
    with pytest.raises(ScopeValidationError, match="Only http and https are permitted"):
        EnterpriseSafetyGuard.validate_target_scope("file:///etc/passwd")


def test_scope_validation_blocks_cloud_metadata():
    """AWS / Cloud metadata endpoint 169.254.169.254 must be blocked."""
    with pytest.raises(ScopeValidationError, match="cloud metadata endpoints is strictly prohibited"):
        EnterpriseSafetyGuard.validate_target_scope("http://169.254.169.254/latest/meta-data")


def test_scope_validation_blocks_unauthorized_domain():
    """Domains outside the authorized scope list must be rejected."""
    with pytest.raises(ScopeValidationError, match="not in the organization's authorized scope list"):
        EnterpriseSafetyGuard.validate_target_scope(
            "https://evil-unauthorized-target.com",
            authorized_domains=["mycompany.com"]
        )


# =============================================================
# 2. SECRET REDACTION TESTS
# =============================================================

def test_secret_redaction_masks_api_keys():
    """OpenAI API keys, Stripe keys, and database passwords must be redacted."""
    dummy_openai = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    dummy_stripe = "sk_" + "live_" + "1234567890abcdefghijklmnop"
    raw_text = (
        f"Found OPENAI_API_KEY={dummy_openai} in config. "
        f"Also found STRIPE_SECRET={dummy_stripe} and "
        "DATABASE_URL=postgresql://postgres:MySecretPass123@db.prod:5432/main."
    )
    redacted = EnterpriseSafetyGuard.redact_secrets(raw_text)

    # Secrets must not appear in plain text
    assert dummy_openai not in redacted
    assert dummy_stripe not in redacted
    assert "MySecretPass123" not in redacted

    # Redaction placeholders must be present
    assert "[REDACTED_API_KEY]" in redacted
    assert "[REDACTED_STRIPE_KEY]" in redacted
    assert "[REDACTED_PASSWORD]" in redacted


def test_redact_finding_evidence():
    """Finding dictionaries must have their evidence fields redacted."""
    dummy_key = "sk-" + "123456789012345678901234567890"
    finding = {
        "title": "Exposed Key",
        "evidence_summary": f"Detected key {dummy_key} in bundle",
        "http_request": f"GET /api HTTP/1.1\nAuthorization: Bearer {dummy_key}",
        "confidence": 0.95
    }
    redacted_finding = EnterpriseSafetyGuard.redact_finding_evidence(finding)
    assert dummy_key not in redacted_finding["evidence_summary"]
    assert redacted_finding["confidence"] == 0.95


# =============================================================
# 3. MULTI-TENANT ISOLATION TESTS
# =============================================================

def test_tenant_isolation_passes_same_org():
    """Accessing resources within the same organization must pass."""
    assert EnterpriseSafetyGuard.verify_tenant_isolation("org_123", "org_123") is True


def test_tenant_isolation_blocks_cross_tenant_access():
    """Cross-tenant access must raise a ScopeValidationError."""
    with pytest.raises(ScopeValidationError, match="Multi-tenant isolation violation"):
        EnterpriseSafetyGuard.verify_tenant_isolation("org_victim", "org_attacker")


# =============================================================
# 4. END-TO-END DEMO WORKFLOW TESTS
# =============================================================

@pytest.mark.asyncio
async def test_enterprise_demo_orchestrator_execution():
    """Execute complete 5-step closed-loop demonstration and verify mathematical proof."""
    result = await EnterpriseDemoOrchestrator.run_demonstration(
        target_url="http://127.0.0.1:9001",
        organization_id="org_test_eval"
    )

    assert result["demo_status"] == "SUCCESS"
    assert len(result["steps"]) == 5

    # Step 1: DAST
    assert result["steps"][0]["status"] == "COMPLETED"
    assert result["steps"][0]["findings_count"] >= 1

    # Step 2: SAST
    assert result["steps"][1]["status"] == "COMPLETED"
    assert result["steps"][1]["rules_evaluated"] == 17

    # Step 3: Correlation
    assert result["steps"][2]["status"] == "COMPLETED"
    assert result["steps"][2]["correlation_links_count"] >= 1

    # Step 4: Formal Graph SAT Proof
    assert result["steps"][3]["status"] == "COMPLETED"
    assert result["steps"][3]["satisfaction_status"] == "SAT"
    assert result["steps"][3]["model_satisfiable"] is True

    # Step 5: Remediation Validation & Post-Fix UNSAT Proof
    assert result["steps"][4]["status"] == "COMPLETED"
    assert result["steps"][4]["pre_fix_reachability"] == "SAT (Proven Reachable)"
    assert result["steps"][4]["post_fix_reachability"] == "UNSAT (Mathematically Proven Unreachable)"
    assert result["steps"][4]["cut_verification_successful"] is True
