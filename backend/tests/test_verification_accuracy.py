"""
P0 Verification Accuracy & Scientific Precision Test Suite
Verifies:
1. Supabase RLS detection precision (Empty array -> inconclusive; sensitive PII -> confirmed critical; public table -> low suspected).
2. Reproduction cURL and structured evidence trace generation across micro-agents.
3. Browser evidence model structured fields.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from ai_engine.agents.ai_app_agents import SupabaseRlsAuditorAgent
from ai_engine.agents.core_agents import SecurityHeadersAgent, CookieSecurityAgent, CORSConfigAgent
from ai_engine.agents.base_agent import AgentSeverity
from ai_engine.verification.browser_verifier import BrowserVerifier, BrowserEvidence


@pytest.mark.asyncio
async def test_supabase_rls_empty_array_is_inconclusive():
    """Verify that HTTP 200 with [] is classified as INCONCLUSIVE, avoiding false positives."""
    agent = SupabaseRlsAuditorAgent()
    crawl_data = {
        "pages": [{
            "url": "https://myapp.vercel.app",
            "scripts": ["https://xyz123.supabase.co/rest/v1/users", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.mocksignature"]
        }]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "[]"
    mock_resp.content = b"[]"
    mock_resp.json.return_value = []

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        result = await agent.assess("https://myapp.vercel.app", crawl_data)

    assert result.success is True
    # Should flag as inconclusive/low, NOT critical
    for finding in result.findings:
        assert finding.verification_status == "inconclusive"
        assert finding.severity == AgentSeverity.LOW
        assert "Empty Result Returned" in finding.title
        assert finding.reproduction_curl is not None
        assert "curl" in finding.reproduction_curl


@pytest.mark.asyncio
async def test_supabase_rls_sensitive_pii_is_confirmed_critical():
    """Verify that HTTP 200 leaking sensitive columns (email, billing) is CONFIRMED CRITICAL."""
    agent = SupabaseRlsAuditorAgent()
    crawl_data = {
        "pages": [{
            "url": "https://myapp.vercel.app",
            "scripts": ["https://xyz123.supabase.co/rest/v1/users", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.mocksignature"]
        }]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '[{"id": 1, "email": "admin@target.com", "stripe_customer_id": "cus_123"}]'
    mock_resp.content = mock_resp.text.encode()
    mock_resp.json.return_value = [{"id": 1, "email": "admin@target.com", "stripe_customer_id": "cus_123"}]

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        result = await agent.assess("https://myapp.vercel.app", crawl_data)

    assert result.success is True
    assert len(result.findings) >= 1
    critical_findings = [f for f in result.findings if f.severity == AgentSeverity.CRITICAL]
    assert len(critical_findings) >= 1
    f = critical_findings[0]
    assert f.verification_status == "confirmed"
    assert "email" in f.sensitive_data_detected or "stripe_customer_id" in f.sensitive_data_detected
    assert f.reproduction_confidence >= 0.95
    assert "curl" in f.reproduction_curl
    assert f.expected_secure_behavior is not None
    assert f.observed_insecure_behavior is not None


@pytest.mark.asyncio
async def test_security_headers_has_reproduction_curl_and_evidence():
    """Verify SecurityHeadersAgent generates structured reproduction curl and expected behaviors."""
    agent = SecurityHeadersAgent()
    crawl_data = {
        "pages": [{
            "url": "https://myapp.com",
            "missing_security_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
            "security_headers": {"Server": "nginx"}
        }]
    }

    result = await agent.assess("https://myapp.com", crawl_data)
    assert result.success is True
    assert len(result.findings) >= 2
    for f in result.findings:
        assert f.verification_status == "confirmed"
        assert f.verification_method == "passive_observation"
        assert f.reproduction_curl == "curl -sS -I 'https://myapp.com'"
        assert f.expected_secure_behavior is not None
        assert f.observed_insecure_behavior is not None
        assert f.observation_timestamp is not None


@pytest.mark.asyncio
async def test_cors_config_has_active_probe_curl():
    """Verify CORSConfigAgent generates active curl proof."""
    agent = CORSConfigAgent()
    crawl_data = {
        "pages": [{
            "url": "https://myapp.com/api/data",
            "security_headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"
            }
        }]
    }

    result = await agent.assess("https://myapp.com", crawl_data)
    assert result.success is True
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.verification_status == "confirmed"
    assert f.verification_method == "active_probe"
    assert "evil-attacker.com" in f.reproduction_curl
    assert f.reproduction_confidence >= 0.95


def test_browser_evidence_model_fields():
    """Verify BrowserEvidence data model contains structured reproduction fields."""
    evidence = BrowserEvidence(
        verification_status="confirmed",
        reproduction_curl="curl -sS -i 'https://test.com'",
        expected_behavior="Defensive headers enforced",
        observed_behavior="Loaded with HTTP 200 without headers",
        response_status_code=200,
        page_title="Dashboard",
        sensitive_indicators=["exposed_emails"]
    )
    assert evidence.verification_status == "confirmed"
    assert evidence.response_status_code == 200
    assert "exposed_emails" in evidence.sensitive_indicators
    assert "curl" in evidence.reproduction_curl
