"""
Tests for Security Test Generator (Automated QA Verification & CI/CD Regression Tests)
"""
import sys
import os
import uuid
from datetime import datetime, timezone
import pytest

# Ensure backend and ai_engine are in path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.models.models import Finding, FindingSeverity, FindingStatus
from app.services.security_test_generator import SecurityTestGenerator


def create_finding(title: str, category: str, cwe_id: str, asset: str) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        organization_id=str(uuid.uuid4()),
        title=title,
        category=category,
        cwe_id=cwe_id,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        affected_asset=asset,
        evidence_summary="Discovered during automated scan",
        risk_score=85.0,
        confidence=0.95,
        discovered_at=datetime.now(timezone.utc)
    )


def test_supabase_rls_regression_tests():
    f = create_finding(
        title="Supabase RLS Disabled on Public Profiles Table",
        category="supabase_rls_security",
        cwe_id="CWE-284",
        asset="https://myapp.supabase.co/rest/v1/profiles"
    )
    res = SecurityTestGenerator.generate_tests_for_finding(f)
    frameworks = res["test_frameworks"]
    assert "typescript_jest" in frameworks
    assert "python_pytest" in frameworks
    assert "playwright_e2e" in frameworks
    assert "safe_curl_verification" in frameworks

    ts_code = frameworks["typescript_jest"]["code"]
    assert "Supabase Row-Level Security (RLS) Guard" in ts_code
    assert "expect([401, 403]).toContain(response.status)" in ts_code

    py_code = frameworks["python_pytest"]["code"]
    assert "test_supabase_rls_blocks_anonymous_data_dump" in py_code
    assert "assert len(records) == 0" in py_code


def test_webhook_signature_regression_tests():
    f = create_finding(
        title="Stripe Webhook Signature Missing Verification",
        category="webhook_signature_integrity",
        cwe_id="CWE-345",
        asset="https://api.vibeapp.com/api/webhooks/stripe"
    )
    res = SecurityTestGenerator.generate_tests_for_finding(f)
    frameworks = res["test_frameworks"]

    ts_code = frameworks["typescript_jest"]["code"]
    assert "Payment Webhook Signature Guard" in ts_code
    assert "stripe-signature" in ts_code
    assert "expect([400, 401, 403]).toContain(response.status)" in ts_code

    py_code = frameworks["python_pytest"]["code"]
    assert "test_webhook_rejects_missing_signature" in py_code


def test_llm_endpoint_regression_tests():
    f = create_finding(
        title="Unauthenticated LLM Chat Route",
        category="llm_prompt_injection_guard",
        cwe_id="CWE-1426",
        asset="https://vibe.lovable.app/api/chat"
    )
    res = SecurityTestGenerator.generate_tests_for_finding(f)
    frameworks = res["test_frameworks"]

    ts_code = frameworks["typescript_jest"]["code"]
    assert "LLM Chat Endpoint Defensive Boundary" in ts_code
    assert "expect([401, 403]).toContain(response.status)" in ts_code


def test_cors_and_headers_regression_tests():
    f_cors = create_finding(
        title="Permissive CORS Wildcard",
        category="cors_misconfiguration",
        cwe_id="CWE-942",
        asset="https://api.vibeapp.com"
    )
    res_cors = SecurityTestGenerator.generate_tests_for_finding(f_cors)
    assert "untrusted-attacker-domain.com" in res_cors["test_frameworks"]["typescript_jest"]["code"]

    f_headers = create_finding(
        title="Missing Security Headers (CSP, HSTS)",
        category="security_headers",
        cwe_id="CWE-693",
        asset="https://vibeapp.com"
    )
    res_headers = SecurityTestGenerator.generate_tests_for_finding(f_headers)
    assert "nosniff" in res_headers["test_frameworks"]["typescript_jest"]["code"]
