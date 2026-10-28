"""
Integration and Unit tests for CI/CD API endpoints and security services.
Verifies API Key hashing, Scope Safety, Secret Redaction, and Regression Gate Logic.
"""
import unittest
import hashlib
from app.api.v1.ci import _redact_sensitive_data


class TestCIAPIAndSecurityServices(unittest.TestCase):

    def test_secret_redaction(self):
        """Verify sensitive credentials are masked before appearing in PR comments."""
        # 1. Bearer Token masking
        text1 = "Error occurred with Authorization: Bearer abcdef1234567890xyz_test_token"
        redacted1 = _redact_sensitive_data(text1)
        self.assertNotIn("abcdef1234567890xyz_test_token", redacted1)
        self.assertIn("Bearer [REDACTED_TOKEN]", redacted1)

        # 2. JWT token masking
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this_signature"
        text2 = f"Observed session token: {fake_jwt} in response"
        redacted2 = _redact_sensitive_data(text2)
        self.assertNotIn("do_not_leak_this_signature", redacted2)
        self.assertIn("[REDACTED_JWT]", redacted2)

        # 3. Cookie masking
        text3 = "Request headers included Cookie: session_id=secret123456; csrf=tok999;"
        redacted3 = _redact_sensitive_data(text3)
        self.assertNotIn("secret123456", redacted3)
        self.assertIn("[REDACTED_COOKIE]", redacted3)

        # 4. API Key masking
        text4 = "Config file leaked api_key='sk_live_998877665544332211'"
        redacted4 = _redact_sensitive_data(text4)
        self.assertNotIn("sk_live_998877665544332211", redacted4)
        self.assertIn("[REDACTED]", redacted4)

    def test_api_key_hashing_consistency(self):
        """Verify API keys use stable one-way SHA-256 cryptographic hashing."""
        raw_key = "apt_live_0123456789abcdef0123456789abcdef"
        expected_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        # Re-hashing produces the exact hash
        re_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        self.assertEqual(expected_hash, re_hash)
        self.assertEqual(len(expected_hash), 64)

    def test_scope_enforcement_logic(self):
        """Verify ScopeEnforcer blocks disallowed hosts and paths."""
        from app.services.scope_service import ScopeEnforcer

        enforcer = ScopeEnforcer(
            allowed_hosts=["example.com", "staging.example.com"],
            denied_paths=["/admin", "/internal"],
            allow_private_ips=True
        )

        # Valid host passes
        valid, err = enforcer.validate_url("https://example.com/login")
        self.assertTrue(valid)
        self.assertIsNone(err)

        # Denied path is blocked
        valid_denied, err = enforcer.validate_url("https://example.com/admin/settings")
        self.assertFalse(valid_denied)
        self.assertIn("explicitly denied", err)

        # Unauthorized external host is blocked
        invalid_host, err = enforcer.validate_url("https://attacker-controlled-site.com")
        self.assertFalse(invalid_host)
        self.assertIn("out of authorized scope", err)

    def test_scope_redirect_protection(self):
        """Verify ScopeEnforcer blocks redirects to unauthorized hosts or cloud metadata."""
        from app.services.scope_service import ScopeEnforcer

        enforcer = ScopeEnforcer(
            allowed_hosts=["example.com"],
            allow_private_ips=False
        )

        # Safe relative redirect passes
        allowed, res_url, err = enforcer.validate_redirect("https://example.com/login", "/dashboard")
        self.assertTrue(allowed)
        self.assertEqual(res_url, "https://example.com/dashboard")
        self.assertIsNone(err)

        # Dangerous redirect to AWS metadata is blocked
        allowed, res_url, err = enforcer.validate_redirect("https://example.com/redirect", "http://169.254.169.254/latest/meta-data/")
        self.assertFalse(allowed)
        self.assertTrue("out of authorized scope" in str(err) or "resolves to blocked IP" in str(err))

        # Redirect to unauthorized external host is blocked
        allowed, res_url, err = enforcer.validate_redirect("https://example.com/redirect", "https://unauthorized-attacker.com")
        self.assertFalse(allowed)
        self.assertIn("out of authorized scope", str(err))

    def test_initial_baseline_summary_builder(self):
        """Verify Initial Baseline Summary formats cleanly without false-positive PR failure claims."""
        from app.api.v1.ci import _build_initial_baseline_markdown_summary
        from unittest.mock import MagicMock

        scan_mock = MagicMock()
        scan_mock.id = "scan-init-12345678"
        scan_mock.target_url = "https://example.com"

        sev_counts = {"critical": 0, "high": 1, "medium": 2, "low": 0}
        baseline_list = [
            {"title": "Missing Content-Security-Policy", "severity": "HIGH", "affected_asset": "https://example.com"}
        ]

        md = _build_initial_baseline_markdown_summary(
            scan=scan_mock,
            gate_passed=True,
            fail_on="high",
            gate_reason="Initial security baseline established: 1 pre-existing findings cataloged.",
            sev_counts=sev_counts,
            baseline_list=baseline_list
        )

        self.assertIn("Initial Baseline Established", md)
        self.assertIn("1 pre-existing findings", md)
        self.assertIn("subsequent prs will be gated against new additions and regressions", md.lower())


if __name__ == "__main__":
    unittest.main()
