"""
Unit tests for APT CI Client (`ci/apt_ci_client.py`)
Tests authentication failures, scope violations, timeouts, cancellation,
secret redaction, gate thresholding, and regression detection.
"""
import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Ensure ci path is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, repo_root)

from ci.apt_ci_client import APTCIClient


class TestAPTCIGateClient(unittest.TestCase):
    def setUp(self):
        self.client = APTCIClient(
            api_url="https://mock.aptagents.io",
            api_key="apt_live_mock_1234567890abcdef",
            project_id="proj-uuid-1111",
            target_url="https://staging.example.com",
            fail_on="high",
            timeout_seconds=10,
            poll_interval=2
        )

    def test_pr_number_extraction(self):
        """Test extraction of PR numbers from GITHUB_REF."""
        with patch.dict(os.environ, {"GITHUB_REF": "refs/pull/42/merge"}):
            self.assertEqual(self.client._extract_pr_number(), 42)

        with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/main"}):
            self.assertIsNone(self.client._extract_pr_number())

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_authentication_failure(self, mock_req):
        """Test handling of 401 Unauthorized API key failures."""
        mock_req.side_effect = RuntimeError("API request failed [401]: Invalid or revoked API Key")
        exit_code = self.client.run()
        self.assertEqual(exit_code, 1)

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_scope_violation(self, mock_req):
        """Test handling of 400 Scope Violation when targeting unauthorized URL."""
        mock_req.side_effect = RuntimeError("API request failed [400]: Scope Violation: Target outside project scope")
        exit_code = self.client.run()
        self.assertEqual(exit_code, 1)

    @patch("ci.apt_ci_client.time.sleep", return_value=None)
    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_scan_timeout_and_cancellation(self, mock_req, mock_sleep):
        """Test that client cancels scan and raises error when timeout exceeded."""
        self.client.timeout_seconds = 1  # 1 second timeout
        # Return queued continually
        mock_req.return_value = {"status": "queued", "current_stage": "queued"}

        # Simulate time passing beyond timeout
        with patch("ci.apt_ci_client.time.time", side_effect=[100.0, 100.0, 105.0]):
            with self.assertRaises(TimeoutError):
                self.client.poll_scan("scan-timeout-id")

        # Verify cancel endpoint was called
        mock_req.assert_any_call("POST", "/api/v1/scans/scan-timeout-id/cancel")

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_scan_failure_and_cancellation_handling(self, mock_req):
        """Test handling when scan ends in FAILED or CANCELLED state."""
        # 1. trigger returns scan_id
        # 2. poll returns failed
        mock_req.side_effect = [
            {"scan_id": "scan-fail-123"},
            {"status": "failed", "current_stage": "failed", "total_findings": 0}
        ]

        exit_code = self.client.run()
        self.assertEqual(exit_code, 1)

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_security_gate_passed(self, mock_req):
        """Test successful execution when gate passes."""
        mock_req.side_effect = [
            {"scan_id": "scan-pass-123"},
            {"status": "completed", "current_stage": "completed", "total_findings": 2},
            {
                "gate_passed": True,
                "reason": "All security gates passed successfully.",
                "new_findings_count": 0,
                "regression_findings_count": 0,
                "summary_markdown": "## ✅ Security Gate Passed"
            }
        ]

        exit_code = self.client.run()
        self.assertEqual(exit_code, 0)

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_security_gate_failed_on_high(self, mock_req):
        """Test that security gate blocks build when threshold is violated."""
        mock_req.side_effect = [
            {"scan_id": "scan-blocked-123"},
            {"status": "completed", "current_stage": "completed", "total_findings": 5},
            {
                "gate_passed": False,
                "reason": "Security gate threshold 'HIGH' violated: 2 finding(s) met or exceeded severity threshold.",
                "new_findings_count": 2,
                "regression_findings_count": 1,
                "summary_markdown": "## 🚨 Security Gate Failed"
            }
        ]

        exit_code = self.client.run()
        self.assertEqual(exit_code, 1)

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_fail_safe_incomplete_scan_rejected(self, mock_req):
        """FAIL-SAFE: Incomplete scans (zero pages crawled) must NEVER pass the gate."""
        mock_req.side_effect = [
            {"scan_id": "scan-incomplete-123"},
            {"status": "completed", "current_stage": "completed", "pages_discovered": 0, "total_findings": 0},
            {
                "status": "incomplete",
                "gate_passed": False,
                "reason": "Scan INCOMPLETE: 0 pages or endpoints were crawled. Cannot certify security posture on an empty scan.",
                "summary_markdown": "### ⚠️ APT Agents Scan Incomplete"
            }
        ]

        exit_code = self.client.run()
        self.assertEqual(exit_code, 1)

    @patch("ci.apt_ci_client.APTCIClient._request")
    def test_idempotent_reused_scan(self, mock_req):
        """Test that client handles idempotent retry responses without duplicating work."""
        mock_req.side_effect = [
            {"scan_id": "scan-idempotent-123", "idempotent_reused": True},
            {"status": "completed", "current_stage": "completed", "pages_discovered": 10, "total_findings": 0},
            {
                "status": "completed",
                "gate_passed": True,
                "reason": "All security gates passed successfully.",
                "new_findings_count": 0,
                "regression_findings_count": 0,
                "summary_markdown": "## ✅ Security Gate Passed"
            }
        ]

        exit_code = self.client.run()
        self.assertEqual(exit_code, 0)

    @patch("ci.apt_ci_client.httpx.Client")
    def test_github_check_run_and_pr_comment(self, mock_client_cls):
        """Verify GitHub Check Run and PR comment posting when GITHUB_TOKEN is present."""
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        with patch.dict(os.environ, {
            "GITHUB_TOKEN": "ghp_mock_token_12345",
            "GITHUB_REPOSITORY": "anas-tech/apt-agents",
            "GITHUB_SHA": "a1b2c3d4e5f6",
            "GITHUB_REF": "refs/pull/99/merge"
        }):
            self.client.publish_github_check_run("Security Gate Passed", "Summary text", "success")
            self.client.post_pr_comment("Summary comment")

            # Check that post was called twice: once for check run, once for PR comment
            self.assertEqual(mock_client.post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
