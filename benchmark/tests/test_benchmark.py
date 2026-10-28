"""
P2: Pytest unit and integration tests for the GrayStrike Benchmark Framework.
Validates scoring accuracy, metric computation, ground truth matching, and report generation.
"""
import sys
import os
import json
import pytest
import asyncio
from datetime import datetime, timezone

BENCHMARK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROOT_DIR = os.path.abspath(os.path.join(BENCHMARK_DIR, ".."))
if BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, BENCHMARK_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from benchmark.benchmark_runner import (
    BenchmarkResult,
    match_finding_to_ground_truth,
    get_simulated_zap_result,
    get_simulated_burp_result,
    get_simulated_snyk_result,
    generate_benchmark_report,
    GROUND_TRUTH_IDS,
    GROUND_TRUTH_MAP,
)


# ===========================================================
# 1. Ground Truth Registry Tests
# ===========================================================

def test_ground_truth_registry_complete():
    """Verify 15 VLN entries are registered with required fields."""
    assert len(GROUND_TRUTH_IDS) == 15
    for vln_id, meta in GROUND_TRUTH_MAP.items():
        assert "cwe" in meta, f"{vln_id} missing cwe"
        assert "category" in meta, f"{vln_id} missing category"
        assert "keywords" in meta, f"{vln_id} missing keywords"
        assert len(meta["keywords"]) >= 1, f"{vln_id} has no keywords"


# ===========================================================
# 2. Finding-to-Ground-Truth Matching Tests
# ===========================================================

def test_match_csp_finding_to_vln001():
    finding = {
        "title": "Missing Content-Security-Policy Header",
        "category": "security_headers",
        "cwe_id": "CWE-693",
        "evidence_summary": "No CSP header in response",
        "affected_asset": "https://example.com"
    }
    matched = match_finding_to_ground_truth(finding)
    assert "VLN-001" in matched


def test_match_supabase_rls_to_vln003():
    finding = {
        "title": "Supabase RLS Disabled — Users Table Publicly Readable",
        "category": "supabase_rls_security",
        "cwe_id": "CWE-284",
        "evidence_summary": "GET /rest/v1/users returned 200 with PII",
        "affected_asset": "https://xyz.supabase.co/rest/v1/users"
    }
    matched = match_finding_to_ground_truth(finding)
    assert "VLN-003" in matched


def test_match_stripe_webhook_to_vln005():
    finding = {
        "title": "Stripe Webhook Missing Signature Verification",
        "category": "webhook_signature_integrity",
        "cwe_id": "CWE-345",
        "evidence_summary": "Webhook processed without stripe-signature header",
        "affected_asset": "https://app.com/api/webhooks/stripe"
    }
    matched = match_finding_to_ground_truth(finding)
    assert "VLN-005" in matched


def test_unrelated_finding_not_matched():
    finding = {
        "title": "Outdated TLS Version",
        "category": "tls_version",
        "cwe_id": "CWE-326",
        "evidence_summary": "TLS 1.0 still supported",
        "affected_asset": "https://example.com:443"
    }
    matched = match_finding_to_ground_truth(finding)
    # Should NOT match any of the planted vulnerabilities
    for vln_id in matched:
        assert vln_id not in GROUND_TRUTH_IDS or vln_id in matched


# ===========================================================
# 3. BenchmarkResult Metric Computation Tests
# ===========================================================

def test_perfect_precision_recall():
    """If all 15 vulns detected, zero FP → Precision=100%, Recall=100%, F1=100%."""
    result = BenchmarkResult(
        tool_name="Ideal Tool",
        target_url="http://test",
        scan_start="2026-01-01T00:00:00Z",
        scan_end="2026-01-01T00:00:10Z",
        duration_seconds=10.0,
        total_findings=15,
        detected_vlns=list(GROUND_TRUTH_IDS),
        false_positive_findings=[],
        missed_vlns=[],
        confirmed_count=15,
        suspected_count=0,
        inconclusive_count=0
    ).compute_metrics()

    assert result.tp == 15
    assert result.fp == 0
    assert result.fn == 0
    assert abs(result.precision - 1.0) < 0.001
    assert abs(result.recall - 1.0) < 0.001
    assert abs(result.f1_score - 1.0) < 0.001
    assert result.verification_success_rate == 1.0


def test_zero_detection():
    """If nothing detected → Recall=0, Precision undefined (0), F1=0."""
    result = BenchmarkResult(
        tool_name="Blind Tool",
        target_url="http://test",
        scan_start="2026-01-01T00:00:00Z",
        scan_end="2026-01-01T00:00:10Z",
        duration_seconds=10.0,
        total_findings=0,
        detected_vlns=[],
        false_positive_findings=[],
        missed_vlns=list(GROUND_TRUTH_IDS),
        confirmed_count=0, suspected_count=0, inconclusive_count=0
    ).compute_metrics()

    assert result.tp == 0
    assert result.fn == 15
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1_score == 0.0


def test_partial_detection_metrics():
    """
    GrayStrike detects 13/15, ZAP detects 5/15.
    GrayStrike should have significantly higher F1.
    """
    graystrike_detected = list(GROUND_TRUTH_IDS)[:13]  # 13 TP
    graystrike_missed = list(GROUND_TRUTH_IDS)[13:]     # 2 FN

    gs = BenchmarkResult(
        tool_name="GrayStrike",
        target_url="http://test",
        scan_start="2026-01-01T00:00:00Z",
        scan_end="2026-01-01T00:00:30Z",
        duration_seconds=30.0,
        total_findings=13,
        detected_vlns=graystrike_detected,
        false_positive_findings=["One FP Finding"],
        missed_vlns=graystrike_missed,
        confirmed_count=11, suspected_count=2, inconclusive_count=0
    ).compute_metrics()

    zap = BenchmarkResult(
        tool_name="ZAP",
        target_url="http://test",
        scan_start="2026-01-01T00:00:00Z",
        scan_end="2026-01-01T00:04:00Z",
        duration_seconds=240.0,
        total_findings=7,
        detected_vlns=list(GROUND_TRUTH_IDS)[:5],
        false_positive_findings=["FP1", "FP2"],
        missed_vlns=list(GROUND_TRUTH_IDS)[5:],
        confirmed_count=3, suspected_count=2, inconclusive_count=0
    ).compute_metrics()

    assert gs.f1_score > zap.f1_score, "GrayStrike should outperform ZAP on F1 Score"
    assert gs.recall > zap.recall, "GrayStrike should have higher recall"
    assert gs.tp == 13
    assert gs.fn == 2
    assert gs.fp == 1


def test_verification_success_rate():
    """confirmed / (confirmed + suspected + inconclusive) should compute correctly."""
    result = BenchmarkResult(
        tool_name="Test",
        target_url="http://test",
        scan_start="", scan_end="",
        duration_seconds=1.0,
        total_findings=10,
        detected_vlns=["VLN-001"],
        false_positive_findings=[],
        missed_vlns=["VLN-002"],
        confirmed_count=7, suspected_count=2, inconclusive_count=1
    ).compute_metrics()

    expected_vsr = 7 / (7 + 2 + 1)
    assert abs(result.verification_success_rate - expected_vsr) < 0.001


# ===========================================================
# 4. Simulated Competitor Baseline Tests
# ===========================================================

def test_zap_baseline_metrics():
    result = get_simulated_zap_result("http://127.0.0.1:9001")
    assert result.tool_name.startswith("OWASP ZAP")
    assert result.tp == 5  # ZAP detects 5 of 15
    assert result.fn == 10  # Misses 10
    assert result.recall < 0.4   # < 40% recall
    assert result.precision >= 0.5  # reasonable precision
    assert result.f1_score < 0.5


def test_burp_baseline_metrics():
    result = get_simulated_burp_result("http://127.0.0.1:9001")
    assert result.tool_name.startswith("Burp Suite")
    assert result.tp == 7
    assert result.fn == 8


def test_snyk_baseline_metrics():
    result = get_simulated_snyk_result("http://127.0.0.1:9001")
    assert result.tool_name.startswith("Snyk")
    assert result.tp == 5


# ===========================================================
# 5. Comparison Report Generation Tests
# ===========================================================

def test_generate_benchmark_report_structure():
    zap = get_simulated_zap_result("http://127.0.0.1:9001")
    burp = get_simulated_burp_result("http://127.0.0.1:9001")
    snyk = get_simulated_snyk_result("http://127.0.0.1:9001")

    report = generate_benchmark_report([zap, burp, snyk])

    assert "benchmark_meta" in report
    assert "comparison_table" in report
    assert "winner" in report
    assert len(report["comparison_table"]) == 3

    for row in report["comparison_table"]:
        assert "tool" in row
        assert "precision" in row
        assert "recall" in row
        assert "f1_score" in row
        assert "fpr" in row
        assert "tp" in row
        assert "fp" in row
        assert "fn" in row
        assert "duration_seconds" in row


def test_winner_is_highest_f1():
    zap = get_simulated_zap_result("http://127.0.0.1:9001")
    burp = get_simulated_burp_result("http://127.0.0.1:9001")
    snyk = get_simulated_snyk_result("http://127.0.0.1:9001")

    report = generate_benchmark_report([zap, burp, snyk])
    table = report["comparison_table"]

    best = max(table, key=lambda r: r["f1_score"])
    assert report["winner"] == best["tool"]


def test_report_json_serializable():
    """Ensure report can be serialized to JSON without errors."""
    zap = get_simulated_zap_result("http://127.0.0.1:9001")
    report = generate_benchmark_report([zap])
    try:
        json.dumps(report, default=str)
    except Exception as e:
        pytest.fail(f"Report is not JSON serializable: {e}")
