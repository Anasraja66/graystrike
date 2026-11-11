"""
Unit and Integration Tests for:
1. Live Multi-LLM Debate Router (DeepSeek, Llama, Qwen, Mistral, Phi)
2. GitHub PR Auto-Patcher & CI/CD Security Bot
"""
import pytest
from app.services.live_llm_debate_router import live_llm_debate_router, DEFAULT_SWARM_ROSTER
from app.services.github_remediation_bot import github_remediation_bot


def test_live_swarm_debate_consensus_cwe89():
    """Tests multi-agent debate and consensus on SQL injection."""
    code = (
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/api/users', async (req, res) => {\n"
        "    const query = 'SELECT * FROM users WHERE id = ' + req.query.id;\n"
        "    const [rows] = await db.query(query);\n"
        "    res.json(rows);\n"
        "});"
    )
    result = live_llm_debate_router.run_live_swarm_debate(
        vulnerable_code=code,
        cwe_id="CWE-89",
        fault_summary="Raw SQL concatenation sink"
    )

    assert result["status"] == "CONSENSUS_REACHED"
    assert result["consensus_metrics"]["decision"] == "APPROVED"
    assert result["consensus_metrics"]["smt_prover_status"] == "UNSAT_SAFE"
    assert result["consensus_metrics"]["effective_independent_voters_neff"] > 5.0
    assert result["consensus_metrics"]["reveal_integrity_all_verified"] is True
    assert len(result["agent_turns"]) == 7

    # Byzantine infiltrator must be detected by stego probe or filtered
    byzantine_turn = next(t for t in result["agent_turns"] if t["agent_id"] == "agent-byzantine-infiltrator")
    assert byzantine_turn["stego_probe"]["detected"] is True or byzantine_turn["status"] == "COLLUSION_SUSPECT"


def test_github_pr_auto_patcher_simulation():
    """Tests full PR review workflow generation."""
    code = (
        "const express = require('express');\n"
        "const { exec } = require('child_process');\n"
        "const app = express();\n"
        "app.get('/api/ping', (req, res) => {\n"
        "    exec('ping -c 4 ' + req.query.host);\n"
        "});"
    )
    pr_result = github_remediation_bot.simulate_pr_security_check(
        pr_number=108,
        repo="graystrike-enterprise/fintech-core",
        commit_sha="f9e8d7c6b5a41234567890abcdef",
        file_name="src/network/ping.js",
        code_content=code
    )

    assert pr_result["status"] == "PROCESSED"
    assert pr_result["pr_number"] == 108
    assert pr_result["consensus_decision"] == "APPROVED"
    assert pr_result["smt_status"] == "UNSAT_SAFE"
    assert "graystrike/auto-fix-cwe-78-pr-108" in pr_result["remediation_branch"]
    assert "### 🛡️ GrayStrike Automated Security Review" in pr_result["github_comment_markdown"]
    assert pr_result["github_check_run"]["conclusion"] == "success"


def test_github_webhook_hmac_signature_verification():
    """Tests cryptographic HMAC-SHA256 signature verification."""
    secret = "graystrike_webhook_secret_2026"
    github_remediation_bot.webhook_secret = secret

    payload = b'{"action": "opened", "pull_request": {"number": 108}}'
    import hmac, hashlib
    valid_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    invalid_sig = "sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad"

    assert github_remediation_bot.verify_webhook_signature(payload, valid_sig) is True
    assert github_remediation_bot.verify_webhook_signature(payload, invalid_sig) is False
    assert github_remediation_bot.verify_webhook_signature(payload, None) is False
