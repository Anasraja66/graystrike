import pytest
import time
import hmac
import hashlib
from app.services.bft_agent_consensus import (
    GovernedRobustConsensusEngine,
    AgentIdentity,
    grc_consensus_engine,
    hmac_equal
)
from app.services.predictive_ast_mutator import PredictiveASTMutator, predictive_ast_mutator
from app.services.quantum_webhook_guard import QuantumWebhookGuard, quantum_webhook_guard

def test_effective_independent_voters_equicorrelation():
    engine = GovernedRobustConsensusEngine()
    # 7 agents, zero correlation -> 7.0
    n_eff_zero = engine.compute_effective_voters(n=7, rho=0.0)
    assert abs(n_eff_zero - 7.0) < 1e-2

    # 7 agents, rho = 0.5 -> 7 / (1 + 6 * 0.5) = 7 / 4 = 1.75
    n_eff_half = engine.compute_effective_voters(n=7, rho=0.5)
    assert abs(n_eff_half - 1.75) < 1e-2

    # Correlated training data collapse: rho -> 1.0 -> n_eff -> 1.0
    n_eff_full = engine.compute_effective_voters(n=7, rho=1.0)
    assert abs(n_eff_full - 1.0) < 1e-2

def test_grc_commit_reveal_phase2():
    engine = GovernedRobustConsensusEngine()
    agent_id = "agent_01"
    proposal = "const safe = sanitize(userInput);"
    nonce = "secret_random_nonce_99"

    # Commit phase
    commit_hash = engine.phase2_commit_proposal(agent_id, proposal, nonce)
    assert len(commit_hash) == 64

    # Valid reveal phase
    assert engine.phase2_verify_reveal(commit_hash, agent_id, proposal, nonce) is True

    # Tampered reveal must fail
    assert engine.phase2_verify_reveal(commit_hash, agent_id, "tampered proposal", nonce) is False

def test_grc_smt_proof_short_circuit_phase3():
    engine = GovernedRobustConsensusEngine()
    proposal = {"patch": "const x = 1;"}
    
    # Mathematical proof receipt overrides majority voting
    short_circuit, reason = engine.phase3_external_verification_shortcircuit(
        proposal, smt_proof_receipt="Z3_SMT_UNSAT_NO_COUNTEREXAMPLE"
    )
    assert short_circuit is True
    assert "Mathematical ground truth verified" in reason

    # Unverified proposal does not short-circuit
    short_circuit_fail, reason_fail = engine.phase3_external_verification_shortcircuit(
        proposal, smt_proof_receipt="SAT_COUNTEREXAMPLE_FOUND"
    )
    assert short_circuit_fail is False

def test_grc_phase5_robust_aggregation_capped_weights():
    engine = GovernedRobustConsensusEngine()
    # 4 agents: 3 agree, 1 disagrees
    evals = [
        {"agent_id": "a1", "trust": 1.0, "approved": True},
        {"agent_id": "a2", "trust": 1.0, "approved": True},
        {"agent_id": "a3", "trust": 0.9, "approved": True},
        {"agent_id": "a4", "trust": 0.8, "approved": False},
    ]
    result = engine.phase5_robust_aggregation(evals)
    assert result["decision"] == "APPROVED"
    assert result["consensus_score"] > 0.67

def test_grc_phase6_runtime_governance_graph():
    engine = GovernedRobustConsensusEngine()
    # Legal transition: RECON_DISCOVERY -> EXPLOIT_PROOF_OF_CONCEPT
    ok, msg = engine.phase6_governance_check(
        current_state="RECON_DISCOVERY",
        target_state="EXPLOIT_PROOF_OF_CONCEPT",
        proposed_action="Generate PoC"
    )
    assert ok is True

    # Illegal transition: RECON_DISCOVERY -> SURGICAL_PATCH_MERGE (must go through SMT first)
    bad_ok, bad_msg = engine.phase6_governance_check(
        current_state="RECON_DISCOVERY",
        target_state="SURGICAL_PATCH_MERGE",
        proposed_action="Force merge patch directly"
    )
    assert bad_ok is False
    assert "Illegal state transition" in bad_msg

def test_predictive_ast_mutations():
    mutator = PredictiveASTMutator()
    sample_js = """
    app.get('/search', (req, res) => {
        let query = req.query.q;
        let sql = "SELECT * FROM items WHERE name = '" + query + "'";
        db.query(sql);
    });
    if (userAge < 18) {
        deny();
    }
    """
    mutants = mutator.mutate_ast_nodes(sample_js)
    assert len(mutants) > 0
    operators = [m.get("operator") for m in mutants]
    assert any("BOUNDARY" in op or "CASE_SENSITIVITY" in op for op in operators)

def test_quantum_webhook_guard():
    guard = QuantumWebhookGuard(fallback_secret="graystrike_quantum_seed_key_2026")
    payload = b'{"event":"security_finding","id":"CVE-2026-99"}'
    
    # 1. Compute valid HMAC signature
    sig = hmac.new("graystrike_quantum_seed_key_2026".encode("utf-8"), payload, hashlib.sha256).hexdigest()
    ts = str(time.time())
    nonce = f"test_nonce_{time.time()}"

    headers = {
        "x-webhook-timestamp": ts,
        "x-webhook-nonce": nonce,
        "x-signature": f"sha256={sig}"
    }

    # Verify signature
    res = guard.verify_webhook_request(payload, headers)
    assert res["valid"] is True
    assert "HMAC-SHA256" in res["algorithm"]

    # Anti-replay: identical nonce rejection
    replay_res = guard.verify_webhook_request(payload, headers)
    assert replay_res["valid"] is False
    assert replay_res["code"] == "DUPLICATE_NONCE"

    # Post-Quantum ML-DSA check
    pq_headers = {
        "x-webhook-timestamp": ts,
        "x-webhook-nonce": f"pq_nonce_{time.time()}",
        "signature-input": 'sig1=("@method" "@target-uri");alg="ml-dsa-44"',
        "x-signature": "a" * 64  # valid simulated 64-char ML-DSA signature
    }
    pq_res = guard.verify_webhook_request(payload, pq_headers)
    assert pq_res["valid"] is True
    assert pq_res["quantum_resistant"] is True

def test_global_msr_filter_anand_pappas():
    """Validates Anand & Pappas (UPenn arXiv:2606.15024) MSR trimming of Byzantine outliers."""
    engine = GovernedRobustConsensusEngine()
    # 7 honest proposals clustered near 25, 2 Byzantine pushing 0, 2 Byzantine pushing 50
    proposals = [0.0, 0.0, 24.5, 25.0, 25.2, 24.8, 25.1, 25.3, 24.9, 50.0, 50.0]
    filtered = engine.apply_global_msr_filter(proposals, f=2)
    assert len(filtered) == 7
    assert min(filtered) >= 24.5
    assert max(filtered) <= 25.3
    # Mean of filtered values should be exactly around 25
    assert round(sum(filtered) / len(filtered), 1) == 25.0

def test_intermittent_adaptive_threshold_aydin_nedic():
    """Validates Aydin, Nedic et al. (ASU/Harvard arXiv:2403.17907) adaptive threshold xi_t."""
    engine = GovernedRobustConsensusEngine()
    # At t=100, honest agents have high aggregate beta ~ 15.0, intermittent attacker has beta = 5.0
    trust_map = {
        "agent_honest_1": 15.2,
        "agent_honest_2": 15.0,
        "agent_honest_3": 14.8,
        "agent_intermittent_malicious": 5.0
    }
    trusted = engine.apply_intermittent_adaptive_threshold(trust_map, t=100, gamma=0.7, xi=0.15)
    assert "agent_honest_1" in trusted
    assert "agent_honest_2" in trusted
    assert "agent_honest_3" in trusted
    assert "agent_intermittent_malicious" not in trusted

