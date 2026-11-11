"""
Unit Tests for Next-Gen Swarm Resilience:
1. Steganography & In-Distribution Collusion Probe (SoK R2/P4)
2. SMT Tool Contract Verifier (Z3 Ground Truth)
3. Wasm Agent Sandbox (Capability-Bounded WASI Execution)
"""
import pytest
from app.services.steganography_collusion_probe import SteganographyCollusionProbe
from app.services.smt_tool_contract_verifier import SMTToolContractVerifier
from app.services.wasm_agent_sandbox import WasmAgentSandbox


def test_steganography_covert_payload_detection():
    probe = SteganographyCollusionProbe()
    
    # Clean message
    clean_msg = "Please verify the authentication middleware logic for session tokens."
    clean_res = probe.detect_covert_payload(clean_msg)
    assert clean_res["has_covert_steganography"] is False
    assert clean_res["status"] == "CLEAN"

    # Steganographic payload with hidden zero-width spaces (\u200b)
    covert_msg = "Please verify the\u200b\u200c authentication middleware logic\u200d for session tokens."
    covert_res = probe.detect_covert_payload(covert_msg)
    assert covert_res["has_covert_steganography"] is True
    assert covert_res["hidden_char_count"] == 3
    assert covert_res["status"] == "COVERT_CHANNEL_DETECTED"


def test_lying_with_truths_z3_verification():
    probe = SteganographyCollusionProbe()

    # Two colluding agents propose values that are locally truthful (<= 50)
    # but their composition (48 + 48 = 96) violates global invariant (x + y <= 80)
    claims = [
        {"agent": "agent_alpha", "claimed_value": 48},
        {"agent": "agent_beta", "claimed_value": 48}
    ]
    res = probe.verify_lying_with_truths(claims, "x + y <= 80")
    assert res["agents_locally_truthful"] is True
    assert res["collective_invariant_violated"] is True
    assert res["verdict"] == "COLLUSION_EXPOSED_BY_Z3"


def test_smt_tool_contract_file_path():
    verifier = SMTToolContractVerifier()
    
    # Valid safe path
    ok, msg = verifier.verify_file_path_contract("/var/app/sandbox/controllers/auth.js")
    assert ok is True
    assert "UNSAT_VERIFIED" in msg

    # CWE-22 Path traversal escape
    bad_ok, bad_msg = verifier.verify_file_path_contract("/var/app/sandbox/../../etc/passwd")
    assert bad_ok is False
    assert "REJECTED_BY_Z3" in bad_msg


def test_smt_tool_contract_command_injection():
    verifier = SMTToolContractVerifier()

    # Valid sanitized command
    ok, msg = verifier.verify_command_exec_contract("npm test")
    assert ok is True
    assert "UNSAT_VERIFIED" in msg

    # Command injection attempt (CWE-78)
    bad_ok, bad_msg = verifier.verify_command_exec_contract("npm test; rm -rf /")
    assert bad_ok is False
    assert "REJECTED_BY_Z3" in bad_msg


def test_smt_tool_contract_database_query():
    verifier = SMTToolContractVerifier()

    # Parameterized query (CWE-89 safe)
    ok, msg = verifier.verify_database_query_contract("SELECT * FROM users WHERE id = ? AND role = ?", 2)
    assert ok is True
    assert "UNSAT_VERIFIED" in msg

    # Unparameterized / injection query
    bad_ok, bad_msg = verifier.verify_database_query_contract("SELECT * FROM users WHERE id = '1' --", 0)
    assert bad_ok is False
    assert "REJECTED_BY_Z3" in bad_msg


def test_smt_tool_contract_network_egress():
    verifier = SMTToolContractVerifier()

    # Allowed external API egress
    ok, msg = verifier.verify_network_egress_contract("api.github.com", 443)
    assert ok is True
    assert "UNSAT_VERIFIED" in msg

    # SSRF attack targeting internal metadata service
    bad_ok, bad_msg = verifier.verify_network_egress_contract("169.254.169.254", 80)
    assert bad_ok is False
    assert "REJECTED_BY_Z3" in bad_msg


def test_wasm_agent_sandbox_capability_and_memory():
    sandbox = WasmAgentSandbox(
        agent_id="test_worker_1",
        memory_limit_mb=1,
        max_fuel_units=500,
        allowed_capabilities=["read_public_docs", "format_code"]
    )

    # Allowed action
    res = sandbox.execute_in_sandbox("format_code", payload_size_bytes=1024, fuel_cost=50)
    assert res["success"] is True

    # Unauthorized action (least privilege)
    bad_cap_res = sandbox.execute_in_sandbox("write_root_fs", payload_size_bytes=1024, fuel_cost=50)
    assert bad_cap_res["success"] is False
    assert "CAPABILITY_DENIED" in bad_cap_res["error"]

    # Fuel exhaustion trapping (DoS defense)
    exhaust_res = sandbox.execute_in_sandbox("format_code", payload_size_bytes=1024, fuel_cost=600)
    assert exhaust_res["success"] is False
    assert "FUEL_EXHAUSTED" in exhaust_res["error"]
    assert sandbox.is_jailed is True

    # Instant $O(1)$ capability revocation
    sandbox2 = WasmAgentSandbox(agent_id="test_worker_2", allowed_capabilities=["action_a"])
    rev = sandbox2.revoke_all_capabilities("Detected erratic prompt infection")
    assert rev["status"] == "CAPABILITIES_REVOKED"
    assert sandbox2.is_jailed is True
