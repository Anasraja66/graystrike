import pytest
import time
from backend.app.services.hardened_resilience_engine import (
    CapabilityToken,
    OpenSystemMembershipManager,
    DecentralizedP2PQuorum,
    SagaCompensatingAction,
    SagaExecutionCoordinator
)


def test_dynamic_capability_token_delegation_and_revocation():
    """
    Tests Open-System Gap:
    Dynamic membership delegation via HMAC CapabilityToken and O(1) instant revocation.
    """
    manager = OpenSystemMembershipManager()

    # 1. Dynamically register new worker agent with specific tool scopes
    token = manager.register_agent(
        agent_id="ephemeral_worker_01",
        role="ast_patcher",
        scopes=["ast:read", "ast:mutate", "git:branch"],
        ttl=60.0
    )

    # Verify granted permissions
    assert manager.check_permission(token.token_id, "ast:mutate") is True
    assert manager.check_permission(token.token_id, "git:branch") is True
    # Unauthorized scope must be denied
    assert manager.check_permission(token.token_id, "db:drop_table") is False

    # 2. Test O(1) instant revocation
    manager.revoke_token(token.token_id)
    assert manager.check_permission(token.token_id, "ast:mutate") is False
    assert "ephemeral_worker_01" not in manager.get_active_roster()


def test_decentralized_p2p_byzantine_quorum():
    """
    Tests SoK A4 Adversary Gap:
    Consensus without a single coordinator. Uses 2f + 1 peer threshold signatures.
    """
    # 4 peers, byzantine tolerance f = 1 -> quorum size = 2f + 1 = 3
    peers = ["peer_deepseek", "peer_llama", "peer_qwen", "peer_mistral"]
    p2p = DecentralizedP2PQuorum(peers, byzantine_threshold_f=1)

    patch_payload = {"cwe": "CWE-89", "file": "routes/user.js", "fix": "parameterized_query"}
    p2p.propose_patch("peer_deepseek", "prop_cwe89", patch_payload)

    # Vote 1 (peer_deepseek approves)
    v1 = p2p.cast_peer_vote("peer_deepseek", "prop_cwe89", True)
    assert v1["decision"] == "PENDING_QUORUM"
    assert v1["current_votes"] == 1

    # Vote 2 (peer_llama approves)
    v2 = p2p.cast_peer_vote("peer_llama", "prop_cwe89", True)
    assert v2["decision"] == "PENDING_QUORUM"
    assert v2["current_votes"] == 2

    # Vote 3 (peer_qwen approves) -> Reaches 2f + 1 = 3 -> Quorum COMMITTED
    v3 = p2p.cast_peer_vote("peer_qwen", "prop_cwe89", True)
    assert v3["decision"] == "COMMITTED"
    assert v3["quorum_reached"] is True
    assert len(v3["signers"]) == 3


def test_saga_compensating_transactions_on_failure():
    """
    Tests Saga Pattern Gap:
    Executing irreversible tool actions and automatically triggering semantic inverses on failure.
    """
    coordinator = SagaExecutionCoordinator()
    cloud_state = {"dns_record": None, "s3_backup": False, "git_branch": None}

    # Step 1: Create Git Branch (Compensating inverse: Delete Git Branch)
    step1 = SagaCompensatingAction(
        step_id="step_git_branch",
        action_name="create_branch",
        forward_func=lambda: cloud_state.update({"git_branch": "graystrike/fix-42"}),
        inverse_func=lambda: cloud_state.update({"git_branch": None})
    )
    ok1, _ = coordinator.execute_step(step1)
    assert ok1 is True
    assert cloud_state["git_branch"] == "graystrike/fix-42"

    # Step 2: Create S3 Backup (Compensating inverse: Purge S3 Backup)
    step2 = SagaCompensatingAction(
        step_id="step_s3_backup",
        action_name="backup_s3",
        forward_func=lambda: cloud_state.update({"s3_backup": True}),
        inverse_func=lambda: cloud_state.update({"s3_backup": False})
    )
    ok2, _ = coordinator.execute_step(step2)
    assert ok2 is True
    assert cloud_state["s3_backup"] is True

    # Step 3: Failing Action (e.g. invalid cloud credentials during DNS update)
    def failing_action():
        raise ConnectionResetError("Cloud API rate limit exceeded")

    step3 = SagaCompensatingAction(
        step_id="step_dns_update",
        action_name="update_dns",
        forward_func=failing_action,
        inverse_func=lambda: None
    )
    ok3, result3 = coordinator.execute_step(step3)
    assert ok3 is False
    assert "compensation_report" in result3
    assert result3["compensation_report"]["total_compensated"] == 2

    # Invariants restored by compensating inverses:
    assert cloud_state["git_branch"] is None
    assert cloud_state["s3_backup"] is False
