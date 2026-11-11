"""
Unit Tests for State Recovery & Diagnostic Metrics Engine.
Validates:
1. Directed Provenance Graph construction
2. Contamination set C(c) attribution
3. Cascading credential/delegation revocation
4. Selective rollback preserving benign state updates
5. Z3 SMT proof that protected property P holds
6. Diagnostic metrics: RCR, Recovery Completeness, TTC, TTR, Collateral Loss
"""
import time
import pytest
from app.services.state_recovery_engine import StateRecoveryEngine


def test_state_recovery_provenance_and_contamination_attribution():
    engine = StateRecoveryEngine()

    # Event 1: Clean admission
    engine.record_event(
        event_id="E1",
        principal_id="orchestrator",
        event_type="ADMISSION",
        payload={"action": "init_session"},
        state_updates={"session_id": "sess_101", "auth_level": "user"}
    )

    # Event 2: Safe specialist action
    engine.record_event(
        event_id="E2",
        principal_id="agent_planner",
        event_type="MESSAGE",
        payload={"plan": "inspect_code"},
        parent_ids=["E1"],
        state_updates={"active_file": "server.js"}
    )

    # Event 3: Initial compromise injected (c)
    engine.record_event(
        event_id="E3",
        principal_id="agent_planner",
        event_type="MESSAGE",
        payload={"prompt_injection": "drop database;"},
        parent_ids=["E2"],
        state_updates={"tainted_sql": "DROP TABLE users;"}
    )

    # Event 4: Cascading delegation to privileged worker
    engine.record_event(
        event_id="E4",
        principal_id="agent_worker",
        event_type="DELEGATION",
        payload={"scope": "db_admin_exec"},
        parent_ids=["E3"],
        state_updates={"tainted_command": "EXEC DROP"}
    )

    # Event 5: Tool action triggered by contaminated delegation
    engine.record_event(
        event_id="E5",
        principal_id="agent_worker",
        event_type="TOOL_ACTION",
        payload={"tool": "sql_query"},
        parent_ids=["E4"]
    )

    # Event 6: Independent benign event occurring concurrently
    engine.record_event(
        event_id="E6",
        principal_id="agent_logger",
        event_type="MESSAGE",
        payload={"log": "audit_metric_pulse"},
        parent_ids=["E1"],
        state_updates={"audit_count": 42}
    )

    # Step 2: Attribute contamination set C(c) starting from E3
    c_set = engine.attribute_contamination_set(initial_compromise_id="E3")
    assert "E3" in c_set
    assert "E4" in c_set
    assert "E5" in c_set
    assert "E1" not in c_set
    assert "E2" not in c_set
    assert "E6" not in c_set  # Benign concurrent event preserved!


def test_cascading_delegation_revocation():
    engine = StateRecoveryEngine()

    engine.record_event(
        event_id="E1",
        principal_id="agent_admin",
        event_type="DELEGATION",
        payload={"scope": "file_write"},
        state_updates={"admin": True}
    )
    assert "file_write" in engine.active_credentials["agent_admin"]

    # Revocation cascade
    res = engine.cascade_revocation({"E1"})
    assert res["revoked_delegations"] == 1
    assert "file_write" not in engine.active_credentials["agent_admin"]


def test_end_to_end_recovery_and_diagnostic_metrics():
    engine = StateRecoveryEngine()
    t_detect = time.time()

    # 1. Base clean state
    engine.record_event(
        event_id="E1",
        principal_id="orchestrator",
        event_type="ADMISSION",
        payload={"init": True},
        state_updates={"app_name": "GrayStrike", "status": "ONLINE"}
    )

    # 2. Compromise event c
    engine.record_event(
        event_id="E2",
        principal_id="agent_malicious",
        event_type="MESSAGE",
        payload={"attack": "inject"},
        parent_ids=["E1"],
        state_updates={"tainted_key": "MALICIOUS_PAYLOAD"}
    )

    # 3. Downstream contaminated event
    engine.record_event(
        event_id="E3",
        principal_id="agent_victim",
        event_type="TOOL_ACTION",
        payload={"exec": "payload"},
        parent_ids=["E2"],
        state_updates={"tainted_output": "STOLEN_SECRETS"}
    )

    # 4. Independent benign event
    engine.record_event(
        event_id="E4",
        principal_id="agent_telemetry",
        event_type="MESSAGE",
        payload={"metric": "cpu_load"},
        parent_ids=["E1"],
        state_updates={"cpu_load": "12%"}
    )

    # Execute complete recovery
    result = engine.execute_recovery(initial_compromise_id="E2", detection_time=t_detect)

    assert result["status"] == "SUCCESS"
    assert result["contamination_set_size"] == 2  # E2 and E3
    assert "E2" in result["contaminated_events"]
    assert "E3" in result["contaminated_events"]

    # Validate paper's diagnostic metrics
    metrics = result["metrics"]
    assert metrics["residual_contamination_ratio_rcr"] == 0.0  # 100% purged
    assert metrics["recovery_completeness"] == 1.0  # (1 - RCR) and P holds
    assert metrics["protected_property_p_verified"] is True
    assert metrics["smt_prover_status"] == "UNSAT_SAFE"
    assert metrics["time_to_containment_ms"] > 0
    assert metrics["time_to_recovery_ms"] >= metrics["time_to_containment_ms"]
    assert metrics["collateral_loss"] == 0

    # Ensure active state is restored to clean state, retaining benign updates
    assert "tainted_key" not in engine.active_state
    assert "tainted_output" not in engine.active_state
    assert engine.active_state.get("app_name") == "GrayStrike"
    assert engine.active_state.get("status") == "ONLINE"
    assert engine.active_state.get("cpu_load") == "12%"
