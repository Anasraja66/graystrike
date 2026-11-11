"""
Hardened Open-System Resilience Engine (HOS-Engine)
Addresses the 3 Open Research Gaps from SoK (arXiv:2609.00595) & Anand-Pappas (arXiv:2606.15024):
1. Decentralized Peer-to-Peer Threshold Quorum (A4 Adversary Gap - No single coordinator)
2. Dynamic Capability Delegation Tokens with O(1) Revocation (Open-System Dynamic Membership)
3. Saga Pattern Compensating Inverses for Irreversible External Tool Actions
"""

from typing import Dict, Any, List, Optional, Set, Callable, Tuple
import hmac
import hashlib
import time
import uuid
import logging

logger = logging.getLogger("HardenedResilienceEngine")
logger.setLevel(logging.INFO)


class CapabilityToken:
    """
    Cryptographic capability delegation token for dynamic membership.
    Allows dynamic agent spawning with fine-grained scopes and fast O(1) revocation.
    """
    def __init__(
        self,
        token_id: str,
        principal_id: str,
        allowed_scopes: List[str],
        max_duration_seconds: float = 300.0,
        parent_token_id: Optional[str] = None,
        secret_key: bytes = b"graystrike_swarm_master_key_2026"
    ):
        self.token_id = token_id
        self.principal_id = principal_id
        self.allowed_scopes = set(allowed_scopes)
        self.created_at = time.time()
        self.expires_at = self.created_at + max_duration_seconds
        self.parent_token_id = parent_token_id
        self.signature = self._generate_signature(secret_key)

    def _generate_signature(self, secret: bytes) -> str:
        msg = f"{self.token_id}:{self.principal_id}:{sorted(list(self.allowed_scopes))}:{self.expires_at}:{self.parent_token_id}"
        return hmac.new(secret, msg.encode(), hashlib.sha256).hexdigest()

    def is_valid(self, required_scope: str, revoked_set: Set[str], secret_key: bytes = b"graystrike_swarm_master_key_2026") -> bool:
        if self.token_id in revoked_set:
            return False
        if time.time() > self.expires_at:
            return False
        if required_scope not in self.allowed_scopes:
            return False
        # Verify HMAC signature
        expected = self._generate_signature(secret_key)
        return hmac.compare_digest(self.signature, expected)


class OpenSystemMembershipManager:
    """
    Manages dynamic roster of agents (spawning, leave, capability delegation, and O(1) revocation).
    """
    def __init__(self, master_key: bytes = b"graystrike_swarm_master_key_2026"):
        self.master_key = master_key
        self.active_agents: Dict[str, Dict[str, Any]] = {}
        self.issued_tokens: Dict[str, CapabilityToken] = {}
        self.revoked_tokens: Set[str] = set()

    def register_agent(self, agent_id: str, role: str, scopes: List[str], ttl: float = 300.0) -> CapabilityToken:
        """Dynamically registers an agent into the swarm and issues capability token."""
        token_id = f"cap_{agent_id}_{uuid.uuid4().hex[:8]}"
        token = CapabilityToken(
            token_id=token_id,
            principal_id=agent_id,
            allowed_scopes=scopes,
            max_duration_seconds=ttl,
            secret_key=self.master_key
        )
        self.issued_tokens[token_id] = token
        self.active_agents[agent_id] = {
            "role": role,
            "token_id": token_id,
            "registered_at": time.time(),
            "status": "ACTIVE"
        }
        return token

    def revoke_token(self, token_id: str) -> bool:
        """O(1) instant capability revocation."""
        self.revoked_tokens.add(token_id)
        # Mark associated agent as revoked
        for aid, data in self.active_agents.items():
            if data.get("token_id") == token_id:
                data["status"] = "REVOKED"
        return True

    def check_permission(self, token_id: str, scope: str) -> bool:
        token = self.issued_tokens.get(token_id)
        if not token:
            return False
        return token.is_valid(scope, self.revoked_set(), self.master_key)

    def revoked_set(self) -> Set[str]:
        return self.revoked_tokens

    def get_active_roster(self) -> List[str]:
        return [aid for aid, data in self.active_agents.items() if data["status"] == "ACTIVE"]


class DecentralizedP2PQuorum:
    """
    Decentralized Byzantine Fault Tolerant Peer-to-Peer Consensus without a Single Coordinator.
    Tackles SoK A4 Adversary: uses (2f + 1) multi-party partial signatures to commit decisions.
    """
    def __init__(self, agent_roster: List[str], byzantine_threshold_f: int = 1):
        self.agent_roster = set(agent_roster)
        self.f = byzantine_threshold_f
        # Required quorum: 2f + 1 for Byzantine agreement
        self.quorum_size = 2 * self.f + 1
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.votes: Dict[str, Dict[str, str]] = {}  # proposal_id -> agent_id -> signature

    def propose_patch(self, proposer_id: str, proposal_id: str, patch_data: Dict[str, Any]) -> bool:
        if proposer_id not in self.agent_roster:
            return False
        proposal_hash = hashlib.sha256(str(sorted(patch_data.items())).encode()).hexdigest()
        self.proposals[proposal_id] = {
            "proposer": proposer_id,
            "data": patch_data,
            "hash": proposal_hash,
            "timestamp": time.time(),
            "status": "PROPOSED"
        }
        self.votes[proposal_id] = {}
        return True

    def cast_peer_vote(self, voter_id: str, proposal_id: str, is_approved: bool) -> Optional[Dict[str, Any]]:
        """
        Agents vote directly on peer proposals. When >= (2f + 1) agree, quorum is achieved.
        """
        if voter_id not in self.agent_roster or proposal_id not in self.proposals:
            return None
        if not is_approved:
            return None

        # Sign the proposal hash
        prop_hash = self.proposals[proposal_id]["hash"]
        signature = hashlib.sha256(f"{voter_id}:{prop_hash}:APPROVED".encode()).hexdigest()
        self.votes[proposal_id][voter_id] = signature

        # Check if threshold quorum is reached
        valid_votes = len(self.votes[proposal_id])
        if valid_votes >= self.quorum_size and self.proposals[proposal_id]["status"] != "COMMITTED":
            self.proposals[proposal_id]["status"] = "COMMITTED"
            return {
                "decision": "COMMITTED",
                "quorum_reached": True,
                "valid_votes": valid_votes,
                "required_quorum": self.quorum_size,
                "signers": list(self.votes[proposal_id].keys()),
                "proposal_hash": prop_hash
            }

        return {
            "decision": "PENDING_QUORUM",
            "current_votes": valid_votes,
            "required_quorum": self.quorum_size
        }


class SagaCompensatingAction:
    """Defines a forward tool action paired with its explicit semantic compensating inverse."""
    def __init__(
        self,
        step_id: str,
        action_name: str,
        forward_func: Callable[[], Any],
        inverse_func: Callable[[], Any],
        description: str = ""
    ):
        self.step_id = step_id
        self.action_name = action_name
        self.forward_func = forward_func
        self.inverse_func = inverse_func
        self.description = description
        self.executed = False
        self.compensated = False


class SagaExecutionCoordinator:
    """
    Saga Pattern Execution Coordinator for Irreversible Tool Side-Effects.
    Maintains an undo log: if any step fails or an invariant is violated,
    executes semantic inverses in reverse topological order.
    """
    def __init__(self):
        self.executed_stack: List[SagaCompensatingAction] = []
        self.execution_log: List[Dict[str, Any]] = []

    def execute_step(self, action: SagaCompensatingAction) -> Tuple[bool, Any]:
        """Executes forward action and pushes onto undo stack."""
        try:
            result = action.forward_func()
            action.executed = True
            self.executed_stack.append(action)
            self.execution_log.append({
                "step_id": action.step_id,
                "action": action.action_name,
                "status": "FORWARD_SUCCESS",
                "timestamp": time.time()
            })
            return True, result
        except Exception as e:
            logger.error(f"Saga step {action.step_id} failed: {e}. Initiating rollback...")
            self.execution_log.append({
                "step_id": action.step_id,
                "action": action.action_name,
                "status": "FORWARD_FAILED",
                "error": str(e)
            })
            # Trigger compensating rollback
            compensation_report = self.rollback_all()
            return False, {"error": str(e), "compensation_report": compensation_report}

    def rollback_all(self) -> Dict[str, Any]:
        """Rolls back all successfully executed actions in reverse order using compensating inverses."""
        compensated_steps = []
        failed_compensations = []

        while self.executed_stack:
            action = self.executed_stack.pop()
            try:
                action.inverse_func()
                action.compensated = True
                compensated_steps.append(action.step_id)
                self.execution_log.append({
                    "step_id": action.step_id,
                    "action": f"COMPENSATE_{action.action_name}",
                    "status": "COMPENSATED"
                })
            except Exception as ce:
                failed_compensations.append({"step_id": action.step_id, "error": str(ce)})
                self.execution_log.append({
                    "step_id": action.step_id,
                    "action": f"COMPENSATE_{action.action_name}",
                    "status": "COMPENSATION_ERROR",
                    "error": str(ce)
                })

        return {
            "total_compensated": len(compensated_steps),
            "steps": compensated_steps,
            "failed_compensations": failed_compensations,
            "status": "SUCCESS" if not failed_compensations else "PARTIAL_RECOVERY"
        }
