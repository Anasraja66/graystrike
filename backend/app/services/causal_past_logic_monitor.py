"""
Causal Past Logic (CPL) Runtime Monitor & Vector Clock Engine
Paper Reference: arXiv:2605.20923 (Causal Past Logic for Runtime Verification of Distributed LLM Agent Workflows - Benedikt Bollig, ZipperGen)

This module implements:
1. Vector Clocks (Fidge/Mattern) for distributed agent lifelines (Orchestrator, Security, TestRunner, Committer, Z3Verifier)
2. Latest-Value Views & Variable Views tracking the latest causally visible event values
3. CPL Past-Time Operators:
   - Previous-local: Y(theta)
   - Since: theta1 S theta2 (past-time since along lifeline)
   - Cross-Lifeline Causal Inspection: @Lifeline(theta) and @Lifeline.variable
   - Causal Past: P_A(theta) = @A(true S theta)
4. Source-Level Runtime Guards before critical transitions (such as Git commits, PR merges, rollback executions)
"""

from typing import Dict, Any, List, Optional, Set, Callable
import time
import copy
import logging

logger = logging.getLogger("CPLMonitor")
logger.setLevel(logging.INFO)


class VectorClock:
    """Vector clock representation across known lifelines."""
    def __init__(self, lifelines: Optional[List[str]] = None):
        self.clocks: Dict[str, int] = {ll: 0 for ll in (lifelines or [])}

    def increment(self, lifeline: str) -> None:
        self.clocks[lifeline] = self.clocks.get(lifeline, 0) + 1

    def get(self, lifeline: str) -> int:
        return self.clocks.get(lifeline, 0)

    def merge(self, other_vc: 'VectorClock') -> 'VectorClock':
        new_vc = VectorClock()
        all_keys = set(self.clocks.keys()) | set(other_vc.clocks.keys())
        for k in all_keys:
            new_vc.clocks[k] = max(self.clocks.get(k, 0), other_vc.clocks.get(k, 0))
        return new_vc

    def to_dict(self) -> Dict[str, int]:
        return dict(self.clocks)

    @classmethod
    def from_dict(cls, data: Dict[str, int]) -> 'VectorClock':
        vc = cls()
        vc.clocks = dict(data)
        return vc

    def __repr__(self) -> str:
        return f"VC({self.clocks})"


class CPLMessage:
    """Asynchronous message exchanged between agent lifelines carrying CPL metadata."""
    def __init__(
        self,
        sender: str,
        receiver: str,
        payload: Dict[str, Any],
        vector_clock: VectorClock,
        view_table: Dict[str, Dict[str, bool]],
        var_table: Dict[str, Dict[str, Any]],
        message_id: Optional[str] = None
    ):
        self.sender = sender
        self.receiver = receiver
        self.payload = payload
        self.vector_clock = vector_clock
        self.view_table = view_table  # lifeline -> formula_id -> bool
        self.var_table = var_table    # lifeline -> var_name -> value
        self.message_id = message_id or f"msg_{sender}_{int(time.time()*1000)}"


class CPLEvent:
    """Event occurring on a specific agent lifeline."""
    def __init__(
        self,
        event_id: str,
        lifeline: str,
        kind: str,  # 'act', 'send', 'recv', 'choice'
        store_delta: Optional[Dict[str, Any]] = None,
        target_lifeline: Optional[str] = None
    ):
        self.event_id = event_id
        self.lifeline = lifeline
        self.kind = kind
        self.store_delta = store_delta or {}
        self.target_lifeline = target_lifeline
        self.timestamp = time.time()


class CPLLifelineMonitor:
    """
    Online monitor for a single agent lifeline according to Bollig's Algorithm 1 & 2.
    Tracks vector clock, latest-value views, variable views, and local store.
    """
    def __init__(self, lifeline_id: str, all_lifelines: List[str]):
        self.lifeline_id = lifeline_id
        self.vector_clock = VectorClock(all_lifelines)
        # view_table: lifeline -> formula_name -> bool (truth of formula at latest visible event of that lifeline)
        self.view_table: Dict[str, Dict[str, bool]] = {ll: {} for ll in all_lifelines}
        # var_table: lifeline -> var_name -> value (value of variable at latest visible event of that lifeline)
        self.var_table: Dict[str, Dict[str, Any]] = {ll: {} for ll in all_lifelines}
        # Local store
        self.store: Dict[str, Any] = {}
        # Previous local truth values: old_A(psi)
        self.old_eval: Dict[str, bool] = {}
        # Registered formulas: id -> (AST or eval function)
        self.registered_formulas: Dict[str, Any] = {}

    def register_formula(self, formula_id: str, formula_spec: Dict[str, Any]) -> None:
        """Register a CPL formula AST for online tracking."""
        self.registered_formulas[formula_id] = formula_spec

    def on_event(self, event: CPLEvent, incoming_msg: Optional[CPLMessage] = None) -> Dict[str, bool]:
        """
        Implements Algorithm 1: Event update and view propagation.
        """
        # Step 1: If receive event, merge incoming vector clock and latest-value views
        if event.kind == "recv" and incoming_msg is not None:
            msg_vc = incoming_msg.vector_clock
            for b_ll, msg_clock in msg_vc.clocks.items():
                local_clock = self.vector_clock.get(b_ll)
                if msg_clock > local_clock:
                    # Sender is strictly ahead on lifeline b_ll; adopt sender's views for b_ll
                    if b_ll in incoming_msg.view_table:
                        self.view_table[b_ll] = copy.deepcopy(incoming_msg.view_table[b_ll])
                    if b_ll in incoming_msg.var_table:
                        self.var_table[b_ll] = copy.deepcopy(incoming_msg.var_table[b_ll])
            # Merge vector clock: vc_A <- max(vc_A, mu.vc)
            self.vector_clock = self.vector_clock.merge(msg_vc)

        # Step 2: Save old_eval = view_A(A, psi)
        local_views = self.view_table.get(self.lifeline_id, {})
        for f_id in self.registered_formulas.keys():
            self.old_eval[f_id] = local_views.get(f_id, False)

        # Step 3: Increment local clock component
        self.vector_clock.increment(self.lifeline_id)

        # Step 4: Apply effect to store
        if event.store_delta:
            self.store.update(event.store_delta)

        # Step 5: Update local var_table entries from current store
        if self.lifeline_id not in self.var_table:
            self.var_table[self.lifeline_id] = {}
        for k, v in self.store.items():
            self.var_table[self.lifeline_id][k] = v

        # Step 6: Evaluate all registered formulas bottom-up (Algorithm 2)
        current_eval: Dict[str, bool] = {}
        for f_id, f_spec in self.registered_formulas.items():
            current_eval[f_id] = self.evaluate_cpl(f_spec)

        # Step 7: Update local view table: view_A(A, psi) <- val_A(psi)
        self.view_table[self.lifeline_id] = current_eval

        return current_eval

    def create_outgoing_message(self, receiver: str, payload: Dict[str, Any]) -> CPLMessage:
        """Create message stamping with local vector clock and latest visible views."""
        return CPLMessage(
            sender=self.lifeline_id,
            receiver=receiver,
            payload=payload,
            vector_clock=VectorClock.from_dict(self.vector_clock.to_dict()),
            view_table=copy.deepcopy(self.view_table),
            var_table=copy.deepcopy(self.var_table)
        )

    def evaluate_cpl(self, formula: Dict[str, Any]) -> bool:
        """
        Implements Algorithm 2: Formula evaluation at the current event on lifeline A.
        """
        op = formula.get("op")

        if op == "atom":
            # Atomic predicate over local store or cross-lifeline variable
            # e.g. {"op": "atom", "predicate": "eq", "lhs": "@TestRunner.candidate", "rhs": "candidate"}
            pred = formula.get("predicate", "eq")
            lhs_val = self._resolve_term(formula.get("lhs"))
            rhs_val = self._resolve_term(formula.get("rhs"))
            if lhs_val is None or rhs_val is None:
                return False
            if pred == "eq":
                return lhs_val == rhs_val
            elif pred == "neq":
                return lhs_val != rhs_val
            return False

        elif op == "previous":  # Y(theta)
            # (vc_A(A) > 1) and old_A(theta)
            sub_id = formula.get("sub_id")
            if self.vector_clock.get(self.lifeline_id) <= 1:
                return False
            return self.old_eval.get(sub_id, False)

        elif op == "at":  # @B(theta)
            target_ll = formula.get("lifeline")
            sub_formula = formula.get("sub_formula")
            sub_id = formula.get("sub_id")

            if target_ll == self.lifeline_id:
                return self.evaluate_cpl(sub_formula)
            elif self.vector_clock.get(target_ll) == 0:
                # No event from target_ll is causally visible
                return False
            else:
                # Read from view_table(target_ll, sub_id)
                target_views = self.view_table.get(target_ll, {})
                return target_views.get(sub_id, False)

        elif op == "since":  # theta1 S theta2
            # prev <- (vc_A(A) > 1) and old_A(theta1 S theta2)
            # return Eval(theta2) or (Eval(theta1) and prev)
            f_id = formula.get("formula_id")
            sub1 = formula.get("theta1")
            sub2 = formula.get("theta2")

            eval2 = self.evaluate_cpl(sub2)
            eval1 = self.evaluate_cpl(sub1)

            prev_since = (self.vector_clock.get(self.lifeline_id) > 1) and self.old_eval.get(f_id, False)
            return eval2 or (eval1 and prev_since)

        elif op == "and":
            return all(self.evaluate_cpl(sub) for sub in formula.get("sub_formulas", []))

        elif op == "or":
            return any(self.evaluate_cpl(sub) for sub in formula.get("sub_formulas", []))

        elif op == "not":
            return not self.evaluate_cpl(formula.get("sub_formula"))

        return False

    def _resolve_term(self, term: Any) -> Any:
        """Resolve either local store variable or cross-lifeline term @B.x."""
        if not isinstance(term, str):
            return term
        if term.startswith("@") and "." in term:
            # Cross-lifeline term: @Lifeline.variable
            prefix, var_name = term.split(".", 1)
            target_ll = prefix[1:]
            if target_ll == self.lifeline_id:
                return self.store.get(var_name)
            if self.vector_clock.get(target_ll) == 0:
                return None  # Not visible
            return self.var_table.get(target_ll, {}).get(var_name)
        else:
            # Local store variable
            return self.store.get(term)


class DistributedCPLCoordinator:
    """
    Coordinates multi-agent workflows with CPL runtime guards.
    Guarantees asynchronous safety without requiring central stop-the-world locks.
    """
    def __init__(self, lifelines: List[str]):
        self.lifelines = lifelines
        self.monitors: Dict[str, CPLLifelineMonitor] = {
            ll: CPLLifelineMonitor(ll, lifelines) for ll in lifelines
        }

    def register_guard(self, lifeline: str, guard_id: str, formula_spec: Dict[str, Any]) -> None:
        """Registers a CPL guard on an owner lifeline."""
        if lifeline in self.monitors:
            self.monitors[lifeline].register_formula(guard_id, formula_spec)

    def record_local_action(self, lifeline: str, action_name: str, store_delta: Dict[str, Any]) -> Dict[str, bool]:
        """Record an internal computation / action on a lifeline."""
        event = CPLEvent(
            event_id=f"evt_{lifeline}_{int(time.time()*1000)}",
            lifeline=lifeline,
            kind="act",
            store_delta=store_delta
        )
        return self.monitors[lifeline].on_event(event)

    def send_message(self, sender: str, receiver: str, payload: Dict[str, Any]) -> CPLMessage:
        """Record send event on sender lifeline, emit message with vector clock and views."""
        event = CPLEvent(
            event_id=f"send_{sender}_{int(time.time()*1000)}",
            lifeline=sender,
            kind="send",
            target_lifeline=receiver
        )
        self.monitors[sender].on_event(event)
        return self.monitors[sender].create_outgoing_message(receiver, payload)

    def receive_message(self, receiver: str, msg: CPLMessage) -> Dict[str, bool]:
        """Record receive event on receiver lifeline, merge causal past."""
        event = CPLEvent(
            event_id=f"recv_{receiver}_{int(time.time()*1000)}",
            lifeline=receiver,
            kind="recv",
            store_delta=msg.payload
        )
        return self.monitors[receiver].on_event(event, incoming_msg=msg)

    def evaluate_owner_guard(self, owner_lifeline: str, guard_formula: Dict[str, Any]) -> bool:
        """
        Evaluate CPL guard at an owner choice event (e.g. before committer merges a PR).
        Returns True if causally authorized, False otherwise.
        """
        # Choice event leaves store unchanged
        event = CPLEvent(
            event_id=f"choice_{owner_lifeline}_{int(time.time()*1000)}",
            lifeline=owner_lifeline,
            kind="choice"
        )
        self.monitors[owner_lifeline].on_event(event)
        return self.monitors[owner_lifeline].evaluate_cpl(guard_formula)
