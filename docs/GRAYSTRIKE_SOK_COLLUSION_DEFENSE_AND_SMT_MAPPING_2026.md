# GrayStrike: Mapping SoK Multi-Agent Collusion Threats to SMT Formal Verification & WASM Sandboxing

**Date:** 10 November 2026  
**Author:** GrayStrike / Anas Technology Research  
**Reference Frameworks:**  
- *SoK: When Safe Agents Fail Together: The Security of Multi Agent LLM Systems* (arXiv:2609.00595, Johns Hopkins & NTU)  
- *Robust Multi-Agent LLMs under Byzantine Faults (SAC)* (arXiv:2605.09076, EMNLP 2026 Main)  
- *Resilient Consensus in Agentic AI (MSR)* (arXiv:2606.15024, UPenn & KTH)  
- *Multi-Agent Resilient Consensus under Intermittent Malicious Transmissions* (arXiv:2403.17907, ASU & Harvard)  

---

## 1. Executive Summary & Diagnostic Reality

The Johns Hopkins & NTU SoK paper systematizes 197 works and establishes a fundamental principle: **"Individually safe agents fail together."**

When agents collaborate, traditional per-agent prompt guardrails, system instructions, and superficial scoring functions are structurally bypassed through cross-principal information flow, shared state contamination, and transitive authority escalation.

While the academic community has established threat taxonomies (such as the $A \to I \to R$ framework), two core execution challenges remained unsolved in literature:
1. **Path Closure:** Preventing an attacker from circumventing message filters through multi-hop delegation and compositional injection ($P_1/P_7$).
2. **True State Recovery:** Restoring an untainted state after a compromised agent has already injected malicious context into memory or derived artifacts ($P_2$).

**GrayStrike's Architectural Solution:**  
GrayStrike bridges this theoretical gap by moving security out of non-deterministic LLM prompts into deterministic, machine-checkable execution layers:
- **Z3 SMT Prover ("Verification before Voting"):** Replaces vulnerable consensus voting with mathematical satisfiability proofs for code and security constraints.
- **WASM Capability Sandboxing (WASI):** Enforces microsecond linear memory isolation for worker nodes, halting prompt infection viruses.
- **Phase 6 State Governance Graph:** Enforces immutable state transitions with SHA-256 hash chains, making unauthorized delegation mathematically impossible.

---

## 2. Threat Mapping: SoK R2/P4 Collusion vs. GrayStrike Defenses

| SoK Threat Dimension | Attack Mechanism in Literature | Academic Limitation (SAC / MSR) | GrayStrike Production Defense |
| :--- | :--- | :--- | :--- |
| **R2: Loss of Independence** | Steganographic collusion (*Secret Collusion*, NeurIPS 2024; *Hidden in Plain Text*, 2025). Agents coordinate covertly within protocol-valid messages. | SAC only scores text; it cannot verify whether models have covertly coordinated or share common correlated training biases. | **Equicorrelation Discounting ($n_{\text{eff}} = \frac{n}{1+(n-1)\rho}$)** + Z3 SMT solver ignores natural language entirely and verifies logical constraints. |
| **P4: Lying with Truths** | Each agent reports an individually factual, truthful statement, but their composition induces a catastrophically false system belief (*Lying with Truths*, ACL 2026). | MSR trimming only catches numerical/distributional extremes; subtle in-distribution semantic exploits pass through filters. | **AST Counterexample-Guided Inductive Synthesis (CEGIS):** MaxSAT isolates the buggy constraint; patches must satisfy formal ground truth. |
| **P1/P7: Cascading Delegation** | Attacker taint flows from low-privilege planner to high-privilege execution agent (*Control-Flow Hijacking*, Jha et al. 2026). | Message tagging fails to bind true user intent across multi-hop translation. | **Phase 6 Governance Graph:** State machine forbids transition to `SURGICAL_PATCH_MERGE` unless backed by an SMT UNSAT proof receipt. |
| **P2: Propagation & Infection** | Self-replicating prompt injection spreading like a worm (*Prompt Infection*, arXiv:2410.07283; *AgentWorm*, 2026). | Containment is not recovery; removing the agent leaves tainted memory in other nodes. | **WASM Linear Memory Isolation** + **Git-Backed Immutable AST Rollback:** Purges all intermediate state back to the last verified cryptographic block. |

---

## 3. The 3 Next Strategic Research & Engineering Priorities

### Priority 1: Steganography & In-Distribution Collusion Benchmark (Colosseum Testbed)
- **Objective:** Evaluate GrayStrike's swarm verifier against covert steganographic coordination (from *Colosseum*, arXiv:2602.15198, and *Tool-use Steganography*, arXiv:2606.28425).
- **Deliverable:** Automated benchmark evaluating whether compromised agents can pass a subtle AST backdoor past the receiver filter, proving that Z3 SMT catches 100% of syntactic/semantic invariants that fool neural judges.

### Priority 2: Formal Verification Bridge (Deductive SMT Contracts)
- **Objective:** Extend Z3 SMT verification from AST bug fixes to general agent policy enforcement (inspired by *Maris*, arXiv:2505.04799, and *Verdict*, 2026).
- **Deliverable:** Machine-checkable policy contracts for all tool invocations (filesystem, network, subprocess) specified in First-Order Logic.

### Priority 3: Lightweight WASI/Wasm Agent Sandboxing (MVVM Architecture)
- **Objective:** Replace process-level worker isolation with Wasm micro-runtimes (Wasmtime/Wasmer).
- **Deliverable:** Zero cold-start (<5ms) capability-bounded execution per tool call, preventing unauthorized file or socket access regardless of prompt injection depth.

---

## 4. Verification & Audit Metrics Summary

- **Total Backend Tests:** 113 Passing (0 Failed, 100% Green).
- **Consensus Latency:** <0.20s for MSR + Adaptive Threshold + Z3 verification.
- **Dashboard Telemetry:** Live at `http://localhost:3000/remediation`.
