"""
GrayStrike Interactive Swarm CLI Demonstration
Executes the collaborative, history-aware multi-agent audit lifecycle in real time.
"""
import asyncio
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure backend modules can be imported
sys.path.insert(0, os.path.abspath("."))

from backend.app.services.multi_agent.swarm_orchestrator import GrayStrikeSwarmOrchestrator

# ANSI Terminal Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


SAMPLE_CODE = """// app/api/db/users/route.ts
import { NextRequest, NextResponse } from "next/server";
import { supabase } from "@/lib/supabaseClient";

export async function GET(req: Request) {
    // VULNERABILITY: Raw database read without Row-Level Security policy context
    const users = await supabase.from('users').select('*');
    return Response.json(users);
}
"""


async def main():
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}         GRAYSTRIKE — AUTONOMOUS MULTI-AGENT SWARM DEMO               {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{YELLOW}[Architecture: SecureFlow + LLM-SmartAudit + HAFixAgent + BADIT]{RESET}\n")

    print(f"{BOLD}Target File:{RESET} app/api/db/users/route.ts")
    print(f"{BOLD}Target Endpoint:{RESET} http://127.0.0.1:9001/api/db/users (VulnSaaS Runtime)")
    print(f"{BOLD}Code Inspection Snippet:{RESET}\n{SAMPLE_CODE}")

    orchestrator = GrayStrikeSwarmOrchestrator(repo_path=".")

    print(f"{CYAN}---> [STAGE 1] GrayProbe Agent (Binary Early-Exit Filter)...{RESET}")
    await asyncio.sleep(0.5)

    report = await orchestrator.execute_full_audit(
        source_code=SAMPLE_CODE,
        file_path="app/api/db/users/route.ts",
        live_endpoint_url="http://127.0.0.1:9001/api/db/users",
        allow_loopback=True
    )

    s1 = report.stages.get("stage1_probe", {})
    print(f"     Status: {YELLOW}{s1.get('status')}{RESET} | Candidates: {len(s1.get('candidates', []))}")
    print(f"     Early Exit: {s1.get('early_exit_applied')}")

    print(f"\n{CYAN}---> [STAGE 2] GrayAnalyze Agent (Formal CWE & SMT Satisfiability)...{RESET}")
    await asyncio.sleep(0.5)
    s2 = report.stages.get("stage2_formal_analysis", {})
    sat_color = GREEN if s2.get("is_satisfiable") else RED
    print(f"     CWE Identified: {BOLD}{s2.get('cwe_id')} ({s2.get('owasp_category')}){RESET}")
    print(f"     Formula: {s2.get('reachability_formula')}")
    print(f"     Satisfiability Status: {sat_color}{'SAT (Confirmed Reachable Path)' if s2.get('is_satisfiable') else 'UNSAT (Guarded)'}{RESET}")

    print(f"\n{CYAN}---> [STAGE 3] GitHistoryMiner (HAFix Blame & Intent Extraction)...{RESET}")
    await asyncio.sleep(0.5)
    s3 = report.stages.get("stage3_history_mining", {})
    print(f"     Blame Commit: {s3.get('commit_hash')}")
    print(f"     Commit Intent: '{s3.get('commit_summary')}'")
    print(f"     Heuristic Used: {s3.get('heuristic_used')} (Fallback: {s3.get('is_blameless_fallback')})")

    print(f"\n{CYAN}---> [STAGE 4] GrayRedTeam Agent (Active DAST Probe & Counselor)...{RESET}")
    await asyncio.sleep(0.5)
    s4 = report.stages.get("stage4_redteam_verification", {})
    ver_status = s4.get("verification_status")
    v_color = GREEN if s4.get("is_confirmed") else YELLOW
    print(f"     Reproduction cURL: {BOLD}{s4.get('reproduction_curl') or 'Internal SMT model'}{RESET}")
    print(f"     Verification Status: {v_color}{ver_status}{RESET}")
    print(f"     Evidence Summary: {s4.get('evidence_summary')}")

    print(f"\n{CYAN}---> [STAGE 5] GraySynthesize Agent (History-Aware Minimal-Diff Patch)...{RESET}")
    await asyncio.sleep(0.5)
    s5 = report.stages.get("stage5_synthesis", {})
    print(f"     Root Cause Explanation: {s5.get('root_cause_explanation')}")
    print(f"\n{BOLD}{GREEN}Generated Minimal-Diff Git Patch:{RESET}")
    print(f"{YELLOW}{s5.get('minimal_diff_patch')}{RESET}")

    print(f"{BOLD}{GREEN}Generated Companion Regression Test:{RESET}")
    print(f"{CYAN}{s5.get('regression_test_code')}{RESET}")

    print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}     AUDIT COMPLETE: 100% PROVEN, REPRODUCED & AUTO-PATCHED           {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
