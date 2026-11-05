"""
FastAPI Router for GrayStrike Multi-Agent Swarm
Exposes the autonomous 5-stage collaborative audit lifecycle to developers and CI/CD pipelines.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from backend.app.services.multi_agent.swarm_orchestrator import (
    GrayStrikeSwarmOrchestrator,
    SwarmAuditReport
)
from backend.app.core.safety_guard import EnterpriseSafetyGuard, ScopeValidationError

router = APIRouter()


class SwarmAuditRequest(BaseModel):
    source_code: Optional[str] = Field(
        default=None,
        description="Source code snippet to audit. If omitted, a sample VulnSaaS route is evaluated."
    )
    file_path: str = Field(
        default="app/api/db/users/route.ts",
        description="Path of the target file in the repository"
    )
    live_endpoint_url: Optional[str] = Field(
        default="http://127.0.0.1:9001/api/db/users",
        description="Live API endpoint to verify runtime exploitability"
    )
    allow_loopback: bool = Field(
        default=True,
        description="Permit loopback testing on localhost/127.0.0.1"
    )


DEFAULT_VULN_SNIPPET = """
// VulnSaaS User Route Handler (app/api/db/users/route.ts)
import { NextRequest, NextResponse } from "next/server";
import { supabase } from "@/lib/supabaseClient";

export async function GET(req: Request) {
    // SECURITY DEFECT: Unauthenticated public query without Row-Level Security session context
    const users = await supabase.from('users').select('*');
    return Response.json(users);
}
"""


@router.post("/audit", response_model=Dict[str, Any])
async def run_swarm_audit(req: SwarmAuditRequest):
    """
    Executes an autonomous 5-stage collaborative security audit using the GrayStrike Swarm:
    1. GrayProbe (Fast Binary Filter)
    2. GrayAnalyze (CWE Taxonomy & SMT/SAT Reachability)
    3. GitHistoryMiner (HAFix Blame & Intent Extraction)
    4. GrayRedTeam (Safe Active DAST Verification & Counselor Refutation)
    5. GraySynthesize (Minimal-Diff Git Patch & Companion Test)
    """
    source_code = req.source_code or DEFAULT_VULN_SNIPPET

    # Enforce Enterprise Safety Guard if live endpoint provided
    if req.live_endpoint_url:
        try:
            EnterpriseSafetyGuard.validate_target_scope(
                target_url=req.live_endpoint_url,
                allow_loopback_for_testing=req.allow_loopback
            )
        except ScopeValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))

    orchestrator = GrayStrikeSwarmOrchestrator(repo_path=".")
    report: SwarmAuditReport = await orchestrator.execute_full_audit(
        source_code=source_code,
        file_path=req.file_path,
        live_endpoint_url=req.live_endpoint_url,
        allow_loopback=req.allow_loopback
    )

    return report.to_dict()


@router.get("/demo", response_model=Dict[str, Any])
async def run_instant_demo():
    """
    Instant 1-Click Interactive Enterprise Demo of the GrayStrike Multi-Agent Swarm.
    """
    orchestrator = GrayStrikeSwarmOrchestrator(repo_path=".")
    report: SwarmAuditReport = await orchestrator.execute_full_audit(
        source_code=DEFAULT_VULN_SNIPPET,
        file_path="app/api/db/users/route.ts",
        live_endpoint_url="http://127.0.0.1:9001/api/db/users",
        allow_loopback=True
    )
    return {
        "status": "success",
        "demo_title": "GrayStrike History-Aware Multi-Agent Autonomous Audit Demo",
        "scientific_inspirations": [
            "SecureFlow (MDPI 2026): 3-Stage Task Decomposition",
            "LLM-SmartAudit (IEEE TSE 2025): Collaborative Chat & Counselor Verification",
            "HAFixAgent (Queen's Univ, 2025): Blame-Derived fl_diff Historical Grounding",
            "BADIT (arXiv 2026): Mitigating Cross-Task Interference via Orthogonal Abilities"
        ],
        "report": report.to_dict()
    }
