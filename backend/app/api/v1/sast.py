"""
P3: SAST API Endpoints — GitHub Repository Static Analysis
Exposes the full SAST pipeline as REST API routes.

Routes:
  POST /api/v1/sast/analyze          — Trigger SAST scan on a GitHub repo
  POST /api/v1/sast/analyze-local    — Analyze inline code (for testing)
  GET  /api/v1/sast/rules            — List all 17+ SAST detection rules
"""
import os
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

router = APIRouter(tags=["sast"])


# =============================================================
# REQUEST / RESPONSE SCHEMAS
# =============================================================

class SASTAnalyzeRequest(BaseModel):
    owner: str = Field(..., description="GitHub repository owner (username or org)")
    repo: str = Field(..., description="GitHub repository name")
    github_token: Optional[str] = Field(None, description="GitHub Personal Access Token (optional for public repos)")
    deployed_url: Optional[str] = Field(None, description="Live deployment URL for Code-to-Runtime mapping")
    branch: Optional[str] = Field(None, description="Target branch (defaults to repo default branch)")
    dast_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Optional DAST findings to correlate with")

    class Config:
        json_schema_extra = {
            "example": {
                "owner": "Anasraja66",
                "repo": "graystrike",
                "deployed_url": "https://graystrike.vercel.app",
                "branch": "main"
            }
        }


class SASTLocalAnalyzeRequest(BaseModel):
    files: Dict[str, str] = Field(..., description="Dict of {filepath: source_code_content}")
    commit_sha: Optional[str] = Field("local-analysis", description="Commit SHA for provenance")
    deployed_url: Optional[str] = Field("http://localhost:3000")
    dast_findings: Optional[List[Dict[str, Any]]] = Field(default_factory=list)


# =============================================================
# ROUTES
# =============================================================

@router.post("/analyze")
async def analyze_github_repo(request: SASTAnalyzeRequest):
    """
    Trigger a full SAST scan on a GitHub repository.
    
    Pipeline:
    1. Fetch security-relevant source files via GitHub API
    2. Run 17-rule AST + regex static analysis engine
    3. Correlate findings with optional DAST scan results
    4. Return unified Code-to-Runtime security posture report
    """
    from backend.app.services.sast.sast_orchestrator import SASTOrchestrator

    # Strip whitespace from token
    token = request.github_token.strip() if request.github_token else None

    result = await SASTOrchestrator.analyze_repository(
        owner=request.owner,
        repo=request.repo,
        github_token=token,
        deployed_url=request.deployed_url,
        dast_findings=request.dast_findings or [],
        branch=request.branch
    )

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


@router.post("/analyze-local")
async def analyze_local_code(request: SASTLocalAnalyzeRequest):
    """
    Analyze inline source code (no GitHub API required).
    Useful for testing SAST rules without a real repository.
    
    Send a dict of filename → source code and receive SAST findings.
    """
    from backend.app.services.sast.sast_orchestrator import SASTOrchestrator

    result = await SASTOrchestrator.analyze_local_files(
        files_dict=request.files,
        commit_sha=request.commit_sha or "local-analysis",
        deployed_url=request.deployed_url or "http://localhost:3000",
        dast_findings=request.dast_findings or []
    )
    return result


@router.get("/rules")
async def list_sast_rules():
    """
    List all 17+ SAST detection rules with their metadata.
    """
    from backend.app.services.sast.ast_analyzer import SAST_RULES
    return {
        "total_rules": len(SAST_RULES),
        "rules": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "cwe_id": r.cwe_id,
                "owasp_ref": r.owasp_ref,
                "severity": r.severity,
                "category": r.category,
                "confidence": r.confidence,
                "file_types": list(r.file_types),
            }
            for r in SAST_RULES
        ]
    }
