"""
GitHub App & Webhook Integration API.
Receives Pull Request webhooks, triggers the Live Swarm Debate & Z3 SMT verification,
and posts automated PR comments and status check runs.
"""
from fastapi import APIRouter, Header, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import json

from app.services.github_remediation_bot import github_remediation_bot

router = APIRouter()


class SimulatePRCheckRequest(BaseModel):
    pr_number: Optional[int] = Field(42, description="Pull Request number")
    repository: Optional[str] = Field("enterprise-corp/secure-core", description="GitHub Repository full name")
    commit_sha: Optional[str] = Field("e8f192b6a7c34d1e", description="Head commit SHA")
    file_name: Optional[str] = Field("src/api/auth.js", description="File path under review")
    code_snippet: str = Field(
        ...,
        description="Source code containing vulnerability to analyze and fix",
        example="const query = 'SELECT * FROM users WHERE id = ' + req.query.id;"
    )


@router.post("/webhook")
async def github_webhook_receiver(
    request: Request,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256")
):
    """
    Receives live webhooks from GitHub.
    Validates HMAC-SHA256 signature and triggers automated remediation.
    """
    body_bytes = await request.body()

    # Verify signature if secret is active and signature is present
    if x_hub_signature_256 and not github_remediation_bot.verify_webhook_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook HMAC-SHA256 signature.")

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    event_type = x_github_event or "pull_request"
    result = github_remediation_bot.process_webhook_event(event_type, payload)

    return {
        "status": "ACCEPTED",
        "event": event_type,
        "result": result
    }


@router.post("/simulate-pr-check")
async def simulate_pr_security_check(request: SimulatePRCheckRequest):
    """
    Simulates a Pull Request check for testing and interactive dashboard demonstration.
    Returns complete GitHub Review Comment, Z3 SMT Proof, Unified Diff, and Check Run.
    """
    result = github_remediation_bot.simulate_pr_security_check(
        pr_number=request.pr_number or 42,
        repo=request.repository or "enterprise-corp/secure-core",
        commit_sha=request.commit_sha or "e8f192b6a7c34d1e",
        file_name=request.file_name or "src/api/auth.js",
        code_content=request.code_snippet
    )
    return result


@router.get("/status")
async def get_github_integration_status():
    """Returns configuration status of the GitHub CI/CD Remediation Bot."""
    return {
        "status": "OPERATIONAL",
        "bot_name": github_remediation_bot.bot_name,
        "supported_events": ["pull_request.opened", "pull_request.synchronize", "push"],
        "governance_engine": "Z3 SMT + Governed Robust Swarm Consensus (GRC v2.6)",
        "compliance_targets": ["NIS 2 Directive Art. 21", "EU AI Act Art. 14", "ISO 42001"]
    }
