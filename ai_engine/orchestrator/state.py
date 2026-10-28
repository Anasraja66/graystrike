"""
LangGraph Typed State for APT Agents
"""
from typing import TypedDict, List, Dict, Any, Optional
from ai_engine.agents.base_agent import AgentFinding


class ScanState(TypedDict):
    scan_id: str
    target_url: str
    allowed_hosts: List[str]
    denied_paths: List[str]
    is_domain_verified: bool
    is_scope_valid: bool
    status: str
    current_stage: str

    # Recon data
    crawl_result: Optional[Dict[str, Any]]

    # Agents execution
    selected_agents: List[str]
    agent_results: Dict[str, Any]

    # Findings
    candidate_findings: List[Dict[str, Any]]
    verified_findings: List[Dict[str, Any]]

    # Execution telemetry
    total_tokens: int
    duration_seconds: float
    error_message: Optional[str]
