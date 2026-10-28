"""
LangGraph Multi-Agent Orchestrator
Coordinates:
Authorization Gate -> Reconnaissance -> Agent Selection -> Execution -> Finding Validation
"""
import asyncio
from typing import Dict, Any
from langgraph.graph import StateGraph, END

from ai_engine.orchestrator.state import ScanState
from ai_engine.agents.crawler_agent import CrawlerAgent
from ai_engine.agents.base_agent import AgentRegistry
from backend.app.services.scope_service import ScopeEnforcer


# Node 1: Authorization Gate
async def authorization_gate(state: ScanState) -> Dict[str, Any]:
    """Verify domain ownership and scope rules before initiating any network packets."""
    if not state.get("is_domain_verified"):
        return {
            "status": "failed",
            "current_stage": "authorization_failed",
            "error_message": "Domain ownership must be verified via DNS TXT record before scanning."
        }

    enforcer = ScopeEnforcer(
        allowed_hosts=state.get("allowed_hosts", []),
        denied_paths=state.get("denied_paths", [])
    )
    is_valid, reason = enforcer.validate_url(state["target_url"])
    if not is_valid:
        return {
            "status": "failed",
            "current_stage": "scope_failed",
            "error_message": f"Scope violation on target URL: {reason}"
        }

    return {
        "is_scope_valid": True,
        "status": "authorized",
        "current_stage": "reconnaissance"
    }


# Node 2: Reconnaissance
async def reconnaissance(state: ScanState) -> Dict[str, Any]:
    """Run crawler agent to discover assets, forms, and headers."""
    if state.get("status") == "failed":
        return state

    enforcer = ScopeEnforcer(
        allowed_hosts=state.get("allowed_hosts", []),
        denied_paths=state.get("denied_paths", [])
    )
    crawler = CrawlerAgent(max_pages=20, max_depth=3)
    crawl_data = await crawler.crawl(state["target_url"], scope_enforcer=enforcer)

    return {
        "crawl_result": crawl_data.model_dump(),
        "current_stage": "agent_selection"
    }


# Node 3: Agent Selection
async def agent_selection(state: ScanState) -> Dict[str, Any]:
    """Select the appropriate micro-agents from registry."""
    if state.get("status") == "failed":
        return state

    # Import all micro-agents to register them
    import ai_engine.agents.core_agents  # noqa: F401
    import ai_engine.agents.extended_agents  # noqa: F401
    import ai_engine.agents.framework_agents  # noqa: F401
    import ai_engine.agents.easm_agents  # noqa: F401
    import ai_engine.agents.redteam_agents  # noqa: F401
    import ai_engine.agents.ai_app_agents  # noqa: F401

    passive_agents = AgentRegistry.list_passive()
    selected_agent_ids = [a.id for a in passive_agents]

    return {
        "selected_agents": selected_agent_ids,
        "current_stage": "agent_execution"
    }


# Node 4: Run Security Agents
async def run_security_agents(state: ScanState) -> Dict[str, Any]:
    """Execute all selected security agents against discovered assets."""
    if state.get("status") == "failed":
        return state

    crawl_data = state.get("crawl_result") or {}
    target_url = state["target_url"]
    selected_ids = state.get("selected_agents") or []

    all_findings = []
    agent_results = {}

    for agent_id in selected_ids:
        agent = AgentRegistry.get(agent_id)
        if not agent:
            continue

        try:
            res = await agent.assess(target_url, crawl_data)
            agent_results[agent_id] = {
                "success": res.success,
                "findings_count": len(res.findings),
                "observations": res.observations
            }
            for f in res.findings:
                all_findings.append(f.model_dump())
        except Exception as e:
            agent_results[agent_id] = {
                "success": False,
                "error": str(e)
            }

    # Phase: Playwright Browser Evidence Verification
    verified_findings = []
    try:
        from ai_engine.verification.browser_verifier import BrowserVerifier
        verifier = BrowserVerifier()
        for idx, f in enumerate(all_findings):
            # Capture browser proof for top candidates matching web assets
            asset = f.get("affected_asset", "")
            if idx < 5 and asset.startswith(("http://", "https://")):
                try:
                    evidence = await verifier.verify_finding(f)
                    if evidence.screenshot_path:
                        f["screenshot_url"] = evidence.screenshot_path
                    if evidence.verification_status:
                        f["verification_status"] = evidence.verification_status
                    if evidence.reproduction_curl and not f.get("reproduction_curl"):
                        f["reproduction_curl"] = evidence.reproduction_curl
                    if evidence.expected_behavior and not f.get("expected_secure_behavior"):
                        f["expected_secure_behavior"] = evidence.expected_behavior
                    if evidence.observed_behavior and not f.get("observed_insecure_behavior"):
                        f["observed_insecure_behavior"] = evidence.observed_behavior
                    if evidence.response_status_code and not f.get("response_status_code"):
                        f["response_status_code"] = evidence.response_status_code
                    if evidence.verification_timestamp and not f.get("observation_timestamp"):
                        f["observation_timestamp"] = evidence.verification_timestamp
                    if evidence.sensitive_indicators:
                        existing_sens = f.get("sensitive_data_detected") or []
                        f["sensitive_data_detected"] = list(set(existing_sens + evidence.sensitive_indicators))
                except Exception:
                    pass
            verified_findings.append(f)
    except Exception:
        verified_findings = all_findings

    return {
        "candidate_findings": all_findings,
        "verified_findings": verified_findings,
        "agent_results": agent_results,
        "current_stage": "classification"
    }


# Node 5: Risk Classification & Finalization
async def risk_classification(state: ScanState) -> Dict[str, Any]:
    """Calculate aggregate metrics and complete scan."""
    if state.get("status") == "failed":
        return state

    return {
        "status": "completed",
        "current_stage": "completed"
    }


def should_continue(state: ScanState) -> str:
    """Conditional routing: Stop if authorization or scope failed."""
    if state.get("status") == "failed":
        return END
    return "reconnaissance"


def build_scan_graph():
    """Build and compile the LangGraph workflow."""
    workflow = StateGraph(ScanState)

    workflow.add_node("authorization_gate", authorization_gate)
    workflow.add_node("reconnaissance", reconnaissance)
    workflow.add_node("agent_selection", agent_selection)
    workflow.add_node("run_security_agents", run_security_agents)
    workflow.add_node("risk_classification", risk_classification)

    workflow.set_entry_point("authorization_gate")

    workflow.add_conditional_edges(
        "authorization_gate",
        should_continue,
        {
            "reconnaissance": "reconnaissance",
            END: END
        }
    )

    workflow.add_edge("reconnaissance", "agent_selection")
    workflow.add_edge("agent_selection", "run_security_agents")
    workflow.add_edge("run_security_agents", "risk_classification")
    workflow.add_edge("risk_classification", END)

    return workflow.compile()
