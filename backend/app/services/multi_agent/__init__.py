"""
Multi-Agent Swarm for GrayStrike
Inspired by SecureFlow, LLM-SmartAudit, and HAFixAgent.
"""
from backend.app.services.multi_agent.history_miner import GitHistoryMiner, GitHistoryContext
from backend.app.services.multi_agent.gray_probe import GrayProbeAgent, ProbeResult, ProbeCandidate
from backend.app.services.multi_agent.gray_analyze import GrayAnalyzeAgent, FormalSecurityFinding
from backend.app.services.multi_agent.gray_redteam import GrayRedTeamAgent, RedTeamVerificationResult
from backend.app.services.multi_agent.gray_synthesize import GraySynthesizeAgent, SynthesisResult
from backend.app.services.multi_agent.swarm_orchestrator import GrayStrikeSwarmOrchestrator, SwarmAuditReport

__all__ = [
    "GitHistoryMiner",
    "GitHistoryContext",
    "GrayProbeAgent",
    "ProbeResult",
    "ProbeCandidate",
    "GrayAnalyzeAgent",
    "FormalSecurityFinding",
    "GrayRedTeamAgent",
    "RedTeamVerificationResult",
    "GraySynthesizeAgent",
    "SynthesisResult",
    "GrayStrikeSwarmOrchestrator",
    "SwarmAuditReport",
]
