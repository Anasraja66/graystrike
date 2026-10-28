"""
Base Security Agent Interface & Registry
Defines the contract that all 20 security micro-agents adhere to.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum


class AgentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentFinding(BaseModel):
    title: str
    category: str
    cwe_id: Optional[str] = None
    owasp_ref: Optional[str] = None
    severity: AgentSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    affected_asset: str
    evidence_summary: str
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    technical_explanation: str
    remediation_steps: str
    ai_fix_prompt: Optional[str] = None
    business_impact: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class AgentExecutionResult(BaseModel):
    agent_id: str
    success: bool
    findings: List[AgentFinding] = Field(default_factory=list)
    observations: List[str] = Field(default_factory=list)
    tokens_used: int = 0
    duration_seconds: float = 0.0
    error_message: Optional[str] = None


class BaseSecurityAgent(ABC):
    """Abstract base class for all 20 security micro-agents."""

    id: str
    name: str
    description: str
    category: str
    cwe_default: Optional[str] = None
    owasp_default: Optional[str] = None
    is_passive: bool = True
    timeout_seconds: int = 60

    @abstractmethod
    async def assess(
        self,
        target_url: str,
        crawl_data: Dict[str, Any],
        knowledge_context: Optional[str] = None
    ) -> AgentExecutionResult:
        """
        Perform assessment on target based on crawl metadata and knowledge retrieval.
        Safe, non-destructive checks only.
        """
        pass


class AgentRegistry:
    """Registry holding all active security agents."""
    _agents: Dict[str, BaseSecurityAgent] = {}

    @classmethod
    def register(cls, agent_cls):
        agent_instance = agent_cls()
        cls._agents[agent_instance.id] = agent_instance
        return agent_cls

    @classmethod
    def get(cls, agent_id: str) -> Optional[BaseSecurityAgent]:
        return cls._agents.get(agent_id)

    @classmethod
    def list_all(cls) -> List[BaseSecurityAgent]:
        return list(cls._agents.values())

    @classmethod
    def list_passive(cls) -> List[BaseSecurityAgent]:
        return [a for a in cls._agents.values() if a.is_passive]
