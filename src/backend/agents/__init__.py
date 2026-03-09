"""
Agent runtime package for dont_lie_to_me_azure.

Phase B.5: Core agent orchestration and routing.
- OrchestratorAgent: Routes requests to appropriate agents based on content
- ReceptionistAgent: Handles conversational interactions and context gathering

Phase D: Extended to full agent classes with tool-calling framework.
Phase E: Team agents (Classifier, Analyzer, Guidance, RecordKeeper).
"""

from .base_models import (
    AgentRequest,
    AgentResponse,
    AgentContext,
    OrchestrationTrace,
)
from .orchestrator import OrchestratorAgent
from .receptionist import ReceptionistAgent

__all__ = [
    "AgentRequest",
    "AgentResponse",
    "AgentContext",
    "OrchestrationTrace",
    "OrchestratorAgent",
    "ReceptionistAgent",
]
