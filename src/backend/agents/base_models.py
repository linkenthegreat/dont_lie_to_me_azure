"""
Base data models and contracts for agent runtime.

Defines typed request/response schemas for agent orchestration:
- AgentRequest: Input to any agent (text, images, session context)
- AgentResponse: Output from any agent (message, data, trace metadata)
- AgentContext: Session-scoped state (session_id, location, role, conversation history)
- OrchestrationTrace: Routing metadata for observability and debugging
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentContext(BaseModel):
    """
    Session-scoped context passed to agents.
    
    Agents are stateless executors; state is managed by orchestrator
    and persisted via RecordKeeperAgent.
    """

    session_id: str = Field(
        ..., description="Unique session identifier for conversation tracking"
    )
    location: Optional[str] = Field(
        None, description="User location for location-aware guidance (e.g., 'AU', 'US')"
    )
    role: Optional[str] = Field(
        None, description="User role or context for personalized responses"
    )
    conversation_history: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Previous messages in conversation for context-aware routing",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional session metadata (e.g., user preferences, flags)",
    )


class AgentRequest(BaseModel):
    """
    Standard input to any agent in the runtime.
    
    Supports multimodal input (text, images) and session context.
    """

    text: str = Field(..., description="User message text")
    images: List[str] = Field(
        default_factory=list,
        description="Base64-encoded images or image URLs for multimodal analysis",
    )
    context: AgentContext = Field(
        ..., description="Session context for state management and personalization"
    )


class OrchestrationTrace(BaseModel):
    """
    Metadata about routing decisions and performance for observability.
    
    Used for debugging, monitoring, and optimization of agent orchestration.
    """

    route_path: List[str] = Field(
        default_factory=list,
        description="Sequence of agents invoked (e.g., ['orchestrator', 'receptionist', 'classifier'])",
    )
    routing_decision: str = Field(
        ..., description="Reason for routing decision (e.g., 'greeting pattern detected')"
    )
    duration_ms: float = Field(
        ..., description="Total execution time in milliseconds"
    )
    model_used: Optional[str] = Field(
        None, description="AI model used for response generation (e.g., 'gpt-4o-mini')"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp of request processing"
    )
    fallback_triggered: bool = Field(
        False, description="Whether fallback logic was used due to errors"
    )


class AgentResponse(BaseModel):
    """
    Standard output from any agent in the runtime.
    
    Combines conversational message with structured data and trace metadata.
    """

    message: str = Field(
        ..., description="Conversational response to user (human-friendly, empathetic tone)"
    )
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured data (e.g., classification, red flags, guidance) for UI rendering",
    )
    agent_used: str = Field(
        ..., description="Name of the agent that generated this response"
    )
    trace: OrchestrationTrace = Field(
        ..., description="Routing and performance metadata for observability"
    )
    next_action: Optional[str] = Field(
        None,
        description="Suggested next action for orchestrator (e.g., 'trigger_analysis', 'request_clarification')",
    )
