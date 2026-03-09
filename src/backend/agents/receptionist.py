"""
ReceptionistAgent - Conversational empathy and context gathering.

Phase B.5: Handles greetings, clarification requests, and empathetic responses.
Phase E: Extended with personality tuning and multi-language support.

Design principles:
- Professional yet empathetic tone
- Guides users to provide necessary context
- Helps users understand what the system can do
- Stateless executor using AgentContext for session state
"""

import logging
from typing import Optional

from .base_models import AgentRequest, AgentResponse, OrchestrationTrace
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

# Fallback prompt for operational resilience
_FALLBACK_RECEPTIONIST_PROMPT = """You are a helpful and empathetic assistant for an anti-scam service.
Your role is to:
1. Greet users warmly and professionally
2. Help users understand how to use the service
3. Gather context when users have ambiguous requests
4. Provide reassurance to concerned users
5. Guide users to share messages, URLs, or other content for analysis

Keep responses conversational, clear, and supportive. Use a professional yet friendly tone.
If a user seems distressed about a potential scam, acknowledge their concern and reassure them they're in the right place."""


class ReceptionistAgent:
    """
    Conversational agent for greetings, clarifications, and empathetic responses.
    
    Phase B.5: Basic conversational handling with empathy.
    Phase E: Extended with personality tuning and proactive context gathering.
    """

    def __init__(self, ai_client: Optional[AzureAIClient] = None):
        """
        Initialize receptionist agent.
        
        Args:
            ai_client: AI client for model calls. If None, creates default instance.
        """
        self.ai_client = ai_client or AzureAIClient()

    def execute(self, request: AgentRequest) -> AgentResponse:
        """
        Execute receptionist response: provide empathetic, helpful conversational reply.
        
        Args:
            request: Incoming agent request with text, images, and context.
            
        Returns:
            Agent response with conversational message and minimal structured data.
        """
        try:
            # Load receptionist prompt configuration
            receptionist_config = get_prompt_config("receptionist")
            system_prompt = receptionist_config.get("system_prompt", _FALLBACK_RECEPTIONIST_PROMPT)
            model = receptionist_config.get("model", "gpt-4o-mini")
            temperature = receptionist_config.get("temperature", 0.7)
            max_tokens = receptionist_config.get("max_tokens", 500)

            # Build context-aware user message
            user_message = self._build_context_message(request)

            # Get conversational response from AI
            response_text = self.ai_client.chat(
                system_prompt=system_prompt,
                user_message=user_message,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            return AgentResponse(
                message=response_text,
                data={
                    "intent": "greeting_or_clarification",
                    "session_id": request.context.session_id,
                },
                agent_used="receptionist",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "receptionist"],
                    routing_decision="Conversational handling via receptionist",
                    duration_ms=0,
                    model_used=model,
                ),
            )

        except Exception as e:
            logger.error(f"Receptionist agent error: {e}", exc_info=True)

            # Fallback to static response
            return AgentResponse(
                message=(
                    "Hello! I'm here to help you check messages, URLs, and other content for potential scams. "
                    "You can:\n"
                    "- Share a suspicious message or email\n"
                    "- Send me a URL to check\n"
                    "- Ask for help understanding scam tactics\n\n"
                    "What would you like to check today?"
                ),
                data={"error": str(e)},
                agent_used="receptionist",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "receptionist"],
                    routing_decision=f"Fallback response due to error: {str(e)}",
                    duration_ms=0,
                    fallback_triggered=True,
                ),
            )

    def _build_context_message(self, request: AgentRequest) -> str:
        """
        Build context-aware message for AI including conversation history.
        
        Args:
            request: Agent request with context.
            
        Returns:
            Formatted message with context for AI model.
        """
        message_parts = []

        # Add conversation history if available
        if request.context.conversation_history:
            message_parts.append("Previous conversation:")
            for msg in request.context.conversation_history[-3:]:  # Last 3 messages
                role = msg.get("role", "user")
                content = msg.get("content", "")
                message_parts.append(f"{role.capitalize()}: {content}")
            message_parts.append("\n---\n")

        # Add current message
        message_parts.append(f"Current message: {request.text}")

        # Add location context if available
        if request.context.location:
            message_parts.append(f"\nUser location: {request.context.location}")

        return "\n".join(message_parts)
