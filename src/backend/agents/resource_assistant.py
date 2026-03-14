"""ResourceAssistantAgent - location-aware reporting contacts and guidance."""

import json
import logging
from typing import Optional

from .base_models import AgentRequest, AgentResponse, OrchestrationTrace
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

_FALLBACK_RESOURCE_ASSISTANT_PROMPT = """You are ResourceAssistantAgent for an anti-scam support service.
Provide location-specific reporting contacts and practical next steps.
Return ONLY valid JSON with keys: reporting_agencies (list), legal_guidance (string), draft_email (string).
No markdown fences."""


class ResourceAssistantAgent:
    """Agent for location-specific reporting and support resources."""

    def __init__(self, ai_client: Optional[AzureAIClient] = None):
        self.ai_client = ai_client or AzureAIClient()

    def execute(self, request: AgentRequest) -> AgentResponse:
        """Generate reporting contacts and guidance from request context."""
        try:
            config = get_prompt_config("resource_assistant")
            system_prompt = config.get("system_prompt", _FALLBACK_RESOURCE_ASSISTANT_PROMPT)
            model = config.get("model", "gpt-4o")
            temperature = config.get("temperature", 0.4)
            max_tokens = config.get("max_tokens", 1400)

            context_payload = {
                "text": request.text,
                "location": request.context.location,
                "metadata": request.context.metadata,
            }
            raw = self.ai_client.chat(
                system_prompt=system_prompt,
                user_message=json.dumps(context_payload),
                max_tokens=max_tokens,
                temperature=temperature,
            )
            data = json.loads(raw)

            return AgentResponse(
                message="I found reporting options and next steps tailored to your situation.",
                data={
                    "reporting_agencies": data.get("reporting_agencies", []),
                    "legal_guidance": data.get("legal_guidance", ""),
                    "draft_email": data.get("draft_email", ""),
                },
                agent_used="resource_assistant",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "victim_support_team", "resource_assistant"],
                    routing_decision="Generated location-aware support resources",
                    duration_ms=0,
                    model_used=model,
                ),
            )
        except Exception as exc:
            logger.error("ResourceAssistantAgent error: %s", exc, exc_info=True)
            return AgentResponse(
                message="I can still help with reporting. Please share your country so I can provide the best contacts.",
                data={
                    "reporting_agencies": [],
                    "legal_guidance": "Please preserve evidence (messages, screenshots, transaction details).",
                    "draft_email": "",
                    "error": str(exc),
                },
                agent_used="resource_assistant",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "victim_support_team", "resource_assistant"],
                    routing_decision=f"Fallback response due to error: {exc}",
                    duration_ms=0,
                    fallback_triggered=True,
                ),
            )
