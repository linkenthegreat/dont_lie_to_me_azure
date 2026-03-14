"""ReportHelperAgent - incident report and formal reporting drafts."""

import json
import logging
from typing import Optional

from .base_models import AgentRequest, AgentResponse, OrchestrationTrace
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

_FALLBACK_REPORT_HELPER_PROMPT = """You are ReportHelperAgent for an anti-scam support service.
Create a concise incident summary and a formal reporting draft.
Return ONLY valid JSON with keys: report_summary, formal_email_draft, script_notes.
No markdown fences."""


class ReportHelperAgent:
    """Agent for report compilation and formal communication drafts."""

    def __init__(self, ai_client: Optional[AzureAIClient] = None):
        self.ai_client = ai_client or AzureAIClient()

    def execute(self, request: AgentRequest) -> AgentResponse:
        """Compile investigation findings into report-friendly output."""
        try:
            config = get_prompt_config("report_helper")
            system_prompt = config.get("system_prompt", _FALLBACK_REPORT_HELPER_PROMPT)
            model = config.get("model", "gpt-4o")
            temperature = config.get("temperature", 0.3)
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
                message="I prepared a user-friendly report summary and a formal draft you can submit.",
                data={
                    "report_summary": data.get("report_summary", ""),
                    "formal_email_draft": data.get("formal_email_draft", ""),
                    "script_notes": data.get("script_notes", ""),
                },
                agent_used="report_helper",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "victim_support_team", "report_helper"],
                    routing_decision="Generated report summary and formal draft",
                    duration_ms=0,
                    model_used=model,
                ),
            )
        except Exception as exc:
            logger.error("ReportHelperAgent error: %s", exc, exc_info=True)
            return AgentResponse(
                message="I can still help draft your report. Please share key details like date/time, sender, and what happened.",
                data={
                    "report_summary": "",
                    "formal_email_draft": "",
                    "script_notes": "",
                    "error": str(exc),
                },
                agent_used="report_helper",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "victim_support_team", "report_helper"],
                    routing_decision=f"Fallback response due to error: {exc}",
                    duration_ms=0,
                    fallback_triggered=True,
                ),
            )
