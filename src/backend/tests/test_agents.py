"""Unit tests for victim support agents."""

import json

from agents.base_models import AgentContext, AgentRequest
from agents.report_helper import ReportHelperAgent
from agents.resource_assistant import ResourceAssistantAgent


class _MockAIClient:
    def __init__(self, response_payload):
        self._response_payload = response_payload

    def chat(self, system_prompt, user_message, max_tokens=1024, temperature=0.2):
        return json.dumps(self._response_payload)


def _make_request(text="Need help reporting", location="AU"):
    return AgentRequest(
        text=text,
        images=[],
        context=AgentContext(
            session_id="test-session",
            location=location,
            metadata={
                "classification": "SCAM",
                "confidence": 0.93,
                "losses_reported": True,
            },
            conversation_history=[],
        ),
    )


class TestReportHelperAgent:
    def test_execute_returns_report_payload(self):
        agent = ReportHelperAgent(
            ai_client=_MockAIClient(
                {
                    "report_summary": "Summary",
                    "formal_email_draft": "Draft",
                    "script_notes": "Call notes",
                }
            )
        )

        response = agent.execute(_make_request())

        assert response.agent_used == "report_helper"
        assert response.data["report_summary"] == "Summary"
        assert response.data["formal_email_draft"] == "Draft"
        assert response.data["script_notes"] == "Call notes"

    def test_execute_handles_missing_fields(self):
        agent = ReportHelperAgent(ai_client=_MockAIClient({}))

        response = agent.execute(_make_request())

        assert response.agent_used == "report_helper"
        assert response.data["report_summary"] == ""
        assert response.data["formal_email_draft"] == ""
        assert response.data["script_notes"] == ""


class TestResourceAssistantAgent:
    def test_execute_returns_resource_payload(self):
        agent = ResourceAssistantAgent(
            ai_client=_MockAIClient(
                {
                    "reporting_agencies": [
                        {
                            "name": "Scamwatch",
                            "url": "https://www.scamwatch.gov.au",
                            "phone": "1300 302 502",
                            "why_contact": "National reporting",
                        }
                    ],
                    "legal_guidance": "Preserve evidence.",
                    "draft_email": "Hello team...",
                }
            )
        )

        response = agent.execute(_make_request())

        assert response.agent_used == "resource_assistant"
        assert len(response.data["reporting_agencies"]) == 1
        assert response.data["legal_guidance"] == "Preserve evidence."
        assert response.data["draft_email"] == "Hello team..."

    def test_execute_handles_missing_fields(self):
        agent = ResourceAssistantAgent(ai_client=_MockAIClient({}))

        response = agent.execute(_make_request())

        assert response.agent_used == "resource_assistant"
        assert response.data["reporting_agencies"] == []
        assert response.data["legal_guidance"] == ""
        assert response.data["draft_email"] == ""
