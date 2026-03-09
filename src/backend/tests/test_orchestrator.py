"""
Unit tests for OrchestratorAgent routing logic.

Tests Phase B.5 deterministic routing rules:
- Greeting patterns → ReceptionistAgent
- URL patterns → URLAnalyzerAgent  
- Suspicious keywords → ClassifierAgent chain
- Default/ambiguous → ReceptionistAgent
"""

import pytest
from unittest.mock import Mock
from agents.base_models import AgentRequest, AgentContext, AgentResponse
import agents.orchestrator as orchestrator_module
from agents.orchestrator import OrchestratorAgent


@pytest.fixture
def mock_ai_client():
    """Mock AzureAIClient for testing."""
    mock = Mock()
    mock.call.return_value = "Mocked AI response"
    return mock


@pytest.fixture
def mock_url_checker():
    """Mock URLChecker for testing."""
    mock = Mock()
    mock.check_url.return_value = {"verdict": "NOT_FLAGGED"}
    return mock


@pytest.fixture
def orchestrator(mock_ai_client, mock_url_checker):
    """Create orchestrator with mocked dependencies."""
    return OrchestratorAgent(
        ai_client=mock_ai_client,
        url_checker=mock_url_checker
    )


@pytest.fixture
def base_context():
    """Create base context for tests."""
    return AgentContext(
        session_id="test_session_123",
        location="US",
        conversation_history=[],
    )


class TestOrchestratorRouting:
    """Test orchestrator routing decisions."""

    def test_greeting_routes_to_receptionist(self, orchestrator, base_context):
        """Test that greeting patterns route to receptionist."""
        greetings = [
            "hello",
            "Hi there!",
            "Hey, can you help?",
            "Good morning",
            "help me",
        ]

        for greeting in greetings:
            request = AgentRequest(
                text=greeting,
                images=[],
                context=base_context,
            )

            reasoning, target = orchestrator._route(request)

            assert target == "receptionist", f"'{greeting}' should route to receptionist"
            assert "greeting" in reasoning.lower() or "help" in reasoning.lower()

    def test_url_routes_to_url_analyzer(self, orchestrator, base_context):
        """Test that URL patterns route to URL analyzer."""
        url_messages = [
            "Check this link: https://suspicious-site.com",
            "What about www.example.org?",
            "I got this: http://bit.ly/abc123",
            "Is phishing-test.com safe?",
        ]

        for message in url_messages:
            request = AgentRequest(
                text=message,
                images=[],
                context=base_context,
            )

            reasoning, target = orchestrator._route(request)

            assert target == "url_analyzer", f"'{message}' should route to url_analyzer"
            assert "url" in reasoning.lower()

    def test_suspicious_keywords_route_to_classifier(self, orchestrator, base_context):
        """Test that suspicious keywords route to classifier chain."""
        suspicious_messages = [
            "I think this is a scam",
            "Suspicious email about urgently verifying my account",
            "Someone impersonating the IRS called",
            "Click here to claim your prize!",
            "Investment opportunity in cryptocurrency",
        ]

        for message in suspicious_messages:
            request = AgentRequest(
                text=message,
                images=[],
                context=base_context,
            )

            reasoning, target = orchestrator._route(request)

            assert target == "classifier", f"'{message}' should route to classifier"
            assert "suspicious" in reasoning.lower() or "keyword" in reasoning.lower()

    def test_ambiguous_routes_to_receptionist(self, orchestrator, base_context):
        """Test that ambiguous messages route to receptionist for clarification."""
        ambiguous_messages = [
            "I'm worried",
            "Not sure what to do",
            "Can you explain?",
            "Tell me more",
        ]

        for message in ambiguous_messages:
            request = AgentRequest(
                text=message,
                images=[],
                context=base_context,
            )

            reasoning, target = orchestrator._route(request)

            assert target == "receptionist", f"'{message}' should route to receptionist"
            assert "clarification" in reasoning.lower() or "no specific pattern" in reasoning.lower()

    def test_url_takes_precedence_over_suspicious_keywords(self, orchestrator, base_context):
        """Test that URL pattern detection takes precedence."""
        request = AgentRequest(
            text="This scam site https://phishing.com tried to steal my info",
            images=[],
            context=base_context,
        )

        reasoning, target = orchestrator._route(request)

        # URL pattern should be detected first
        assert target == "url_analyzer"

    def test_execute_returns_valid_response(self, orchestrator, base_context):
        """Test that execute returns properly structured AgentResponse."""
        request = AgentRequest(
            text="hello",
            images=[],
            context=base_context,
        )

        response = orchestrator.execute(request)

        # Validate response structure
        assert isinstance(response, AgentResponse)
        assert response.message is not None
        assert isinstance(response.data, dict)
        assert response.agent_used is not None
        assert response.trace is not None
        assert len(response.trace.route_path) > 0

    def test_execute_handles_empty_message_gracefully(self, orchestrator, base_context):
        """Test handling of edge cases like empty messages."""
        request = AgentRequest(
            text="",
            images=[],
            context=base_context,
        )

        response = orchestrator.execute(request)

        # Should still return a valid response (routes to receptionist)
        assert isinstance(response, AgentResponse)
        assert response.message is not None

    def test_routing_patterns_can_be_overridden_from_config(self, mock_ai_client, mock_url_checker, base_context, monkeypatch):
        """Test routing pattern overrides from prompts config with deterministic behavior."""

        def mock_get_prompt_config(key):
            if key == "routing_patterns":
                return {
                    "greeting_patterns": [r"\b(aloha)\b"],
                    "url_patterns": [r"https?://"],
                    "suspicious_keywords": [r"\b(ponzi)\b"],
                }
            return {}

        monkeypatch.setattr(orchestrator_module, "get_prompt_config", mock_get_prompt_config)
        orchestrator = OrchestratorAgent(ai_client=mock_ai_client, url_checker=mock_url_checker)

        request = AgentRequest(
            text="This sounds like a Ponzi scheme",
            images=[],
            context=base_context,
        )
        reasoning, target = orchestrator._route(request)

        assert target == "classifier"
        assert "suspicious" in reasoning.lower() or "keyword" in reasoning.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
