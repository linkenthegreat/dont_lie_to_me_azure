"""
Integration tests for /api/chat endpoint.

Tests Phase B.5 unified chat interface with agent orchestration.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def mock_ai_client():
    """Mock AI client to avoid real API calls."""
    with patch("agents.orchestrator.AzureAIClient") as mock_client_class:
        mock_instance = MagicMock()
        mock_instance.chat.return_value = "Hello! I'm here to help you check for scams."
        mock_client_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_url_checker():
    """Mock URL checker to avoid real API calls."""
    with patch("agents.orchestrator.URLChecker") as mock_checker_class:
        mock_instance = MagicMock()
        mock_result = MagicMock()
        mock_result.verdict = "NOT_FLAGGED"
        mock_result.confidence = "HIGH"
        mock_result.threat_category = None
        mock_result.summary = "URL appears clean"
        mock_result.risk_hints = []
        mock_result.sources_checked = ["virustotal", "gsb"]
        mock_instance.check_url.return_value = mock_result
        mock_checker_class.return_value = mock_instance
        yield mock_instance


class TestChatEndpoint:
    """Integration tests for /api/chat endpoint."""

    def test_chat_greeting_returns_conversational_response(self, mock_ai_client):
        """Test that greeting message gets conversational response."""
        # Import here to apply mocks
        import azure.functions as func

        # Create request
        req_body = {
            "message": "hello",
            "session_id": "test_session_001",
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        # Execute
        # Import chat function directly (app.get_functions()[0] was returning health, not chat)
        from function_app import chat
        response = chat(req)

        # Verify
        assert response.status_code == 200
        data = json.loads(response.get_body())

        assert "message" in data
        assert "agent_used" in data
        assert "trace" in data
        assert data["agent_used"] == "receptionist"
        assert "receptionist" in data["trace"]["route_path"]

    def test_chat_url_triggers_url_analysis(self, mock_url_checker, mock_ai_client):
        """Test that URL message triggers URL analysis."""
        import azure.functions as func

        req_body = {
            "message": "Check this link: https://suspicious-site.com",
            "session_id": "test_session_002",
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        from function_app import chat
        response = chat(req)

        assert response.status_code == 200
        data = json.loads(response.get_body())

        assert data["agent_used"] == "url_analyzer"
        assert "url_analyzer" in data["trace"]["route_path"]
        mock_url_checker.check_url.assert_called_once()

    def test_chat_requires_message_field(self):
        """Test that endpoint validates required fields."""
        import azure.functions as func

        req_body = {
            # Missing "message" field
            "session_id": "test_session_003",
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        from function_app import chat
        response = chat(req)

        assert response.status_code == 400
        data = json.loads(response.get_body())
        assert "error" in data

    def test_chat_generates_session_id_if_missing(self, mock_ai_client):
        """Test that endpoint generates session ID if not provided."""
        import azure.functions as func

        req_body = {
            "message": "hello",
            # No session_id provided
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        from function_app import chat
        response = chat(req)

        assert response.status_code == 200
        data = json.loads(response.get_body())

        assert "session_id" in data
        assert data["session_id"].startswith("session_") or len(data["session_id"]) > 0

    def test_chat_accepts_multimodal_input(self, mock_ai_client):
        """Test that endpoint accepts images along with text."""
        import azure.functions as func

        req_body = {
            "message": "What do you think of this?",
            "images": ["data:image/png;base64,iVBORw0KGgoAAAANSUhEU..."],
            "session_id": "test_session_004",
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        from function_app import chat
        response = chat(req)

        assert response.status_code == 200
        data = json.loads(response.get_body())
        assert "message" in data

    def test_chat_includes_trace_metadata(self, mock_ai_client):
        """Test that response includes routing trace for observability."""
        import azure.functions as func

        req_body = {
            "message": "hello",
            "session_id": "test_session_005",
        }

        req = func.HttpRequest(
            method="POST",
            url="/api/chat",
            body=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        from function_app import chat
        response = chat(req)

        assert response.status_code == 200
        data = json.loads(response.get_body())

        assert "trace" in data
        trace = data["trace"]
        assert "route_path" in trace
        assert "routing_decision" in trace
        assert "duration_ms" in trace
        assert isinstance(trace["route_path"], list)
        assert len(trace["route_path"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
