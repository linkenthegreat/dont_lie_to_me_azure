"""Unit tests for MCP tool handler functions."""

import json
import unittest
from unittest.mock import MagicMock, patch


class TestStoreAnalysis(unittest.TestCase):

    @patch("services.cosmos_service.get_cosmos_service")
    def test_store_analysis_returns_doc_id(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_store_analysis

        mock_service = MagicMock()
        mock_service.upsert_analysis.return_value = {"id": "doc-123", "sessionId": "s1"}
        mock_get_service.return_value = mock_service

        result = _handle_store_analysis({
            "session_id": "s1",
            "endpoint": "classify",
            "input_text": "You won a prize!",
            "result": '{"classification": "SCAM"}',
        })

        self.assertIn("doc-123", result["content"])
        mock_service.upsert_analysis.assert_called_once()

    @patch("services.cosmos_service.get_cosmos_service")
    def test_store_analysis_accepts_dict_result(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_store_analysis

        mock_service = MagicMock()
        mock_service.upsert_analysis.return_value = {"id": "doc-456", "sessionId": "s2"}
        mock_get_service.return_value = mock_service

        result = _handle_store_analysis({
            "session_id": "s2",
            "endpoint": "analyze",
            "input_text": "Pay now",
            "result": {"classification": "LIKELY_SCAM"},
        })

        self.assertIn("doc-456", result["content"])


class TestQueryHistory(unittest.TestCase):

    @patch("services.cosmos_service.get_cosmos_service")
    def test_query_history_returns_results(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_query_history

        mock_service = MagicMock()
        mock_service.query_history.return_value = [
            {"id": "1", "sessionId": "s1", "endpoint": "classify"},
        ]
        mock_get_service.return_value = mock_service

        result = _handle_query_history({"session_id": "s1"})

        parsed = json.loads(result["content"])
        self.assertEqual(len(parsed), 1)
        mock_service.query_history.assert_called_once_with(session_id="s1", limit=10)

    @patch("services.cosmos_service.get_cosmos_service")
    def test_query_history_respects_limit(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_query_history

        mock_service = MagicMock()
        mock_service.query_history.return_value = []
        mock_get_service.return_value = mock_service

        _handle_query_history({"session_id": "s1", "limit": "5"})

        mock_service.query_history.assert_called_once_with(session_id="s1", limit=5)


class TestCheckKnownScam(unittest.TestCase):

    @patch("services.cosmos_service.get_cosmos_service")
    def test_check_known_scam_returns_matches(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_check_known_scam

        mock_service = MagicMock()
        mock_service.query_known_scams.return_value = [
            {"inputText": "You won a prize!", "similarity": 0.95},
        ]
        mock_get_service.return_value = mock_service

        result = _handle_check_known_scam({"text": "You won a prize"})

        parsed = json.loads(result["content"])
        self.assertEqual(len(parsed), 1)
        mock_service.query_known_scams.assert_called_once_with(
            text="You won a prize", threshold=0.8
        )

    @patch("services.cosmos_service.get_cosmos_service")
    def test_check_known_scam_custom_threshold(self, mock_get_service):
        from mcp_tools.tool_definitions import _handle_check_known_scam

        mock_service = MagicMock()
        mock_service.query_known_scams.return_value = []
        mock_get_service.return_value = mock_service

        _handle_check_known_scam({"text": "abc", "threshold": "0.5"})

        mock_service.query_known_scams.assert_called_once_with(text="abc", threshold=0.5)


if __name__ == "__main__":
    unittest.main()
