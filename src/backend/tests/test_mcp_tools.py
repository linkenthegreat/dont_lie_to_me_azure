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

class TestCheckUrlThreat(unittest.TestCase):
    """Tests for _handle_check_url_threat."""

    def _make_mock_result(self, verdict="NOT_FLAGGED", confidence="HIGH",
                          threat_category=None, summary="Clean", cached=False):
        result = MagicMock()
        result.verdict = verdict
        result.confidence = confidence
        result.threat_category = threat_category
        result.summary = summary
        result.risk_hints = []
        result.sources_checked = ["google_safe_browsing", "urlhaus"]
        result.cached = cached
        return result

    @patch("shared.url_checker.get_url_checker")
    def test_clean_url_returns_verdict(self, mock_factory):
        from mcp_tools.tool_definitions import _handle_check_url_threat

        mock_checker = MagicMock()
        mock_checker.check_url.return_value = self._make_mock_result()
        mock_factory.return_value = mock_checker

        result = _handle_check_url_threat({"url": "https://example.com"})
        payload = json.loads(result["content"])

        self.assertEqual(payload["verdict"], "NOT_FLAGGED")
        self.assertEqual(payload["confidence"], "HIGH")
        mock_checker.check_url.assert_called_once_with("https://example.com")

    @patch("shared.url_checker.get_url_checker")
    def test_flagged_url_returns_threat_info(self, mock_factory):
        from mcp_tools.tool_definitions import _handle_check_url_threat

        mock_checker = MagicMock()
        mock_checker.check_url.return_value = self._make_mock_result(
            verdict="FLAGGED", confidence="HIGH", threat_category="MALWARE",
            summary="Known malware distribution site"
        )
        mock_factory.return_value = mock_checker

        result = _handle_check_url_threat({"url": "https://malicious.example.com"})
        payload = json.loads(result["content"])

        self.assertEqual(payload["verdict"], "FLAGGED")
        self.assertEqual(payload["threat_category"], "MALWARE")

    def test_missing_url_returns_error(self):
        from mcp_tools.tool_definitions import _handle_check_url_threat

        result = _handle_check_url_threat({})
        payload = json.loads(result["content"])
        self.assertIn("error", payload)

    @patch("shared.url_checker.get_url_checker")
    def test_service_unavailable_returns_error(self, mock_factory):
        from mcp_tools.tool_definitions import _handle_check_url_threat

        mock_factory.side_effect = ValueError("API key not configured")

        result = _handle_check_url_threat({"url": "https://example.com"})
        payload = json.loads(result["content"])
        self.assertIn("error", payload)


class TestAnalyzeImageAuthenticity(unittest.TestCase):
    """Tests for _handle_analyze_image_authenticity."""

    _SMALL_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

    @patch("services.image_analysis_service.analyze_image")
    def test_authentic_image_returns_verdict(self, mock_analyze):
        from mcp_tools.tool_definitions import _handle_analyze_image_authenticity

        mock_analyze.return_value = {
            "verdict": "AUTHENTIC",
            "authenticity_score": 0.95,
            "manipulation_indicators": [],
            "summary": "No manipulation detected",
        }

        result = _handle_analyze_image_authenticity({"image_base64": self._SMALL_PNG_B64})
        payload = json.loads(result["content"])

        self.assertEqual(payload["verdict"], "AUTHENTIC")
        self.assertEqual(payload["authenticity_score"], 0.95)
        mock_analyze.assert_called_once_with(
            image_base64=self._SMALL_PNG_B64, image_media_type="image/png"
        )

    @patch("services.image_analysis_service.analyze_image")
    def test_data_uri_prefix_is_stripped(self, mock_analyze):
        from mcp_tools.tool_definitions import _handle_analyze_image_authenticity

        mock_analyze.return_value = {
            "verdict": "LIKELY_MANIPULATED",
            "authenticity_score": 0.3,
            "manipulation_indicators": ["inconsistent lighting"],
            "summary": "Possible manipulation",
        }

        data_uri = f"data:image/png;base64,{self._SMALL_PNG_B64}"
        result = _handle_analyze_image_authenticity({"image_base64": data_uri})
        payload = json.loads(result["content"])

        self.assertEqual(payload["verdict"], "LIKELY_MANIPULATED")
        call_kwargs = mock_analyze.call_args[1]
        self.assertFalse(call_kwargs["image_base64"].startswith("data:"))

    def test_missing_image_returns_error(self):
        from mcp_tools.tool_definitions import _handle_analyze_image_authenticity

        result = _handle_analyze_image_authenticity({})
        payload = json.loads(result["content"])
        self.assertIn("error", payload)

    def test_oversized_image_returns_error(self):
        from mcp_tools.tool_definitions import _handle_analyze_image_authenticity

        oversized = "A" * 1_500_000
        result = _handle_analyze_image_authenticity({"image_base64": oversized})
        payload = json.loads(result["content"])
        self.assertIn("error", payload)
        self.assertIn("too large", payload["error"].lower())


if __name__ == "__main__":
    unittest.main()
