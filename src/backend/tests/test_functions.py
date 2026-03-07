"""
Unit tests for the Azure Functions backend.

These tests mock the Azure AI client so they do not require a live
Azure AI Foundry endpoint.
"""

import json
import unittest
from unittest.mock import MagicMock, patch


class TestHealthEndpoint(unittest.TestCase):
    """Tests for GET /api/health."""

    def test_health_returns_ok(self):
        """Health endpoint should return 200 with status=ok."""
        import azure.functions as func
        from blueprints.http_api import health

        req = func.HttpRequest(
            method="GET",
            url="http://localhost:7071/api/health",
            body=b"",
            headers={},
            params={},
        )
        response = health(req)
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertEqual(body["status"], "ok")


class TestClassifyEndpoint(unittest.TestCase):
    """Tests for POST /api/classify."""

    def _make_request(self, body: dict):
        import azure.functions as func

        return func.HttpRequest(
            method="POST",
            url="http://localhost:7071/api/classify",
            body=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            params={},
        )

    def test_missing_text_returns_400(self):
        """Request without 'text' should return 400."""
        from blueprints.http_api import classify_scam

        req = self._make_request({})
        response = classify_scam(req)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.get_body())
        self.assertIn("error", body)

    def test_empty_text_returns_400(self):
        """Request with empty 'text' should return 400."""
        from blueprints.http_api import classify_scam

        req = self._make_request({"text": "   "})
        response = classify_scam(req)
        self.assertEqual(response.status_code, 400)

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    @patch("services.scam_classifier.classify_scam")
    def test_valid_request_returns_classification(self, mock_classify):
        """Valid request should return classification JSON from the AI model."""
        from blueprints.http_api import classify_scam

        mock_classify.return_value = {
            "classification": "SCAM",
            "confidence": 0.97,
            "reasoning": "Phishing attempt"
        }
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_classification(self, MockClient):
        """Valid request should return classification JSON from the AI model."""
        from blueprints.http_api import classify_scam

=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_classification(self, MockClient):
        """Valid request should return classification JSON from the AI model."""
        from blueprints.http_api import classify_scam

>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_classification(self, MockClient):
        """Valid request should return classification JSON from the AI model."""
        from blueprints.http_api import classify_scam

>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(
            {"classification": "SCAM", "confidence": 0.97, "reasoning": "Phishing attempt"}
        )
        MockClient.return_value = mock_instance
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

        req = self._make_request({"text": "Your account has been compromised. Click here."})
        response = classify_scam(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertEqual(body["classification"], "SCAM")
        self.assertAlmostEqual(body["confidence"], 0.97)
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        mock_classify.assert_called_once()
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

    @patch("blueprints.http_api.AzureAIClient")
    def test_non_json_model_response_returns_unknown(self, MockClient):
        """If the model returns non-JSON, classification should be UNKNOWN."""
        from blueprints.http_api import classify_scam

<<<<<<< HEAD
<<<<<<< HEAD
        mock_classify.return_value = {
            "classification": "UNKNOWN",
            "confidence": 0.0,
            "reasoning": "This looks like a scam."
        }
=======

    @patch("blueprints.http_api.AzureAIClient")
    def test_non_json_model_response_returns_unknown(self, MockClient):
        """If the model returns non-JSON, classification should be UNKNOWN."""
        from blueprints.http_api import classify_scam

        mock_instance = MagicMock()
        mock_instance.chat.return_value = "This looks like a scam."
        MockClient.return_value = mock_instance
>>>>>>> origin/main
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = "This looks like a scam."
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = "This looks like a scam."
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

        req = self._make_request({"text": "Win a free prize!"})
        response = classify_scam(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertEqual(body["classification"], "UNKNOWN")

    def test_invalid_json_body_returns_400(self):
        """Malformed JSON in request body should return 400."""
        import azure.functions as func
        from blueprints.http_api import classify_scam

        req = func.HttpRequest(
            method="POST",
            url="http://localhost:7071/api/classify",
            body=b"not-json",
            headers={"Content-Type": "application/json"},
            params={},
        )
        response = classify_scam(req)
        self.assertEqual(response.status_code, 400)


class TestAnalyzeEndpoint(unittest.TestCase):
    """Tests for POST /api/analyze."""

    def _make_request(self, body: dict):
        import azure.functions as func

        return func.HttpRequest(
            method="POST",
            url="http://localhost:7071/api/analyze",
            body=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            params={},
        )

    def test_missing_text_returns_400(self):
        from blueprints.http_api import analyze_message

        req = self._make_request({})
        response = analyze_message(req)
        self.assertEqual(response.status_code, 400)

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    @patch("services.message_analyzer.analyze_message")
    def test_valid_request_returns_analysis(self, mock_analyze):
        from blueprints.http_api import analyze_message

        mock_analyze.return_value = {
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_analysis(self, MockClient):
        from blueprints.http_api import analyze_message

        expected = {
>>>>>>> origin/main
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_analysis(self, MockClient):
        from blueprints.http_api import analyze_message

        expected = {
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_analysis(self, MockClient):
        from blueprints.http_api import analyze_message

        expected = {
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
            "red_flags": ["Urgency"],
            "persuasion_techniques": ["Fear appeal"],
            "impersonation_indicators": ["Claims to be HMRC"],
            "summary": "Classic phishing email.",
        }
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> origin/main
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

        req = self._make_request({"text": "Pay your tax bill now or face arrest."})
        response = analyze_message(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertIn("red_flags", body)
        self.assertEqual(body["summary"], "Classic phishing email.")
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        mock_analyze.assert_called_once()
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


class TestGuidanceEndpoint(unittest.TestCase):
    """Tests for POST /api/guidance."""

    def _make_request(self, body: dict):
        import azure.functions as func

        return func.HttpRequest(
            method="POST",
            url="http://localhost:7071/api/guidance",
            body=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            params={},
        )

    def test_missing_text_returns_400(self):
        from blueprints.http_api import safety_guidance

        req = self._make_request({})
        response = safety_guidance(req)
        self.assertEqual(response.status_code, 400)

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    @patch("services.guidance_generator.generate_guidance")
    def test_valid_request_returns_guidance(self, mock_generate):
        from blueprints.http_api import safety_guidance

        mock_generate.return_value = {
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_guidance(self, MockClient):
        from blueprints.http_api import safety_guidance

        expected = {
>>>>>>> origin/main
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_guidance(self, MockClient):
        from blueprints.http_api import safety_guidance

        expected = {
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    @patch("blueprints.http_api.AzureAIClient")
    def test_valid_request_returns_guidance(self, MockClient):
        from blueprints.http_api import safety_guidance

        expected = {
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
            "immediate_actions": ["Do not click links"],
            "reporting_steps": ["Report to Action Fraud"],
            "prevention_tips": ["Use 2FA"],
            "resources": ["https://www.actionfraud.police.uk/"],
        }
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> origin/main
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        mock_instance = MagicMock()
        mock_instance.chat.return_value = json.dumps(expected)
        MockClient.return_value = mock_instance
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

        req = self._make_request(
            {"text": "Your package is on hold.", "context": "Received via SMS"}
        )
        response = safety_guidance(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertIn("immediate_actions", body)
        self.assertIn("resources", body)
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        mock_generate.assert_called_once()
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


class TestAzureAIClient(unittest.TestCase):
    """Tests for shared/ai_client.py."""

    def test_raises_without_endpoint(self):
        """AzureAIClient should raise EnvironmentError if endpoint is not set."""
        import os
        from shared.ai_client import AzureAIClient

        with unittest.mock.patch.dict(os.environ, {"AZURE_AI_ENDPOINT": "", "AZURE_AI_API_KEY": "dummy"}):
            with self.assertRaises(EnvironmentError):
                AzureAIClient()

    @patch("shared.ai_client.AzureOpenAI")
    def test_chat_returns_model_content(self, MockOpenAI):
        """chat() should return the content of the first choice."""
        import os
        from shared.ai_client import AzureAIClient

        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client

        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"classification": "SAFE"}'
        mock_client.chat.completions.create.return_value = mock_response

        with unittest.mock.patch.dict(
            os.environ,
            {
                "AZURE_AI_ENDPOINT": "https://example.openai.azure.com/",
                "AZURE_AI_API_KEY": "testkey",
                "AZURE_AI_DEPLOYMENT_NAME": "gpt-4o",
            },
        ):
            client = AzureAIClient()
            result = client.chat("system prompt", "user message")

        self.assertEqual(result, '{"classification": "SAFE"}')


class TestKeyVaultHelper(unittest.TestCase):
    """Tests for shared/keyvault.py."""

    def test_falls_back_to_env_var_when_no_vault_url(self):
        """get_secret should return the env var value when AZURE_KEYVAULT_URL is empty."""
        import os
        from shared.keyvault import get_secret

        with unittest.mock.patch.dict(
            os.environ,
            {"AZURE_KEYVAULT_URL": "", "MY_SECRET": "my-secret-value"},
        ):
            value = get_secret("not-in-vault", fallback_env_var="MY_SECRET")

        self.assertEqual(value, "my-secret-value")

    def test_raises_when_secret_not_found(self):
        """get_secret should raise ValueError when secret is missing everywhere."""
        import os
        from shared.keyvault import get_secret

        env = {"AZURE_KEYVAULT_URL": "", "MISSING_VAR": ""}
        with unittest.mock.patch.dict(os.environ, env, clear=False):
            # Ensure the fallback var is absent
            os.environ.pop("DEFINITELY_MISSING_VAR", None)
            with self.assertRaises(ValueError):
                get_secret("some-secret", fallback_env_var="DEFINITELY_MISSING_VAR")


if __name__ == "__main__":
    unittest.main()
