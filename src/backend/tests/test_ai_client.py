"""
Unit tests for the AI client provider abstraction.

These tests verify that the AzureAIClient can be initialized with different
providers (azure, github, mock) and that the provider selection logic works.
"""

import unittest
from unittest.mock import patch, MagicMock


class TestProviderSelection(unittest.TestCase):
    """Tests for AI provider selection logic."""

    @patch("shared.ai_client.config")
    def test_mock_provider_initialization(self, mock_config):
        """Mock provider should initialize without external dependencies."""
        mock_config.AI_PROVIDER.return_value = "mock"
        
        from shared.ai_client import AzureAIClient
        
        client = AzureAIClient()
        self.assertIsNotNone(client._client)
        self.assertEqual(client._provider, "mock")
        self.assertEqual(client._deployment, "mock-model")

    @patch("shared.ai_client.config")
    @patch("shared.ai_client.OpenAI")
    def test_github_provider_initialization(self, mock_openai, mock_config):
        """GitHub provider should initialize with token."""
        mock_config.AI_PROVIDER.return_value = "github"
        mock_config.GITHUB_TOKEN.return_value = "ghp_test_token"
        mock_config.GITHUB_MODEL.return_value = "gpt-4o-mini"
        mock_config.GITHUB_MODELS_ENDPOINT.return_value = "https://models.github.ai/inference"
        
        from shared.ai_client import AzureAIClient
        
        client = AzureAIClient()
        mock_openai.assert_called_once_with(
            base_url="https://models.github.ai/inference",
            api_key="ghp_test_token",
        )
        self.assertEqual(client._provider, "github")
        self.assertEqual(client._deployment, "gpt-4o-mini")

    @patch("shared.ai_client.config")
    def test_github_provider_requires_token(self, mock_config):
        """GitHub provider should raise error if token missing."""
        mock_config.AI_PROVIDER.return_value = "github"
        mock_config.GITHUB_TOKEN.return_value = ""
        
        from shared.ai_client import AzureAIClient
        
        with self.assertRaises(EnvironmentError) as ctx:
            AzureAIClient()
        self.assertIn("GITHUB_TOKEN", str(ctx.exception))

    @patch("shared.ai_client.config")
    @patch("shared.ai_client.AzureOpenAI")
    def test_azure_provider_with_api_key(self, mock_azure_openai, mock_config):
        """Azure provider should initialize with API key."""
        mock_config.AI_PROVIDER.return_value = "azure"
        mock_config.AZURE_AI_ENDPOINT.return_value = "https://test.openai.azure.com/"
        mock_config.AZURE_AI_API_KEY.return_value = "test-api-key"
        mock_config.AZURE_AI_API_VERSION.return_value = "2024-02-01"
        mock_config.AZURE_AI_DEPLOYMENT_NAME.return_value = "gpt-4o"
        
        from shared.ai_client import AzureAIClient
        
        client = AzureAIClient()
        mock_azure_openai.assert_called_once()
        call_kwargs = mock_azure_openai.call_args[1]
        self.assertEqual(call_kwargs["azure_endpoint"], "https://test.openai.azure.com/")
        self.assertEqual(call_kwargs["api_key"], "test-api-key")
        self.assertEqual(call_kwargs["api_version"], "2024-02-01")
        self.assertEqual(client._provider, "azure")
        self.assertEqual(client._deployment, "gpt-4o")

    @patch("shared.ai_client.config")
    def test_azure_provider_requires_endpoint(self, mock_config):
        """Azure provider should raise error if endpoint missing."""
        mock_config.AI_PROVIDER.return_value = "azure"
        mock_config.AZURE_AI_ENDPOINT.return_value = ""
        mock_config.AZURE_AI_API_KEY.return_value = "test-key"
        
        from shared.ai_client import AzureAIClient
        
        with self.assertRaises(EnvironmentError) as ctx:
            AzureAIClient()
        self.assertIn("AZURE_AI_ENDPOINT", str(ctx.exception))

    @patch("shared.ai_client.config")
    def test_invalid_provider_raises_error(self, mock_config):
        """Invalid provider should raise ValueError."""
        mock_config.AI_PROVIDER.return_value = "unsupported"
        
        from shared.ai_client import AzureAIClient
        
        with self.assertRaises(ValueError) as ctx:
            AzureAIClient()
        self.assertIn("Unsupported AI_PROVIDER", str(ctx.exception))
        self.assertIn("unsupported", str(ctx.exception))

    @patch("shared.ai_client.config")
    def test_provider_override_in_constructor(self, mock_config):
        """Provider can be overridden in constructor."""
        mock_config.AI_PROVIDER.return_value = "azure"  # Default in env
        
        from shared.ai_client import AzureAIClient
        
        # Override to use mock
        client = AzureAIClient(provider="mock")
        self.assertEqual(client._provider, "mock")


class TestChatMethod(unittest.TestCase):
    """Tests for the chat() method with different providers."""

    @patch("shared.ai_client.config")
    def test_mock_chat_returns_response(self, mock_config):
        """Mock provider should return canned response."""
        mock_config.AI_PROVIDER.return_value = "mock"
        
        from shared.ai_client import AzureAIClient
        
        client = AzureAIClient()
        response = client.chat(
            system_prompt="You are a helpful assistant.",
            user_message="Is this a scam?",
        )
        self.assertIsInstance(response, str)
        self.assertIn("[MOCK]", response)

    @patch("shared.ai_client.config")
    @patch("shared.ai_client.OpenAI")
    def test_github_chat_calls_api(self, mock_openai_class, mock_config):
        """GitHub provider should call OpenAI API."""
        mock_config.AI_PROVIDER.return_value = "github"
        mock_config.GITHUB_TOKEN.return_value = "ghp_test"
        mock_config.GITHUB_MODEL.return_value = "gpt-4o-mini"
        mock_config.GITHUB_MODELS_ENDPOINT.return_value = "https://models.github.ai/inference"
        
        # Mock the client instance and API response
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "This looks suspicious."
        mock_client.chat.completions.create.return_value = mock_response
        
        from shared.ai_client import AzureAIClient
        
        client = AzureAIClient()
        response = client.chat(
            system_prompt="You are a scam detector.",
            user_message="Check this message.",
        )
        
        self.assertEqual(response, "This looks suspicious.")
        mock_client.chat.completions.create.assert_called_once()
        call_args = mock_client.chat.completions.create.call_args[1]
        self.assertEqual(call_args["model"], "gpt-4o-mini")
        self.assertEqual(len(call_args["messages"]), 2)
        self.assertEqual(call_args["messages"][0]["role"], "system")
        self.assertEqual(call_args["messages"][1]["role"], "user")


if __name__ == "__main__":
    unittest.main()
