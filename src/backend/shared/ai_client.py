"""
Shared AI client with provider abstraction.

Supports Azure AI Foundry, GitHub Models, and mock providers.
Reads configuration from environment variables (populated from local.settings.json
locally, or from Application Settings / Key Vault references in Azure).
"""

import logging
from typing import Optional
from openai import AzureOpenAI, OpenAI
from shared import config

logger = logging.getLogger(__name__)

_DEFAULT_MAX_TOKENS = 1024
_DEFAULT_TEMPERATURE = 0.2


class MockAIClient:
    """Mock AI client for testing without live API calls."""

    def __init__(self):
        logger.info("MockAIClient initialized")

    def chat_completions_create(self, model: str, messages: list, max_tokens: int, temperature: float):
        class MockResponse:
            class Choice:
                class Message:
                    content = "[MOCK] This appears to be a potential scam. Please exercise caution."
                message = Message()
            choices = [Choice()]
        return MockResponse()


class AzureAIClient:
    """
    Multi-provider AI client supporting Azure AI Foundry, GitHub Models, and mock.

    Provider selection via AI_PROVIDER environment variable:
        - "azure"  : Azure AI Foundry (production)
        - "github" : GitHub Models (local development)
        - "mock"   : Mock responses (testing)

    Azure Configuration:
        AZURE_AI_ENDPOINT          – e.g. https://<name>.openai.azure.com/
        AZURE_AI_DEPLOYMENT_NAME   – deployment name, e.g. "gpt-4o"
        AZURE_AI_API_VERSION       – API version, e.g. "2024-02-01"
        AZURE_AI_API_KEY           – API key (or use managed identity)

    GitHub Models Configuration:
        GITHUB_TOKEN               – GitHub personal access token
        GITHUB_MODEL               – Model ID, e.g. "gpt-4o-mini"
        GITHUB_MODELS_ENDPOINT     – Endpoint URL (default: https://models.github.ai/inference)
    """

    def __init__(self, provider: Optional[str] = None) -> None:
        """
        Initialize AI client with specified provider.

        Parameters
        ----------
        provider : str, optional
            Override AI_PROVIDER environment variable. One of: azure, github, mock.
            If None, reads from AI_PROVIDER env var (defaults to "azure").
        """
        self._provider = provider or config.AI_PROVIDER()
        self._client = None
        self._deployment = None

        if self._provider == "mock":
            self._client = MockAIClient()
            self._deployment = "mock-model"
            logger.info("AzureAIClient initialized with mock provider")

        elif self._provider == "github":
            token = config.GITHUB_TOKEN()
            if not token:
                raise EnvironmentError(
                    "GITHUB_TOKEN environment variable is required for github provider"
                )
            self._deployment = config.GITHUB_MODEL()
            endpoint = config.GITHUB_MODELS_ENDPOINT()
            self._client = OpenAI(
                base_url=endpoint,
                api_key=token,
            )
            logger.info("AzureAIClient initialized with GitHub Models provider (model: %s)", self._deployment)

        elif self._provider == "azure":
            endpoint = config.AZURE_AI_ENDPOINT()
            api_key = config.AZURE_AI_API_KEY()
            api_version = config.AZURE_AI_API_VERSION()
            self._deployment = config.AZURE_AI_DEPLOYMENT_NAME()

            if not endpoint:
                raise EnvironmentError(
                    "AZURE_AI_ENDPOINT environment variable is not set."
                )

            if api_key:
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    api_key=api_key,
                    api_version=api_version,
                )
            else:
                # Fallback to DefaultAzureCredential (managed identity / Azure CLI)
                from azure.identity import DefaultAzureCredential, get_bearer_token_provider

                credential = DefaultAzureCredential()
                token_provider = get_bearer_token_provider(
                    credential, "https://cognitiveservices.azure.com/.default"
                )
                self._client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    azure_ad_token_provider=token_provider,
                    api_version=api_version,
                )
            logger.info("AzureAIClient initialized with Azure AI Foundry provider (deployment: %s)", self._deployment)

        else:
            raise ValueError(
                f"Unsupported AI_PROVIDER: {self._provider}. Must be one of: azure, github, mock"
            )

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        temperature: float = _DEFAULT_TEMPERATURE,
    ) -> str:
        """
        Send a chat completion request and return the model's reply as a string.

        Parameters
        ----------
        system_prompt:
            Instructions that set the behaviour / persona of the model.
        user_message:
            The user-supplied content to analyse.
        max_tokens:
            Maximum number of tokens in the response.
        temperature:
            Sampling temperature (lower = more deterministic).

        Returns
        -------
        str
            The content of the first choice returned by the model.
        """
        if self._provider == "mock":
            # Mock provider uses simplified interface
            response = self._client.chat_completions_create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
        else:
            # Azure and GitHub providers use standard OpenAI SDK interface
            response = self._client.chat.completions.create(
                model=self._deployment,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
        return response.choices[0].message.content
