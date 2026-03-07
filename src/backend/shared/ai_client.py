"""
Shared Azure AI Foundry client.

Reads configuration from environment variables (populated from local.settings.json
locally, or from Application Settings / Key Vault references in Azure).
"""

import os
import logging
from openai import AzureOpenAI

logger = logging.getLogger(__name__)

_DEFAULT_MAX_TOKENS = 1024
_DEFAULT_TEMPERATURE = 0.2


class AzureAIClient:
    """
    Thin wrapper around the Azure OpenAI SDK for Azure AI Foundry deployments.

    Supported models: GPT-4o, GPT-4o mini, Phi-3 (deployed via Azure AI Foundry).

    Configuration (environment variables):
        AZURE_AI_ENDPOINT          – e.g. https://<name>.openai.azure.com/
        AZURE_AI_DEPLOYMENT_NAME   – deployment name, e.g. "gpt-4o"
        AZURE_AI_API_VERSION       – API version, e.g. "2024-02-01"
        AZURE_AI_API_KEY           – API key  (or use managed identity)
    """

    def __init__(self) -> None:
        endpoint = os.environ.get("AZURE_AI_ENDPOINT", "")
        api_key = os.environ.get("AZURE_AI_API_KEY", "")
        api_version = os.environ.get("AZURE_AI_API_VERSION", "2024-02-01")
        self._deployment = os.environ.get("AZURE_AI_DEPLOYMENT_NAME", "gpt-4o")

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

        logger.info("AzureAIClient initialised with deployment '%s'", self._deployment)

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
