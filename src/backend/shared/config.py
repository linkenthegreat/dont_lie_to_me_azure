"""Centralized environment variable access."""

import os


def get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


# AI Provider Selection
AI_PROVIDER = lambda: get("AI_PROVIDER", "azure")  # azure | github | mock

# Azure AI
AZURE_AI_ENDPOINT = lambda: get("AZURE_AI_ENDPOINT")
AZURE_AI_API_KEY = lambda: get("AZURE_AI_API_KEY")
AZURE_AI_API_VERSION = lambda: get("AZURE_AI_API_VERSION", "2024-02-01")
AZURE_AI_DEPLOYMENT_NAME = lambda: get("AZURE_AI_DEPLOYMENT_NAME", "gpt-4o")
AZURE_AI_ENDPOINT_SECRET_NAME = lambda: get("AZURE_AI_ENDPOINT_SECRET_NAME", "AzureAIEndpoint")
AZURE_AI_API_KEY_SECRET_NAME = lambda: get("AZURE_AI_API_KEY_SECRET_NAME", "AzureAIApiKey")

# GitHub Models
GITHUB_TOKEN = lambda: get("GITHUB_TOKEN")
GITHUB_MODEL = lambda: get("GITHUB_MODEL", "gpt-4o-mini")
GITHUB_MODELS_ENDPOINT = lambda: get("GITHUB_MODELS_ENDPOINT", "https://models.github.ai/inference")

# Cosmos DB
COSMOS_DB_CONNECTION_STRING = lambda: get("COSMOS_DB_CONNECTION_STRING")
COSMOS_DB_ENDPOINT = lambda: get("COSMOS_DB_ENDPOINT")
COSMOS_DB_KEY = lambda: get("COSMOS_DB_KEY")
COSMOS_DB_DATABASE = lambda: get("COSMOS_DB_DATABASE", "antiscam")
COSMOS_DB_CONTAINER = lambda: get("COSMOS_DB_CONTAINER", "analyses")

# Key Vault
AZURE_KEYVAULT_URL = lambda: get("AZURE_KEYVAULT_URL")

# Threat Intelligence
# On Azure: secret name in Key Vault is "GoogleSafeBrowsingApiKey".
# Locally: read from GOOGLE_SAFE_BROWSING_API_KEY in env/.env.
GOOGLE_SB_API_KEY_SECRET = "GoogleSafeBrowsingApiKey"
GOOGLE_SB_API_KEY_ENV_VAR = "GOOGLE_SAFE_BROWSING_API_KEY"

# On Azure: secret name in Key Vault is "UrlhausApiKey".
# Locally: read from URLHAUS_API_KEY in local.settings.json or env/.env.
URLHAUS_API_KEY_SECRET = "UrlhausApiKey"
URLHAUS_API_KEY_ENV_VAR = "URLHAUS_API_KEY"
