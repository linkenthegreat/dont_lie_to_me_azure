"""Centralized environment variable access."""

import os


def get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


# Azure AI
AZURE_AI_ENDPOINT = lambda: get("AZURE_AI_ENDPOINT")
AZURE_AI_API_KEY = lambda: get("AZURE_AI_API_KEY")
AZURE_AI_API_VERSION = lambda: get("AZURE_AI_API_VERSION", "2024-02-01")
AZURE_AI_DEPLOYMENT_NAME = lambda: get("AZURE_AI_DEPLOYMENT_NAME", "gpt-4o")

# Cosmos DB
COSMOS_DB_CONNECTION_STRING = lambda: get("COSMOS_DB_CONNECTION_STRING")
COSMOS_DB_ENDPOINT = lambda: get("COSMOS_DB_ENDPOINT")
COSMOS_DB_KEY = lambda: get("COSMOS_DB_KEY")
COSMOS_DB_DATABASE = lambda: get("COSMOS_DB_DATABASE", "antiscam")
COSMOS_DB_CONTAINER = lambda: get("COSMOS_DB_CONTAINER", "analyses")

# Key Vault
AZURE_KEYVAULT_URL = lambda: get("AZURE_KEYVAULT_URL")

# Azure Cache for Redis
AZURE_REDIS_CONNECTION_STRING = lambda: get("AZURE_REDIS_CONNECTION_STRING")

# Microsoft Teams
TEAMS_WEBHOOK_URL = lambda: get("TEAMS_WEBHOOK_URL")
