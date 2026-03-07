"""Centralized environment variable access."""

import os


def get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


<<<<<<< HEAD
# AI Provider Selection
AI_PROVIDER = lambda: get("AI_PROVIDER", "azure")  # azure | github | mock

=======
>>>>>>> origin/main
# Azure AI
AZURE_AI_ENDPOINT = lambda: get("AZURE_AI_ENDPOINT")
AZURE_AI_API_KEY = lambda: get("AZURE_AI_API_KEY")
AZURE_AI_API_VERSION = lambda: get("AZURE_AI_API_VERSION", "2024-02-01")
AZURE_AI_DEPLOYMENT_NAME = lambda: get("AZURE_AI_DEPLOYMENT_NAME", "gpt-4o")

<<<<<<< HEAD
# GitHub Models
GITHUB_TOKEN = lambda: get("GITHUB_TOKEN")
GITHUB_MODEL = lambda: get("GITHUB_MODEL", "gpt-4o-mini")
GITHUB_MODELS_ENDPOINT = lambda: get("GITHUB_MODELS_ENDPOINT", "https://models.github.ai/inference")

=======
>>>>>>> origin/main
# Cosmos DB
COSMOS_DB_CONNECTION_STRING = lambda: get("COSMOS_DB_CONNECTION_STRING")
COSMOS_DB_ENDPOINT = lambda: get("COSMOS_DB_ENDPOINT")
COSMOS_DB_KEY = lambda: get("COSMOS_DB_KEY")
COSMOS_DB_DATABASE = lambda: get("COSMOS_DB_DATABASE", "antiscam")
COSMOS_DB_CONTAINER = lambda: get("COSMOS_DB_CONTAINER", "analyses")

# Key Vault
AZURE_KEYVAULT_URL = lambda: get("AZURE_KEYVAULT_URL")
<<<<<<< HEAD
=======

# Azure Cache for Redis
AZURE_REDIS_CONNECTION_STRING = lambda: get("AZURE_REDIS_CONNECTION_STRING")

# Microsoft Teams
TEAMS_WEBHOOK_URL = lambda: get("TEAMS_WEBHOOK_URL")
>>>>>>> origin/main
