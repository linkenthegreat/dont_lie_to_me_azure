"""
Azure Key Vault helper.

Retrieves secrets by name from the configured Key Vault.
Falls back gracefully to environment variables for local development.
"""

import os
import logging

logger = logging.getLogger(__name__)


def get_secret(secret_name: str, fallback_env_var: str | None = None) -> str:
    """
    Retrieve a secret from Azure Key Vault.

    For local development the function falls back to reading the value from
    the environment variable specified by *fallback_env_var* (or *secret_name*
    if *fallback_env_var* is None), so you don't need a real Key Vault running
    on your laptop.

    Parameters
    ----------
    secret_name:
        Name of the secret in Key Vault (e.g. ``"AzureAIApiKey"``).
    fallback_env_var:
        Name of the environment variable to use as a local fallback.
        Defaults to *secret_name*.

    Returns
    -------
    str
        The secret value.

    Raises
    ------
    ValueError
        If the secret cannot be found in Key Vault or the environment.
    """
    keyvault_url = os.environ.get("AZURE_KEYVAULT_URL", "")

    if keyvault_url:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=keyvault_url, credential=credential)
            secret = client.get_secret(secret_name)
            logger.info("Retrieved secret '%s' from Key Vault.", secret_name)
            return secret.value
        except Exception:
            logger.warning(
                "Failed to retrieve secret '%s' from Key Vault; falling back to env var.",
                secret_name,
                exc_info=True,
            )

    env_var = fallback_env_var or secret_name
    value = os.environ.get(env_var, "")
    if not value:
        raise ValueError(
            f"Secret '{secret_name}' not found in Key Vault or environment variable '{env_var}'."
        )
    return value
