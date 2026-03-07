"""
Centralized Prompt Configuration Loader

This module provides runtime access to AI system prompts defined in prompts.yaml.
If the YAML file is missing or malformed, each service automatically falls back
to embedded constants for operational resilience.

Architecture v3.0 - Prompt Management System
See docs/CONTRIBUTING.md for editing guidelines.
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Cache loaded configuration to avoid repeated file I/O
_config_cache: Optional[Dict[str, Any]] = None


def get_prompt_config(service_key: str) -> Dict[str, Any]:
    """
    Load prompt configuration for a given service key.

    Args:
        service_key: The service identifier (e.g., 'scam_classifier', 'message_analyzer')

    Returns:
        Dictionary with keys: system_prompt, model, temperature, max_tokens
        Returns empty dict if service_key not found (caller should use fallback)

    Example:
        config = get_prompt_config("scam_classifier")
        system_prompt = config.get("system_prompt", FALLBACK_PROMPT)
        model = config.get("model", "gpt-4o-mini")
    """
    global _config_cache

    # Load YAML config once and cache it
    if _config_cache is None:
        _config_cache = _load_prompts_yaml()

    return _config_cache.get(service_key, {})


def _load_prompts_yaml() -> Dict[str, Any]:
    """
    Load prompts.yaml from the backend root directory.

    Returns:
        Parsed YAML configuration, or empty dict if file missing/invalid
    """
    try:
        import yaml
    except ImportError:
        logger.warning(
            "PyYAML not installed. Using embedded fallback prompts. "
            "Install with: pip install pyyaml"
        )
        return {}

    # Construct path to prompts.yaml (same directory as function_app.py)
    backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    yaml_path = os.path.join(backend_root, "prompts.yaml")

    if not os.path.exists(yaml_path):
        logger.warning(
            f"prompts.yaml not found at {yaml_path}. Using embedded fallback prompts."
        )
        return {}

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                logger.error("prompts.yaml root must be a dictionary. Using fallbacks.")
                return {}
            logger.info(f"Loaded prompt configuration for {len(config)} services")
            return config
    except yaml.YAMLError as exc:
        logger.error(f"Failed to parse prompts.yaml: {exc}. Using fallbacks.")
        return {}
    except Exception as exc:
        logger.error(f"Unexpected error loading prompts.yaml: {exc}. Using fallbacks.")
        return {}


def reload_prompts():
    """
    Force reload of prompts.yaml from disk.

    Useful for testing or hot-reloading prompt changes without restarting the service.
    """
    global _config_cache
    _config_cache = None
    logger.info("Prompt configuration cache cleared. Will reload on next access.")
