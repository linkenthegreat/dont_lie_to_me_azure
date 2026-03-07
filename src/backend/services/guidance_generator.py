"""
Safety guidance service.

Provides business logic for generating safety guidance for suspicious messages.
Decoupled from HTTP/MCP transport layers.
"""

import json
import logging
from typing import Dict, Any, Optional
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

# Embedded fallback prompt - used if prompts.yaml is missing or invalid
# This ensures services remain operational even if external config fails
_FALLBACK_SYSTEM_PROMPT = (
    "You are a consumer protection advisor. "
    "A user has received a potentially fraudulent message. "
    "Provide practical safety guidance as a JSON object with keys: "
    '"immediate_actions" (list), "reporting_steps" (list), '
    '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
    "Do not include markdown fences."
)

# Load prompt from YAML config with fallback to embedded constant
_config = get_prompt_config("guidance_generator")
_SYSTEM_PROMPT = _config.get("system_prompt", _FALLBACK_SYSTEM_PROMPT)


def generate_guidance(
    text: str,
    context: Optional[str] = None,
    client: Optional[AzureAIClient] = None
) -> Dict[str, Any]:
    """
    Generate step-by-step safety guidance for a suspicious message.

    Parameters
    ----------
    text : str
        The suspicious message text.
    context : str, optional
        Additional context about the situation.
    client : AzureAIClient, optional
        AI client instance. If None, creates a new one.

    Returns
    -------
    dict
        Guidance with keys: immediate_actions, reporting_steps,
        prevention_tips, resources.
        Format: {
            "immediate_actions": ["..."],
            "reporting_steps": ["..."],
            "prevention_tips": ["..."],
            "resources": ["..."]
        }

    Raises
    ------
    ValueError
        If text is empty or invalid.
    Exception
        If AI service fails.
    """
    if not text or not text.strip():
        raise ValueError("Text must not be empty")

    if client is None:
        client = AzureAIClient()

    user_message = f"Message: {text}"
    if context and context.strip():
        user_message += f"\n\nAdditional context: {context}"

    try:
        raw = client.chat(system_prompt=_SYSTEM_PROMPT, user_message=user_message)
        result = json.loads(raw)
        return result
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        return {
            "immediate_actions": [],
            "reporting_steps": [],
            "prevention_tips": [],
            "resources": [],
            "note": raw,
        }
