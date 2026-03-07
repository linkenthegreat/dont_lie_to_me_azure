"""
Message analysis service.

Provides business logic for detailed scam message analysis.
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
    "You are a cybersecurity expert specialising in social engineering and scam detection. "
    "Analyse the provided message and return a JSON object with these keys: "
    '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
    '"impersonation_indicators" (list of strings), "summary" (string). '
    "Do not include markdown fences."
)

# Load prompt from YAML config with fallback to embedded constant
_config = get_prompt_config("message_analyzer")
_SYSTEM_PROMPT = _config.get("system_prompt", _FALLBACK_SYSTEM_PROMPT)


def analyze_message(text: str, client: Optional[AzureAIClient] = None) -> Dict[str, Any]:
    """
    Perform detailed analysis of a message, identifying red flags and techniques.

    Parameters
    ----------
    text : str
        The message text to analyze.
    client : AzureAIClient, optional
        AI client instance. If None, creates a new one.

    Returns
    -------
    dict
        Analysis result with keys: red_flags, persuasion_techniques,
        impersonation_indicators, summary.
        Format: {
            "red_flags": ["..."],
            "persuasion_techniques": ["..."],
            "impersonation_indicators": ["..."],
            "summary": "..."
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

    try:
        raw = client.chat(system_prompt=_SYSTEM_PROMPT, user_message=text)
        result = json.loads(raw)
        return result
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        return {
            "red_flags": [],
            "persuasion_techniques": [],
            "impersonation_indicators": [],
            "summary": raw,
        }
