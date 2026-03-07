"""
Scam classification service.

Provides business logic for classifying text messages as scams.
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
    "You are an expert anti-scam analyst. "
    "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
    "Reply ONLY with a JSON object matching this schema: "
    '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
    "Do not include markdown fences."
)

# Load prompt from YAML config with fallback to embedded constant
_config = get_prompt_config("scam_classifier")
_SYSTEM_PROMPT = _config.get("system_prompt", _FALLBACK_SYSTEM_PROMPT)


def classify_scam(text: str, client: Optional[AzureAIClient] = None) -> Dict[str, Any]:
    """
    Classify whether the supplied text is a scam.

    Parameters
    ----------
    text : str
        The message text to classify.
    client : AzureAIClient, optional
        AI client instance. If None, creates a new one.

    Returns
    -------
    dict
        Classification result with keys: classification, confidence, reasoning.
        Format: {
            "classification": "SCAM" | "LIKELY_SCAM" | "SUSPICIOUS" | "SAFE",
            "confidence": 0.0-1.0,
            "reasoning": "..."
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
            "classification": "UNKNOWN",
            "confidence": 0.0,
            "reasoning": raw
        }
