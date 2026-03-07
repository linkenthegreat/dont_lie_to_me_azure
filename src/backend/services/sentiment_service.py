"""Sentiment analysis and manipulation detection service."""

import json
import logging

from shared.ai_client import AzureAIClient

logger = logging.getLogger(__name__)

SENTIMENT_SYSTEM_PROMPT = """You are an expert in psychological manipulation and social engineering analysis.
Analyze the provided message for:
1. Emotional sentiment (fear, urgency, greed, trust, curiosity)
2. Manipulation techniques (social proof, authority, scarcity, reciprocity, commitment, liking)
3. Emotional pressure score (0.0-1.0)
4. Language patterns associated with fraud

Return a JSON object:
{
    "sentiment": {
        "primary_emotion": "fear|urgency|greed|trust|curiosity|neutral",
        "emotion_scores": {"fear": 0.0, "urgency": 0.0, "greed": 0.0, "trust": 0.0, "curiosity": 0.0},
        "overall_tone": "threatening|persuasive|deceptive|neutral|informational"
    },
    "manipulation": {
        "techniques_detected": ["technique_name"],
        "pressure_score": 0.0,
        "urgency_indicators": ["..."],
        "authority_claims": ["..."],
        "emotional_triggers": ["..."]
    },
    "language_analysis": {
        "formality_level": "formal|informal|mixed",
        "grammar_quality": "poor|moderate|good",
        "suspicious_phrases": ["..."],
        "call_to_action": "..."
    },
    "risk_assessment": "HIGH|MODERATE|LOW",
    "summary": "..."
}
Do not include markdown fences."""


def analyze_sentiment(text: str) -> dict:
    """Perform sentiment analysis and manipulation detection."""
    client = AzureAIClient()
    raw = client.chat(
        system_prompt=SENTIMENT_SYSTEM_PROMPT,
        user_message=text,
        max_tokens=1500,
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Sentiment model returned non-JSON: %s", raw[:200])
        return {
            "sentiment": {"primary_emotion": "unknown", "emotion_scores": {}, "overall_tone": "unknown"},
            "manipulation": {"techniques_detected": [], "pressure_score": 0.0, "urgency_indicators": [], "authority_claims": [], "emotional_triggers": []},
            "language_analysis": {"formality_level": "unknown", "grammar_quality": "unknown", "suspicious_phrases": [], "call_to_action": ""},
            "risk_assessment": "UNKNOWN",
            "summary": raw,
        }
