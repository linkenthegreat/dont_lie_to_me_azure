"""Microsoft Teams incoming webhook integration for scam alerts."""

import json
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class TeamsNotifier:
    """Send adaptive cards to Microsoft Teams via incoming webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_scam_alert(
        self,
        classification: str,
        confidence: float,
        text_snippet: str,
        reasoning: str,
        analysis_id: Optional[str] = None,
    ) -> bool:
        """Send a scam alert adaptive card to Teams."""
        color_map = {
            "SCAM": "attention",
            "LIKELY_SCAM": "warning",
            "SUSPICIOUS": "accent",
            "SAFE": "good",
        }
        color = color_map.get(classification, "default")

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "Don't Lie To Me - Scam Alert",
                                "weight": "Bolder",
                                "size": "Large",
                                "color": color,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Classification", "value": classification},
                                    {"title": "Confidence", "value": f"{confidence:.0%}" if isinstance(confidence, (int, float)) else str(confidence)},
                                    {"title": "Reasoning", "value": reasoning[:200]},
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Message snippet: {text_snippet[:150]}...",
                                "wrap": True,
                                "isSubtle": True,
                            },
                        ],
                    },
                }
            ],
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=card,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Failed to send Teams notification: %s", exc)
            return False


_instance: Optional[TeamsNotifier] = None


def get_teams_notifier() -> Optional[TeamsNotifier]:
    """Get Teams notifier if webhook URL is configured."""
    global _instance
    if _instance is None:
        import os

        webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
        if webhook_url:
            _instance = TeamsNotifier(webhook_url)
    return _instance
