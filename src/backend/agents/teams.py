"""Team agents that wrap service-layer business logic."""

import logging
import re
from typing import Any, Dict, List, Optional

from services import guidance_generator, message_analyzer, scam_classifier
from shared.url_checker import URLChecker
from shared.url_validators import extract_urls

logger = logging.getLogger(__name__)


class ClassifierAgent:
    """Agent wrapper for scam classification capability."""

    def run(self, text: str) -> Dict[str, Any]:
        return scam_classifier.classify_scam(text)


class ReceptionistAgent:
    """Collects lightweight context and clarification cues before routing."""

    _ENGLISH_HINTS = {
        "the",
        "you",
        "your",
        "help",
        "please",
        "scam",
        "message",
        "bank",
    }

    def run(self, text: str) -> Dict[str, Any]:
        lowered = text.lower()
        tokens = re.findall(r"[a-z']+", lowered)
        english_hits = sum(1 for token in tokens if token in self._ENGLISH_HINTS)

        clarification_needed = len(text.strip()) < 20
        return {
            "detected_language": "en" if english_hits > 0 else "unknown",
            "clarification_needed": clarification_needed,
            "clarification_prompts": (
                ["Can you share the full message text and sender details?"]
                if clarification_needed
                else []
            ),
            "url_candidates": extract_urls(text),
        }


class TextAnalyzerAgent:
    """Agent wrapper for deep message analysis capability."""

    def run(self, text: str) -> Dict[str, Any]:
        return message_analyzer.analyze_message(text)


class URLAnalyzerAgent:
    """Analyzer team member that reuses URLChecker for URL-specific checks."""

    def __init__(self, checker: Optional[URLChecker] = None) -> None:
        self._checker = checker

    def run(self, text: str, url_candidates: Optional[List[str]] = None) -> Dict[str, Any]:
        urls = url_candidates or extract_urls(text)
        if not urls:
            return {
                "checked_urls": [],
                "overall_verdict": "NO_URL_FOUND",
                "results": [],
            }

        checker = self._checker
        if checker is None:
            try:
                checker = URLChecker()
            except Exception as exc:
                logger.warning("URL checker unavailable: %s", exc)
                return {
                    "checked_urls": urls,
                    "overall_verdict": "UNABLE_TO_VERIFY",
                    "error": "URL checker unavailable",
                    "results": [],
                }

        results: List[Dict[str, Any]] = []
        for url in urls:
            try:
                result = checker.check_url(url)
                results.append(result.model_dump())
            except Exception as exc:
                logger.exception("URL analysis failed for %s", url)
                results.append(
                    {
                        "url": url,
                        "overall_verdict": "UNABLE_TO_VERIFY",
                        "error": str(exc),
                    }
                )

        overall = "NOT_FLAGGED"
        for item in results:
            verdict = item.get("overall_verdict")
            if verdict == "THREAT_DETECTED":
                overall = "THREAT_DETECTED"
                break
            if verdict == "SUSPICIOUS":
                overall = "SUSPICIOUS"

        return {
            "checked_urls": urls,
            "overall_verdict": overall,
            "results": results,
        }


class GuidanceAgent:
    """Agent wrapper for safety guidance capability."""

    def run(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        return guidance_generator.generate_guidance(text, context=context)


class ReportGeneratorAgent:
    """Creates structured summary report from prior team outputs."""

    def run(
        self,
        classification: Dict[str, Any],
        analysis: Optional[Dict[str, Any]],
        guidance: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "risk_level": classification.get("classification", "UNKNOWN"),
            "confidence": classification.get("confidence", 0.0),
            "analysis_summary": (
                (analysis or {}).get("summary")
                or (analysis or {}).get("text_analysis", {}).get("summary")
                or "No analysis summary available"
            ),
            "immediate_actions": guidance.get("immediate_actions", []),
        }


class ResourceAssistantAgent:
    """Provides location-aware reporting resources and next-step links."""

    def run(self, location_hint: Optional[str] = None) -> Dict[str, Any]:
        country = (location_hint or "").strip().upper()
        if country in {"US", "USA", "UNITED STATES"}:
            resources = [
                "https://reportfraud.ftc.gov/",
                "https://www.ic3.gov/",
            ]
        elif country in {"SG", "SINGAPORE"}:
            resources = [
                "https://www.scamshield.gov.sg/",
                "https://www.police.gov.sg/i-witness",
            ]
        else:
            resources = [
                "https://consumer.ftc.gov/scams",
                "https://www.actionfraud.police.uk/",
            ]

        return {
            "location_hint": location_hint,
            "reporting_resources": resources,
        }


class FakeImageDetectorAgent:
    """Phase E extension stub for future fake-image detection."""

    def run(self, image_reference: str) -> Dict[str, Any]:
        return {
            "status": "not_implemented",
            "capability": "fake_image_detection",
            "input": image_reference,
        }


class PhoneNumberAnalyzerAgent:
    """Phase E extension stub for phone-number risk analysis."""

    def run(self, phone_number: str) -> Dict[str, Any]:
        return {
            "status": "not_implemented",
            "capability": "phone_number_analysis",
            "input": phone_number,
        }
