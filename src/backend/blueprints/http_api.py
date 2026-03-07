"""HTTP API endpoints for scam analysis."""

import json
import logging

import azure.functions as func
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

bp = func.Blueprint()
logger = logging.getLogger(__name__)
# ---------------------------------------------------------------------------
# Fallback prompt constants (operational resilience if prompts.yaml fails)
# Keep these in sync with prompts.yaml and function_app.py
# ---------------------------------------------------------------------------

_FALLBACK_SCAM_CLASSIFIER_PROMPT = (
    "You are an expert anti-scam analyst. "
    "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
    "Reply ONLY with a JSON object matching this schema: "
    '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
    "Do not include markdown fences."
)

_FALLBACK_MESSAGE_ANALYZER_PROMPT = (
    "You are a cybersecurity expert specialising in social engineering and scam detection. "
    "Analyse the provided message and return a JSON object with these keys: "
    '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
    '"impersonation_indicators" (list of strings), "summary" (string). '
    "Do not include markdown fences."
)

_FALLBACK_GUIDANCE_GENERATOR_PROMPT = (
    "You are a consumer protection advisor. "
    "A user has received a potentially fraudulent message. "
    "Provide practical safety guidance as a JSON object with keys: "
    '"immediate_actions" (list), "reporting_steps" (list), '
    '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
    "Do not include markdown fences."
)



# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@bp.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe – no auth required."""
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "dont-lie-to-me-azure"}),
        status_code=200,
        mimetype="application/json",
    )


# ---------------------------------------------------------------------------
# Scam classification
# ---------------------------------------------------------------------------


@bp.route(route="classify", methods=["POST"])
def classify_scam(req: func.HttpRequest) -> func.HttpResponse:
    """Classify whether the supplied text / message is a scam."""
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    text = body.get("text", "").strip()
    if not text:
        return _bad_request("'text' field is required and must not be empty.")

    # Load prompt from centralized config with fallback
    _config = get_prompt_config("scam_classifier")
    system_prompt = _config.get("system_prompt", _FALLBACK_SCAM_CLASSIFIER_PROMPT)

    try:
        client = AzureAIClient()
        raw = client.chat(system_prompt=system_prompt, user_message=text)
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        result = {"classification": "UNKNOWN", "confidence": 0.0, "reasoning": raw}
    except Exception as exc:
        logger.exception("Classification failed")
        return _internal_error(str(exc))

    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------


@bp.route(route="analyze", methods=["POST"])
def analyze_message(req: func.HttpRequest) -> func.HttpResponse:
    """Detailed analysis: red flags, persuasion techniques, impersonation."""
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    text = body.get("text", "").strip()
    if not text:
        return _bad_request("'text' field is required and must not be empty.")

    # Load prompt from centralized config with fallback
    _config = get_prompt_config("message_analyzer")
    system_prompt = _config.get("system_prompt", _FALLBACK_MESSAGE_ANALYZER_PROMPT)

    try:
        client = AzureAIClient()
        raw = client.chat(system_prompt=system_prompt, user_message=text)
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        result = {
            "red_flags": [],
            "persuasion_techniques": [],
            "impersonation_indicators": [],
            "summary": raw,
        }
    except Exception as exc:
        logger.exception("Analysis failed")
        return _internal_error(str(exc))

    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )


# ---------------------------------------------------------------------------
# Safety guidance
# ---------------------------------------------------------------------------


@bp.route(route="guidance", methods=["POST"])
def safety_guidance(req: func.HttpRequest) -> func.HttpResponse:
    """Generate step-by-step safety guidance for a suspicious message."""
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    text = body.get("text", "").strip()
    if not text:
        return _bad_request("'text' field is required and must not be empty.")

    context = body.get("context", "").strip()
    user_message = f"Message: {text}"
    if context:
        user_message += f"\n\nAdditional context: {context}"

    # Load prompt from centralized config with fallback
    _config = get_prompt_config("guidance_generator")
    system_prompt = _config.get("system_prompt", _FALLBACK_GUIDANCE_GENERATOR_PROMPT)

    try:
        client = AzureAIClient()
        raw = client.chat(system_prompt=system_prompt, user_message=user_message)
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        result = {
            "immediate_actions": [],
            "reporting_steps": [],
            "prevention_tips": [],
            "resources": [],
            "note": raw,
        }
    except Exception as exc:
        logger.exception("Guidance generation failed")
        return _internal_error(str(exc))

    return func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bad_request(message: str) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=400,
        mimetype="application/json",
    )


def _internal_error(message: str) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"error": "Internal server error.", "detail": message}),
        status_code=500,
        mimetype="application/json",
    )
