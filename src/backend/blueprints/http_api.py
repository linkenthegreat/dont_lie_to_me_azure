"""HTTP API endpoints for scam analysis."""

import json
import logging

import azure.functions as func
from shared.ai_client import AzureAIClient

bp = func.Blueprint()
logger = logging.getLogger(__name__)


<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@bp.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe – no auth required."""
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======
    return func.HttpResponse(
>>>>>>> origin/main
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps({"status": "ok", "service": "dont-lie-to-me-azure"}),
        status_code=200,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    try:
        result = scam_classifier.classify_scam(text)
=======
    system_prompt = (
        "You are an expert anti-scam analyst. "
        "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
        "Reply ONLY with a JSON object matching this schema: "
        '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
        "Do not include markdown fences."
    )

    try:
=======
    system_prompt = (
        "You are an expert anti-scam analyst. "
        "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
        "Reply ONLY with a JSON object matching this schema: "
        '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    system_prompt = (
        "You are an expert anti-scam analyst. "
        "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
        "Reply ONLY with a JSON object matching this schema: "
        '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        client = AzureAIClient()
        raw = client.chat(system_prompt=system_prompt, user_message=text)
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        result = {"classification": "UNKNOWN", "confidence": 0.0, "reasoning": raw}
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    except Exception as exc:
        logger.exception("Classification failed")
        return _internal_error(str(exc))

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======
    return func.HttpResponse(
>>>>>>> origin/main
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    try:
        result = message_analyzer.analyze_message(text)
=======
    system_prompt = (
        "You are a cybersecurity expert specialising in social engineering and scam detection. "
        "Analyse the provided message and return a JSON object with these keys: "
        '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
        '"impersonation_indicators" (list of strings), "summary" (string). '
        "Do not include markdown fences."
    )

    try:
=======
    system_prompt = (
        "You are a cybersecurity expert specialising in social engineering and scam detection. "
        "Analyse the provided message and return a JSON object with these keys: "
        '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
        '"impersonation_indicators" (list of strings), "summary" (string). '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    system_prompt = (
        "You are a cybersecurity expert specialising in social engineering and scam detection. "
        "Analyse the provided message and return a JSON object with these keys: "
        '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
        '"impersonation_indicators" (list of strings), "summary" (string). '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    except Exception as exc:
        logger.exception("Analysis failed")
        return _internal_error(str(exc))

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======
    return func.HttpResponse(
>>>>>>> origin/main
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

    try:
        result = guidance_generator.generate_guidance(text, context)
=======
    user_message = f"Message: {text}"
    if context:
        user_message += f"\n\nAdditional context: {context}"

    system_prompt = (
        "You are a consumer protection advisor. "
        "A user has received a potentially fraudulent message. "
        "Provide practical safety guidance as a JSON object with keys: "
        '"immediate_actions" (list), "reporting_steps" (list), '
        '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
        "Do not include markdown fences."
    )

    try:
=======
    user_message = f"Message: {text}"
    if context:
        user_message += f"\n\nAdditional context: {context}"

    system_prompt = (
        "You are a consumer protection advisor. "
        "A user has received a potentially fraudulent message. "
        "Provide practical safety guidance as a JSON object with keys: "
        '"immediate_actions" (list), "reporting_steps" (list), '
        '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    user_message = f"Message: {text}"
    if context:
        user_message += f"\n\nAdditional context: {context}"

    system_prompt = (
        "You are a consumer protection advisor. "
        "A user has received a potentially fraudulent message. "
        "Provide practical safety guidance as a JSON object with keys: "
        '"immediate_actions" (list), "reporting_steps" (list), '
        '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
        "Do not include markdown fences."
    )

    try:
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    except Exception as exc:
        logger.exception("Guidance generation failed")
        return _internal_error(str(exc))

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======
    return func.HttpResponse(
>>>>>>> origin/main
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bad_request(message: str) -> func.HttpResponse:
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======
    return func.HttpResponse(
>>>>>>> origin/main
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps({"error": message}),
        status_code=400,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)


def _internal_error(message: str) -> func.HttpResponse:
    response = func.HttpResponse(
=======


def _internal_error(message: str) -> func.HttpResponse:
    return func.HttpResponse(
>>>>>>> origin/main
=======


def _internal_error(message: str) -> func.HttpResponse:
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======


def _internal_error(message: str) -> func.HttpResponse:
    return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
        json.dumps({"error": "Internal server error.", "detail": message}),
        status_code=500,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
