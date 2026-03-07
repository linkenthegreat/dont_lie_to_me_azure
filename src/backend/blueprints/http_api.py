"""HTTP API endpoints for scam analysis."""

import json
import logging

import azure.functions as func
from services import scam_classifier, message_analyzer, guidance_generator
from shared.cors import add_cors_headers

bp = func.Blueprint()
logger = logging.getLogger(__name__)



# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@bp.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe – no auth required."""
    response = func.HttpResponse(
        json.dumps({"status": "ok", "service": "dont-lie-to-me-azure"}),
        status_code=200,
        mimetype="application/json",
    )
    return add_cors_headers(response)


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

    try:
        result = scam_classifier.classify_scam(text)
    except Exception as exc:
        logger.exception("Classification failed")
        return _internal_error(str(exc))

    response = func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
    return add_cors_headers(response)


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

    try:
        result = message_analyzer.analyze_message(text)
    except Exception as exc:
        logger.exception("Analysis failed")
        return _internal_error(str(exc))

    response = func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
    return add_cors_headers(response)


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

    try:
        result = guidance_generator.generate_guidance(text, context)
    except Exception as exc:
        logger.exception("Guidance generation failed")
        return _internal_error(str(exc))

    response = func.HttpResponse(
        json.dumps(result),
        status_code=200,
        mimetype="application/json",
    )
    return add_cors_headers(response)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bad_request(message: str) -> func.HttpResponse:
    response = func.HttpResponse(
        json.dumps({"error": message}),
        status_code=400,
        mimetype="application/json",
    )
    return add_cors_headers(response)


def _internal_error(message: str) -> func.HttpResponse:
    response = func.HttpResponse(
        json.dumps({"error": "Internal server error.", "detail": message}),
        status_code=500,
        mimetype="application/json",
    )
    return add_cors_headers(response)
