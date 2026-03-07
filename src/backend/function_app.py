"""
Dont Lie To Me – Azure
Azure Functions v2 (Python) entry point.

HTTP endpoints use shared service layer.
MCP tools are registered directly on the FunctionApp.
CORS is enabled for local development and cross-origin requests.
"""

import json
import logging

import azure.functions as func
from shared.url_checker import URLChecker
from shared.models import CheckURLRequest, CheckURLResponse
from shared.cors import add_cors_headers
from services import scam_classifier, message_analyzer, guidance_generator

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger(__name__)

# Initialize URL checker (will raise error if API key not configured)
_url_checker = None

def _get_url_checker() -> URLChecker:
    """Lazy initialization of URL checker."""
    global _url_checker
    if _url_checker is None:
        try:
            _url_checker = URLChecker()
        except ValueError as e:
            logger.error("Failed to initialize URL checker: %s", e)
            # Will be handled in the endpoint
    return _url_checker


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route(route="health", methods=["GET", "OPTIONS"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe – no auth required."""
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
    response = func.HttpResponse(
        json.dumps({"status": "ok", "service": "dont-lie-to-me-azure"}),
        status_code=200,
        mimetype="application/json",
    )
    return add_cors_headers(response)


# ---------------------------------------------------------------------------
# URL threat checking
# ---------------------------------------------------------------------------

@app.route(route="check-url", methods=["POST", "OPTIONS"])
def check_url(req: func.HttpRequest) -> func.HttpResponse:
    """
    Check if a URL is flagged as a threat by threat intelligence sources.

    Performs parallel checks using:
    - Google Safe Browsing API (phishing/malware detection)
    - URLhaus API (malware database)
    - Local risk heuristics (punycode, typosquatting, etc.)

    Request body (JSON):
        {
            "url": "<URL to check>",
            "use_cache": true  (optional, default: true)
        }

    Response (JSON):
        {
            "success": true,
            "data": {
                "url": "<normalized URL>",
                "overall_verdict": "THREAT_DETECTED" | "SUSPICIOUS" | "NOT_FLAGGED" | "UNABLE_TO_VERIFY",
                "confidence": "HIGH" | "MODERATE" | "LOW",
                "primary_threat_type": "PHISHING" | "MALWARE" | "SCAM" | ... | null,
                "recommendation": "<human-readable recommendation>",
                "sources": {
                    "google_safe_browsing": {...},
                    "urlhaus": {...},
                    "risk_hints": {...}
                },
                "timestamp": "<ISO 8601 timestamp>",
                "total_response_time_ms": <int>,
                "cached": false
            },
            "error": null,
            "error_code": null
        }

    Error Response (400-500):
        {
            "success": false,
            "data": null,
            "error": "<error message>",
            "error_code": "<error code>"
        }
    """
    try:
        body = req.get_json()
    except ValueError:
        response = CheckURLResponse(
            success=False,
            error="Request body must be valid JSON",
            error_code="INVALID_JSON",
        )
        http_response = func.HttpResponse(
            response.model_dump_json(),
            status_code=400,
            mimetype="application/json",
        )
        return add_cors_headers(http_response)

    # Validate request
    try:
        request_data = CheckURLRequest(**body)
    except ValueError as exc:
        response = CheckURLResponse(
            success=False,
            error=f"Invalid request: {str(exc)}",
            error_code="INVALID_REQUEST",
        )
        http_response = func.HttpResponse(
            response.model_dump_json(),
            status_code=400,
            mimetype="application/json",
        )
        return add_cors_headers(http_response)

    # Get URL checker
    url_checker = _get_url_checker()
    if url_checker is None:
        response = CheckURLResponse(
            success=False,
            error="URL checker is not available. Please check configuration.",
            error_code="CHECKER_UNAVAILABLE",
        )
        return func.HttpResponse(
            response.model_dump_json(),
            status_code=500,
            mimetype="application/json",
        )

    # Perform check
    try:
        result = url_checker.check_url(
            url=request_data.url,
            use_cache=request_data.use_cache,
        )
        response = CheckURLResponse(
            success=True,
            data=result,
            error=None,
            error_code=None,
        )
        http_response = func.HttpResponse(
            response.model_dump_json(),
            status_code=200,
            mimetype="application/json",
        )
        return add_cors_headers(http_response)

    except Exception as exc:
        logger.exception("URL check failed for URL: %s", request_data.url)
        response = CheckURLResponse(
            success=False,
            error=f"Check failed: {str(exc)}",
            error_code="CHECK_FAILED",
        )
        http_response = func.HttpResponse(
            response.model_dump_json(),
            status_code=500,
            mimetype="application/json",
        )
        return add_cors_headers(http_response)




@app.route(route="classify", methods=["POST", "OPTIONS"])
def classify_scam(req: func.HttpRequest) -> func.HttpResponse:
    """
    Classify whether the supplied text / message is a scam.

    Request body (JSON):
        {
            "text": "<message to classify>"
        }

    Response (JSON):
        {
            "classification": "SCAM" | "LIKELY_SCAM" | "SUSPICIOUS" | "SAFE",
            "confidence": 0.0-1.0,
            "reasoning": "<brief explanation>"
        }
    """
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
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

@app.route(route="analyze", methods=["POST", "OPTIONS"])
def analyze_message(req: func.HttpRequest) -> func.HttpResponse:
    """
    Perform a detailed analysis of the supplied text, highlighting red flags,
    persuasion techniques, and any impersonation indicators.

    Request body (JSON):
        {
            "text": "<message to analyze>"
        }

    Response (JSON):
        {
            "red_flags": ["..."],
            "persuasion_techniques": ["..."],
            "impersonation_indicators": ["..."],
            "summary": "..."
        }
    """
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
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

@app.route(route="guidance", methods=["POST", "OPTIONS"])
def safety_guidance(req: func.HttpRequest) -> func.HttpResponse:
    """
    Generate step-by-step safety guidance for a user who has received a
    suspicious message.

    Request body (JSON):
        {
            "text": "<message the user received>",
            "context": "<optional additional context>"
        }

    Response (JSON):
        {
            "immediate_actions": ["..."],
            "reporting_steps": ["..."],
            "prevention_tips": ["..."],
            "resources": ["..."]
        }
    """
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
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
