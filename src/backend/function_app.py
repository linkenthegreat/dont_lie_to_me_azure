"""
<<<<<<< HEAD
Dont Lie To Me – Azure
Azure Functions v2 (Python) entry point.

HTTP endpoints are served via Blueprint.
MCP tools are registered directly on the FunctionApp.
<<<<<<< HEAD
<<<<<<< HEAD
CORS is enabled for local development and cross-origin requests.
=======
Dont Lie To Me -- Azure
Azure Functions v2 (Python) entry point.

HTTP endpoints are served directly on the FunctionApp.
MCP tools are registered directly on the FunctionApp.
>>>>>>> origin/main
"""

import json
import logging
<<<<<<< HEAD

=======
"""

>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
"""

>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
import azure.functions as func
from shared.ai_client import AzureAIClient
from shared.url_checker import URLChecker
from shared.models import CheckURLRequest, CheckURLResponse
<<<<<<< HEAD
<<<<<<< HEAD
from shared.cors import add_cors_headers
from services import scam_classifier, message_analyzer, guidance_generator
=======
import time
import uuid
from datetime import datetime, timezone

import azure.functions as func
from shared.ai_client import AzureAIClient
from shared.url_checker import URLChecker
from shared.models import CheckURLRequest, CheckURLResponse
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

logger = logging.getLogger(__name__)

<<<<<<< HEAD
# Initialize URL checker (will raise error if API key not configured)
_url_checker = None

=======
# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_url_checker = None


>>>>>>> origin/main
def _get_url_checker() -> URLChecker:
    """Lazy initialization of URL checker."""
    global _url_checker
    if _url_checker is None:
        try:
            _url_checker = URLChecker()
        except ValueError as e:
            logger.error("Failed to initialize URL checker: %s", e)
<<<<<<< HEAD
            # Will be handled in the endpoint
    return _url_checker


=======
    return _url_checker


def _persist_analysis(
    endpoint: str, input_text: str, result: dict, session_id: str = ""
) -> None:
    """Best-effort persistence of analysis results to Cosmos DB."""
    try:
        from services.cosmos_service import get_cosmos_service

        cosmos = get_cosmos_service()
        if not session_id:
            session_id = str(uuid.uuid4())
        cosmos.upsert_analysis(
            session_id=session_id,
            endpoint=endpoint,
            input_text=input_text,
            result=result,
        )
    except Exception as exc:
        logger.warning("Failed to persist analysis to Cosmos DB: %s", exc)


def _try_cache_get(endpoint: str, text: str):
    """Try to get a cached result. Returns (cache_key, result) or (key, None)."""
    try:
        from services.cache_service import get_cache_service, CacheService

        cache = get_cache_service()
        if cache:
            cache_key = CacheService.make_key(endpoint, text)
            cached = cache.get(cache_key)
            if cached:
                from services.telemetry import track_cache_event

                track_cache_event(endpoint, hit=True)
                return cache_key, cached
            else:
                from services.telemetry import track_cache_event

                track_cache_event(endpoint, hit=False)
                return cache_key, None
    except Exception:
        pass
    return None, None


def _try_cache_set(cache_key: str, result: dict, ttl: int = 1800) -> None:
    """Try to cache a result."""
    if not cache_key:
        return
    try:
        from services.cache_service import get_cache_service

        cache = get_cache_service()
        if cache:
            cache.set(cache_key, result, ttl=ttl)
    except Exception:
        pass


def _track_request(endpoint: str, start_time: float, status: str, cached: bool = False):
    """Track request telemetry."""
    try:
        from services.telemetry import track_request

        latency_ms = (time.time() - start_time) * 1000
        track_request(endpoint, latency_ms, status, cached)
    except Exception:
        pass


>>>>>>> origin/main
# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
@app.route(route="health", methods=["GET", "OPTIONS"], auth_level=func.AuthLevel.ANONYMOUS)
=======
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe – no auth required."""
    return func.HttpResponse(
        json.dumps({"status": "ok", "service": "dont-lie-to-me-azure"}),
        status_code=200,
        mimetype="application/json",
    )
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======

@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Simple liveness probe -- no auth required."""
    health_data = {"status": "ok", "service": "dont-lie-to-me-azure"}

    # Include Redis health if configured
    try:
        from services.cache_service import get_cache_service

        cache = get_cache_service()
        if cache:
            health_data["redis"] = "connected" if cache.health_check() else "disconnected"
    except Exception:
        pass

    return func.HttpResponse(
        json.dumps(health_data),
        status_code=200,
        mimetype="application/json",
    )
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


# ---------------------------------------------------------------------------
# URL threat checking
# ---------------------------------------------------------------------------

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
@app.route(route="check-url", methods=["POST", "OPTIONS"])
=======
@app.route(route="check-url", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
@app.route(route="check-url", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
=======

@app.route(route="check-url", methods=["POST"])
def check_url(req: func.HttpRequest) -> func.HttpResponse:
    """Check if a URL is flagged as a threat by threat intelligence sources."""
    start_time = time.time()
>>>>>>> origin/main
    try:
        body = req.get_json()
    except ValueError:
        response = CheckURLResponse(
            success=False,
            error="Request body must be valid JSON",
            error_code="INVALID_JSON",
        )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        http_response = func.HttpResponse(
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
            response.model_dump_json(),
            status_code=400,
            mimetype="application/json",
        )

    # Validate request
=======
        return func.HttpResponse(
            response.model_dump_json(), status_code=400, mimetype="application/json"
        )

>>>>>>> origin/main
    try:
        request_data = CheckURLRequest(**body)
    except ValueError as exc:
        response = CheckURLResponse(
            success=False,
            error=f"Invalid request: {str(exc)}",
            error_code="INVALID_REQUEST",
        )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        http_response = func.HttpResponse(
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
            response.model_dump_json(),
            status_code=400,
            mimetype="application/json",
        )

    # Get URL checker
=======
        return func.HttpResponse(
            response.model_dump_json(), status_code=400, mimetype="application/json"
        )

>>>>>>> origin/main
    url_checker = _get_url_checker()
    if url_checker is None:
        response = CheckURLResponse(
            success=False,
            error="URL checker is not available. Please check configuration.",
            error_code="CHECKER_UNAVAILABLE",
        )
        return func.HttpResponse(
<<<<<<< HEAD
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
        return func.HttpResponse(
            response.model_dump_json(),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:
        logger.exception("URL check failed for URL: %s", request_data.url)
=======
            response.model_dump_json(), status_code=500, mimetype="application/json"
        )

    try:
        result = url_checker.check_url(
            url=request_data.url, use_cache=request_data.use_cache
        )
        response = CheckURLResponse(
            success=True, data=result, error=None, error_code=None
        )
        _track_request("check-url", start_time, "success")
        return func.HttpResponse(
            response.model_dump_json(), status_code=200, mimetype="application/json"
        )
    except Exception as exc:
        logger.exception("URL check failed for URL: %s", request_data.url)
        _track_request("check-url", start_time, "error")
>>>>>>> origin/main
        response = CheckURLResponse(
            success=False,
            error=f"Check failed: {str(exc)}",
            error_code="CHECK_FAILED",
        )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        http_response = func.HttpResponse(
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
        return func.HttpResponse(
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
            response.model_dump_json(),
            status_code=500,
            mimetype="application/json",
        )




@app.route(route="classify", methods=["POST"])
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
<<<<<<< HEAD
<<<<<<< HEAD
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
=======
        return func.HttpResponse(
            response.model_dump_json(), status_code=500, mimetype="application/json"
        )


# ---------------------------------------------------------------------------
# Scam classification
# ---------------------------------------------------------------------------


@app.route(route="classify", methods=["POST"])
def classify_scam(req: func.HttpRequest) -> func.HttpResponse:
    """Classify whether the supplied text / message is a scam."""
    start_time = time.time()
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
=======
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    system_prompt = (
        "You are an expert anti-scam analyst. "
        "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
        "Reply ONLY with a JSON object matching this schema: "
        '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
        "Do not include markdown fences."
    )

<<<<<<< HEAD
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
    session_id = body.get("session_id", "")

    # Check cache
    cache_key, cached_result = _try_cache_get("classify", text)
    if cached_result:
        cached_result["_cached"] = True
        _track_request("classify", start_time, "success", cached=True)
        return func.HttpResponse(
            json.dumps(cached_result), status_code=200, mimetype="application/json"
        )

    system_prompt = (
        "You are an expert anti-scam analyst. "
        "Classify the following message as one of: SCAM, LIKELY_SCAM, SUSPICIOUS, or SAFE. "
        "Reply ONLY with a JSON object matching this schema: "
        '{"classification": "...", "confidence": 0.0, "reasoning": "..."}. '
        "Do not include markdown fences."
    )

    try:
        client = AzureAIClient()
        raw = client.chat(system_prompt=system_prompt, user_message=text)
        result = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Model returned non-JSON output: %s", raw)
        result = {"classification": "UNKNOWN", "confidence": 0.0, "reasoning": raw}
    except Exception as exc:
        logger.exception("Classification failed")
        _track_request("classify", start_time, "error")
        return _internal_error(str(exc))

    # Cache result
    _try_cache_set(cache_key, result, ttl=1800)

    # Persist to Cosmos DB
    _persist_analysis("classify", text, result, session_id)

    # Track classification type
    try:
        from services.telemetry import track_classification

        track_classification(result.get("classification", "UNKNOWN"))
    except Exception:
        pass

    # Notify Teams on scam detection
    classification = result.get("classification", "")
    if classification in ("SCAM", "LIKELY_SCAM"):
        try:
            from services.teams_integration import get_teams_notifier

            notifier = get_teams_notifier()
            if notifier:
                notifier.send_scam_alert(
                    classification=classification,
                    confidence=result.get("confidence", 0),
                    text_snippet=text[:150],
                    reasoning=result.get("reasoning", ""),
                )
        except Exception as exc:
            logger.warning("Teams notification failed: %s", exc)

    _track_request("classify", start_time, "success")
    return func.HttpResponse(
        json.dumps(result), status_code=200, mimetype="application/json"
    )
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
@app.route(route="analyze", methods=["POST", "OPTIONS"])
=======
@app.route(route="analyze", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
@app.route(route="analyze", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
=======

@app.route(route="analyze", methods=["POST"])
def analyze_message(req: func.HttpRequest) -> func.HttpResponse:
    """Perform a detailed analysis of the supplied text."""
    start_time = time.time()
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
=======
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    system_prompt = (
        "You are a cybersecurity expert specialising in social engineering and scam detection. "
        "Analyse the provided message and return a JSON object with these keys: "
        '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
        '"impersonation_indicators" (list of strings), "summary" (string). '
        "Do not include markdown fences."
    )

<<<<<<< HEAD
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
    session_id = body.get("session_id", "")

    # Check cache
    cache_key, cached_result = _try_cache_get("analyze", text)
    if cached_result:
        cached_result["_cached"] = True
        _track_request("analyze", start_time, "success", cached=True)
        return func.HttpResponse(
            json.dumps(cached_result), status_code=200, mimetype="application/json"
        )

    system_prompt = (
        "You are a cybersecurity expert specialising in social engineering and scam detection. "
        "Analyse the provided message and return a JSON object with these keys: "
        '"red_flags" (list of strings), "persuasion_techniques" (list of strings), '
        '"impersonation_indicators" (list of strings), "summary" (string). '
        "Do not include markdown fences."
    )

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
        _track_request("analyze", start_time, "error")
        return _internal_error(str(exc))

    _try_cache_set(cache_key, result, ttl=1800)
    _persist_analysis("analyze", text, result, session_id)
    _track_request("analyze", start_time, "success")

    return func.HttpResponse(
        json.dumps(result), status_code=200, mimetype="application/json"
    )
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


# ---------------------------------------------------------------------------
# Safety guidance
# ---------------------------------------------------------------------------

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
@app.route(route="guidance", methods=["POST", "OPTIONS"])
=======
@app.route(route="guidance", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
@app.route(route="guidance", methods=["POST"])
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
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
<<<<<<< HEAD
<<<<<<< HEAD
    if req.method == "OPTIONS":
        return func.HttpResponse("", status_code=200, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })
    
=======

@app.route(route="guidance", methods=["POST"])
def safety_guidance(req: func.HttpRequest) -> func.HttpResponse:
    """Generate step-by-step safety guidance for a suspicious message."""
    start_time = time.time()
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    text = body.get("text", "").strip()
    if not text:
        return _bad_request("'text' field is required and must not be empty.")

<<<<<<< HEAD
    context = body.get("context", "").strip()
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
<<<<<<< HEAD
<<<<<<< HEAD
    return add_cors_headers(response)
=======
    session_id = body.get("session_id", "")
    context = body.get("context", "").strip()
    user_message = f"Message: {text}"
    if context:
        user_message += f"\n\nAdditional context: {context}"

    # Check cache
    cache_key, cached_result = _try_cache_get("guidance", text)
    if cached_result:
        cached_result["_cached"] = True
        _track_request("guidance", start_time, "success", cached=True)
        return func.HttpResponse(
            json.dumps(cached_result), status_code=200, mimetype="application/json"
        )

    system_prompt = (
        "You are a consumer protection advisor. "
        "A user has received a potentially fraudulent message. "
        "Provide practical safety guidance as a JSON object with keys: "
        '"immediate_actions" (list), "reporting_steps" (list), '
        '"prevention_tips" (list), "resources" (list of helpful URLs or organisations). '
        "Do not include markdown fences."
    )

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
        _track_request("guidance", start_time, "error")
        return _internal_error(str(exc))

    _try_cache_set(cache_key, result, ttl=1800)
    _persist_analysis("guidance", text, result, session_id)
    _track_request("guidance", start_time, "success")

    return func.HttpResponse(
        json.dumps(result), status_code=200, mimetype="application/json"
    )


# ---------------------------------------------------------------------------
# Sentiment analysis & manipulation detection (Issue #8)
# ---------------------------------------------------------------------------


@app.route(route="sentiment", methods=["POST"])
def sentiment_analysis(req: func.HttpRequest) -> func.HttpResponse:
    """Analyze sentiment and manipulation techniques in a message."""
    start_time = time.time()
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    text = body.get("text", "").strip()
    if not text:
        return _bad_request("'text' field is required and must not be empty.")

    session_id = body.get("session_id", "")

    # Check cache
    cache_key, cached_result = _try_cache_get("sentiment", text)
    if cached_result:
        cached_result["_cached"] = True
        _track_request("sentiment", start_time, "success", cached=True)
        return func.HttpResponse(
            json.dumps(cached_result), status_code=200, mimetype="application/json"
        )

    try:
        from services.sentiment_service import analyze_sentiment

        result = analyze_sentiment(text)
    except Exception as exc:
        logger.exception("Sentiment analysis failed")
        _track_request("sentiment", start_time, "error")
        return _internal_error(str(exc))

    _try_cache_set(cache_key, result, ttl=1800)
    _persist_analysis("sentiment", text, result, session_id)
    _track_request("sentiment", start_time, "success")

    return func.HttpResponse(
        json.dumps(result), status_code=200, mimetype="application/json"
    )


# ---------------------------------------------------------------------------
# Analysis history (Issue #7 / #8 -- Cosmos DB wired)
# ---------------------------------------------------------------------------


@app.route(route="history", methods=["GET"])
def get_history(req: func.HttpRequest) -> func.HttpResponse:
    """Retrieve past analyses for a session."""
    session_id = req.params.get("session_id", "")
    if not session_id:
        return _bad_request("'session_id' query parameter is required.")

    limit = int(req.params.get("limit", "10"))

    try:
        from services.cosmos_service import get_cosmos_service

        cosmos = get_cosmos_service()
        results = cosmos.query_history(session_id=session_id, limit=limit)
        return func.HttpResponse(
            json.dumps(results, default=str),
            status_code=200,
            mimetype="application/json",
        )
    except Exception as exc:
        logger.exception("History query failed")
        return _internal_error(str(exc))


# ---------------------------------------------------------------------------
# i18n translations (Issue #8)
# ---------------------------------------------------------------------------


@app.route(route="i18n", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_i18n(req: func.HttpRequest) -> func.HttpResponse:
    """Get translation bundle for a language."""
    from i18n.translations import get_translations_bundle, SUPPORTED_LANGUAGES

    lang = req.params.get("lang", "en")
    bundle = get_translations_bundle(lang)
    bundle["supported_languages"] = SUPPORTED_LANGUAGES
    return func.HttpResponse(
        json.dumps(bundle), status_code=200, mimetype="application/json"
    )


# ---------------------------------------------------------------------------
# Export reports (Issue #8)
# ---------------------------------------------------------------------------


@app.route(route="export", methods=["GET"])
def export_report(req: func.HttpRequest) -> func.HttpResponse:
    """Export analysis history as CSV or PDF."""
    session_id = req.params.get("session_id", "")
    format_type = req.params.get("format", "csv").lower()

    if not session_id:
        return _bad_request("'session_id' query parameter is required.")

    try:
        from services.cosmos_service import get_cosmos_service

        cosmos = get_cosmos_service()
        analyses = cosmos.query_history(session_id=session_id, limit=100)

        if format_type == "pdf":
            from services.export_service import generate_pdf_report

            pdf_bytes = generate_pdf_report(analyses)
            return func.HttpResponse(
                pdf_bytes,
                status_code=200,
                mimetype="application/pdf",
                headers={"Content-Disposition": "attachment; filename=scam-report.pdf"},
            )
        else:
            from services.export_service import generate_csv_report

            csv_data = generate_csv_report(analyses)
            return func.HttpResponse(
                csv_data,
                status_code=200,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=scam-report.csv"},
            )
    except Exception as exc:
        logger.exception("Export failed")
        return _internal_error(str(exc))


# ---------------------------------------------------------------------------
# GDPR compliance (Issue #8 / #9)
# ---------------------------------------------------------------------------


@app.route(route="gdpr/delete", methods=["DELETE"])
def gdpr_delete(req: func.HttpRequest) -> func.HttpResponse:
    """GDPR right to erasure -- delete all data for a session."""
    session_id = req.params.get("session_id", "")
    if not session_id:
        return _bad_request("'session_id' query parameter is required.")

    try:
        from services.gdpr_service import delete_user_data
        from services.audit_logger import log_gdpr_request

        result = delete_user_data(session_id)
        log_gdpr_request("ERASURE", session_id, "completed")
        return func.HttpResponse(
            json.dumps(result), status_code=200, mimetype="application/json"
        )
    except Exception as exc:
        logger.exception("GDPR delete failed")
        return _internal_error(str(exc))


@app.route(route="gdpr/export", methods=["GET"])
def gdpr_export(req: func.HttpRequest) -> func.HttpResponse:
    """GDPR data portability -- export all data for a session."""
    session_id = req.params.get("session_id", "")
    if not session_id:
        return _bad_request("'session_id' query parameter is required.")

    try:
        from services.gdpr_service import export_user_data
        from services.audit_logger import log_gdpr_request

        data = export_user_data(session_id)
        log_gdpr_request("EXPORT", session_id, "completed")
        return func.HttpResponse(
            json.dumps(data, default=str),
            status_code=200,
            mimetype="application/json",
        )
    except Exception as exc:
        logger.exception("GDPR export failed")
        return _internal_error(str(exc))


# ---------------------------------------------------------------------------
# Microsoft Teams notification (Issue #8)
# ---------------------------------------------------------------------------


@app.route(route="notify-teams", methods=["POST"])
def notify_teams(req: func.HttpRequest) -> func.HttpResponse:
    """Send a scam report to Microsoft Teams."""
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    classification = body.get("classification", "")
    confidence = body.get("confidence", 0)
    text_snippet = body.get("text_snippet", "")
    reasoning = body.get("reasoning", "")

    if not classification:
        return _bad_request("'classification' field is required.")

    try:
        from services.teams_integration import get_teams_notifier

        notifier = get_teams_notifier()
        if not notifier:
            return _bad_request("Teams webhook URL not configured.")

        success = notifier.send_scam_alert(
            classification=classification,
            confidence=confidence,
            text_snippet=text_snippet,
            reasoning=reasoning,
        )
        return func.HttpResponse(
            json.dumps({"sent": success}),
            status_code=200,
            mimetype="application/json",
        )
    except Exception as exc:
        logger.exception("Teams notification failed")
        return _internal_error(str(exc))


# ---------------------------------------------------------------------------
# User feedback (Issue #10)
# ---------------------------------------------------------------------------


@app.route(route="feedback", methods=["POST"])
def submit_feedback(req: func.HttpRequest) -> func.HttpResponse:
    """Collect user feedback on analysis accuracy."""
    try:
        body = req.get_json()
    except ValueError:
        return _bad_request("Request body must be valid JSON.")

    rating = body.get("rating")
    if rating is None:
        return _bad_request("'rating' field is required.")

    analysis_id = body.get("analysis_id", "")
    comment = body.get("comment", "")
    was_accurate = body.get("was_accurate")

    try:
        from services.cosmos_service import get_cosmos_service

        cosmos = get_cosmos_service()
        feedback_doc = {
            "id": str(uuid.uuid4()),
            "sessionId": "feedback",
            "type": "feedback",
            "analysisId": analysis_id,
            "rating": rating,
            "wasAccurate": was_accurate,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        cosmos._container.upsert_item(feedback_doc)
        return func.HttpResponse(
            json.dumps({"status": "received"}),
            status_code=200,
            mimetype="application/json",
        )
    except Exception as exc:
        logger.exception("Feedback submission failed")
        return _internal_error(str(exc))


# ---------------------------------------------------------------------------
# Scheduled data cleanup (Issue #9 / #10)
# ---------------------------------------------------------------------------


@app.timer_trigger(
    schedule="0 0 3 * * 0",
    arg_name="timer",
    run_on_startup=False,
)
def cleanup_expired_data(timer: func.TimerRequest) -> None:
    """Periodic cleanup of expired data -- runs weekly at 3 AM Sunday.

    Cosmos DB TTL handles document expiration automatically.
    This function handles supplementary cleanup (audit logs, cache).
    """
    logger.info("Running scheduled data cleanup")
    try:
        from services.cache_service import get_cache_service

        cache = get_cache_service()
        if cache:
            logger.info("Cache service is available for cleanup")
    except Exception as exc:
        logger.warning("Scheduled cleanup encountered an error: %s", exc)
>>>>>>> origin/main
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)
=======
>>>>>>> parent of 666ce7a (AI agent UI not refined and online search function not adding yet, branch phase E)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

<<<<<<< HEAD
def _bad_request(message: str) -> func.HttpResponse:
<<<<<<< HEAD
<<<<<<< HEAD
    response = func.HttpResponse(
=======

def _bad_request(message: str) -> func.HttpResponse:
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
