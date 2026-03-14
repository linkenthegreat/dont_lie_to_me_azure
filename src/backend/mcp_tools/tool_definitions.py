"""MCP tool triggers registered on the main FunctionApp.

MCP tool triggers do not support Blueprints, so we use a
register_mcp_tools(app) pattern to keep definitions modular
while registering on the main app object.
"""

import json
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Testable handler functions (no Azure decorator dependency)
# ---------------------------------------------------------------------------


def _handle_store_analysis(args: dict) -> dict:
    """Store a scam analysis result in Cosmos DB."""
    from services.cosmos_service import get_cosmos_service

    service = get_cosmos_service()
    result_data = args.get("result", "{}")
    if isinstance(result_data, str):
        result_data = json.loads(result_data)

    doc = service.upsert_analysis(
        session_id=args["session_id"],
        endpoint=args["endpoint"],
        input_text=args["input_text"],
        result=result_data,
    )
    return {"content": f"Analysis stored. Document ID: {doc['id']}"}


def _handle_query_history(args: dict) -> dict:
    """Query past scam analyses for a session."""
    from services.cosmos_service import get_cosmos_service

    service = get_cosmos_service()
    limit = int(args.get("limit", "10"))
    results = service.query_history(session_id=args["session_id"], limit=limit)
    return {"content": json.dumps(results, default=str)}


def _handle_check_known_scam(args: dict) -> dict:
    """Search for similar known scam patterns."""
    from services.cosmos_service import get_cosmos_service

    service = get_cosmos_service()
    threshold = float(args.get("threshold", "0.8"))
    matches = service.query_known_scams(text=args["text"], threshold=threshold)
    return {"content": json.dumps(matches, default=str)}


# Maximum base64 characters accepted for the image MCP tool (~1 MB raw → ~1.4 MB base64).
# Prevents oversized JSON payloads from exhausting function memory.
_IMAGE_MCP_MAX_BASE64_CHARS = 1_400_000


def _handle_check_url_threat(args: dict) -> dict:
    """Check a URL against threat intelligence sources (Google Safe Browsing + URLhaus + risk hints)."""
    url = args.get("url", "").strip()
    if not url:
        return {"content": json.dumps({"error": "url argument is required"})}

    from shared.url_checker import get_url_checker

    try:
        checker = get_url_checker()
    except ValueError as exc:
        logger.warning("URL checker unavailable: %s", exc)
        return {"content": json.dumps({"error": "URL checking service is unavailable", "detail": str(exc)})}

    result = checker.check_url(url)
    payload = {
        "url": url,
        "verdict": result.verdict if hasattr(result, "verdict") else str(result.verdict),
        "confidence": result.confidence if hasattr(result, "confidence") else str(result.confidence),
        "threat_category": result.threat_category,
        "summary": result.summary,
        "risk_hints": result.risk_hints if hasattr(result, "risk_hints") else [],
        "sources_checked": result.sources_checked if hasattr(result, "sources_checked") else [],
        "cached": getattr(result, "cached", False),
    }
    return {"content": json.dumps(payload, default=str)}


def _handle_analyze_image_authenticity(args: dict) -> dict:
    """Analyze an image for signs of manipulation, AI generation, or deepfake."""
    image_data = args.get("image_base64", "").strip()
    if not image_data:
        return {"content": json.dumps({"error": "image_base64 argument is required"})}

    # Strip data URI prefix if present (e.g. "data:image/png;base64,...")
    if image_data.startswith("data:"):
        comma_pos = image_data.find(",")
        if comma_pos != -1:
            image_data = image_data[comma_pos + 1:]

    # Size guard: reject excessively large payloads
    if len(image_data) > _IMAGE_MCP_MAX_BASE64_CHARS:
        return {
            "content": json.dumps({
                "error": "Image too large",
                "detail": f"base64 length {len(image_data)} exceeds limit {_IMAGE_MCP_MAX_BASE64_CHARS}",
            })
        }

    image_media_type = args.get("image_media_type", "image/png")

    from services.image_analysis_service import analyze_image

    try:
        result = analyze_image(image_base64=image_data, image_media_type=image_media_type)
    except Exception as exc:
        logger.exception("Image analysis failed")
        return {"content": json.dumps({"error": "Image analysis failed", "detail": str(exc)})}

    # Return bounded output — callers only need the top-level summary fields
    payload = {
        "verdict": result.get("verdict", "INCONCLUSIVE"),
        "authenticity_score": result.get("authenticity_score"),
        "manipulation_indicators": result.get("manipulation_indicators", []),
        "summary": result.get("summary", ""),
    }
    return {"content": json.dumps(payload, default=str)}


# ---------------------------------------------------------------------------
# Registration (decorators must be applied on the FunctionApp)
# ---------------------------------------------------------------------------


def register_mcp_tools(app):
    """Register all MCP tool triggers on the given FunctionApp."""

    @app.generic_trigger(
        arg_name="context",
        type="mcpToolTrigger",
        toolName="store_analysis",
        description="Store a scam analysis result in Cosmos DB for future reference",
        toolProperties=json.dumps([
            {"propertyName": "session_id", "propertyType": "string", "description": "Unique session identifier"},
            {"propertyName": "endpoint", "propertyType": "string", "description": "Analysis endpoint: classify, analyze, or guidance"},
            {"propertyName": "input_text", "propertyType": "string", "description": "The original text that was analyzed"},
            {"propertyName": "result", "propertyType": "string", "description": "JSON string of the analysis result"},
        ]),
    )
    def store_analysis(context: str) -> str:
        request = json.loads(context)
        args = request.get("arguments", {})
        return json.dumps(_handle_store_analysis(args))

    @app.generic_trigger(
        arg_name="context",
        type="mcpToolTrigger",
        toolName="query_history",
        description="Query past scam analyses for a given session",
        toolProperties=json.dumps([
            {"propertyName": "session_id", "propertyType": "string", "description": "Session ID to query history for"},
            {"propertyName": "limit", "propertyType": "string", "description": "Maximum number of results to return (default: 10)"},
        ]),
    )
    def query_history(context: str) -> str:
        request = json.loads(context)
        args = request.get("arguments", {})
        return json.dumps(_handle_query_history(args))

    @app.generic_trigger(
        arg_name="context",
        type="mcpToolTrigger",
        toolName="check_known_scam",
        description="Search for similar known scam patterns in the database",
        toolProperties=json.dumps([
            {"propertyName": "text", "propertyType": "string", "description": "Text to check against known scam patterns"},
            {"propertyName": "threshold", "propertyType": "string", "description": "Similarity threshold 0.0-1.0 (default: 0.8)"},
        ]),
    )
    def check_known_scam(context: str) -> str:
        request = json.loads(context)
        args = request.get("arguments", {})
        return json.dumps(_handle_check_known_scam(args))

    @app.generic_trigger(
        arg_name="context",
        type="mcpToolTrigger",
        toolName="check_url_threat",
        description="Check a URL against threat intelligence sources (Google Safe Browsing, URLhaus, local risk hints). Returns verdict, confidence, and threat summary.",
        toolProperties=json.dumps([
            {"propertyName": "url", "propertyType": "string", "description": "The URL to check for threats (must be a valid http/https URL)"},
        ]),
    )
    def check_url_threat(context: str) -> str:
        request = json.loads(context)
        args = request.get("arguments", {})
        return json.dumps(_handle_check_url_threat(args))

    @app.generic_trigger(
        arg_name="context",
        type="mcpToolTrigger",
        toolName="analyze_image_authenticity",
        description="Analyze an image for manipulation, AI generation, or deepfake artifacts. Returns verdict, authenticity score, and manipulation indicators.",
        toolProperties=json.dumps([
            {"propertyName": "image_base64", "propertyType": "string", "description": "Base64-encoded image data, with or without a data URI prefix (data:image/...;base64,...)"},
            {"propertyName": "image_media_type", "propertyType": "string", "description": "MIME type of the image, e.g. image/png or image/jpeg (default: image/png)"},
        ]),
    )
    def analyze_image_authenticity(context: str) -> str:
        request = json.loads(context)
        args = request.get("arguments", {})
        return json.dumps(_handle_analyze_image_authenticity(args))
