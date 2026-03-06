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
