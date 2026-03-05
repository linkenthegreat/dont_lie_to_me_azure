"""
Dont Lie To Me – Azure
Azure Functions v2 (Python) entry point.

HTTP endpoints are served via Blueprint.
MCP tools are registered directly on the FunctionApp.
"""

import azure.functions as func
from blueprints.http_api import bp as http_bp
from mcp_tools.tool_definitions import register_mcp_tools

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# HTTP endpoints (Blueprint)
app.register_functions(http_bp)

# MCP tool triggers (must be on main app, not Blueprint)
register_mcp_tools(app)
