"""CORS middleware helper for local development and production."""

from typing import Dict
import azure.functions as func


def add_cors_headers(response: func.HttpResponse, allowed_origins: str = "*") -> func.HttpResponse:
    """
    Add CORS headers to any HTTP response.

    Parameters
    ----------
    response : func.HttpResponse
        The response to augment with CORS headers.
    allowed_origins : str
        Allowed origins (default: "*" for development; restrict in production).

    Returns
    -------
    func.HttpResponse
        The response with CORS headers added.
    """
    response.headers["Access-Control-Allow-Origin"] = allowed_origins
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, DELETE, PUT"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Max-Age"] = "3600"
    return response


def create_options_response(allowed_origins: str = "*") -> func.HttpResponse:
    """
    Create a preflight OPTIONS response for CORS.

    Parameters
    ----------
    allowed_origins : str
        Allowed origins (default: "*" for development).

    Returns
    -------
    func.HttpResponse
        204 No Content response with CORS headers.
    """
    response = func.HttpResponse("", status_code=204)
    return add_cors_headers(response, allowed_origins)
