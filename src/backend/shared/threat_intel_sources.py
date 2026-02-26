"""
Threat intelligence API clients for URL checking.

Provides clients for:
- Google Safe Browsing API (primary phishing/malware detection)
- URLhaus API (malware-specific threat detection)
"""

import os
import time
import logging
import requests
from typing import Optional, List
from shared.models import GoogleSafeBrowsingResult, URLhausResult

logger = logging.getLogger(__name__)

# Configuration
GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

# Request/response timeouts (milliseconds)
REQUEST_TIMEOUT_SECONDS = 5.0
URLHAUS_TIMEOUT_SECONDS = 5.0


class GoogleSafeBrowsingClient:
    """Client for Google Safe Browsing API."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Google Safe Browsing client.

        Args:
            api_key: Optional API key. If not provided, will use
                     GOOGLE_SAFE_BROWSING_API_KEY environment variable.

        Raises:
            ValueError: If no API key is provided or available.
        """
        self.api_key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GOOGLE_SAFE_BROWSING_API_KEY environment variable not set"
            )
        self.base_url = GOOGLE_SAFE_BROWSING_API_URL

    def check_url(self, url: str) -> GoogleSafeBrowsingResult:
        """
        Check if URL is flagged by Google Safe Browsing.

        Args:
            url: URL to check.

        Returns:
            GoogleSafeBrowsingResult with findings.
        """
        start_time = time.time()

        try:
            payload = {
                "client": {
                    "clientId": "dont-lie-to-me",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["WINDOWS", "LINUX", "ANDROID", "MACOS"],
                    "uris": [url],
                },
            }

            response = requests.post(
                self.base_url,
                json=payload,
                params={"key": self.api_key},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            response_time_ms = int((time.time() - start_time) * 1000)
            data = response.json()

            # Check if matches were found
            if "matches" in data and data["matches"]:
                matches = data["matches"]
                threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
                platform_types = list(
                    set(
                        m.get("platformType", "UNKNOWN")
                        for m in matches
                        if "platformType" in m
                    )
                )
                cache_duration = (
                    data.get("cacheDuration", "3600s")
                    .replace("s", "")
                    .replace("m", "m")
                )

                return GoogleSafeBrowsingResult(
                    is_flagged=True,
                    threat_types=threat_types,
                    platform_types=platform_types,
                    cache_duration_seconds=int(cache_duration),
                    error=None,
                    response_time_ms=response_time_ms,
                )
            else:
                return GoogleSafeBrowsingResult(
                    is_flagged=False,
                    threat_types=[],
                    platform_types=[],
                    cache_duration_seconds=3600,
                    error=None,
                    response_time_ms=response_time_ms,
                )

        except requests.exceptions.Timeout:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.warning(
                "Google Safe Browsing API timeout for URL: %s", url
            )
            return GoogleSafeBrowsingResult(
                is_flagged=False,
                error="API timeout",
                response_time_ms=response_time_ms,
            )

        except requests.exceptions.RequestException as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "Google Safe Browsing API error for URL %s: %s", url, str(exc)
            )
            return GoogleSafeBrowsingResult(
                is_flagged=False,
                error=f"API error: {str(exc)}",
                response_time_ms=response_time_ms,
            )

        except Exception as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.exception(
                "Unexpected error checking URL with Google Safe Browsing: %s", url
            )
            return GoogleSafeBrowsingResult(
                is_flagged=False,
                error=f"Unexpected error: {str(exc)}",
                response_time_ms=response_time_ms,
            )


class URLhausClient:
    """Client for URLhaus API (abuse.ch)."""

    def __init__(self):
        """Initialize URLhaus client (no API key required)."""
        self.base_url = URLHAUS_API_URL

    def check_url(self, url: str) -> URLhausResult:
        """
        Check if URL is listed in URLhaus malware database.

        Args:
            url: URL to check.

        Returns:
            URLhausResult with findings.
        """
        start_time = time.time()

        try:
            # URLhaus expects URL as a form parameter
            payload = {"url": url}

            response = requests.post(
                self.base_url,
                data=payload,
                timeout=URLHAUS_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            response_time_ms = int((time.time() - start_time) * 1000)
            data = response.json()

            # Check response status
            if data.get("query_status") == "ok":
                result = data.get("result", "not_found")

                if result == "not_found":
                    return URLhausResult(
                        is_flagged=False,
                        threat_type=None,
                        date_added=None,
                        url_status=None,
                        error=None,
                        response_time_ms=response_time_ms,
                    )
                else:
                    # URL is in database
                    threat_type = result[0].get("threat", "unknown")
                    date_added = result[0].get("date_added")
                    url_status = result[0].get("url_status")

                    return URLhausResult(
                        is_flagged=True,
                        threat_type=threat_type,
                        date_added=date_added,
                        url_status=url_status,
                        error=None,
                        response_time_ms=response_time_ms,
                    )
            else:
                error_msg = data.get("query_status", "unknown error")
                logger.warning(
                    "URLhaus API error for URL %s: %s", url, error_msg
                )
                return URLhausResult(
                    is_flagged=False,
                    error=error_msg,
                    response_time_ms=response_time_ms,
                )

        except requests.exceptions.Timeout:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.warning("URLhaus API timeout for URL: %s", url)
            return URLhausResult(
                is_flagged=False,
                error="API timeout",
                response_time_ms=response_time_ms,
            )

        except requests.exceptions.RequestException as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error("URLhaus API error for URL %s: %s", url, str(exc))
            return URLhausResult(
                is_flagged=False,
                error=f"API error: {str(exc)}",
                response_time_ms=response_time_ms,
            )

        except Exception as exc:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.exception("Unexpected error checking URL with URLhaus: %s", url)
            return URLhausResult(
                is_flagged=False,
                error=f"Unexpected error: {str(exc)}",
                response_time_ms=response_time_ms,
            )
