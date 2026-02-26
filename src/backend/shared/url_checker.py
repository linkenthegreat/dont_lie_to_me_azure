"""
URL Checker orchestrator for coordinating threat intelligence checks.

Coordinates:
- URL extraction and validation
- Parallel API calls to threat intelligence sources
- Local risk analysis
- Result merging and decision making
- Caching of results
"""

import logging
import time
from functools import lru_cache
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from shared.models import (
    URLCheckResult,
    VerdictType,
    ConfidenceLevel,
    ThreatType,
    GoogleSafeBrowsingResult,
    URLhausResult,
    RiskHintsResult,
)
from shared.url_validators import normalize_url, is_valid_url
from shared.threat_intel_sources import GoogleSafeBrowsingClient, URLhausClient
from shared.risk_hints import analyze_url_hints

logger = logging.getLogger(__name__)

# Configuration (should come from environment)
DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hour
DEFAULT_CHECK_TIMEOUT_SECONDS = 10


class URLChecker:
    """Main orchestrator for URL threat checking."""

    def __init__(
        self,
        google_sb_api_key: Optional[str] = None,
        cache_ttl_seconds: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ):
        """
        Initialize URL checker.

        Args:
            google_sb_api_key: Optional Google Safe Browsing API key.
            cache_ttl_seconds: Optional cache TTL in seconds.
            timeout_seconds: Optional timeout for checks in seconds.

        Raises:
            ValueError: If required API key is missing.
        """
        try:
            self.google_sb_client = GoogleSafeBrowsingClient(api_key=google_sb_api_key)
        except ValueError as e:
            logger.error("Failed to initialize Google Safe Browsing client: %s", e)
            raise

        self.urlhaus_client = URLhausClient()
        self.cache_ttl_seconds = cache_ttl_seconds or DEFAULT_CACHE_TTL_SECONDS
        self.timeout_seconds = timeout_seconds or DEFAULT_CHECK_TIMEOUT_SECONDS

        # Results cache: {url_hash: (result, timestamp)}
        self._results_cache: Dict[str, tuple] = {}

    def check_url(
        self, url: str, use_cache: bool = True
    ) -> URLCheckResult:
        """
        Check URL for threats using all available sources.

        Performs:
        1. URL validation and normalization
        2. Cache lookup (if enabled)
        3. Parallel API checks (Google Safe Browsing, URLhaus)
        4. Local risk analysis
        5. Result merging and decision
        6. Cache storage

        Args:
            url: URL to check.
            use_cache: Whether to use cached result if available.

        Returns:
            URLCheckResult with aggregated findings.
        """
        start_time = time.time()

        # Step 1: Validate and normalize URL
        normalized_url = normalize_url(url)
        if not normalized_url or not is_valid_url(url):
            return self._make_error_result(
                url,
                "Invalid or malformed URL",
                start_time,
            )

        # Step 2: Check cache
        if use_cache:
            cached = self._get_cached_result(normalized_url)
            if cached:
                cached.cached = True
                return cached

        # Step 3: Perform checks
        try:
            google_result, urlhaus_result, risk_hints_result = (
                self._perform_parallel_checks(normalized_url)
            )
        except Exception as exc:
            logger.exception("Error during parallel checks")
            return self._make_error_result(
                url,
                f"Check failed: {str(exc)}",
                start_time,
            )

        # Step 4: Merge results and decide on verdict
        result = self._merge_results(
            normalized_url,
            google_result,
            urlhaus_result,
            risk_hints_result,
            start_time,
        )

        # Step 5: Cache result
        self._cache_result(normalized_url, result)

        return result

    def _perform_parallel_checks(
        self, url: str
    ) -> tuple[GoogleSafeBrowsingResult, URLhausResult, RiskHintsResult]:
        """
        Perform threat checks in parallel.

        Args:
            url: Normalized URL to check.

        Returns:
            Tuple of (GoogleSafeBrowsingResult, URLhausResult, RiskHintsResult).
        """
        google_result = None
        urlhaus_result = None
        risk_hints_result = None

        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all checks
            google_future = executor.submit(
                self.google_sb_client.check_url, url
            )
            urlhaus_future = executor.submit(
                self.urlhaus_client.check_url, url
            )
            risk_hints_future = executor.submit(analyze_url_hints, url)

            # Collect results with timeout
            try:
                google_result = google_future.result(
                    timeout=self.timeout_seconds
                )
            except Exception as exc:
                logger.warning("Google Safe Browsing check failed: %s", exc)
                google_result = GoogleSafeBrowsingResult(
                    is_flagged=False,
                    error=str(exc),
                    response_time_ms=int(self.timeout_seconds * 1000),
                )

            try:
                urlhaus_result = urlhaus_future.result(
                    timeout=self.timeout_seconds
                )
            except Exception as exc:
                logger.warning("URLhaus check failed: %s", exc)
                urlhaus_result = URLhausResult(
                    is_flagged=False,
                    error=str(exc),
                    response_time_ms=int(self.timeout_seconds * 1000),
                )

            try:
                risk_hints_result = risk_hints_future.result(
                    timeout=self.timeout_seconds
                )
            except Exception as exc:
                logger.warning("Risk hints analysis failed: %s", exc)
                risk_hints_result = RiskHintsResult(
                    is_suspicious=False,
                    detected_issues=[],
                    risk_score=0.0,
                    checks_performed=[],
                    response_time_ms=int(self.timeout_seconds * 1000),
                )

        return google_result, urlhaus_result, risk_hints_result

    def _merge_results(
        self,
        url: str,
        google_result: GoogleSafeBrowsingResult,
        urlhaus_result: URLhausResult,
        risk_hints: RiskHintsResult,
        start_time: float,
    ) -> URLCheckResult:
        """
        Merge individual results into final verdict.

        Decision logic:
        - If either API flags URL as threat → THREAT_DETECTED (HIGH confidence)
        - Else if risk hints suspicious → SUSPICIOUS (MODERATE confidence)
        - Else all clean → NOT_FLAGGED (HIGH confidence)
        - Else if all APIs failed → UNABLE_TO_VERIFY (LOW confidence)

        Args:
            url: Normalized URL.
            google_result: Google Safe Browsing result.
            urlhaus_result: URLhaus result.
            risk_hints: Risk hints result.
            start_time: Check start time.

        Returns:
            Merged URLCheckResult.
        """
        total_response_time_ms = int((time.time() - start_time) * 1000)

        # Determine verdict
        google_flagged = google_result and google_result.is_flagged
        urlhaus_flagged = urlhaus_result and urlhaus_result.is_flagged
        risk_hints_suspicious = risk_hints and risk_hints.is_suspicious

        if google_flagged or urlhaus_flagged:
            # Threat detected by authoritative source
            verdict = VerdictType.THREAT_DETECTED
            confidence = ConfidenceLevel.HIGH
            threat_type = self._extract_threat_type(
                google_result, urlhaus_result
            )
            recommendation = (
                "This URL is flagged as a known threat. "
                "We recommend avoiding this site and not clicking links from this URL."
            )

        elif risk_hints_suspicious:
            # Local heuristics suggest suspicion
            verdict = VerdictType.SUSPICIOUS
            confidence = (
                ConfidenceLevel.MODERATE
                if not google_result.error and not urlhaus_result.error
                else ConfidenceLevel.LOW
            )
            threat_type = ThreatType.SUSPICIOUS
            recommendation = (
                "This URL exhibits suspicious characteristics. "
                "Use caution before visiting this site."
            )

        elif not google_result.error and not urlhaus_result.error:
            # All checks passed, no issues found
            verdict = VerdictType.NOT_FLAGGED
            confidence = ConfidenceLevel.HIGH
            threat_type = None
            recommendation = (
                "This URL appears to be safe based on our analysis. "
                "However, exercise normal caution when visiting any website."
            )

        else:
            # APIs not available
            verdict = VerdictType.UNABLE_TO_VERIFY
            confidence = ConfidenceLevel.LOW
            threat_type = None
            recommendation = (
                "We were unable to fully verify this URL due to service issues. "
                "Please try again later or use additional security tools."
            )

        return URLCheckResult(
            url=url,
            overall_verdict=verdict,
            confidence=confidence,
            primary_threat_type=threat_type,
            recommendation=recommendation,
            sources={
                "google_safe_browsing": google_result.model_dump(),
                "urlhaus": urlhaus_result.model_dump(),
                "risk_hints": risk_hints.model_dump(),
            },
            total_response_time_ms=total_response_time_ms,
            cached=False,
        )

    @staticmethod
    def _extract_threat_type(
        google_result: Optional[GoogleSafeBrowsingResult],
        urlhaus_result: Optional[URLhausResult],
    ) -> Optional[ThreatType]:
        """
        Extract primary threat type from results.

        Args:
            google_result: Google Safe Browsing result.
            urlhaus_result: URLhaus result.

        Returns:
            Primary ThreatType, or None if no threat.
        """
        threat_map = {
            "PHISHING": ThreatType.PHISHING,
            "MALWARE": ThreatType.MALWARE,
            "SOCIAL_ENGINEERING": ThreatType.SCAM,
            "UNWANTED_SOFTWARE": ThreatType.UNWANTED_SOFTWARE,
            "malware": ThreatType.MALWARE,
            "phishing": ThreatType.PHISHING,
        }

        # Check Google Safe Browsing
        if (
            google_result
            and google_result.is_flagged
            and google_result.threat_types
        ):
            for threat in google_result.threat_types:
                if threat in threat_map:
                    return threat_map[threat]

        # Check URLhaus
        if urlhaus_result and urlhaus_result.is_flagged and urlhaus_result.threat_type:
            if urlhaus_result.threat_type in threat_map:
                return threat_map[urlhaus_result.threat_type]

        return ThreatType.UNKNOWN

    def _get_cached_result(self, url: str) -> Optional[URLCheckResult]:
        """
        Get cached result if available and not expired.

        Args:
            url: Normalized URL.

        Returns:
            Cached URLCheckResult if valid, None otherwise.
        """
        cache_key = self._make_cache_key(url)
        if cache_key not in self._results_cache:
            return None

        result, timestamp = self._results_cache[cache_key]
        age_seconds = time.time() - timestamp

        if age_seconds > self.cache_ttl_seconds:
            del self._results_cache[cache_key]
            return None

        return result

    def _cache_result(self, url: str, result: URLCheckResult) -> None:
        """
        Cache result.

        Args:
            url: Normalized URL.
            result: URLCheckResult to cache.
        """
        cache_key = self._make_cache_key(url)
        self._results_cache[cache_key] = (result, time.time())

        # Simple LRU-like cleanup: remove oldest if cache too large
        if len(self._results_cache) > 1000:
            oldest_key = min(
                self._results_cache.keys(),
                key=lambda k: self._results_cache[k][1],
            )
            del self._results_cache[oldest_key]

    @staticmethod
    def _make_cache_key(url: str) -> str:
        """
        Create cache key from URL (lowercase, no fragments).

        Args:
            url: Normalized URL.

        Returns:
            Cache key.
        """
        return url.lower().split("#")[0]

    @staticmethod
    def _make_error_result(
        url: str, error_message: str, start_time: float
    ) -> URLCheckResult:
        """
        Create error result.

        Args:
            url: Original URL.
            error_message: Error description.
            start_time: Check start time.

        Returns:
            URLCheckResult indicating error.
        """
        return URLCheckResult(
            url=url,
            overall_verdict=VerdictType.UNABLE_TO_VERIFY,
            confidence=ConfidenceLevel.LOW,
            primary_threat_type=None,
            recommendation=error_message,
            sources={},
            total_response_time_ms=int((time.time() - start_time) * 1000),
            cached=False,
        )
