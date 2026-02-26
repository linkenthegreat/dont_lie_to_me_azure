"""
Local risk heuristics for URL analysis.

Provides fast, local analysis of URL characteristics that may indicate:
- International Domain Name (IDN) spoofing (punycode)
- Typosquatting attacks
- Suspicious TLD usage
- Non-standard URL structures
- HTTPS enforcement
"""

import time
from typing import List, Dict, Any
from shared.models import RiskHintsResult
from shared.url_validators import (
    is_punycode_url,
    is_suspicious_tld,
    has_non_ascii_domain,
    extract_domain,
    extract_path,
)


class RiskHintsAnalyzer:
    """Analyzes URLs for local risk indicators without external API calls."""

    # Common legitimate domains that might look suspicious
    COMMON_DOMAINS = {
        "google.com",
        "facebook.com",
        "amazon.com",
        "microsoft.com",
        "apple.com",
        "github.com",
        "stackoverflow.com",
        "linkedin.com",
        "twitter.com",
        "youtube.com",
        "wikipedia.org",
        "reddit.com",
    }

    # Common legitimate TLDs
    SAFE_TLDS = {
        "com",
        "org",
        "net",
        "gov",
        "edu",
        "co.uk",
        "de",
        "fr",
        "ca",
        "au",
        "jp",
        "cn",
        "in",
        "br",
        "ru",
        "us",
        "io",
        "co",
        "uk",
        "ai",
        "app",
        "dev",
        "info",
    }

    def __init__(self):
        """Initialize the analyzer."""
        self.start_time = None
        self.checks_performed: List[str] = []

    def analyze(self, url: str) -> RiskHintsResult:
        """
        Analyze URL for risk hints using local heuristics.

        Args:
            url: URL to analyze.

        Returns:
            RiskHintsResult with findings.
        """
        import time as time_module  # Import at function scope to ensure fresh timing
        self.start_time = time_module.time()
        self.checks_performed = []
        detected_issues: List[str] = []
        risk_score = 0.0

        # Check 1: Punycode (IDN spoofing)
        if self._check_punycode(url):
            detected_issues.append("punycode_detected")
            risk_score += 0.5  # Increased from 0.3 - punycode is a serious indicator

        # Check 2: Suspicious TLD
        if self._check_suspicious_tld(url):
            detected_issues.append("suspicious_tld")
            risk_score += 0.5  # Increased from 0.2 - suspicious TLDs are commonly abused

        # Check 3: Non-ASCII domain
        if self._check_non_ascii_domain(url):
            detected_issues.append("non_ascii_domain")
            risk_score += 0.4

        # Check 4: URL structure issues
        if self._check_suspicious_structure(url):
            detected_issues.append("suspicious_structure")
            risk_score += 0.3

        # Check 5: Missing HTTPS
        if self._check_no_https(url):
            detected_issues.append("no_https")
            risk_score += 0.1  # Minor issue compared to others

        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)

        response_time_ms = max(1, int((time_module.time() - self.start_time) * 1000))

        return RiskHintsResult(
            is_suspicious=risk_score >= 0.5,
            detected_issues=detected_issues,
            risk_score=risk_score,
            checks_performed=self.checks_performed,
            response_time_ms=response_time_ms,
        )

    def _check_punycode(self, url: str) -> bool:
        """
        Check if URL contains punycode (xn--) encoding.

        Punycode can be used for IDN spoofing attacks where URLs look legitimate
        to users but point to malicious sites.

        Returns:
            True if punycode detected, False otherwise.
        """
        self.checks_performed.append("PUNYCODE")
        return is_punycode_url(url)

    def _check_suspicious_tld(self, url: str) -> bool:
        """
        Check if URL uses a suspicious or commonly abused TLD.

        Certain TLDs have lax registration policies and are commonly used for
        phishing and malware distribution.

        Returns:
            True if TLD is suspicious, False otherwise.
        """
        self.checks_performed.append("TLD_ANALYSIS")
        return is_suspicious_tld(url)

    def _check_non_ascii_domain(self, url: str) -> bool:
        """
        Check if domain contains non-ASCII characters (potential IDN spoofing).

        Non-ASCII domains can be visually similar to legitimate domains to users
        but are technically different.

        Returns:
            True if non-ASCII detected, False otherwise.
        """
        self.checks_performed.append("NON_ASCII_DOMAIN")
        return has_non_ascii_domain(url)

    def _check_suspicious_structure(self, url: str) -> bool:
        """
        Check for suspicious URL structure patterns.

        Patterns checked:
        - IP address instead of domain
        - Port numbers in domain
        - Excessive subdomains
        - Double dots in path

        Returns:
            True if suspicious structure detected, False otherwise.
        """
        self.checks_performed.append("URL_STRUCTURE")

        domain = extract_domain(url)
        if not domain:
            return False

        # Check for IP address
        if self._looks_like_ip(domain):
            return True

        # Check for excessive subdomains (>3 levels)
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            return True

        # Check for port numbers (suspicious in domain)
        if ":" in domain:
            return True

        path = extract_path(url)
        if path and ".." in path:
            return True

        return False

    def _check_no_https(self, url: str) -> bool:
        """
        Check if URL uses unencrypted HTTP instead of HTTPS.

        Returns:
            True if URL uses HTTP (not HTTPS), False otherwise.
        """
        self.checks_performed.append("HTTPS_CHECK")
        return url.lower().startswith("http://")

    @staticmethod
    def _looks_like_ip(domain: str) -> bool:
        """
        Check if domain looks like an IP address.

        Args:
            domain: Domain to check.

        Returns:
            True if looks like IP, False otherwise.
        """
        # IPv4 pattern
        parts = domain.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False

        # IPv6 pattern (basic)
        if ":" in domain:
            return True

        return False


# Singleton instance for convenience
_analyzer = None


def get_analyzer() -> RiskHintsAnalyzer:
    """Get or create singleton RiskHintsAnalyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = RiskHintsAnalyzer()
    return _analyzer


def analyze_url_hints(url: str) -> RiskHintsResult:
    """
    Convenience function to analyze URL for risk hints.

    Args:
        url: URL to analyze.

    Returns:
        RiskHintsResult with findings.
    """
    analyzer = get_analyzer()
    return analyzer.analyze(url)
