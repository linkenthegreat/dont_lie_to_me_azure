"""
Unit tests for URL checking feature.

Tests cover:
- URL validation and normalization
- Threat intelligence API clients
- Risk hints analysis
- URL checker orchestration
- Integration tests
"""

import unittest
import time
from unittest.mock import patch, MagicMock
from shared.url_validators import (
    normalize_url,
    is_valid_url,
    extract_domain,
    is_punycode_url,
    extract_urls,
)
from shared.risk_hints import analyze_url_hints
from shared.models import VerdictType, ConfidenceLevel, CheckURLRequest
from shared.threat_intel_sources import URLhausClient


class TestURLValidators(unittest.TestCase):
    """Tests for URL validation and normalization."""

    def test_normalize_url_adds_https(self):
        """Test that HTTPS is added to URLs without protocol."""
        result = normalize_url("example.com")
        self.assertEqual(result, "https://example.com")

    def test_normalize_url_lowercases(self):
        """Test that URLs are converted to lowercase."""
        result = normalize_url("HTTPS://Example.COM")
        self.assertEqual(result, "https://example.com")

    def test_normalize_url_removes_fragment(self):
        """Test that URL fragments are removed."""
        result = normalize_url("https://example.com/page#section")
        self.assertEqual(result, "https://example.com/page")

    def test_normalize_url_removes_default_https_port(self):
        """Test that default HTTPS port (443) is removed."""
        result = normalize_url("https://example.com:443/path")
        self.assertEqual(result, "https://example.com/path")

    def test_normalize_url_removes_default_http_port(self):
        """Test that default HTTP port (80) is removed."""
        result = normalize_url("http://example.com:80/path")
        self.assertEqual(result, "http://example.com/path")

    def test_is_valid_url_rejects_empty(self):
        """Test that empty URLs are rejected."""
        self.assertFalse(is_valid_url(""))
        self.assertFalse(is_valid_url(None))

    def test_is_valid_url_rejects_localhost(self):
        """Test that localhost URLs are rejected."""
        self.assertFalse(is_valid_url("http://localhost"))
        self.assertFalse(is_valid_url("http://127.0.0.1"))

    def test_is_valid_url_rejects_private_ip(self):
        """Test that private IP addresses are rejected."""
        self.assertFalse(is_valid_url("http://192.168.1.1"))
        self.assertFalse(is_valid_url("http://10.0.0.1"))

    def test_is_valid_url_accepts_public_domain(self):
        """Test that public domains are accepted."""
        self.assertTrue(is_valid_url("https://example.com"))

    def test_extract_domain(self):
        """Test domain extraction."""
        result = extract_domain("https://subdomain.example.com/path")
        self.assertEqual(result, "subdomain.example.com")

    def test_is_punycode_url(self):
        """Test punycode detection."""
        self.assertTrue(is_punycode_url("https://xn--example.com"))
        self.assertFalse(is_punycode_url("https://example.com"))

    def test_extract_urls(self):
        """Test URL extraction from text."""
        text = "Check https://example.com and https://google.com"
        result = extract_urls(text)
        self.assertEqual(len(result), 2)
        self.assertIn("https://example.com", result)
        self.assertIn("https://google.com", result)


class TestRiskHints(unittest.TestCase):
    """Tests for local risk hints analysis."""

    def test_analyze_safe_url(self):
        """Test analysis of a safe URL."""
        result = analyze_url_hints("https://example.com")
        self.assertFalse(result.is_suspicious)
        self.assertEqual(result.risk_score, 0.0)
        self.assertGreater(result.response_time_ms, 0)

    def test_analyze_punycode_url(self):
        """Test detection of punycode URL."""
        result = analyze_url_hints("https://xn--example.com")
        self.assertTrue(result.is_suspicious)
        self.assertIn("punycode_detected", result.detected_issues)
        self.assertGreater(result.risk_score, 0.0)

    def test_analyze_suspicious_tld(self):
        """Test detection of suspicious TLD."""
        # .tk is in the suspicious TLD list
        result = analyze_url_hints("https://example.tk")
        self.assertTrue(result.is_suspicious)
        self.assertIn("suspicious_tld", result.detected_issues)

    def test_analyze_http_url(self):
        """Test detection of HTTP (non-HTTPS) URL."""
        result = analyze_url_hints("http://example.com")
        # Should have at least one issue (no HTTPS)
        self.assertIn("no_https", result.detected_issues)

    def test_analyze_response_time(self):
        """Test that response time is measured."""
        result = analyze_url_hints("https://example.com")
        self.assertGreater(result.response_time_ms, 0)
        self.assertLess(result.response_time_ms, 5000)  # Should be <5 seconds


class TestCheckURLRequest(unittest.TestCase):
    """Tests for CheckURLRequest validation."""

    def test_valid_request(self):
        """Test that valid request is accepted."""
        req = CheckURLRequest(url="https://example.com", use_cache=True)
        self.assertEqual(req.url, "https://example.com")
        self.assertTrue(req.use_cache)

    def test_request_requires_url(self):
        """Test that URL field is required."""
        with self.assertRaises(ValueError):
            CheckURLRequest(url="")

    def test_request_use_cache_default(self):
        """Test that use_cache defaults to True."""
        req = CheckURLRequest(url="https://example.com")
        self.assertTrue(req.use_cache)


class TestURLCheckerFactory(unittest.TestCase):
    """Tests for Key Vault/env-backed URL checker factory."""

    @patch("shared.url_checker.URLChecker")
    @patch("shared.keyvault.get_secret")
    def test_get_url_checker_resolves_both_secrets(self, mock_get_secret, mock_url_checker):
        from shared.url_checker import get_url_checker

        mock_get_secret.side_effect = ["google-secret", "urlhaus-secret"]

        get_url_checker()

        self.assertEqual(mock_get_secret.call_count, 2)
        mock_url_checker.assert_called_once_with(
            google_sb_api_key="google-secret",
            urlhaus_api_key="urlhaus-secret",
        )

    @patch("shared.url_checker.URLChecker")
    @patch("shared.keyvault.get_secret")
    def test_get_url_checker_tolerates_missing_urlhaus_secret(self, mock_get_secret, mock_url_checker):
        from shared.url_checker import get_url_checker

        mock_get_secret.side_effect = ["google-secret", ValueError("missing urlhaus")]

        get_url_checker()

        mock_url_checker.assert_called_once_with(
            google_sb_api_key="google-secret",
            urlhaus_api_key=None,
        )


class TestURLhausClient(unittest.TestCase):
    """Tests for URLhaus client parsing resilience."""

    @patch("shared.threat_intel_sources.requests.post")
    def test_urlhaus_accepts_object_result_shape(self, mock_post):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "query_status": "ok",
            "result": {
                "threat": "malware",
                "date_added": "2026-03-15 10:00:00",
                "url_status": "online",
            },
        }
        mock_post.return_value = mock_response

        client = URLhausClient(api_key="dummy")
        result = client.check_url("https://evil.example")

        self.assertTrue(result.is_flagged)
        self.assertEqual(result.threat_type, "malware")
        self.assertEqual(result.url_status, "online")
        self.assertIsNone(result.error)

    @patch("shared.threat_intel_sources.requests.post")
    def test_urlhaus_accepts_top_level_result_shape(self, mock_post):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "query_status": "ok",
            "threat": "phishing",
            "date_added": "2026-03-15 10:00:00",
            "url_status": "offline",
        }
        mock_post.return_value = mock_response

        client = URLhausClient(api_key="dummy")
        result = client.check_url("https://evil.example")

        self.assertTrue(result.is_flagged)
        self.assertEqual(result.threat_type, "phishing")
        self.assertEqual(result.url_status, "offline")
        self.assertIsNone(result.error)

    @patch("shared.threat_intel_sources.requests.post")
    def test_urlhaus_no_results_is_not_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_response

        client = URLhausClient(api_key="dummy")
        result = client.check_url("https://benign.example")

        self.assertFalse(result.is_flagged)
        self.assertIsNone(result.error)


class TestGoogleSafeBrowsingClient(unittest.TestCase):
    """Tests for Google Safe Browsing request payload shape."""

    @patch("shared.threat_intel_sources.requests.post")
    def test_gsb_uses_v4_threat_entries_schema(self, mock_post):
        from shared.threat_intel_sources import GoogleSafeBrowsingClient

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response

        client = GoogleSafeBrowsingClient(api_key="dummy")
        client.check_url("https://example.com")

        kwargs = mock_post.call_args.kwargs
        sent_json = kwargs["json"]
        threat_info = sent_json["threatInfo"]
        self.assertIn("threatEntryTypes", threat_info)
        self.assertIn("threatEntries", threat_info)
        self.assertEqual(threat_info["threatEntryTypes"], ["URL"])
        self.assertEqual(threat_info["threatEntries"], [{"url": "https://example.com"}])


class TestURLCheckerRecommendationDiagnostics(unittest.TestCase):
    """Tests for clearer UNABLE_TO_VERIFY recommendation details."""

    @patch("shared.url_checker.URLChecker._perform_parallel_checks")
    def test_unable_to_verify_includes_source_details_and_urlhaus_hint(self, mock_checks):
        from shared.url_checker import URLChecker
        from shared.models import GoogleSafeBrowsingResult, URLhausResult, RiskHintsResult

        mock_checks.return_value = (
            GoogleSafeBrowsingResult(
                is_flagged=False,
                threat_types=[],
                platform_types=[],
                cache_duration_seconds=3600,
                error="API timeout",
                response_time_ms=100,
            ),
            URLhausResult(
                is_flagged=False,
                threat_type=None,
                date_added=None,
                url_status=None,
                error="API error: 401 Unauthorized",
                response_time_ms=100,
            ),
            RiskHintsResult(
                is_suspicious=False,
                detected_issues=[],
                risk_score=0.0,
                checks_performed=[],
                response_time_ms=1,
            ),
        )

        checker = URLChecker(google_sb_api_key="dummy", urlhaus_api_key="dummy")
        result = checker.check_url("https://urlhaus.abuse.ch/url/3796493/", use_cache=False)

        self.assertEqual(result.overall_verdict, VerdictType.UNABLE_TO_VERIFY)
        self.assertIn("GoogleSafeBrowsing: API timeout", result.recommendation)
        self.assertIn("URLhaus: API error: 401 Unauthorized", result.recommendation)
        self.assertIn("URLhaus report page URL", result.recommendation)

    @patch("shared.url_checker.URLChecker._perform_parallel_checks")
    def test_partial_verification_returns_not_flagged_low_confidence(self, mock_checks):
        from shared.url_checker import URLChecker
        from shared.models import GoogleSafeBrowsingResult, URLhausResult, RiskHintsResult

        mock_checks.return_value = (
            GoogleSafeBrowsingResult(
                is_flagged=False,
                threat_types=[],
                platform_types=[],
                cache_duration_seconds=3600,
                error="API timeout",
                response_time_ms=100,
            ),
            URLhausResult(
                is_flagged=False,
                threat_type=None,
                date_added=None,
                url_status=None,
                error=None,
                response_time_ms=100,
            ),
            RiskHintsResult(
                is_suspicious=False,
                detected_issues=[],
                risk_score=0.0,
                checks_performed=[],
                response_time_ms=1,
            ),
        )

        checker = URLChecker(google_sb_api_key="dummy", urlhaus_api_key="dummy")
        result = checker.check_url("https://example.com", use_cache=False)

        self.assertEqual(result.overall_verdict, VerdictType.NOT_FLAGGED)
        self.assertEqual(result.confidence, ConfidenceLevel.LOW)
        self.assertIn("verification was partial", result.recommendation)


if __name__ == "__main__":
    unittest.main()
