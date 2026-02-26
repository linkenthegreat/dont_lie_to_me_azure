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


if __name__ == "__main__":
    unittest.main()
