"""
Integration test script for the /api/check-url endpoint.

This script directly tests the URL checking endpoint by creating mock
HTTP requests and verifying responses.
"""

import json
import sys
import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent / "env" / ".env"
load_dotenv(env_path)
print(f"Loaded .env from: {env_path}")

sys.path.insert(0, r"c:\Users\k1235\OneDrive\AI devOp day project\dont_lie_to_me_azure\src\backend")

from unittest.mock import Mock
from shared.url_checker import URLChecker
from shared.models import CheckURLRequest, CheckURLResponse

def test_check_url_safe():
    """Test checking a safe URL."""
    print("\n" + "="*70)
    print("TEST 1: Safe URL (google.com)")
    print("="*70)
    
    try:
        checker = URLChecker()
        result = checker.check_url("https://www.google.com")
        
        print(f"✓ URL checked successfully")
        print(f"  Verdict: {result.overall_verdict}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Threat Type: {result.primary_threat_type}")
        print(f"  Response time: {result.total_response_time_ms}ms")
        print(f"  Cached: {result.cached}")
        print(f"  Recommendation: {result.recommendation}")
        
        # Verify response
        assert result.url == "https://www.google.com", "URL normalization failed"
        print("✓ Test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_check_url_suspicious_tld():
    """Test checking a URL with suspicious TLD."""
    print("\n" + "="*70)
    print("TEST 2: Suspicious TLD (example.tk)")
    print("="*70)
    
    try:
        checker = URLChecker()
        result = checker.check_url("https://example.tk")
        
        print(f"✓ URL checked successfully")
        print(f"  Verdict: {result.overall_verdict}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Threat Type: {result.primary_threat_type}")
        print(f"  Response time: {result.total_response_time_ms}ms")
        print(f"  Risk hints: {result.sources.get('risk_hints', {}).get('detected_issues', [])}")
        print(f"  Recommendation: {result.recommendation}")
        
        # Should be marked as suspicious by risk hints
        assert result.sources['risk_hints']['is_suspicious'], "Should detect suspicious TLD"
        print("✓ Test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_check_url_punycode():
    """Test checking a URL with punycode."""
    print("\n" + "="*70)
    print("TEST 3: Punycode URL (xn--example.com)")
    print("="*70)
    
    try:
        checker = URLChecker()
        result = checker.check_url("https://xn--example.com")
        
        print(f"✓ URL checked successfully")
        print(f"  Verdict: {result.overall_verdict}")
        print(f"  Confidence: {result.confidence}")
        print(f"  Response time: {result.total_response_time_ms}ms")
        print(f"  Risk hints: {result.sources.get('risk_hints', {}).get('detected_issues', [])}")
        
        # Should be marked as suspicious by risk hints
        assert result.sources['risk_hints']['is_suspicious'], "Should detect punycode"
        assert 'punycode_detected' in result.sources['risk_hints']['detected_issues']
        print("✓ Test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_check_url_http():
    """Test checking a URL with HTTP instead of HTTPS."""
    print("\n" + "="*70)
    print("TEST 4: HTTP URL (http://example.com)")
    print("="*70)
    
    try:
        checker = URLChecker()
        result = checker.check_url("http://example.com")
        
        print(f"✓ URL checked successfully")
        print(f"  Verdict: {result.overall_verdict}")
        print(f"  Response time: {result.total_response_time_ms}ms")
        print(f"  Risk hints: {result.sources.get('risk_hints', {}).get('detected_issues', [])}")
        
        # Should flag no HTTPS
        assert 'no_https' in result.sources['risk_hints']['detected_issues']
        print("✓ Test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_check_url_private_ip():
    """Test that private IPs are rejected."""
    print("\n" + "="*70)
    print("TEST 5: Private IP (should be rejected)")
    print("="*70)
    
    try:
        checker = URLChecker()
        result = checker.check_url("http://192.168.1.1")
        
        print(f"✓ Request processed")
        print(f"  Verdict: {result.overall_verdict}")
        print(f"  Recommendation: {result.recommendation}")
        
        # Should indicate unable to verify (invalid URL)
        assert result.overall_verdict.value == "UNABLE_TO_VERIFY"
        print("✓ Test PASSED - Private IP correctly rejected")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_caching():
    """Test that caching works."""
    print("\n" + "="*70)
    print("TEST 6: Caching (same URL should be cached)")
    print("="*70)
    
    try:
        checker = URLChecker()
        
        # First request (not cached)
        result1 = checker.check_url("https://example.com")
        time1 = result1.total_response_time_ms
        cached1 = result1.cached
        
        print(f"✓ First request: {time1}ms, cached={cached1}")
        assert not cached1, "First request should not be cached"
        
        # Second request (should be cached)
        result2 = checker.check_url("https://example.com")
        time2 = result2.total_response_time_ms
        cached2 = result2.cached
        
        print(f"✓ Second request: {time2}ms, cached={cached2}")
        assert cached2, "Second request should be cached"
        # Cache should be returned quickly, not require API calls
        # Note: If APIs are failing, both may take similar time, so we just verify cached flag
        
        # Verify results are identical
        assert result1.url == result2.url, "URLs should match"
        assert result1.overall_verdict == result2.overall_verdict, "Verdicts should match"
        
        print("✓ Test PASSED - Caching works correctly")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_request_validation():
    """Test that request validation works."""
    print("\n" + "="*70)
    print("TEST 7: Request validation")
    print("="*70)
    
    try:
        # Valid request
        req = CheckURLRequest(url="https://example.com")
        assert req.url == "https://example.com"
        print("✓ Valid request accepted")
        
        # Invalid request (empty URL)
        try:
            req = CheckURLRequest(url="")
            print("✗ Should have rejected empty URL")
            return False
        except ValueError:
            print("✓ Empty URL correctly rejected")
        
        # Test use_cache default
        req = CheckURLRequest(url="https://example.com")
        assert req.use_cache == True, "use_cache should default to True"
        print("✓ use_cache defaults to True")
        
        print("✓ Test PASSED")
        return True
        
    except Exception as e:
        print(f"✗ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all integration tests."""
    print("\n" + "█"*70)
    print("█ URL CHECKING FEATURE - INTEGRATION TESTS")
    print("█"*70)
    
    tests = [
        test_request_validation,
        test_check_url_safe,
        test_check_url_suspicious_tld,
        test_check_url_punycode,
        test_check_url_http,
        test_check_url_private_ip,
        test_caching,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n✗ Test crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
