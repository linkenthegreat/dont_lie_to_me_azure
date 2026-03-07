"""
URL validators and normalizers for the URL checking feature.

Provides functionality to:
- Extract URLs from text
- Validate URL format and structure
- Normalize URLs (lowercase, remove fragments, etc.)
- Prepare URLs for threat checking
"""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urlsplit


# Regex patterns for URL detection and validation
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"\'\(\)\[\]\{\}|\\^`]+",
    re.IGNORECASE,
)

# HTTPS URL pattern (more permissive for internal use)
INTERNAL_URL_PATTERN = re.compile(
    r"(?:https?://)?(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}(?:/[\w\-\.~:/?#\[\]@!$&\'()*+,;=%]*)?",
    re.IGNORECASE,
)

# Allowed protocols
ALLOWED_PROTOCOLS = {"http", "https"}


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text using regex pattern.

    Args:
        text: Text containing URLs.

    Returns:
        List of extracted URLs (in original form).

    Example:
        >>> extract_urls("Check out https://example.com for more info")
        ['https://example.com']
    """
    if not text or not isinstance(text, str):
        return []

    matches = URL_PATTERN.findall(text)
    return list(set(matches))  # Deduplicate


def normalize_url(url: str) -> Optional[str]:
    """
    Normalize a URL for consistent comparison and checking.

    Normalizations applied:
    - Add https:// if protocol is missing
    - Convert to lowercase
    - Remove fragment identifier (#...)
    - Remove default port numbers (80 for http, 443 for https)
    - Strip trailing slash from domain-only URLs

    Args:
        url: URL to normalize.

    Returns:
        Normalized URL, or None if URL is invalid.

    Example:
        >>> normalize_url("HTTPS://Example.COM/path")
        'https://example.com/path'
        >>> normalize_url("example.com")
        'https://example.com'
    """
    if not url or not isinstance(url, str):
        return None

    url = url.strip()

    # Add protocol if missing (check before lowercasing)
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    try:
        # Parse URL (lowercase the whole thing)
        parsed = urlparse(url.lower())

        # Validate protocol
        if parsed.scheme not in ALLOWED_PROTOCOLS:
            return None

        # Validate netloc (domain)
        if not parsed.netloc:
            return None

        # Remove default ports
        netloc = parsed.netloc
        if parsed.scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif parsed.scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Reconstruct URL without fragment
        normalized = urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, "")
        )

        # Remove trailing slash for domain-only URLs
        if normalized.endswith("/") and parsed.path in ("", "/"):
            normalized = normalized.rstrip("/")

        return normalized

    except Exception:
        return None


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid and can be checked.

    Validation checks:
    - URL is not empty
    - URL has a valid protocol (http/https)
    - URL has a valid domain/netloc
    - URL is not a local/private address

    Args:
        url: URL to validate.

    Returns:
        True if URL is valid for checking, False otherwise.

    Example:
        >>> is_valid_url("https://example.com")
        True
        >>> is_valid_url("not a url")
        False
    """
    if not url or not isinstance(url, str):
        return False

    normalized = normalize_url(url)
    if not normalized:
        return False

    # Check for private/local addresses
    private_patterns = {
        r"^https?://(localhost|127\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)",
        r"^https?://\[::1\]",  # IPv6 localhost
        r"^https?://.*\.local\b",  # mDNS
    }

    for pattern in private_patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            return False

    return True


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain/netloc from a URL.

    Args:
        url: URL to extract domain from.

    Returns:
        Domain/netloc (e.g., 'example.com'), or None if URL is invalid.

    Example:
        >>> extract_domain("https://subdomain.example.com/path?query=1")
        'subdomain.example.com'
    """
    normalized = normalize_url(url)
    if not normalized:
        return None

    try:
        return urlparse(normalized).netloc
    except Exception:
        return None


def extract_path(url: str) -> Optional[str]:
    """
    Extract path from a URL.

    Args:
        url: URL to extract path from.

    Returns:
        Path component (e.g., '/page/to/resource'), or None if URL is invalid.

    Example:
        >>> extract_path("https://example.com/page?query=1")
        '/page'
    """
    normalized = normalize_url(url)
    if not normalized:
        return None

    try:
        path = urlparse(normalized).path
        return path if path else "/"
    except Exception:
        return None


def is_punycode_url(url: str) -> bool:
    """
    Check if URL contains punycode (xn--) encoding (potential IDN spoofing).

    Args:
        url: URL to check.

    Returns:
        True if punycode is detected, False otherwise.

    Example:
        >>> is_punycode_url("https://xn--example.com")
        True
    """
    domain = extract_domain(url)
    if not domain:
        return False

    return "xn--" in domain.lower()


def looks_like_typosquatting(domain: str, target_domain: str) -> bool:
    """
    Simple heuristic check if a domain looks like typosquatting of target domain.

    Checks for:
    - Single character substitution (a -> 0, l -> 1, etc.)
    - Adjacent character transposition
    - Common misspellings

    Args:
        domain: Domain to check.
        target_domain: Target domain to check against.

    Returns:
        True if typosquatting is likely, False otherwise.

    Example:
        >>> looks_like_typosquatting("examp1e.com", "example.com")
        True
    """
    if not domain or not target_domain:
        return False

    domain = domain.lower()
    target_domain = target_domain.lower()

    # If domains are identical, not typosquatting
    if domain == target_domain:
        return False

    # If target domain is not in domain, unlikely to be typosquatting
    if target_domain not in domain:
        return False

    # Calculate Levenshtein distance (simple version)
    # If distance is small (1-2 changes) and lengths are similar, likely typosquatting
    distance = _levenshtein_distance(domain, target_domain)
    if 1 <= distance <= 2 and abs(len(domain) - len(target_domain)) <= 1:
        return True

    return False


def _levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein distance between two strings (simple edit distance).

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Edit distance (number of edits required).
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def get_tld(url: str) -> Optional[str]:
    """
    Extract top-level domain (TLD) from a URL.

    Args:
        url: URL to extract TLD from.

    Returns:
        TLD (e.g., 'com', 'co.uk'), or None if URL is invalid.

    Example:
        >>> get_tld("https://example.com")
        'com'
        >>> get_tld("https://example.co.uk")
        'co.uk'
    """
    domain = extract_domain(url)
    if not domain:
        return None

    parts = domain.split(".")
    if len(parts) < 2:
        return None

    # Simple heuristic: assume last two parts for most cases
    # (won't handle all edge cases like .co.uk perfectly, but good enough)
    if len(parts) >= 3 and parts[-2] in {"co", "ac", "com", "gov", "org", "edu"}:
        return ".".join(parts[-2:])

    return parts[-1]


def is_suspicious_tld(url: str) -> bool:
    """
    Check if URL has a suspicious or less common TLD.

    Args:
        url: URL to check.

    Returns:
        True if TLD is in suspicious list, False otherwise.

    Example:
        >>> is_suspicious_tld("https://example.tk")
        True  # .tk is commonly abused
    """
    # List of commonly abused or suspicious TLDs
    suspicious_tlds = {
        "tk",  # Tokelau - very permissive registration
        "ml",  # Mali - very permissive registration
        "ga",  # Gabon - very permissive registration
        "cf",  # Central African Republic - very permissive
        "tk",  # Free domain provider
    }

    tld = get_tld(url)
    if not tld:
        return False

    return tld.lower() in suspicious_tlds


def has_non_ascii_domain(url: str) -> bool:
    """
    Check if domain contains non-ASCII characters (may indicate IDN potential spoofing).

    Args:
        url: URL to check.

    Returns:
        True if domain contains non-ASCII characters, False otherwise.
    """
    domain = extract_domain(url)
    if not domain:
        return False

    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True
