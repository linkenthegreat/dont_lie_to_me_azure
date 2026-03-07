"""
Pydantic data models for URL checking feature.

Provides structured, validated data models for:
- Individual threat intelligence source results
- Risk hint analysis results
- Final aggregated URL check results
- API request/response contracts
"""

from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums for structured classification
# ---------------------------------------------------------------------------


class VerdictType(str, Enum):
    """Possible verdicts from URL checking."""

    THREAT_DETECTED = "THREAT_DETECTED"
    """URL is flagged as a known threat by one or more sources."""

    SUSPICIOUS = "SUSPICIOUS"
    """URL exhibits characteristics that suggest it may be malicious, but no definitive threat found."""

    NOT_FLAGGED = "NOT_FLAGGED"
    """URL has been checked and is not flagged as a known threat."""

    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"
    """URL could not be verified due to API failures or other technical issues."""


class ConfidenceLevel(str, Enum):
    """Confidence level of the verdict."""

    HIGH = "HIGH"
    """High confidence in the verdict (e.g., flagged by multiple sources or authoritative check)."""

    MODERATE = "MODERATE"
    """Moderate confidence (e.g., risk hints detected, single source flagged)."""

    LOW = "LOW"
    """Low confidence (e.g., APIs unavailable, only local heuristics available)."""


class ThreatType(str, Enum):
    """Classification of threat type."""

    PHISHING = "PHISHING"
    """Phishing attempt."""

    SCAM = "SCAM"
    """Scam/fraud."""

    MALWARE = "MALWARE"
    """Malware distribution."""

    UNWANTED_SOFTWARE = "UNWANTED_SOFTWARE"
    """Unwanted software."""

    SUSPICIOUS = "SUSPICIOUS"
    """Suspicious but not definitively classified."""

    UNKNOWN = "UNKNOWN"
    """Unknown threat type."""


# ---------------------------------------------------------------------------
# Threat Intelligence Source Results
# ---------------------------------------------------------------------------


class GoogleSafeBrowsingResult(BaseModel):
    """Result from Google Safe Browsing API check."""

    is_flagged: bool = Field(
        ..., description="Whether URL is flagged as a threat by Google Safe Browsing."
    )
    threat_types: List[str] = Field(
        default_factory=list,
        description="List of threat types (e.g., PHISHING, MALWARE). Empty if not flagged.",
    )
    platform_types: List[str] = Field(
        default_factory=list,
        description="Platform types affected (e.g., WINDOWS, LINUX). Empty if not flagged.",
    )
    cache_duration_seconds: Optional[int] = Field(
        default=None,
        description="Recommended cache duration for this result (in seconds).",
    )
    error: Optional[str] = Field(
        default=None, description="Error message if check failed."
    )
    response_time_ms: int = Field(
        ..., description="Time taken to get response from API (milliseconds)."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "is_flagged": True,
                "threat_types": ["PHISHING"],
                "platform_types": ["WINDOWS", "LINUX"],
                "cache_duration_seconds": 3600,
                "error": None,
                "response_time_ms": 245,
            }
        }


class URLhausResult(BaseModel):
    """Result from URLhaus API check."""

    is_flagged: bool = Field(..., description="Whether URL is listed in URLhaus.")
    threat_type: Optional[str] = Field(
        default=None,
        description="Type of threat (e.g., 'malware', 'phishing'). None if not flagged.",
    )
    date_added: Optional[str] = Field(
        default=None,
        description="Date URL was added to URLhaus (ISO format). None if not flagged.",
    )
    url_status: Optional[str] = Field(
        default=None,
        description="Status of URL in URLhaus (e.g., 'online', 'offline'). None if not flagged.",
    )
    error: Optional[str] = Field(
        default=None, description="Error message if check failed."
    )
    response_time_ms: int = Field(
        ..., description="Time taken to get response from API (milliseconds)."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "is_flagged": True,
                "threat_type": "malware",
                "date_added": "2024-01-15T10:30:00Z",
                "url_status": "online",
                "error": None,
                "response_time_ms": 180,
            }
        }


class RiskHintsResult(BaseModel):
    """Result from local risk heuristics analysis."""

    is_suspicious: bool = Field(
        ..., description="Whether URL exhibits suspicious characteristics."
    )
    detected_issues: List[str] = Field(
        default_factory=list,
        description="List of detected risk indicators (e.g., 'punycode_detected', 'typosquatting_risk').",
    )
    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="Risk score from 0.0 (safe) to 1.0 (highly suspicious)."
    )
    checks_performed: List[str] = Field(
        default_factory=list,
        description="List of checks performed (e.g., 'PUNYCODE', 'TYPOSQUATTING', 'TLD_ANALYSIS').",
    )
    response_time_ms: int = Field(
        ..., description="Time taken to analyze (milliseconds)."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "is_suspicious": True,
                "detected_issues": ["punycode_detected"],
                "risk_score": 0.7,
                "checks_performed": ["PUNYCODE", "TYPOSQUATTING", "TLD_ANALYSIS"],
                "response_time_ms": 15,
            }
        }


# ---------------------------------------------------------------------------
# Final Aggregated Result
# ---------------------------------------------------------------------------


class URLCheckResult(BaseModel):
    """Aggregated result from URL checking across all sources."""

    url: str = Field(..., description="The URL that was checked (normalized).")
    overall_verdict: VerdictType = Field(
        ..., description="Overall verdict based on all sources."
    )
    confidence: ConfidenceLevel = Field(
        ..., description="Confidence level of the verdict."
    )
    primary_threat_type: Optional[ThreatType] = Field(
        default=None,
        description="Primary threat type detected (if applicable). None if no threat.",
    )
    recommendation: str = Field(
        ...,
        description="Human-readable recommendation for the user (e.g., 'Avoid this site', 'This appears safe').",
    )
    sources: Dict[str, dict] = Field(
        ...,
        description="Results from individual sources (keys: 'google_safe_browsing', 'urlhaus', 'risk_hints').",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Timestamp when the check was performed (ISO 8601).",
    )
    total_response_time_ms: int = Field(
        ..., description="Total time to complete all checks (milliseconds)."
    )
    cached: bool = Field(
        default=False, description="Whether this result was retrieved from cache."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com",
                "overall_verdict": "THREAT_DETECTED",
                "confidence": "HIGH",
                "primary_threat_type": "PHISHING",
                "recommendation": "This URL is flagged as a phishing attempt. Do not visit or click links from this site.",
                "sources": {
                    "google_safe_browsing": {
                        "is_flagged": True,
                        "threat_types": ["PHISHING"],
                        "response_time_ms": 245,
                    },
                    "urlhaus": {
                        "is_flagged": False,
                        "response_time_ms": 180,
                    },
                    "risk_hints": {
                        "is_suspicious": False,
                        "risk_score": 0.1,
                        "response_time_ms": 15,
                    },
                },
                "timestamp": "2024-02-26T14:30:45.123456Z",
                "total_response_time_ms": 440,
                "cached": False,
            }
        }

    @field_validator("overall_verdict")
    @classmethod
    def validate_verdict(cls, v: VerdictType) -> VerdictType:
        """Ensure verdict is one of the valid values."""
        if v not in VerdictType:
            raise ValueError(f"Invalid verdict: {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: ConfidenceLevel) -> ConfidenceLevel:
        """Ensure confidence level is valid."""
        if v not in ConfidenceLevel:
            raise ValueError(f"Invalid confidence level: {v}")
        return v


# ---------------------------------------------------------------------------
# API Request/Response Models
# ---------------------------------------------------------------------------


class CheckURLRequest(BaseModel):
    """Request body for /api/check-url endpoint."""

    url: str = Field(..., description="URL to check for threats.")
    use_cache: bool = Field(
        default=True,
        description="Whether to use cached result if available (within TTL).",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://example.com",
                "use_cache": True,
            }
        }

    @field_validator("url")
    @classmethod
    def validate_url_field(cls, v: str) -> str:
        """Ensure URL is not empty."""
        if not v or not v.strip():
            raise ValueError("URL must not be empty")
        return v.strip()


class CheckURLResponse(BaseModel):
    """Response body for /api/check-url endpoint."""

    success: bool = Field(..., description="Whether check was successful.")
    data: Optional[URLCheckResult] = Field(
        default=None,
        description="Check result if successful. None if there was an error.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if check failed. None if successful.",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Error code for programmatic handling.",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "data": {
                    "url": "https://example.com",
                    "overall_verdict": "NOT_FLAGGED",
                    "confidence": "HIGH",
                    "primary_threat_type": None,
                    "recommendation": "This URL appears safe.",
                    "sources": {},
                    "timestamp": "2024-02-26T14:30:45.123456Z",
                    "total_response_time_ms": 450,
                    "cached": False,
                },
                "error": None,
                "error_code": None,
            }
        }
