"""Application Insights custom telemetry via structured logging."""

import logging

logger = logging.getLogger(__name__)


def track_request(
    endpoint: str, latency_ms: float, status: str, cached: bool = False
) -> None:
    """Log structured telemetry that Application Insights can query."""
    logger.info(
        "RequestMetric",
        extra={
            "custom_dimensions": {
                "endpoint": endpoint,
                "latency_ms": str(round(latency_ms, 2)),
                "status": status,
                "cached": str(cached),
            }
        },
    )


def track_cache_event(endpoint: str, hit: bool) -> None:
    """Track cache hit or miss."""
    logger.info(
        "CacheMetric",
        extra={
            "custom_dimensions": {
                "endpoint": endpoint,
                "cache_hit": str(hit),
            }
        },
    )


def track_classification(classification_type: str) -> None:
    """Track classification type distribution."""
    logger.info(
        "ClassificationMetric",
        extra={
            "custom_dimensions": {
                "classification": classification_type,
            }
        },
    )


def track_error(endpoint: str, error_type: str) -> None:
    """Track error occurrence."""
    logger.info(
        "ErrorMetric",
        extra={
            "custom_dimensions": {
                "endpoint": endpoint,
                "error_type": error_type,
            }
        },
    )
