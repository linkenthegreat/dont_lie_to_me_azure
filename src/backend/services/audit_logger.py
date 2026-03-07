"""Audit logging for compliance (GDPR/CCPA)."""

import logging
from datetime import datetime, timezone

logger = logging.getLogger("audit")


def log_data_access(
    action: str,
    session_id: str,
    endpoint: str,
    ip_address: str = "",
    details: str = "",
) -> None:
    """Log a data access event for audit purposes.

    Actions: CREATE, READ, DELETE, EXPORT
    """
    audit_entry = {
        "event_type": "DATA_ACCESS",
        "action": action,
        "session_id": session_id,
        "endpoint": endpoint,
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    logger.info("AuditLog", extra={"custom_dimensions": audit_entry})


def log_gdpr_request(
    request_type: str,
    session_id: str,
    result: str,
) -> None:
    """Log GDPR-related requests (erasure, export)."""
    audit_entry = {
        "event_type": "GDPR_REQUEST",
        "request_type": request_type,
        "session_id": session_id,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logger.info("GDPRAuditLog", extra={"custom_dimensions": audit_entry})
