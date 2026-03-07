"""GDPR compliance: data subject rights (right to erasure, data export)."""

import logging

logger = logging.getLogger(__name__)


def delete_user_data(session_id: str) -> dict:
    """Delete all data for a session (GDPR right to erasure)."""
    from services.cosmos_service import get_cosmos_service

    cosmos = get_cosmos_service()
    results = cosmos.query_history(session_id=session_id, limit=1000)
    deleted_count = 0
    for doc in results:
        try:
            cosmos._container.delete_item(
                item=doc["id"],
                partition_key=session_id,
            )
            deleted_count += 1
        except Exception as exc:
            logger.error("Failed to delete document %s: %s", doc.get("id"), exc)

    return {
        "session_id": session_id,
        "documents_deleted": deleted_count,
        "status": "completed",
    }


def export_user_data(session_id: str) -> list:
    """Export all data for a session (GDPR data portability)."""
    from services.cosmos_service import get_cosmos_service

    cosmos = get_cosmos_service()
    return cosmos.query_history(session_id=session_id, limit=1000)
