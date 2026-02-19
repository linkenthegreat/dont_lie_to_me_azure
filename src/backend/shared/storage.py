"""
Optional storage helper – placeholder for future query logging.

Replace the stub implementations with real Azure Blob Storage or
Cosmos DB calls once logging requirements are finalised.
"""

import os
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def log_query(endpoint: str, payload: dict, result: dict) -> None:
    """
    Persist a query + result pair for audit/analytics purposes.

    Currently a no-op placeholder. Uncomment and complete one of the
    implementations below when you are ready to enable logging.

    Parameters
    ----------
    endpoint:
        The function route that was called (e.g. "classify").
    payload:
        The sanitised request body (strip PII before storing).
    result:
        The response returned to the user.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "payload": payload,
        "result": result,
    }

    # ------------------------------------------------------------------
    # Option A: Azure Blob Storage
    # ------------------------------------------------------------------
    # from azure.storage.blob import BlobServiceClient
    # connection_string = os.environ.get("STORAGE_ACCOUNT_CONNECTION_STRING", "")
    # if connection_string:
    #     blob_client = BlobServiceClient.from_connection_string(connection_string)
    #     container = blob_client.get_container_client("query-logs")
    #     blob_name = f"{record['timestamp']}-{endpoint}.json"
    #     container.upload_blob(name=blob_name, data=json.dumps(record))
    #     return

    # ------------------------------------------------------------------
    # Option B: Azure Cosmos DB
    # ------------------------------------------------------------------
    # from azure.cosmos import CosmosClient
    # cosmos_conn = os.environ.get("COSMOS_DB_CONNECTION_STRING", "")
    # if cosmos_conn:
    #     client = CosmosClient.from_connection_string(cosmos_conn)
    #     db = client.get_database_client("antiscam")
    #     container_client = db.get_container_client("queries")
    #     container_client.upsert_item(record)
    #     return

    logger.debug("Storage logging not configured – skipping log_query for '%s'.", endpoint)
