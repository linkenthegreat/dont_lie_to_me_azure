"""Cosmos DB service for storing and querying scam analyses."""

import logging
import uuid
from datetime import datetime, timezone

from azure.cosmos import CosmosClient, PartitionKey
from azure.cosmos.exceptions import CosmosResourceNotFoundError

from services.scam_patterns import filter_by_similarity

logger = logging.getLogger(__name__)


class CosmosService:
    """CRUD operations against an Azure Cosmos DB NoSQL container."""

    def __init__(
        self,
        connection_string: str = "",
        endpoint: str = "",
        key: str = "",
        database_name: str = "antiscam",
        container_name: str = "analyses",
    ):
        if connection_string:
            self._client = CosmosClient.from_connection_string(connection_string)
        elif endpoint and key:
            self._client = CosmosClient(endpoint, credential=key)
        else:
            raise ValueError(
                "Provide either COSMOS_DB_CONNECTION_STRING or COSMOS_DB_ENDPOINT + COSMOS_DB_KEY"
            )

        self._db = self._client.get_database_client(database_name)
        self._container = self._db.get_container_client(container_name)

    def upsert_analysis(
        self, session_id: str, endpoint: str, input_text: str, result: dict
    ) -> dict:
        """Store an analysis result. Returns the upserted document."""
        doc = {
            "id": str(uuid.uuid4()),
            "sessionId": session_id,
            "endpoint": endpoint,
            "inputText": input_text,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._container.upsert_item(doc)

    def query_history(self, session_id: str, limit: int = 10) -> list:
        """Return past analyses for a session, newest first."""
        query = (
            "SELECT TOP @limit * FROM c "
            "WHERE c.sessionId = @sid "
            "ORDER BY c.timestamp DESC"
        )
        params = [
            {"name": "@limit", "value": limit},
            {"name": "@sid", "value": session_id},
        ]
        items = self._container.query_items(
            query=query,
            parameters=params,
            partition_key=session_id,
        )
        return list(items)

    def query_known_scams(self, text: str, threshold: float = 0.8) -> list:
        """Find past analyses classified as SCAM/LIKELY_SCAM similar to text.

        Uses in-memory text similarity via difflib. For production scale,
        consider Azure AI Search or Cosmos DB vector indexing.
        """
        query = (
            "SELECT * FROM c "
            "WHERE c.result.classification IN ('SCAM', 'LIKELY_SCAM')"
        )
        items = self._container.query_items(
            query=query, enable_cross_partition_query=True
        )
        candidates = list(items)
        return filter_by_similarity(candidates, text, threshold)


_instance = None


def get_cosmos_service() -> CosmosService:
    """Lazy singleton accessor."""
    global _instance
    if _instance is None:
        from shared import config

        _instance = CosmosService(
            connection_string=config.COSMOS_DB_CONNECTION_STRING(),
            endpoint=config.COSMOS_DB_ENDPOINT(),
            key=config.COSMOS_DB_KEY(),
            database_name=config.COSMOS_DB_DATABASE(),
            container_name=config.COSMOS_DB_CONTAINER(),
        )
    return _instance
