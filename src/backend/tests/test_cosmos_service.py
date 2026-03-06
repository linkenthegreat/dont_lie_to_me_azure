"""Unit tests for CosmosService."""

import json
import unittest
from unittest.mock import MagicMock, patch


class TestCosmosServiceInit(unittest.TestCase):

    @patch("services.cosmos_service.CosmosClient")
    def test_init_with_connection_string(self, MockClient):
        from services.cosmos_service import CosmosService

        CosmosService(connection_string="AccountEndpoint=https://x;AccountKey=y;")
        MockClient.from_connection_string.assert_called_once()

    @patch("services.cosmos_service.CosmosClient")
    def test_init_with_endpoint_and_key(self, MockClient):
        from services.cosmos_service import CosmosService

        CosmosService(endpoint="https://x.documents.azure.com", key="mykey")
        MockClient.assert_called_once_with("https://x.documents.azure.com", credential="mykey")

    def test_init_raises_without_credentials(self):
        from services.cosmos_service import CosmosService

        with self.assertRaises(ValueError):
            CosmosService()


class TestUpsertAnalysis(unittest.TestCase):

    @patch("services.cosmos_service.CosmosClient")
    def test_upsert_creates_document(self, MockClient):
        from services.cosmos_service import CosmosService

        mock_container = MagicMock()
        mock_container.upsert_item.return_value = {"id": "test-id", "sessionId": "s1"}
        mock_db = MagicMock()
        mock_db.get_container_client.return_value = mock_container
        MockClient.from_connection_string.return_value.get_database_client.return_value = mock_db

        service = CosmosService(connection_string="dummy")
        doc = service.upsert_analysis("s1", "classify", "hello", {"classification": "SAFE"})

        self.assertEqual(doc["id"], "test-id")
        call_args = mock_container.upsert_item.call_args[0][0]
        self.assertEqual(call_args["sessionId"], "s1")
        self.assertEqual(call_args["endpoint"], "classify")
        self.assertEqual(call_args["inputText"], "hello")
        self.assertIn("timestamp", call_args)


class TestQueryHistory(unittest.TestCase):

    @patch("services.cosmos_service.CosmosClient")
    def test_query_history_calls_query_items(self, MockClient):
        from services.cosmos_service import CosmosService

        mock_container = MagicMock()
        mock_container.query_items.return_value = iter([{"id": "1"}])
        mock_db = MagicMock()
        mock_db.get_container_client.return_value = mock_container
        MockClient.from_connection_string.return_value.get_database_client.return_value = mock_db

        service = CosmosService(connection_string="dummy")
        results = service.query_history("s1", limit=5)

        self.assertEqual(len(results), 1)
        mock_container.query_items.assert_called_once()


class TestQueryKnownScams(unittest.TestCase):

    @patch("services.cosmos_service.CosmosClient")
    def test_filters_by_similarity(self, MockClient):
        from services.cosmos_service import CosmosService

        mock_container = MagicMock()
        mock_container.query_items.return_value = iter([
            {"inputText": "You won a prize!", "result": {"classification": "SCAM"}},
            {"inputText": "Meeting at 3pm", "result": {"classification": "SCAM"}},
        ])
        mock_db = MagicMock()
        mock_db.get_container_client.return_value = mock_container
        MockClient.from_connection_string.return_value.get_database_client.return_value = mock_db

        service = CosmosService(connection_string="dummy")
        matches = service.query_known_scams("You won a prize!", threshold=0.8)

        self.assertTrue(len(matches) >= 1)
        self.assertGreaterEqual(matches[0]["similarity"], 0.8)


if __name__ == "__main__":
    unittest.main()
