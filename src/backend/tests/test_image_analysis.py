"""
Unit tests for image authenticity analysis feature.

Tests cover:
- AI client chat_with_image() method
- Image analysis service (vision + metadata)
- POST /api/analyze-image endpoint
"""

import base64
import json
import os
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helper: tiny 1x1 PNG as base64 (valid image for Pillow)
# ---------------------------------------------------------------------------
_TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4"
    "nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)
_TINY_PNG_DATA_URI = f"data:image/png;base64,{_TINY_PNG_B64}"


# ---------------------------------------------------------------------------
# AzureAIClient.chat_with_image tests
# ---------------------------------------------------------------------------


class TestAzureAIClientChatWithImage(unittest.TestCase):
    """Tests for shared/ai_client.py chat_with_image() method."""

    @patch("shared.ai_client.AzureOpenAI")
    def test_chat_with_image_returns_model_content(self, MockOpenAI):
        """chat_with_image() should return the model's response content."""
        from shared.ai_client import AzureAIClient

        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client

        expected_response = json.dumps({
            "authenticity_score": 0.9,
            "verdict": "AUTHENTIC",
            "summary": "Image appears authentic.",
        })
        mock_response = MagicMock()
        mock_response.choices[0].message.content = expected_response
        mock_client.chat.completions.create.return_value = mock_response

        with unittest.mock.patch.dict(os.environ, {
            "AZURE_AI_ENDPOINT": "https://example.openai.azure.com/",
            "AZURE_AI_API_KEY": "testkey",
            "AZURE_AI_DEPLOYMENT_NAME": "gpt-4o",
        }):
            client = AzureAIClient()
            result = client.chat_with_image(
                system_prompt="Analyze image",
                user_message="Check this image",
                image_base64=_TINY_PNG_B64,
                image_media_type="image/png",
            )

        self.assertEqual(result, expected_response)

    @patch("shared.ai_client.AzureOpenAI")
    def test_chat_with_image_sends_correct_message_format(self, MockOpenAI):
        """chat_with_image() should send image_url content part to the API."""
        from shared.ai_client import AzureAIClient

        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "{}"
        mock_client.chat.completions.create.return_value = mock_response

        with unittest.mock.patch.dict(os.environ, {
            "AZURE_AI_ENDPOINT": "https://example.openai.azure.com/",
            "AZURE_AI_API_KEY": "testkey",
        }):
            client = AzureAIClient()
            client.chat_with_image(
                system_prompt="system",
                user_message="analyze",
                image_base64="abc123",
                image_media_type="image/jpeg",
            )

        call_args = mock_client.chat.completions.create.call_args
        messages = call_args.kwargs["messages"]

        # System message
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "system")

        # User message with image
        user_content = messages[1]["content"]
        self.assertIsInstance(user_content, list)
        self.assertEqual(len(user_content), 2)
        self.assertEqual(user_content[0]["type"], "text")
        self.assertEqual(user_content[1]["type"], "image_url")
        self.assertIn("data:image/jpeg;base64,abc123", user_content[1]["image_url"]["url"])
        self.assertEqual(user_content[1]["image_url"]["detail"], "high")

    def test_chat_with_image_mock_provider(self):
        """Mock provider should return image analysis mock response."""
        from shared.ai_client import AzureAIClient

        with unittest.mock.patch.dict(os.environ, {"AI_PROVIDER": "mock"}):
            client = AzureAIClient()
            result = client.chat_with_image(
                system_prompt="Detect authenticity_score and manipulation_indicators",
                user_message="analyze",
                image_base64=_TINY_PNG_B64,
            )

        data = json.loads(result)
        self.assertIn("authenticity_score", data)
        self.assertIn("verdict", data)
        self.assertIn("manipulation_indicators", data)
        self.assertIn("ai_generation_analysis", data)


# ---------------------------------------------------------------------------
# Image analysis service tests
# ---------------------------------------------------------------------------


class TestImageAnalysisService(unittest.TestCase):
    """Tests for services/image_analysis_service.py."""

    @patch("services.image_analysis_service.AzureAIClient")
    def test_analyze_image_returns_complete_structure(self, MockClient):
        """analyze_image() should return all expected keys."""
        from services.image_analysis_service import analyze_image

        mock_instance = MagicMock()
        mock_instance.chat_with_image.return_value = json.dumps({
            "authenticity_score": 0.8,
            "verdict": "AUTHENTIC",
            "manipulation_indicators": [],
            "visual_analysis": {
                "text_consistency": "Consistent",
                "font_analysis": "Normal",
                "layout_anomalies": "None",
                "pixel_artifacts": "None",
                "lighting_consistency": "Consistent",
            },
            "ai_generation_analysis": {
                "is_ai_generated": False,
                "confidence": 0.05,
                "generator_hints": "UNKNOWN",
                "artifacts_found": [],
                "deepfake_indicators": [],
            },
            "context_analysis": {
                "platform_identified": "WhatsApp",
                "expected_vs_actual": "Consistent",
                "suspicious_patterns": [],
            },
            "summary": "Image appears authentic.",
        })
        MockClient.return_value = mock_instance

        result = analyze_image(_TINY_PNG_B64, "image/png")

        self.assertIn("authenticity_score", result)
        self.assertIn("verdict", result)
        self.assertIn("manipulation_indicators", result)
        self.assertIn("visual_analysis", result)
        self.assertIn("ai_generation_analysis", result)
        self.assertIn("context_analysis", result)
        self.assertIn("metadata_analysis", result)  # Added by service
        self.assertIn("summary", result)

    @patch("services.image_analysis_service.AzureAIClient")
    def test_analyze_image_includes_metadata(self, MockClient):
        """analyze_image() should include Pillow metadata analysis."""
        from services.image_analysis_service import analyze_image

        mock_instance = MagicMock()
        mock_instance.chat_with_image.return_value = json.dumps({
            "authenticity_score": 0.5,
            "verdict": "INCONCLUSIVE",
            "manipulation_indicators": [],
            "visual_analysis": {},
            "ai_generation_analysis": {},
            "context_analysis": {},
            "summary": "test",
        })
        MockClient.return_value = mock_instance

        result = analyze_image(_TINY_PNG_B64, "image/png")

        meta = result["metadata_analysis"]
        self.assertIn("exif_present", meta)
        self.assertIn("image_format", meta)
        self.assertIn("image_size", meta)

    @patch("services.image_analysis_service.AzureAIClient")
    def test_analyze_image_handles_non_json_vision_response(self, MockClient):
        """Service should handle non-JSON response from vision model gracefully."""
        from services.image_analysis_service import analyze_image

        mock_instance = MagicMock()
        mock_instance.chat_with_image.return_value = "This image looks suspicious but I cannot format JSON."
        MockClient.return_value = mock_instance

        result = analyze_image(_TINY_PNG_B64, "image/png")

        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(result["authenticity_score"], 0.5)
        self.assertIn("metadata_analysis", result)

    @patch("services.image_analysis_service.AzureAIClient")
    def test_analyze_image_ai_generated_verdict(self, MockClient):
        """Service should correctly pass through AI_GENERATED verdict."""
        from services.image_analysis_service import analyze_image

        mock_instance = MagicMock()
        mock_instance.chat_with_image.return_value = json.dumps({
            "authenticity_score": 0.15,
            "verdict": "AI_GENERATED",
            "manipulation_indicators": [
                {"type": "ai_generation", "description": "Waxy skin texture", "confidence": 0.9}
            ],
            "visual_analysis": {},
            "ai_generation_analysis": {
                "is_ai_generated": True,
                "confidence": 0.92,
                "generator_hints": "Possible Midjourney",
                "artifacts_found": ["Waxy skin", "Perfect symmetry"],
                "deepfake_indicators": [],
            },
            "context_analysis": {},
            "summary": "Image appears to be AI-generated.",
        })
        MockClient.return_value = mock_instance

        result = analyze_image(_TINY_PNG_B64, "image/png")

        self.assertEqual(result["verdict"], "AI_GENERATED")
        self.assertTrue(result["ai_generation_analysis"]["is_ai_generated"])
        self.assertGreater(result["ai_generation_analysis"]["confidence"], 0.9)

    @patch("services.image_analysis_service.AzureAIClient")
    def test_analyze_image_deepfake_verdict(self, MockClient):
        """Service should correctly pass through DEEPFAKE verdict."""
        from services.image_analysis_service import analyze_image

        mock_instance = MagicMock()
        mock_instance.chat_with_image.return_value = json.dumps({
            "authenticity_score": 0.1,
            "verdict": "DEEPFAKE",
            "manipulation_indicators": [
                {"type": "deepfake", "description": "Face boundary artifacts", "confidence": 0.88}
            ],
            "visual_analysis": {},
            "ai_generation_analysis": {
                "is_ai_generated": False,
                "confidence": 0.3,
                "generator_hints": "UNKNOWN",
                "artifacts_found": [],
                "deepfake_indicators": ["Face/neck boundary mismatch", "Inconsistent lighting"],
            },
            "context_analysis": {},
            "summary": "Likely a deepfake.",
        })
        MockClient.return_value = mock_instance

        result = analyze_image(_TINY_PNG_B64, "image/png")

        self.assertEqual(result["verdict"], "DEEPFAKE")
        self.assertEqual(len(result["ai_generation_analysis"]["deepfake_indicators"]), 2)


# ---------------------------------------------------------------------------
# Metadata analysis tests
# ---------------------------------------------------------------------------


class TestMetadataAnalysis(unittest.TestCase):
    """Tests for _analyze_metadata in image_analysis_service.py."""

    def test_metadata_for_png_without_exif(self):
        """PNG screenshots typically lack EXIF; should report exif_present=False."""
        from services.image_analysis_service import _analyze_metadata

        result = _analyze_metadata(_TINY_PNG_B64)

        self.assertFalse(result["exif_present"])
        self.assertIsNone(result["editing_software_detected"])
        self.assertEqual(result["image_format"], "PNG")
        self.assertEqual(result["image_size"]["width"], 1)
        self.assertEqual(result["image_size"]["height"], 1)

    def test_metadata_handles_invalid_base64(self):
        """Invalid base64 should return graceful fallback."""
        from services.image_analysis_service import _analyze_metadata

        result = _analyze_metadata("not-valid-base64!!!")

        self.assertFalse(result["exif_present"])
        self.assertIn("note", result)


# ---------------------------------------------------------------------------
# Resize for vision tests
# ---------------------------------------------------------------------------


class TestResizeForVision(unittest.TestCase):
    """Tests for _resize_for_vision in image_analysis_service.py."""

    def test_small_image_not_resized(self):
        """Image within limits should be returned as-is."""
        from services.image_analysis_service import _resize_for_vision

        result_b64, result_type = _resize_for_vision(_TINY_PNG_B64, "image/png")

        self.assertEqual(result_b64, _TINY_PNG_B64)
        self.assertEqual(result_type, "image/png")

    def test_large_image_is_resized(self):
        """Image exceeding max dimension should be resized."""
        from PIL import Image
        import io

        # Create a 3000x3000 image
        img = Image.new("RGB", (3000, 3000), color="red")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        large_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        from services.image_analysis_service import _resize_for_vision

        result_b64, result_type = _resize_for_vision(large_b64, "image/png")

        # Should be different (resized)
        self.assertNotEqual(result_b64, large_b64)

        # Verify resized dimensions
        result_bytes = base64.b64decode(result_b64)
        result_img = Image.open(io.BytesIO(result_bytes))
        self.assertLessEqual(max(result_img.width, result_img.height), 2048)

    def test_invalid_image_returns_original(self):
        """Invalid image data should return original without crashing."""
        from services.image_analysis_service import _resize_for_vision

        result_b64, result_type = _resize_for_vision("invalid", "image/png")

        self.assertEqual(result_b64, "invalid")
        self.assertEqual(result_type, "image/png")


# ---------------------------------------------------------------------------
# POST /api/analyze-image endpoint tests
# ---------------------------------------------------------------------------


class TestAnalyzeImageEndpoint(unittest.TestCase):
    """Tests for POST /api/analyze-image."""

    def _make_request(self, body):
        import azure.functions as func

        if isinstance(body, dict):
            body_bytes = json.dumps(body).encode()
        else:
            body_bytes = body
        return func.HttpRequest(
            method="POST",
            url="http://localhost:7071/api/analyze-image",
            body=body_bytes,
            headers={"Content-Type": "application/json"},
            params={},
        )

    def test_missing_image_returns_400(self):
        """Request without 'image' field should return 400."""
        from function_app import analyze_image

        req = self._make_request({})
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.get_body())
        self.assertIn("error", body)

    def test_empty_image_returns_400(self):
        """Request with empty 'image' should return 400."""
        from function_app import analyze_image

        req = self._make_request({"image": ""})
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)

    def test_invalid_data_uri_returns_400(self):
        """Request with non-data-URI image should return 400."""
        from function_app import analyze_image

        req = self._make_request({"image": "not-a-data-uri"})
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.get_body())
        self.assertIn("Invalid image format", body["error"])

    def test_invalid_json_body_returns_400(self):
        """Malformed JSON body should return 400."""
        from function_app import analyze_image

        req = self._make_request(b"not-json")
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)

    def test_oversized_image_returns_400(self):
        """Image exceeding 10MB should return 400."""
        from function_app import analyze_image

        # Create a data URI with >10MB of base64
        huge_b64 = "A" * (11 * 1024 * 1024)
        req = self._make_request({"image": f"data:image/png;base64,{huge_b64}"})
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)
        body = json.loads(response.get_body())
        self.assertIn("too large", body["error"])

    @patch("function_app._try_cache_get", return_value=(None, None))
    @patch("function_app._try_cache_set")
    @patch("function_app._persist_analysis")
    @patch("function_app._track_request")
    def test_valid_request_returns_analysis(self, mock_track, mock_persist, mock_cache_set, mock_cache_get):
        """Valid image request should return analysis JSON."""
        from function_app import analyze_image

        mock_result = {
            "authenticity_score": 0.85,
            "verdict": "AUTHENTIC",
            "manipulation_indicators": [],
            "visual_analysis": {},
            "ai_generation_analysis": {},
            "context_analysis": {},
            "metadata_analysis": {},
            "summary": "Image appears authentic.",
        }

        with patch("services.image_analysis_service.analyze_image", return_value=mock_result):
            req = self._make_request({
                "image": _TINY_PNG_DATA_URI,
                "session_id": "test-session",
            })
            response = analyze_image(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertEqual(body["verdict"], "AUTHENTIC")
        self.assertAlmostEqual(body["authenticity_score"], 0.85)

    @patch("function_app._try_cache_get")
    @patch("function_app._track_request")
    def test_cached_result_returns_with_flag(self, mock_track, mock_cache_get):
        """Cached result should be returned with _cached=True."""
        from function_app import analyze_image

        cached = {"verdict": "MANIPULATED", "authenticity_score": 0.2}
        mock_cache_get.return_value = ("cache-key", cached)

        req = self._make_request({"image": _TINY_PNG_DATA_URI})
        response = analyze_image(req)

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.get_body())
        self.assertTrue(body.get("_cached"))
        self.assertEqual(body["verdict"], "MANIPULATED")

    @patch("function_app._try_cache_get", return_value=(None, None))
    @patch("function_app._track_request")
    def test_service_error_returns_500(self, mock_track, mock_cache_get):
        """If image analysis service raises, should return 500."""
        from function_app import analyze_image

        with patch(
            "services.image_analysis_service.analyze_image",
            side_effect=RuntimeError("Vision API unavailable"),
        ):
            req = self._make_request({"image": _TINY_PNG_DATA_URI})
            response = analyze_image(req)

        self.assertEqual(response.status_code, 500)
        body = json.loads(response.get_body())
        self.assertIn("error", body)

    def test_non_image_media_type_rejected(self):
        """Data URI with non-image MIME type should be rejected."""
        from function_app import analyze_image

        req = self._make_request({"image": "data:text/plain;base64,SGVsbG8="})
        response = analyze_image(req)
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
