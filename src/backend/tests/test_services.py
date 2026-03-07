"""
Unit tests for service layer.

Tests that services correctly call AI client and handle responses.
"""

import unittest
from unittest.mock import MagicMock, patch
from services import scam_classifier, message_analyzer, guidance_generator


class TestScamClassifier(unittest.TestCase):
    """Tests for scam_classifier service."""

    def test_classify_with_valid_json(self):
        """Service should parse and return valid JSON from AI."""
        mock_client = MagicMock()
        mock_client.chat.return_value = '{"classification": "SCAM", "confidence": 0.95, "reasoning": "Test"}'
        
        result = scam_classifier.classify_scam("Suspicious message", client=mock_client)
        
        self.assertEqual(result["classification"], "SCAM")
        self.assertEqual(result["confidence"], 0.95)
        self.assertEqual(result["reasoning"], "Test")
        mock_client.chat.assert_called_once()

    def test_classify_with_invalid_json(self):
        """Service should handle non-JSON response gracefully."""
        mock_client = MagicMock()
        mock_client.chat.return_value = "This is not JSON"
        
        result = scam_classifier.classify_scam("Test message", client=mock_client)
        
        self.assertEqual(result["classification"], "UNKNOWN")
        self.assertEqual(result["confidence"], 0.0)
        self.assertIn("This is not JSON", result["reasoning"])

    def test_classify_requires_text(self):
        """Service should raise ValueError for empty text."""
        with self.assertRaises(ValueError) as ctx:
            scam_classifier.classify_scam("")
        self.assertIn("must not be empty", str(ctx.exception))


class TestMessageAnalyzer(unittest.TestCase):
    """Tests for message_analyzer service."""

    def test_analyze_with_valid_json(self):
        """Service should parse and return valid JSON from AI."""
        mock_client = MagicMock()
        mock_client.chat.return_value = '''{
            "red_flags": ["urgency"],
            "persuasion_techniques": ["fear"],
            "impersonation_indicators": ["bank"],
            "summary": "Suspicious"
        }'''
        
        result = message_analyzer.analyze_message("Test message", client=mock_client)
        
        self.assertEqual(result["red_flags"], ["urgency"])
        self.assertEqual(result["persuasion_techniques"], ["fear"])
        self.assertEqual(result["impersonation_indicators"], ["bank"])
        self.assertEqual(result["summary"], "Suspicious")

    def test_analyze_with_invalid_json(self):
        """Service should handle non-JSON response gracefully."""
        mock_client = MagicMock()
        mock_client.chat.return_value = "Not JSON"
        
        result = message_analyzer.analyze_message("Test", client=mock_client)
        
        self.assertEqual(result["red_flags"], [])
        self.assertEqual(result["persuasion_techniques"], [])
        self.assertEqual(result["impersonation_indicators"], [])
        self.assertIn("Not JSON", result["summary"])

    def test_analyze_requires_text(self):
        """Service should raise ValueError for empty text."""
        with self.assertRaises(ValueError) as ctx:
            message_analyzer.analyze_message("  ")
        self.assertIn("must not be empty", str(ctx.exception))


class TestGuidanceGenerator(unittest.TestCase):
    """Tests for guidance_generator service."""

    def test_generate_with_valid_json(self):
        """Service should parse and return valid JSON from AI."""
        mock_client = MagicMock()
        mock_client.chat.return_value = '''{
            "immediate_actions": ["Don't respond"],
            "reporting_steps": ["Report to authorities"],
            "prevention_tips": ["Enable 2FA"],
            "resources": ["https://example.com"]
        }'''
        
        result = guidance_generator.generate_guidance("Scam message", client=mock_client)
        
        self.assertEqual(result["immediate_actions"], ["Don't respond"])
        self.assertEqual(result["reporting_steps"], ["Report to authorities"])
        self.assertEqual(result["prevention_tips"], ["Enable 2FA"])
        self.assertEqual(result["resources"], ["https://example.com"])

    def test_generate_with_context(self):
        """Service should include context in prompt."""
        mock_client = MagicMock()
        mock_client.chat.return_value = '{"immediate_actions": [],"reporting_steps": [],"prevention_tips": [],"resources": []}'
        
        guidance_generator.generate_guidance("Message", context="Extra info", client=mock_client)
        
        call_args = mock_client.chat.call_args[1]
        user_message = call_args["user_message"]
        self.assertIn("Message", user_message)
        self.assertIn("Extra info", user_message)

    def test_generate_with_invalid_json(self):
        """Service should handle non-JSON response gracefully."""
        mock_client = MagicMock()
        mock_client.chat.return_value = "Not JSON"
        
        result = guidance_generator.generate_guidance("Test", client=mock_client)
        
        self.assertEqual(result["immediate_actions"], [])
        self.assertEqual(result["reporting_steps"], [])
        self.assertEqual(result["prevention_tips"], [])
        self.assertEqual(result["resources"], [])
        self.assertIn("Not JSON", result["note"])

    def test_generate_requires_text(self):
        """Service should raise ValueError for empty text."""
        with self.assertRaises(ValueError):
            guidance_generator.generate_guidance("")


if __name__ == "__main__":
    unittest.main()
