"""Phase E tests for deterministic orchestrator routing."""

import unittest
from unittest.mock import MagicMock

from agents.orchestrator import OrchestratorAgent
from agents.teams import FakeImageDetectorAgent, PhoneNumberAnalyzerAgent
from shared.models import AgentContext, AgentIntent, AgentRequest


class TestOrchestratorAgent(unittest.TestCase):
    """Validate deterministic routing and response contracts."""

    def test_triage_message_runs_classify_and_guidance(self):
        receptionist = MagicMock()
        receptionist.run.return_value = {
            "detected_language": "en",
            "clarification_needed": False,
            "clarification_prompts": [],
            "url_candidates": [],
        }
        classifier = MagicMock()
        classifier.run.return_value = {"classification": "SUSPICIOUS", "confidence": 0.8}
        analyzer = MagicMock()
        url_analyzer = MagicMock()
        guidance = MagicMock()
        guidance.run.return_value = {
            "immediate_actions": ["Do not click links"],
            "reporting_steps": [],
            "prevention_tips": [],
            "resources": [],
        }
        report_generator = MagicMock()
        report_generator.run.return_value = {"risk_level": "SUSPICIOUS"}
        resource_assistant = MagicMock()
        resource_assistant.run.return_value = {"reporting_resources": ["https://example.org"]}

        orchestrator = OrchestratorAgent(
            receptionist_agent=receptionist,
            classifier_agent=classifier,
            analyzer_agent=analyzer,
            url_analyzer_agent=url_analyzer,
            guidance_agent=guidance,
            report_generator_agent=report_generator,
            resource_assistant_agent=resource_assistant,
        )

        request = AgentRequest(message="I got a weird SMS from my bank")
        response = orchestrator.run(request)

        self.assertEqual(response.intent, AgentIntent.TRIAGE)
        self.assertIn("receptionist", response.result)
        self.assertIn("classification", response.result)
        self.assertIsNone(response.result["analysis"])
        receptionist.run.assert_called_once()
        classifier.run.assert_called_once()
        analyzer.run.assert_not_called()
        url_analyzer.run.assert_not_called()
        guidance.run.assert_called_once()
        report_generator.run.assert_called_once()
        resource_assistant.run.assert_called_once_with(location_hint=None)
        self.assertEqual(len(response.trace.steps), 2)

    def test_url_message_triggers_analyzer_team(self):
        receptionist = MagicMock()
        receptionist.run.return_value = {
            "detected_language": "en",
            "clarification_needed": False,
            "clarification_prompts": [],
            "url_candidates": ["https://bad-site.example"],
        }
        classifier = MagicMock()
        classifier.run.return_value = {"classification": "LIKELY_SCAM", "confidence": 0.9}
        analyzer = MagicMock()
        analyzer.run.return_value = {"summary": "URL looks suspicious"}
        url_analyzer = MagicMock()
        url_analyzer.run.return_value = {
            "checked_urls": ["https://bad-site.example"],
            "overall_verdict": "SUSPICIOUS",
        }
        guidance = MagicMock()
        guidance.run.return_value = {
            "immediate_actions": ["Report phishing URL"],
            "reporting_steps": [],
            "prevention_tips": [],
            "resources": [],
        }
        report_generator = MagicMock()
        report_generator.run.return_value = {"risk_level": "LIKELY_SCAM"}
        resource_assistant = MagicMock()
        resource_assistant.run.return_value = {"reporting_resources": ["https://example.org"]}

        orchestrator = OrchestratorAgent(
            receptionist_agent=receptionist,
            classifier_agent=classifier,
            analyzer_agent=analyzer,
            url_analyzer_agent=url_analyzer,
            guidance_agent=guidance,
            report_generator_agent=report_generator,
            resource_assistant_agent=resource_assistant,
        )

        request = AgentRequest(message="Please analyze this link: https://bad-site.example")
        response = orchestrator.run(request)

        self.assertEqual(response.intent, AgentIntent.ANALYZE)
        self.assertIsNotNone(response.result["analysis"])
        self.assertIn("text_analysis", response.result["analysis"])
        self.assertIn("url_analysis", response.result["analysis"])
        analyzer.run.assert_called_once()
        url_analyzer.run.assert_called_once_with(
            request.message,
            url_candidates=["https://bad-site.example"],
        )
        self.assertEqual(len(response.trace.steps), 4)
        self.assertTrue(response.trace.has_url)

    def test_guidance_intent_still_performs_triage_first(self):
        receptionist = MagicMock()
        receptionist.run.return_value = {
            "detected_language": "en",
            "clarification_needed": False,
            "clarification_prompts": [],
            "url_candidates": [],
        }
        classifier = MagicMock()
        classifier.run.return_value = {"classification": "SCAM", "confidence": 0.99}
        analyzer = MagicMock()
        url_analyzer = MagicMock()
        guidance = MagicMock()
        guidance.run.return_value = {
            "immediate_actions": ["Block sender"],
            "reporting_steps": [],
            "prevention_tips": [],
            "resources": [],
        }
        report_generator = MagicMock()
        report_generator.run.return_value = {"risk_level": "SCAM"}
        resource_assistant = MagicMock()
        resource_assistant.run.return_value = {"reporting_resources": ["https://example.org"]}

        orchestrator = OrchestratorAgent(
            receptionist_agent=receptionist,
            classifier_agent=classifier,
            analyzer_agent=analyzer,
            url_analyzer_agent=url_analyzer,
            guidance_agent=guidance,
            report_generator_agent=report_generator,
            resource_assistant_agent=resource_assistant,
        )

        request = AgentRequest(message="Help me with next steps for this scam text")
        context = AgentContext(session_id="s1", latest_summary="User is worried")
        response = orchestrator.run(request, context=context)

        self.assertEqual(response.intent, AgentIntent.GUIDANCE)
        classifier.run.assert_called_once()
        analyzer.run.assert_not_called()
        url_analyzer.run.assert_not_called()
        guidance.run.assert_called_once_with(request.message, context="User is worried")
        self.assertEqual(response.trace.routing_version, "phase-e-v1")

    def test_extension_stubs_return_not_implemented(self):
        image_agent = FakeImageDetectorAgent()
        phone_agent = PhoneNumberAnalyzerAgent()

        image_result = image_agent.run("sample.png")
        phone_result = phone_agent.run("+15551234567")

        self.assertEqual(image_result["status"], "not_implemented")
        self.assertEqual(phone_result["status"], "not_implemented")

    def test_empty_message_is_rejected_by_contract(self):
        with self.assertRaises(ValueError):
            AgentRequest(message="   ")


if __name__ == "__main__":
    unittest.main()
