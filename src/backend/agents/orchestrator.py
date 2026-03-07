"""Deterministic orchestrator for Phase E team composition."""

from datetime import datetime, timezone
import re
from typing import Dict, Optional

from agents.teams import (
    ClassifierAgent,
    GuidanceAgent,
    ReceptionistAgent,
    ReportGeneratorAgent,
    ResourceAssistantAgent,
    TextAnalyzerAgent,
    URLAnalyzerAgent,
)
from shared.models import (
    AgentContext,
    AgentIntent,
    AgentRequest,
    AgentResponse,
    OrchestrationTrace,
    OrchestrationTraceStep,
)


class OrchestratorAgent:
    """Routes requests to team agents with deterministic Phase E rules."""

    def __init__(
        self,
        receptionist_agent: Optional[ReceptionistAgent] = None,
        classifier_agent: Optional[ClassifierAgent] = None,
        analyzer_agent: Optional[TextAnalyzerAgent] = None,
        url_analyzer_agent: Optional[URLAnalyzerAgent] = None,
        guidance_agent: Optional[GuidanceAgent] = None,
        report_generator_agent: Optional[ReportGeneratorAgent] = None,
        resource_assistant_agent: Optional[ResourceAssistantAgent] = None,
    ) -> None:
        self.receptionist_agent = receptionist_agent or ReceptionistAgent()
        self.classifier_agent = classifier_agent or ClassifierAgent()
        self.analyzer_agent = analyzer_agent or TextAnalyzerAgent()
        self.url_analyzer_agent = url_analyzer_agent or URLAnalyzerAgent()
        self.guidance_agent = guidance_agent or GuidanceAgent()
        self.report_generator_agent = report_generator_agent or ReportGeneratorAgent()
        self.resource_assistant_agent = resource_assistant_agent or ResourceAssistantAgent()

    def run(self, request: AgentRequest, context: Optional[AgentContext] = None) -> AgentResponse:
        """Execute deterministic flow: classify -> optional analyze -> guidance."""
        context = context or AgentContext(session_id=request.session_id)
        steps = []

        receptionist = self.receptionist_agent.run(request.message)
        detected_intent = self._detect_intent(request.message)
        has_url = self._contains_url(request.message)

        classification = self.classifier_agent.run(request.message)
        steps.append(
            self._step(
                selected_team="classifier_team",
                reason="Always run triage classification first",
            )
        )

        text_analysis = None
        if has_url or detected_intent == AgentIntent.ANALYZE:
            text_analysis = self.analyzer_agent.run(request.message)
            steps.append(
                self._step(
                    selected_team="analyzer_team",
                    reason="URL present or analysis intent detected",
                )
            )

        url_analysis = None
        if has_url:
            url_analysis = self.url_analyzer_agent.run(
                request.message,
                url_candidates=receptionist.get("url_candidates"),
            )
            steps.append(
                self._step(
                    selected_team="url_analyzer_team",
                    reason="URL candidate detected by receptionist",
                )
            )

        analysis = None
        if text_analysis or url_analysis:
            analysis = {
                "text_analysis": text_analysis,
                "url_analysis": url_analysis,
            }

        guidance_context = context.latest_summary
        if text_analysis and isinstance(text_analysis, dict):
            guidance_context = text_analysis.get("summary") or guidance_context

        guidance = self.guidance_agent.run(request.message, context=guidance_context)

        report = self.report_generator_agent.run(classification, analysis, guidance)
        resources = self.resource_assistant_agent.run(
            location_hint=request.metadata.get("location")
        )
        guidance["report"] = report
        guidance["resources"] = resources

        steps.append(
            self._step(
                selected_team="guidance_team",
                reason="Always produce user action guidance",
            )
        )

        trace = OrchestrationTrace(
            routing_version="phase-e-v1",
            detected_intent=detected_intent,
            has_url=has_url,
            steps=steps,
            notes=[
                "Deterministic routing used (no model-based planner).",
                "Phase E team composition enabled (receptionist/url analyzer/report/resources).",
            ],
        )

        return AgentResponse(
            team="orchestrator",
            intent=detected_intent,
            confidence=0.75,
            result={
                "receptionist": receptionist,
                "classification": classification,
                "analysis": analysis,
                "guidance": guidance,
            },
            trace=trace,
        )

    @staticmethod
    def _contains_url(text: str) -> bool:
        return bool(re.search(r"https?://|www\\.", text, flags=re.IGNORECASE))

    @staticmethod
    def _detect_intent(text: str) -> AgentIntent:
        lowered = text.lower()
        if any(token in lowered for token in ["analyze", "analyse", "details", "why"]):
            return AgentIntent.ANALYZE
        if any(token in lowered for token in ["what should i do", "help me", "next steps", "guidance"]):
            return AgentIntent.GUIDANCE
        return AgentIntent.TRIAGE

    @staticmethod
    def _step(selected_team: str, reason: str) -> OrchestrationTraceStep:
        return OrchestrationTraceStep(
            selected_team=selected_team,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
