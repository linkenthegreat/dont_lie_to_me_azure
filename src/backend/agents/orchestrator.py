"""
OrchestratorAgent - Request routing and agent coordination.

Phase B.5: Deterministic routing based on content patterns.
Phase D: Extended with LLM-assisted routing and advanced context handling.

Routing rules (deterministic):
1. Greeting patterns ("hello", "hi", "help") → ReceptionistAgent
2. URL patterns (http://, https://, www.) → URLAnalyzerAgent (existing url_checker)
3. Suspicious content keywords → ClassifierAgent (auto-chains to Analyzer + Guidance if high risk)
4. Default/ambiguous → ReceptionistAgent for clarification

Design principles:
- Stateless executor: All state managed via AgentContext
- Thin wrapper: Routes to existing shared functions (url_checker, ai_client)
- Traceability: Every request produces OrchestrationTrace metadata
- Provider-agnostic: Uses ai_client interface, no provider branching
"""

import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_models import AgentRequest, AgentResponse, AgentContext, OrchestrationTrace
from shared.url_checker import URLChecker
from shared.ai_client import AzureAIClient
from shared.prompts import get_prompt_config

logger = logging.getLogger(__name__)

# Routing patterns
DEFAULT_GREETING_PATTERNS = [
    r"\b(hello|hi|hey|greetings|good\s+(morning|afternoon|evening))\b",
    r"\b(help|assist|support)\b",
]

DEFAULT_URL_PATTERNS = [
    r"https?://",
    r"www\.",
    r"\b[a-zA-Z0-9-]+\.(com|net|org|edu|gov|co\.uk|au|nz)\b",
]

DEFAULT_SUSPICIOUS_KEYWORDS = [
    r"\b(scam|fraud|phishing|suspicious|fake|impersonat\w*|urgent|verify account|click here|claim prize)\b",
    r"\b(bitcoin|crypto|investment|tax refund|lottery|inheritance)\b",
]


class OrchestratorAgent:
    """
    Orchestrates requests to appropriate agents based on content analysis.
    
    Phase B.5: Deterministic routing with simple pattern matching.
    Phase D: Extended with LLM-assisted routing for complex cases.
    """

    def __init__(self, ai_client: Optional[AzureAIClient] = None, url_checker: Optional[URLChecker] = None):
        """
        Initialize orchestrator.
        
        Args:
            ai_client: AI client for model calls. If None, creates default instance.
            url_checker: URL checker for URL analysis. If None, creates default instance.
        """
        try:
            self.ai_client = ai_client or AzureAIClient()
        except Exception as e:
            logger.error(f"Failed to initialize AI client: {e}", exc_info=True)
            raise
        
        try:
            self.url_checker = url_checker or URLChecker()
        except Exception as e:
            logger.warning(f"Failed to initialize URL checker: {e}. Continuing without URL checking.", exc_info=True)
            self.url_checker = None
        
        try:
            self.greeting_patterns = self._load_patterns("greeting_patterns", DEFAULT_GREETING_PATTERNS)
            self.url_patterns = self._load_patterns("url_patterns", DEFAULT_URL_PATTERNS)
            self.suspicious_keywords = self._load_patterns("suspicious_keywords", DEFAULT_SUSPICIOUS_KEYWORDS)
        except Exception as e:
            logger.warning(f"Failed to load routing patterns: {e}. Using defaults.", exc_info=True)
            self.greeting_patterns = DEFAULT_GREETING_PATTERNS
            self.url_patterns = DEFAULT_URL_PATTERNS
            self.suspicious_keywords = DEFAULT_SUSPICIOUS_KEYWORDS

    def _load_patterns(self, key: str, defaults: List[str]) -> List[str]:
        """
        Load deterministic routing patterns from prompts.yaml with safe fallbacks.

        This keeps routing deterministic/testable while allowing pattern tuning without code edits.
        """
        routing_config = get_prompt_config("routing_patterns")
        configured = routing_config.get(key, []) if isinstance(routing_config, dict) else []
        if isinstance(configured, list) and all(isinstance(item, str) for item in configured) and configured:
            return configured
        return defaults

    def execute(self, request: AgentRequest) -> AgentResponse:
        """
        Execute orchestration: analyze request, route to appropriate agent, return response.
        
        Args:
            request: Incoming agent request with text, images, and context.
            
        Returns:
            Agent response with conversational message, structured data, and trace.
        """
        start_time = time.time()
        route_path = ["orchestrator"]

        try:
            # Determine routing decision
            routing_decision, target_agent = self._route(request)
            route_path.append(target_agent)

            # Execute target agent
            if target_agent == "receptionist":
                response = self._execute_receptionist(request)
            elif target_agent == "url_analyzer":
                response = self._execute_url_analyzer(request)
            elif target_agent == "classifier":
                response = self._execute_classifier_chain(request)
            else:
                # Fallback to receptionist
                logger.warning(f"Unknown target agent '{target_agent}', falling back to receptionist")
                response = self._execute_receptionist(request)
                routing_decision = f"Fallback: unknown target '{target_agent}'"

            # Add orchestration metadata
            duration_ms = (time.time() - start_time) * 1000
            response.trace = OrchestrationTrace(
                route_path=route_path,
                routing_decision=routing_decision,
                duration_ms=duration_ms,
                model_used=response.trace.model_used if hasattr(response.trace, 'model_used') else None,
                timestamp=datetime.utcnow(),
                fallback_triggered=False,
            )

            return response

        except Exception as e:
            logger.error(f"Orchestration error: {e}", exc_info=True)
            duration_ms = (time.time() - start_time) * 1000

            # Return fallback response
            return AgentResponse(
                message="I'm having trouble processing your request right now. Please try again or rephrase your message.",
                data={"error": str(e)},
                agent_used="orchestrator_fallback",
                trace=OrchestrationTrace(
                    route_path=route_path,
                    routing_decision=f"Error: {str(e)}",
                    duration_ms=duration_ms,
                    timestamp=datetime.utcnow(),
                    fallback_triggered=True,
                ),
            )

    def _route(self, request: AgentRequest) -> tuple[str, str]:
        """
        Determine routing decision based on request content.
        
        Returns:
            Tuple of (reasoning, target_agent_name)
        """
        text_lower = request.text.lower()

        # Rule 1: Greeting patterns → receptionist
        for pattern in self.greeting_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return "Greeting pattern detected", "receptionist"

        # Rule 2: URL patterns → url_analyzer
        for pattern in self.url_patterns:
            if re.search(pattern, request.text, re.IGNORECASE):
                return "URL pattern detected", "url_analyzer"

        # Rule 3: Suspicious content keywords → classifier chain
        for pattern in self.suspicious_keywords:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return "Suspicious content keywords detected", "classifier"

        # Rule 4: Default → receptionist for clarification
        return "No specific pattern matched, routing to receptionist for clarification", "receptionist"

    def _execute_receptionist(self, request: AgentRequest) -> AgentResponse:
        """
        Execute receptionist agent for conversational empathy and context gathering.
        
        Deferred to receptionist.py for full implementation.
        This is a placeholder that will be replaced.
        """
        from .receptionist import ReceptionistAgent

        receptionist = ReceptionistAgent(ai_client=self.ai_client)
        return receptionist.execute(request)

    def _execute_url_analyzer(self, request: AgentRequest) -> AgentResponse:
        """
        Execute URL analysis using existing url_checker capability.
        
        Phase B.5: Wrapper around shared/url_checker.py
        Phase E: Refactored into URLAnalyzerAgent class
        """
        try:
            # Extract first URL from text
            url_match = None
            for pattern in self.url_patterns:
                match = re.search(pattern, request.text, re.IGNORECASE)
                if match:
                    # Try to extract full URL
                    words = request.text.split()
                    for word in words:
                        if "http" in word.lower() or "www." in word.lower():
                            url_match = word.strip()
                            break
                    if url_match:
                        break

            if not url_match:
                return AgentResponse(
                    message="I noticed you might be sharing a URL, but I couldn't extract it clearly. Could you share the complete URL?",
                    data={},
                    agent_used="url_analyzer",
                    trace=OrchestrationTrace(
                        route_path=["orchestrator", "url_analyzer"],
                        routing_decision="URL pattern detected but extraction failed",
                        duration_ms=0,
                    ),
                )

                # Check URL (with safety fallback if url_checker unavailable)
                if not self.url_checker:
                    return AgentResponse(
                        message=f"I detected a URL in your message: {url_match}\n\nUnfortunately, I'm currently unable to perform a security check on this URL due to technical limitations. **Please exercise caution** and verify the URL is legitimate before visiting it.",
                        data={"url": url_match, "verdict": "UNABLE_TO_CHECK"},
                        agent_used="url_analyzer",
                        trace=OrchestrationTrace(
                            route_path=["orchestrator", "url_analyzer"],
                            routing_decision="URL detector unavailable",
                            duration_ms=0,
                            fallback_triggered=True,
                        ),
                    )
            
                result = self.url_checker.check_url(url_match)

            # Format conversational response
            if result.verdict == "THREAT_DETECTED":
                message = f"⚠️ **Warning**: This URL has been flagged as a **known threat** by security sources. I strongly recommend **not visiting** this site.\n\n**Threat type**: {result.threat_category or 'General malicious activity'}\n\n**Why it's flagged**: {result.summary}"
            elif result.verdict == "SUSPICIOUS":
                message = f"🟡 **Caution**: This URL shows **suspicious characteristics** that could indicate risk.\n\n**Concerns**: {result.summary}\n\nI'd recommend proceeding with caution or avoiding this site."
            elif result.verdict == "NOT_FLAGGED":
                message = f"✅ This URL appears to be **not flagged** by threat intelligence sources.\n\n{result.summary}\n\nHowever, always exercise caution with unfamiliar links."
            else:
                message = f"⚠️ I wasn't able to fully verify this URL due to technical limitations.\n\n{result.summary}"

            return AgentResponse(
                message=message,
                data={
                    "url": url_match,
                    "verdict": result.verdict,
                    "confidence": result.confidence,
                    "threat_category": result.threat_category,
                    "risk_hints": result.risk_hints,
                    "sources_checked": result.sources_checked,
                },
                agent_used="url_analyzer",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "url_analyzer"],
                    routing_decision=f"URL analysis completed: {result.verdict}",
                    duration_ms=0,
                ),
            )

        except Exception as e:
            logger.error(f"URL analysis error: {e}", exc_info=True)
            return AgentResponse(
                message="I encountered an error while analyzing the URL. Please try again.",
                data={"error": str(e)},
                agent_used="url_analyzer",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "url_analyzer"],
                    routing_decision=f"URL analysis failed: {str(e)}",
                    duration_ms=0,
                    fallback_triggered=True,
                ),
            )

    def _execute_classifier_chain(self, request: AgentRequest) -> AgentResponse:
        """
        Execute classifier chain: classify → analyze → guidance (if high risk).
        
        Phase B.5: Wrapper around existing ai_client calls
        Phase E: Refactored into ClassifierAgent, TextAnalyzerAgent, GuidanceAgent classes
        """
        try:
            # Step 1: Classify
            classifier_config = get_prompt_config("scam_classifier")
            classify_response = self.ai_client.chat(
                system_prompt=classifier_config.get("system_prompt", ""),
                user_message=request.text,
                max_tokens=classifier_config.get("max_tokens", 500),
                temperature=classifier_config.get("temperature", 0.2),
            )

            import json
            classification_data = json.loads(classify_response)
            classification = classification_data.get("classification", "UNKNOWN")
            confidence = classification_data.get("confidence", 0.0)

            # Step 2: If high risk, trigger deeper analysis
            if classification in ["SCAM", "LIKELY_SCAM"] and confidence > 0.6:
                analyzer_config = get_prompt_config("message_analyzer")
                analysis_response = self.ai_client.chat(
                    system_prompt=analyzer_config.get("system_prompt", ""),
                    user_message=request.text,
                    max_tokens=analyzer_config.get("max_tokens", 1000),
                    temperature=analyzer_config.get("temperature", 0.3),
                )
                analysis_data = json.loads(analysis_response)

                # Step 3: Generate guidance
                guidance_config = get_prompt_config("guidance_generator")
                guidance_response = self.ai_client.chat(
                    system_prompt=guidance_config.get("system_prompt", ""),
                    user_message=f"Classification: {classification}\nAnalysis: {json.dumps(analysis_data)}",
                    max_tokens=guidance_config.get("max_tokens", 1200),
                    temperature=guidance_config.get("temperature", 0.4),
                )
                guidance_data = json.loads(guidance_response)

                message = f"⚠️ **{classification}** (Confidence: {confidence:.0%})\n\n"
                message += f"**Analysis**: {analysis_data.get('summary', 'No summary available')}\n\n"
                message += f"**What to do**: {', '.join(guidance_data.get('immediate_actions', []))}"

                return AgentResponse(
                    message=message,
                    data={
                        "classification": classification,
                        "confidence": confidence,
                        "reasoning": classification_data.get("reasoning", ""),
                        "analysis": analysis_data,
                        "guidance": guidance_data,
                    },
                    agent_used="classifier_chain",
                    trace=OrchestrationTrace(
                        route_path=["orchestrator", "classifier", "analyzer", "guidance"],
                        routing_decision=f"High-risk classification triggered full chain: {classification}",
                        duration_ms=0,
                        model_used="gpt-4o (chain)",
                    ),
                )
            else:
                # Low risk - just classification
                message = f"Classification: **{classification}** (Confidence: {confidence:.0%})\n\n"
                message += f"Reasoning: {classification_data.get('reasoning', 'No additional details')}"

                return AgentResponse(
                    message=message,
                    data={
                        "classification": classification,
                        "confidence": confidence,
                        "reasoning": classification_data.get("reasoning", ""),
                    },
                    agent_used="classifier",
                    trace=OrchestrationTrace(
                        route_path=["orchestrator", "classifier"],
                        routing_decision=f"Low-risk classification, no chain triggered: {classification}",
                        duration_ms=0,
                        model_used="gpt-4o-mini",
                    ),
                )

        except Exception as e:
            logger.error(f"Classifier chain error: {e}", exc_info=True)
            return AgentResponse(
                message="I encountered an error while analyzing this message. Please try again.",
                data={"error": str(e)},
                agent_used="classifier_chain",
                trace=OrchestrationTrace(
                    route_path=["orchestrator", "classifier"],
                    routing_decision=f"Classification failed: {str(e)}",
                    duration_ms=0,
                    fallback_triggered=True,
                ),
            )
