# Architecture Overview

## System Diagram (v5.0)

See the full Mermaid diagram: [architecture_v5.mmd](architecture_v5.mmd)

```
                    ┌───────────────────────┐
                    │   Azure Static Web    │  CDN · Auto SSL
                    │   Apps                │  API Proxy → /api/*
                    └──────────┬────────────┘
                               │
               ┌───────────────┴───────────────┐
               │                               │
    ┌──────────▼──────────┐         ┌──────────▼───────────┐
    │  Blazor WASM        │         │  Azure Functions     │
    │  .NET 8.0 Standalone│         │  Python 3.11         │
    │                     │         │                      │
    │  Chat-first UI:     │         │  /api/chat (primary) │
    │  · ChatPage.razor   │ ──────► │  /api/classify       │
    │  · DataCard.razor   │  POST   │  /api/analyze        │
    │  · TracePanel.razor │ /chat   │  /api/guidance       │
    │  · WelcomeMessage   │         │  /api/sentiment      │
    │                     │         │  /api/analyze-image   │
    │  PWA · Mobile-first │         │  /api/check-url      │
    │  SEO · Open Graph   │         │                      │
    └─────────────────────┘         └─────┬────────────────┘
                                          │
                               ┌──────────▼───────────┐
                               │  Agent Orchestrator   │
                               │  Deterministic routing│
                               └──┬──┬──┬──┬──┬──┬────┘
                                  │  │  │  │  │  │
          ┌───────────────────────┘  │  │  │  │  └──────────┐
          ▼          ▼               ▼  ▼  ▼               ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │Receptionist│ │Classifier│ │Text      │ │URL       │ │Image     │
    │Agent     │ │Agent     │ │Analyzer  │ │Analyzer  │ │Analyzer  │
    │Empathy   │ │Triage    │ │Red flags │ │Threat    │ │Vision    │
    │Context   │ │SCAM/SAFE │ │Persuasion│ │intel     │ │Deepfake  │
    └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
              ┌──────────┐              ┌──────────┐
              │Report    │              │Resource  │
              │Generator │              │Assistant │
              │Structured│              │Location- │
              │output    │              │aware     │
              └──────────┘              └──────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
       ┌──────────┐        ┌──────────┐        ┌──────────┐
       │Azure AI  │        │Cosmos DB │        │Redis     │
       │Foundry   │        │NoSQL     │        │Cache     │
       │GPT-4o    │        │History   │        │30min TTL │
       │Vision    │        │Sessions  │        │SHA-256   │
       └──────────┘        └──────────┘        └──────────┘
```

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | Blazor WebAssembly (.NET 8.0) | Chat-first PWA — mobile-first, SEO, Open Graph, brand design system |
| Backend API | Azure Functions v2 (Python 3.11) | REST endpoints, agent orchestration, timer triggers |
| AI Model | Azure AI Foundry (GPT-4o) | Text classification, analysis, guidance, multimodal vision |
| Agent Runtime | Framework-agnostic Python | Deterministic orchestration with 7+ specialist agents |
| Image Processing | Pillow (PIL) + GPT-4o Vision | EXIF extraction, resize, manipulation/deepfake/AI detection |
| Prompt System | `prompts.yaml` + loader | Centralized AI system prompts with fallback pattern |
| Database | Azure Cosmos DB (NoSQL) | Analysis history, feedback, session data |
| Cache | Azure Cache for Redis | Response caching with SHA-256 key hashing |
| Secret management | Azure Key Vault | Securely store API keys and connection strings |
| Telemetry | Azure Application Insights | Logging, tracing, performance monitoring |
| Hosting | Azure Static Web Apps | CDN, auto SSL, API proxy to Functions |
| Infrastructure | Bicep | Repeatable, version-controlled IaC |
| CI/CD | GitHub Actions | Backend pytest + Frontend dotnet build |

## Prompt Management Architecture

The system uses a **centralized prompt configuration** to enable rapid iteration without code changes:

- **`prompts.yaml`**: Single source of truth for all AI system prompts, model settings, temperature, and token limits
- **`shared/prompts.py`**: Loader module with PyYAML for runtime configuration
- **Fallback pattern**: Each service contains an embedded `_FALLBACK_SYSTEM_PROMPT` constant for operational resilience

**Benefits:**
- Prompt engineers can iterate without deploying code
- Version control for prompt evolution
- Graceful degradation if YAML is missing or malformed
- Consistent model selection and temperature settings

**Example workflow:**
1. Edit `prompts.yaml` to tune scam detection behavior
2. Test locally via Azure Functions
3. Commit YAML changes (no Python code modified)
4. Deploy with confidence - fallback ensures stability

See [CONTRIBUTING.md](CONTRIBUTING.md#ai-prompt-management) for detailed editing guidelines.

## Unified Chat Interface & Agent Orchestration

The system features a **conversational chat interface** inspired by the proven UX of `have_I_been_scammed`, eliminating the friction of explicit mode selection:

**Frontend Experience** (Blazor WebAssembly):
- **Unified chat window**: Natural conversation flow with message bubbles — no mode selection
- **Multimodal drag-and-drop**: Drop screenshots anywhere in the chat area via JS interop
- **Clipboard paste support**: Paste images directly from clipboard into message input
- **Polymorphic data cards**: `DataCard.razor` renders classification, URL analysis, image analysis, sentiment, and guidance results based on the agent's `data{}` response
- **Agent trace display**: Collapsible panel showing orchestrator route path, agent used, and duration
- **PWA**: Installable as "Scam Detector" with offline splash, manifest, and app icons
- **Mobile-first**: Responsive design with `100dvh`, `safe-area-inset-bottom`, 44px touch targets

**Backend Agent Architecture**:
- **OrchestratorAgent**: Deterministic routing based on input patterns
  - Greetings ("hello", "hi", "help") → ReceptionistAgent
  - URL patterns → URLAnalyzerAgent
  - Suspicious content → ClassifierAgent → TextAnalyzerAgent → GuidanceAgent (chain)
  - Ambiguous input → ReceptionistAgent for clarification
- **ReceptionistAgent**: Conversational empathy layer, provides professional customer service tone, gathers context (location, role) optionally
- **Specialist agents**: ClassifierAgent, TextAnalyzerAgent, URLAnalyzerAgent, ReportGeneratorAgent, ResourceAssistantAgent
- **RecordKeeperAgent**: Cross-team persistence via Cosmos DB, exposed as MCP tool

**Key Contracts**:
- `AgentRequest`: Standardized input (text, images[], session_context{})
- `AgentResponse`: Standardized output (message, data{}, agent_used, trace{})
- `AgentContext`: Session state (session_id, user_location, user_role, conversation_history[])
- `OrchestrationTrace`: Logging/debugging metadata (route_path, duration_ms)

**Routing Example**:
```python
User: "Is this a scam? [screenshot of suspicious email]"
→ OrchestratorAgent detects suspicious content pattern
→ Routes to ClassifierAgent (risk_score: HIGH)
→ Auto-chains to TextAnalyzerAgent (red_flags: urgency, threats)
→ Auto-chains to GuidanceAgent (immediate_actions, reporting_steps)
→ Returns conversational response: "This is a high-risk scam attempt. Here's what to do immediately..."
```

See [architecture_v5.mmd](architecture_v5.mmd) for the complete visual architecture.

## API Endpoints

### `POST /api/chat` (NEW - Unified Endpoint)
Conversational endpoint with intelligent agent routing. Accepts text and images in natural language format.

**Request**
```json
{
  "message": "<user text>",
  "images": ["<base64_string>"],  // optional
  "session_id": "<uuid>",
  "context": {
    "location": "<optional>",
    "role": "<optional>",
    "conversation_history": []
  }
}
```
**Response**
```json
{
  "message": "<conversational response>",
  "data": {
    "classification": "SCAM",
    "red_flags": [...],
    "guidance": {...}
  },
  "agent_used": "orchestrator",
  "trace": {
    "route_path": ["orchestrator", "classifier", "analyzer", "guidance"],
    "duration_ms": 1234
  }
}
```

---

### `POST /api/classify`
Quickly classifies a message as `SCAM`, `LIKELY_SCAM`, `SUSPICIOUS`, or `SAFE`.

**Request**
```json
{ "text": "<message>" }
```
**Response**
```json
{
  "classification": "SCAM",
  "confidence": 0.95,
  "reasoning": "..."
}
```

---

### `POST /api/analyze`
Performs a detailed breakdown of red flags, persuasion techniques, and impersonation indicators.

**Request**
```json
{ "text": "<message>" }
```
**Response**
```json
{
  "red_flags": ["Urgency language", "..."],
  "persuasion_techniques": ["Fear appeal", "..."],
  "impersonation_indicators": ["Claims to be HMRC", "..."],
  "summary": "..."
}
```

---

### `POST /api/guidance`
Returns step-by-step safety guidance for the user.

**Request**
```json
{ "text": "<message>", "context": "<optional>" }
```
**Response**
```json
{
  "immediate_actions": ["Do not click any links", "..."],
  "reporting_steps": ["Report to Action Fraud", "..."],
  "prevention_tips": ["..."],
  "resources": ["https://www.actionfraud.police.uk/", "..."]
}
```

---

### `POST /api/sentiment`
Analyses sentiment, emotional manipulation, and language patterns.

**Request**
```json
{ "text": "<message>" }
```
**Response**
```json
{
  "sentiment": {
    "primary_emotion": "urgency",
    "emotion_scores": {"fear": 0.8, "urgency": 0.95, "greed": 0.1, "trust": 0.05, "curiosity": 0.1},
    "overall_tone": "threatening"
  },
  "manipulation": {
    "techniques_detected": ["Authority", "Scarcity"],
    "pressure_score": 0.9,
    "urgency_indicators": ["ACT NOW"],
    "authority_claims": [],
    "emotional_triggers": ["Fear of loss"]
  },
  "language_analysis": {
    "formality_level": "formal",
    "grammar_quality": "moderate",
    "suspicious_phrases": ["ACT NOW"],
    "call_to_action": "Click the link"
  },
  "risk_assessment": "HIGH",
  "summary": "..."
}
```

---

### `POST /api/analyze-image`
Analyses an uploaded image for signs of manipulation, AI generation, or deepfake using GPT-4o Vision.

**Request**
```json
{
  "image": "data:image/png;base64,iVBORw0KGgo...",
  "session_id": "optional-uuid"
}
```
**Response**
```json
{
  "authenticity_score": 0.35,
  "verdict": "LIKELY_MANIPULATED",
  "manipulation_indicators": [
    {"type": "text_editing", "description": "Font inconsistency", "confidence": 0.85}
  ],
  "visual_analysis": {
    "text_consistency": "...",
    "font_analysis": "...",
    "layout_anomalies": "...",
    "pixel_artifacts": "...",
    "lighting_consistency": "..."
  },
  "ai_generation_analysis": {
    "is_ai_generated": false,
    "confidence": 0.1,
    "generator_hints": "UNKNOWN",
    "artifacts_found": [],
    "deepfake_indicators": []
  },
  "context_analysis": {
    "platform_identified": "WhatsApp",
    "expected_vs_actual": "...",
    "suspicious_patterns": ["..."]
  },
  "metadata_analysis": {
    "exif_present": false,
    "editing_software_detected": null,
    "metadata_anomalies": ["No EXIF metadata"],
    "image_format": "PNG",
    "image_size": {"width": 1170, "height": 2532}
  },
  "summary": "..."
}
```

**Verdicts:** `AUTHENTIC`, `LIKELY_MANIPULATED`, `MANIPULATED`, `AI_GENERATED`, `DEEPFAKE`, `INCONCLUSIVE`

**Limits:** Max image size 10 MB. Images >2048px are automatically resized.

---

### `GET /api/health`
Unauthenticated liveness probe. Returns `{"status": "ok"}`.

## Security Considerations

- All function endpoints (except `/health`) require a **function key** by default.
- Secrets are stored in **Azure Key Vault** and accessed via the Function App's system-assigned managed identity.
- The frontend never handles API keys directly.
- HTTPS is enforced on the Function App.
- Storage accounts use TLS 1.2 minimum and no public blob access.
