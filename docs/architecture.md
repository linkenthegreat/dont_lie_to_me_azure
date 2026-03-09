# Architecture Overview

## System Diagram

> **See also**: 
> - [architecture_v1.mmd](architecture_v1.mmd) - Original direct-call architecture
> - [architecture_v2.mmd](architecture_v2.mmd) - Planned Microsoft Foundry integration
> - [architecture_v3.mmd](architecture_v3.mmd) - **Current target**: Unified chat + agent orchestration

### Simplified View

```
┌─────────────────────────────────────────────────────────┐
│                       Browser                           │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Frontend  (HTML / CSS / JS)            │  │
│  │  - Unified chat interface (default)              │  │
│  │  - Drag & drop screenshots anywhere              │  │
│  │  - Paste clipboard images                        │  │
│  │  - Advanced mode (legacy tabs/dropdowns)         │  │
│  │  - Display conversational results                │  │
│  └──────────────────────┬───────────────────────────┘  │
└─────────────────────────┼───────────────────────────────┘
                          │ HTTPS / JSON
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Azure Functions  (Python v2)               │
│                                                         │
│   POST /api/chat       – Unified conversational endpoint│
│                          (OrchestratorAgent routing)    │
│   POST /api/classify   – Direct scam classification     │
│   POST /api/analyze    – Direct detailed analysis       │
│   POST /api/guidance   – Direct safety guidance         │
│   GET  /api/health     – Liveness probe                 │
│                                                         │
│   agents/              – Agent runtime (orchestrator,   │
│                          receptionist, specialists)     │
│   prompts.yaml         – Centralized AI system prompts  │
│   shared/prompts.py    – Prompt loader with fallback    │
│   shared/ai_client.py  – Provider-agnostic AI client    │
│   shared/keyvault.py   – Key Vault secret helper        │
│   shared/storage.py    – Optional query logging stub    │
└────────────┬────────────────────────┬───────────────────┘
             │                        │
             ▼                        ▼
┌──────────────────────┐  ┌──────────────────────────────┐
│  Azure AI Foundry    │  │      Azure Key Vault          │
│  (GPT-4o / GPT-4o   │  │  - AZURE_AI_API_KEY           │
│   mini / Phi-3)      │  │  - AZURE_AI_ENDPOINT          │
└──────────────────────┘  │  - connection strings         │
                          └──────────────────────────────┘
                                       │
                          ┌────────────▼─────────────────┐
                          │   Azure Blob Storage /        │
                          │   Azure Cosmos DB  (optional) │
                          │   query-logs container        │
                          └──────────────────────────────┘
```

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | HTML5 / Vanilla JS / CSS | Unified chat interface + advanced mode (backward compat) |
| Backend API | Azure Functions v2 (Python 3.11) | REST endpoints, agent orchestration |
| Agent Runtime | Custom framework-agnostic | OrchestratorAgent, ReceptionistAgent, specialist agents |
| AI Provider Layer | Dual-mode (GitHub/Azure) | GitHub Models (local dev) + Azure AI Foundry (cloud) |
| AI Models | GPT-4o / GPT-4o-mini | Fast triage (mini) + deep analysis (4o) |
| Prompt System | `prompts.yaml` + loader | Centralized AI system prompts with fallback pattern |
| Secret management | Azure Key Vault | Securely store API keys and connection strings |
| Telemetry | Azure Application Insights | Logging, tracing, agent traces, performance monitoring |
| Storage (optional) | Azure Blob Storage | Persist query logs for analytics |
| Infrastructure | Bicep | Repeatable, version-controlled IaC |

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

**Frontend Experience**:
- **Unified chat window**: Natural conversation flow with message bubbles
- **Multimodal drag-and-drop**: Drop screenshots anywhere in the chat area (not restricted to file upload zones)
- **Clipboard paste support**: Paste images directly from clipboard into message input
- **No mode selection required**: System intelligently routes to appropriate analysis
- **Backward compatibility**: "Advanced" tab preserves legacy explicit mode selection for power users

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

See [architecture_v3.mmd](architecture_v3.mmd) for the complete visual architecture.

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

### `GET /api/health`
Unauthenticated liveness probe. Returns `{"status": "ok"}`.

## Security Considerations

- All function endpoints (except `/health`) require a **function key** by default.
- Secrets are stored in **Azure Key Vault** and accessed via the Function App's system-assigned managed identity.
- The frontend never handles API keys directly.
- HTTPS is enforced on the Function App.
- Storage accounts use TLS 1.2 minimum and no public blob access.
