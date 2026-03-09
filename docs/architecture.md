# Architecture Overview

## System Diagram (v3.1)

```mermaid
flowchart TB
    subgraph Client["🌐 Client Layer"]
        Browser["Browser<br/><small>HTML / CSS / JS</small>"]
    end

    subgraph FrontDoor["Azure Front Door"]
        CDN["CDN + WAF<br/><small>Global load balancing</small>"]
    end

    subgraph Functions["Azure Functions (Python v2)"]
        direction TB
        subgraph CoreAPI["Core Analysis Endpoints"]
            classify["POST /classify"]
            analyze["POST /analyze"]
            guidance["POST /guidance"]
            sentiment["POST /sentiment"]
            analyzeimg["POST /analyze-image"]
            checkurl["POST /check-url"]
            health["GET /health"]
        end
        subgraph DataAPI["Data & Compliance Endpoints"]
            history["GET /history"]
            export["GET /export"]
            feedback["POST /feedback"]
            i18n["GET /i18n"]
            gdpr_del["DELETE /gdpr/delete"]
            gdpr_exp["GET /gdpr/export"]
            teams["POST /notify-teams"]
        end
        subgraph Internals["Shared Modules"]
            prompts["prompts.yaml + shared/prompts.py"]
            ai_client["shared/ai_client.py"]
            url_checker["shared/url_checker.py"]
            models["shared/models.py"]
            risk["shared/risk_hints.py"]
            threat["shared/threat_intel_sources.py"]
        end
        subgraph Services["Service Layer"]
            cache_svc["cache_service.py"]
            cosmos_svc["cosmos_service.py"]
            telemetry_svc["telemetry.py"]
            sentiment_svc["sentiment_service.py"]
            image_svc["image_analysis_service.py"]
            export_svc["export_service.py"]
            gdpr_svc["gdpr_service.py"]
            audit_svc["audit_logger.py"]
            teams_svc["teams_integration.py"]
        end
        subgraph ImagePipeline["Image Forensics Pipeline"]
            pillow["Pillow<br/><small>Resize / EXIF / Format</small>"]
            gpt4v["GPT-4o Vision<br/><small>Multimodal analysis</small>"]
        end
        cleanup["⏰ Timer: cleanup_expired_data<br/><small>Weekly @ 3 AM Sunday</small>"]
    end

    subgraph Azure["Azure Platform Services"]
        AI["Azure AI Foundry<br/><small>GPT-4o / GPT-4o-mini</small>"]
        KV["Azure Key Vault<br/><small>Secrets & keys</small>"]
        Cosmos["Azure Cosmos DB<br/><small>Analysis history</small>"]
        Redis["Azure Cache for Redis<br/><small>Response caching</small>"]
        AppInsights["Application Insights<br/><small>Telemetry & monitoring</small>"]
    end

    subgraph External["External Integrations"]
        Teams["Microsoft Teams<br/><small>Scam alerts webhook</small>"]
    end

    Browser -->|HTTPS / JSON| CDN
    CDN --> Functions

    CoreAPI --> ai_client
    CoreAPI --> url_checker
    ai_client --> prompts
    ai_client --> AI
    ai_client --> KV
    url_checker --> threat
    url_checker --> risk

    analyzeimg --> image_svc
    image_svc --> pillow
    pillow --> gpt4v
    gpt4v --> AI

    CoreAPI --> cache_svc
    CoreAPI --> cosmos_svc
    CoreAPI --> telemetry_svc
    DataAPI --> cosmos_svc
    DataAPI --> export_svc
    DataAPI --> gdpr_svc
    DataAPI --> audit_svc
    DataAPI --> teams_svc

    cache_svc --> Redis
    cosmos_svc --> Cosmos
    telemetry_svc --> AppInsights
    teams_svc --> Teams
    cleanup --> cache_svc
    classify -->|SCAM detected| teams_svc
```

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | HTML5 / Vanilla JS / CSS | User interface – paste text, upload screenshots, view results |
| Backend API | Azure Functions v2 (Python 3.11) | REST endpoints, orchestration, timer triggers |
| AI Model | Azure AI Foundry (GPT-4o) | Text classification, analysis, guidance, multimodal vision |
| Image Processing | Pillow (PIL) | EXIF extraction, image resize, format detection |
| Prompt System | `prompts.yaml` + loader | Centralized AI system prompts with fallback pattern |
| Database | Azure Cosmos DB (NoSQL) | Analysis history, feedback, session data |
| Cache | Azure Cache for Redis | Response caching with SHA-256 key hashing |
| Secret management | Azure Key Vault | Securely store API keys and connection strings |
| Telemetry | Azure Application Insights | Logging, tracing, performance monitoring |
| CDN/WAF | Azure Front Door | Global load balancing, DDoS protection |
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

## API Endpoints

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
