# Architecture Overview

## System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                       Browser                           │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Frontend  (HTML / CSS / JS)            │  │
│  │  - Paste text or upload screenshot               │  │
│  │  - Choose analysis mode                          │  │
│  │  - Display results                               │  │
│  └──────────────────────┬───────────────────────────┘  │
└─────────────────────────┼───────────────────────────────┘
                          │ HTTPS / JSON
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Azure Functions  (Python v2)               │
│                                                         │
│   POST /api/classify   – Scam classification            │
│   POST /api/analyze    – Detailed message analysis      │
│   POST /api/guidance   – Safety guidance generation     │
│   GET  /api/health     – Liveness probe                 │
│                                                         │
│   shared/ai_client.py  – Azure AI Foundry wrapper       │
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
| Frontend | HTML5 / Vanilla JS / CSS | User interface – paste text, upload screenshots, view results |
| Backend API | Azure Functions v2 (Python 3.11) | REST endpoints, orchestration |
| AI Model | Azure AI Foundry (GPT-4o) | Natural language understanding, classification, guidance |
| Secret management | Azure Key Vault | Securely store API keys and connection strings |
| Telemetry | Azure Application Insights | Logging, tracing, performance monitoring |
| Storage (optional) | Azure Blob Storage | Persist query logs for analytics |
| Infrastructure | Bicep | Repeatable, version-controlled IaC |

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

### `GET /api/health`
Unauthenticated liveness probe. Returns `{"status": "ok"}`.

## Security Considerations

- All function endpoints (except `/health`) require a **function key** by default.
- Secrets are stored in **Azure Key Vault** and accessed via the Function App's system-assigned managed identity.
- The frontend never handles API keys directly.
- HTTPS is enforced on the Function App.
- Storage accounts use TLS 1.2 minimum and no public blob access.
