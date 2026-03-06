<p align="center">
  <img src="assets/dont_lie_to_me_banner.jpg" alt="Don't Lie to Me – Scammer Detector" width="700">
</p>

<h1 align="center">Don't Lie To Me – Azure</h1>

<p align="center">
  An Azure-native anti-scam assistant that helps users identify potential scams,
  analyse suspicious messages, and receive actionable safety guidance — powered by
  <strong>Azure AI Foundry</strong> and <strong>Azure Functions</strong>.
</p>

---

## Features

- **Scam Classification** – Labels a message as `SCAM`, `LIKELY_SCAM`, `SUSPICIOUS`, or `SAFE`
- **Detailed Analysis** – Surfaces red flags, persuasion techniques, and impersonation indicators
- **Safety Guidance** – Generates step-by-step advice on what to do next
- **MCP Server** – Exposes 3 tools (`store_analysis`, `query_history`, `check_known_scam`) for AI-agent integration
- **Cosmos DB Persistence** – Stores analysis history and known scam patterns for future reference
- **Screenshot Support** – Upload an image of a message; the backend handles OCR
- **Azure-native** – Azure Functions, Cosmos DB, Key Vault, Application Insights, Bicep IaC

---

## Architecture

The backend follows a **modular architecture** using Azure Functions Blueprints:

```
                   ┌─────────────────────┐
                   │    function_app.py   │  ← Entry point
                   │  (registers modules) │
                   └──────┬────────┬──────┘
                          │        │
              ┌───────────┘        └───────────┐
              ▼                                ▼
   ┌──────────────────┐            ┌──────────────────┐
   │  blueprints/     │            │  mcp_tools/      │
   │  http_api.py     │            │  tool_definitions │
   │  (REST endpoints)│            │  (MCP triggers)   │
   └────────┬─────────┘            └────────┬─────────┘
            │                               │
            └──────────┬───────────────────┘
                       ▼
            ┌──────────────────┐
            │    services/     │
            │  cosmos_service  │  ← Cosmos DB CRUD
            │  scam_patterns   │  ← Text similarity
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │    shared/       │
            │  ai_client       │  ← Azure AI Foundry
            │  config          │  ← Environment vars
            │  keyvault        │  ← Key Vault helper
            └──────────────────┘
```

---

## Project Structure

```
dont_lie_to_me_azure/
├── assets/                        # Static assets (images, etc.)
│   └── dont_lie_to_me_banner.jpg
├── src/
│   ├── backend/                   # Azure Functions (Python v2)
│   │   ├── function_app.py        # Entry point – registers Blueprint & MCP tools
│   │   ├── host.json
│   │   ├── requirements.txt
│   │   ├── local.settings.json.example
│   │   ├── blueprints/
│   │   │   └── http_api.py        # REST endpoints (health, classify, analyze, guidance)
│   │   ├── mcp_tools/
│   │   │   └── tool_definitions.py # MCP tool triggers (store_analysis, query_history, check_known_scam)
│   │   ├── services/
│   │   │   ├── cosmos_service.py   # Cosmos DB operations
│   │   │   └── scam_patterns.py    # Text similarity matching
│   │   ├── shared/
│   │   │   ├── ai_client.py        # Azure AI Foundry wrapper
│   │   │   ├── config.py           # Centralized env var access
│   │   │   └── keyvault.py         # Key Vault secret helper
│   │   └── tests/
│   │       ├── test_cosmos_service.py
│   │       ├── test_functions.py
│   │       └── test_mcp_tools.py
│   └── frontend/                  # Static web UI
│       ├── index.html
│       ├── style.css
│       └── app.js
├── infra/                         # Bicep IaC templates
│   ├── main.bicep
│   └── modules/
│       ├── functions.bicep
│       ├── keyvault.bicep
│       └── storage.bicep
├── docs/
│   ├── architecture.md
│   ├── setup.md
│   └── CONTRIBUTING.md
└── README.md
```

---

## Quick Start (Local)

### Prerequisites

- Python 3.11+
- [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- An Azure AI Foundry endpoint with a deployed model (GPT-4o, GPT-4o mini, or Phi-3)
- An Azure Cosmos DB account (for MCP tools and history features)

### 1 – Install backend dependencies

```bash
cd src/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2 – Configure environment variables

```bash
cp local.settings.json.example local.settings.json
# Edit local.settings.json with your Azure AI and Cosmos DB credentials
```

### 3 – Start the Function App

```bash
func start
```

### HTTP Endpoints

Available at `http://localhost:7071`:

| Method | Path            | Description                  |
|--------|-----------------|------------------------------|
| `GET`  | `/api/health`   | Liveness probe (no auth)     |
| `POST` | `/api/classify` | Scam classification          |
| `POST` | `/api/analyze`  | Detailed message analysis    |
| `POST` | `/api/guidance` | Safety guidance generation   |

### MCP Tools

Exposed via Azure Functions MCP tool triggers for AI-agent integration:

| Tool               | Description                                      |
|--------------------|--------------------------------------------------|
| `store_analysis`   | Store a scam analysis result in Cosmos DB        |
| `query_history`    | Query past analyses for a given session          |
| `check_known_scam` | Search for similar known scam patterns           |

### 4 – Open the frontend

```bash
cd src/frontend && python -m http.server 8080
# → http://localhost:8080
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_AI_ENDPOINT` | Yes | Azure AI Foundry endpoint URL |
| `AZURE_AI_DEPLOYMENT_NAME` | Yes | Model deployment name (default: `gpt-4o`) |
| `AZURE_AI_API_KEY` | Yes* | API key (*omit to use managed identity) |
| `AZURE_AI_API_VERSION` | – | API version (default: `2024-02-01`) |
| `COSMOS_DB_CONNECTION_STRING` | Yes** | Cosmos DB connection string |
| `COSMOS_DB_ENDPOINT` | Yes** | Cosmos DB endpoint (**provide connection string OR endpoint+key) |
| `COSMOS_DB_KEY` | Yes** | Cosmos DB key |
| `COSMOS_DB_DATABASE` | – | Database name (default: `antiscam`) |
| `COSMOS_DB_CONTAINER` | – | Container name (default: `analyses`) |
| `AZURE_KEYVAULT_URL` | – | Key Vault URL for production secret retrieval |

---

## Testing

```bash
cd src/backend
python -m pytest tests/ -v
```

---

## Deploy to Azure

See [docs/setup.md](docs/setup.md) for the full deployment walkthrough using
Azure CLI and Bicep templates.

```bash
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters environmentName=dev aiDeploymentName=gpt-4o
```

---

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Setup & Deployment Guide](docs/setup.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

---

## Contributing

Contributions are welcome! Please read [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
before opening a pull request.

---

## License

Apache License 2.0 – see [LICENSE](LICENSE) for details.
