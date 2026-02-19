# 🛡️ Don't Lie To Me – Azure

An Azure-native anti-scam assistant that helps users identify potential scams,
analyse suspicious messages, and receive actionable safety guidance — powered by
**Azure AI Foundry** (GPT-4o, GPT-4o mini, or Phi-3) and **Azure Functions**.

---

## Features

- **Scam Classification** – Quickly labels a message as `SCAM`, `LIKELY_SCAM`, `SUSPICIOUS`, or `SAFE`
- **Detailed Analysis** – Surfaces red flags, persuasion techniques, and impersonation indicators
- **Safety Guidance** – Generates step-by-step advice on what to do next
- **Screenshot support** – Upload an image of a message; the backend handles it
- **Azure-native** – Azure Functions, Key Vault, Application Insights, Bicep IaC

---

## Project Structure

```
dont_lie_to_me_azure/
├── src/
│   ├── backend/           # Azure Functions (Python v2)
│   │   ├── function_app.py               # All function routes
│   │   ├── host.json
│   │   ├── requirements.txt
│   │   ├── local.settings.json.example   # Copy → local.settings.json
│   │   └── shared/
│   │       ├── ai_client.py              # Azure AI Foundry wrapper
│   │       ├── keyvault.py               # Key Vault secret helper
│   │       └── storage.py               # Optional query-logging stub
│   └── frontend/          # Static web UI
│       ├── index.html
│       ├── style.css
│       └── app.js
├── infra/                 # Bicep IaC templates
│   ├── main.bicep
│   └── modules/
│       ├── functions.bicep
│       ├── keyvault.bicep
│       └── storage.bicep
├── docs/
│   ├── architecture.md    # System diagram & API reference
│   ├── setup.md           # Full local dev & deployment guide
│   └── CONTRIBUTING.md    # How to contribute
└── README.md
```

---

## Quick Start (Local)

### Prerequisites

- Python 3.11+
- [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- An Azure AI Foundry endpoint with a deployed model (GPT-4o, GPT-4o mini, or Phi-3)

### 1 – Install backend dependencies

```bash
cd src/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2 – Configure environment variables

```bash
cp local.settings.json.example local.settings.json
# Edit local.settings.json with your Azure AI endpoint and API key
```

### 3 – Start the Function App

```bash
func start
```

The following endpoints will be available at `http://localhost:7071`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Liveness probe (no auth) |
| `POST` | `/api/classify` | Scam classification |
| `POST` | `/api/analyze` | Detailed message analysis |
| `POST` | `/api/guidance` | Safety guidance generation |

### 4 – Open the frontend

Open `src/frontend/index.html` in your browser, or run a local static server:

```bash
cd src/frontend && python -m http.server 8080
# → http://localhost:8080
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_AI_ENDPOINT` | ✅ | Azure AI Foundry endpoint URL |
| `AZURE_AI_DEPLOYMENT_NAME` | ✅ | Model deployment name (e.g. `gpt-4o`) |
| `AZURE_AI_API_KEY` | ✅* | API key (*omit to use managed identity) |
| `AZURE_AI_API_VERSION` | – | API version (default: `2024-02-01`) |
| `AZURE_KEYVAULT_URL` | – | Key Vault URL for production secret retrieval |
| `STORAGE_ACCOUNT_CONNECTION_STRING` | – | For optional query logging |

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

MIT
