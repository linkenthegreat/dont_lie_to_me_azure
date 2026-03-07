# Setup & Local Development Guide

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.11+ | https://python.org |
| Azure Functions Core Tools | v4 | https://learn.microsoft.com/azure/azure-functions/functions-run-local |
| Azure CLI | latest | https://learn.microsoft.com/cli/azure/install-azure-cli |
| Azurite (local storage emulator) | latest | `npm install -g azurite` |

> **Note:** You need access to an **Azure AI Foundry** endpoint (Azure OpenAI Service)
> with a model deployed (e.g. GPT-4o, GPT-4o mini, or Phi-3).

---

## 1. Clone and install dependencies

```bash
git clone https://github.com/linkenthegreat/dont_lie_to_me_azure.git
cd dont_lie_to_me_azure/src/backend

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 2. Configure environment variables

Copy the example settings file:

```bash
cp local.settings.json.example local.settings.json
```

Edit `local.settings.json` and fill in your values:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "AZURE_AI_ENDPOINT": "https://<your-resource>.openai.azure.com/",
    "AZURE_AI_DEPLOYMENT_NAME": "gpt-4o",
    "AZURE_AI_API_VERSION": "2024-02-01",
    "AZURE_AI_API_KEY": "<your-api-key>",
    "AZURE_KEYVAULT_URL": "",
    "STORAGE_ACCOUNT_CONNECTION_STRING": ""
  }
}
```

> `local.settings.json` is in `.gitignore` and will **never** be committed.

---

## 3. Start local storage emulator

In a separate terminal:

```bash
azurite --silent --location /tmp/azurite --debug /tmp/azurite/debug.log
```

---

## 4. Run the Azure Functions locally

```bash
cd src/backend
func start
```

You should see output like:

```
Functions:
    classify: [POST] http://localhost:7071/api/classify
    analyze_message: [POST] http://localhost:7071/api/analyze
    safety_guidance: [POST] http://localhost:7071/api/guidance
    health: [GET] http://localhost:7071/api/health
```

---

## 5. Open the frontend

Open `src/frontend/index.html` in your browser. The frontend defaults to
`http://localhost:7071/api` for API calls, which matches the local Functions runtime.

Alternatively serve it with any static file server:

```bash
# Python built-in server
cd src/frontend
python -m http.server 8080
# open http://localhost:8080
```

---

## 6. Test the API manually

```bash
# Health check (no auth key needed locally)
curl http://localhost:7071/api/health

# Classify a message
curl -X POST http://localhost:7071/api/classify \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Your bank account has been compromised. Click here immediately."}'

# Detailed analysis
curl -X POST http://localhost:7071/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Congratulations! You have won a $1000 gift card. Claim now."}'

# Safety guidance
curl -X POST http://localhost:7071/api/guidance \
  -H "Content-Type: application/json" \
  -d '{"text": "Your package is on hold. Pay £2.99 customs fee at this link."}'
```

---

## 7. Deploy to Azure

### Deploy infrastructure

```bash
az login
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters environmentName=dev aiDeploymentName=gpt-4o
```

### Deploy the Function App code

```bash
cd src/backend
func azure functionapp publish func-dont-lie-to-me-dev
```

### After deployment

1. Note the Function App URL from the deployment output.
2. Add secrets to Key Vault:
   ```bash
   az keyvault secret set --vault-name <your-vault> --name AzureAIEndpoint --value "<endpoint>"
   az keyvault secret set --vault-name <your-vault> --name AzureAIApiKey --value "<api-key>"
   ```
3. Update the Function App settings to use Key Vault references:
   ```bash
   az functionapp config appsettings set \
     --name func-dont-lie-to-me-dev \
     --resource-group rg-dont-lie-to-me-dev \
     --settings "AZURE_AI_API_KEY=@Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/AzureAIApiKey/)"
   ```

---

## Choosing a different model

Update `AZURE_AI_DEPLOYMENT_NAME` in your settings (or the Bicep parameter) to switch models:

| Model | Deployment name example | Best for |
|-------|------------------------|---------|
| GPT-4o | `gpt-4o` | Highest accuracy, multi-modal |
| GPT-4o mini | `gpt-4o-mini` | Cost-efficient, fast |
| Phi-3 medium | `phi-3-medium-128k` | Lower cost, smaller context |

---

## Running tests

```bash
cd src/backend
pip install pytest
pytest tests/
```
