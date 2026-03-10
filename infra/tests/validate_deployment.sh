#!/bin/bash
# validate_deployment.sh
# Validate deployed infrastructure resources exist and are configured correctly.

set -euo pipefail

RG_NAME="dont_lie_to_me"
echo "=== Validating deployment for resource group: $RG_NAME ==="

echo ""
echo "[1/6] Checking resource group..."
STATE=$(az group show --name "$RG_NAME" --query "properties.provisioningState" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ "$STATE" = "Succeeded" ]; then
  echo "  Resource group: OK"
else
  echo "  Resource group: FAILED (state=$STATE)"
  exit 1
fi

echo ""
echo "[2/6] Checking Function App..."
FUNC_STATE=$(az functionapp show \
  --name "func-dont-lie-to-me-${ENVIRONMENT_NAME:-dev}" \
  --resource-group "$RG_NAME" \
  --query "state" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ "$FUNC_STATE" = "Running" ]; then
  echo "  Function App: OK (Running)"
else
  echo "  Function App: WARNING (state=$FUNC_STATE)"
fi

echo ""
echo "[3/6] Checking Application Insights..."
APPI_STATE=$(az monitor app-insights component show \
  --app "appi-dont-lie-to-me-${ENVIRONMENT_NAME:-dev}" \
  --resource-group "$RG_NAME" \
  --query "provisioningState" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ "$APPI_STATE" = "Succeeded" ]; then
  echo "  Application Insights: OK"
else
  echo "  Application Insights: WARNING (state=$APPI_STATE)"
fi

echo ""
echo "[4/6] Checking Azure Cache for Redis..."
REDIS_STATE=$(az redis show \
  --name "redis-dontlie-${ENVIRONMENT_NAME:-dev}-*" \
  --resource-group "$RG_NAME" \
  --query "provisioningState" -o tsv 2>/dev/null || echo "NOT_FOUND")
echo "  Redis: $REDIS_STATE"

echo ""
echo "[5/6] Checking Cosmos DB..."
COSMOS_ACCOUNTS=$(az cosmosdb list \
  --resource-group "$RG_NAME" \
  --query "[].name" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ -n "$COSMOS_ACCOUNTS" ] && [ "$COSMOS_ACCOUNTS" != "NOT_FOUND" ]; then
  echo "  Cosmos DB accounts: $COSMOS_ACCOUNTS"
else
  echo "  Cosmos DB: NOT_FOUND"
fi

echo ""
echo "[6/6] Checking Key Vault..."
KV_LIST=$(az keyvault list \
  --resource-group "$RG_NAME" \
  --query "[].name" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ -n "$KV_LIST" ] && [ "$KV_LIST" != "NOT_FOUND" ]; then
  echo "  Key Vault: $KV_LIST"
else
  echo "  Key Vault: NOT_FOUND"
fi

echo ""
echo "=== Validation complete ==="
