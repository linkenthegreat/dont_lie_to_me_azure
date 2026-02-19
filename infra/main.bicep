/*
  main.bicep
  Top-level Bicep template for the Don't Lie To Me Azure deployment.

  Deploy with:
    az deployment sub create \
      --location eastus \
      --template-file infra/main.bicep \
      --parameters environmentName=dev aiDeploymentName=gpt-4o

  Parameters
  ----------
  environmentName     : Short environment tag, e.g. "dev" / "prod".
  location            : Azure region (defaults to deployment location).
  aiDeploymentName    : Azure OpenAI deployment name (e.g. "gpt-4o").
*/

targetScope = 'subscription'

@description('Short environment name used in resource naming.')
@allowed(['dev', 'staging', 'prod'])
param environmentName string = 'dev'

@description('Azure region for all resources.')
param location string = deployment().location

@description('Azure OpenAI deployment name (model).')
param aiDeploymentName string = 'gpt-4o'

// ── Resource group ────────────────────────────────────────────────────────
resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'rg-dont-lie-to-me-${environmentName}'
  location: location
}

// ── Modules ───────────────────────────────────────────────────────────────
module storage 'modules/storage.bicep' = {
  name: 'storage'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
  }
}

module functions 'modules/functions.bicep' = {
  name: 'functions'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
    storageAccountName: storage.outputs.storageAccountName
    aiDeploymentName: aiDeploymentName
  }
}

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
    functionPrincipalId: functions.outputs.functionPrincipalId
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────
output functionAppUrl string = functions.outputs.functionAppUrl
output keyVaultUrl    string = keyVault.outputs.keyVaultUrl
