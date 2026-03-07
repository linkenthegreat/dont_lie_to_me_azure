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
<<<<<<< HEAD
=======
  enableMultiRegion   : Enable multi-region deployment with Front Door.
  secondaryLocation   : Secondary Azure region for geo-redundancy.
>>>>>>> origin/main
*/

targetScope = 'subscription'

@description('Short environment name used in resource naming.')
@allowed(['dev', 'staging', 'prod'])
param environmentName string = 'dev'

<<<<<<< HEAD
@description('Azure region for all resources.')
=======
@description('Primary Azure region for all resources.')
>>>>>>> origin/main
param location string = deployment().location

@description('Azure OpenAI deployment name (model).')
param aiDeploymentName string = 'gpt-4o'

<<<<<<< HEAD
// ── Resource group ────────────────────────────────────────────────────────
=======
@description('Enable multi-region deployment with Azure Front Door.')
param enableMultiRegion bool = false

@description('Secondary Azure region for geo-redundancy.')
param secondaryLocation string = 'westus2'

// -- Resource group --------------------------------------------------------
>>>>>>> origin/main
resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'rg-dont-lie-to-me-${environmentName}'
  location: location
}

<<<<<<< HEAD
// ── Modules ───────────────────────────────────────────────────────────────
=======
// -- Modules ---------------------------------------------------------------

>>>>>>> origin/main
module storage 'modules/storage.bicep' = {
  name: 'storage'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
  }
}

<<<<<<< HEAD
=======
module cosmosDb 'modules/cosmosdb.bicep' = {
  name: 'cosmosdb'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
  }
}

module redis 'modules/redis.bicep' = {
  name: 'redis'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
  }
}

>>>>>>> origin/main
module functions 'modules/functions.bicep' = {
  name: 'functions'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
    storageAccountName: storage.outputs.storageAccountName
    aiDeploymentName: aiDeploymentName
<<<<<<< HEAD
=======
    redisConnectionString: redis.outputs.redisConnectionString
    cosmosConnectionString: cosmosDb.outputs.cosmosConnectionString
>>>>>>> origin/main
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

<<<<<<< HEAD
// ── Outputs ───────────────────────────────────────────────────────────────
output functionAppUrl string = functions.outputs.functionAppUrl
output keyVaultUrl    string = keyVault.outputs.keyVaultUrl
=======
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  scope: rg
  params: {
    environmentName: environmentName
    appInsightsId: functions.outputs.appInsightsId
    functionAppId: functions.outputs.functionAppId
  }
}

// -- Multi-region (conditional) --------------------------------------------

module storageSecondary 'modules/storage.bicep' = if (enableMultiRegion) {
  name: 'storage-secondary'
  scope: rg
  params: {
    environmentName: '${environmentName}2'
    location: secondaryLocation
  }
}

module functionsSecondary 'modules/functions.bicep' = if (enableMultiRegion) {
  name: 'functions-secondary'
  scope: rg
  params: {
    environmentName: '${environmentName}2'
    location: secondaryLocation
    storageAccountName: enableMultiRegion ? storageSecondary.outputs.storageAccountName : ''
    aiDeploymentName: aiDeploymentName
    redisConnectionString: redis.outputs.redisConnectionString
    cosmosConnectionString: cosmosDb.outputs.cosmosConnectionString
  }
}

module frontDoor 'modules/frontdoor.bicep' = if (enableMultiRegion) {
  name: 'frontdoor'
  scope: rg
  params: {
    environmentName: environmentName
    primaryBackendUrl: functions.outputs.functionAppUrl
    secondaryBackendUrl: enableMultiRegion ? functionsSecondary.outputs.functionAppUrl : ''
  }
}

// -- Outputs ---------------------------------------------------------------
output functionAppUrl     string = functions.outputs.functionAppUrl
output keyVaultUrl        string = keyVault.outputs.keyVaultUrl
output cosmosEndpoint     string = cosmosDb.outputs.cosmosEndpoint
output redisHostName      string = redis.outputs.redisHostName
output frontDoorEndpoint  string = enableMultiRegion ? frontDoor.outputs.frontDoorEndpoint : ''
>>>>>>> origin/main
