/*
  modules/functions.bicep
  Azure Functions (Python 3.11) with Application Insights,
  Redis, Cosmos DB, and optional staging slot for blue-green deployment.
*/

@description('Short environment name used in resource naming.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

@description('Storage account name for the Functions host.')
param storageAccountName string

@description('Azure OpenAI deployment name.')
param aiDeploymentName string = 'gpt-4o'

@description('Azure Cache for Redis resource name.')
param redisCacheName string = ''

@description('Cosmos DB account name.')
param cosmosAccountName string = ''

var appName         = 'func-dont-lie-to-me-${environmentName}'
var appInsightsName = 'appi-dont-lie-to-me-${environmentName}'
var hostingPlanName = 'asp-dont-lie-to-me-${environmentName}'

// -- Existing resource references (for secret retrieval) --------------------
// These resources are assumed to exist in the same resource group as this module.
// The deploying identity requires at minimum Contributor access on the resource group
// (or Redis Cache Contributor for Redis and Cosmos DB Account Reader Role for Cosmos DB).
resource existingRedis 'Microsoft.Cache/redis@2023-08-01' existing = if (!empty(redisCacheName)) {
  name: redisCacheName
}

resource existingCosmos 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' existing = if (!empty(cosmosAccountName)) {
  name: cosmosAccountName
}

var redisConnectionString = empty(redisCacheName) ? '' : '${redisCacheName}.redis.cache.windows.net:6380,password=${existingRedis!.listKeys().primaryKey},ssl=True,abortConnect=False'
var cosmosConnectionString = empty(cosmosAccountName) ? '' : existingCosmos!.listConnectionStrings().connectionStrings[0].connectionString

// -- Application Insights ---------------------------------------------------
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    RetentionInDays: 30
  }
}

// -- Hosting plan -----------------------------------------------------------
// Use Consumption (Y1) for dev, ElasticPremium (EP1) for prod (supports slots)
resource hostingPlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: hostingPlanName
  location: location
  sku: {
    name: environmentName == 'prod' ? 'EP1' : 'Y1'
    tier: environmentName == 'prod' ? 'ElasticPremium' : 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

// -- Reference the storage account -----------------------------------------
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

// -- Function App -----------------------------------------------------------
var sharedSiteConfig = {
  linuxFxVersion: 'Python|3.11'
  appSettings: [
    {
      name: 'AzureWebJobsStorage'
      value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=core.windows.net'
    }
    {
      name: 'FUNCTIONS_EXTENSION_VERSION'
      value: '~4'
    }
    {
      name: 'FUNCTIONS_WORKER_RUNTIME'
      value: 'python'
    }
    {
      name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
      value: appInsights.properties.InstrumentationKey
    }
    {
      name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
      value: appInsights.properties.ConnectionString
    }
    {
      name: 'AZURE_AI_DEPLOYMENT_NAME'
      value: aiDeploymentName
    }
    {
      name: 'AZURE_AI_API_VERSION'
      value: '2024-02-01'
    }
    {
      name: 'AZURE_REDIS_CONNECTION_STRING'
      value: redisConnectionString
    }
    {
      name: 'COSMOS_DB_CONNECTION_STRING'
      value: cosmosConnectionString
    }
    // AZURE_AI_ENDPOINT and AZURE_AI_API_KEY are stored in Key Vault and
    // referenced here as Key Vault references once the vault is deployed.
  ]
  ftpsState: 'Disabled'
  minTlsVersion: '1.2'
}

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: appName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    httpsOnly: true
    siteConfig: sharedSiteConfig
  }
}

// -- Staging slot (prod only -- requires EP1 plan) -------------------------
resource stagingSlot 'Microsoft.Web/sites/slots@2023-01-01' = if (environmentName == 'prod') {
  parent: functionApp
  name: 'staging'
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    httpsOnly: true
    siteConfig: sharedSiteConfig
  }
}

// -- Outputs ----------------------------------------------------------------
output functionAppUrl      string = 'https://${functionApp.properties.defaultHostName}'
output functionPrincipalId string = functionApp.identity.principalId
output appInsightsId       string = appInsights.id
output functionAppId       string = functionApp.id
