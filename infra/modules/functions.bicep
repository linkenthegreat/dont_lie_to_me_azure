/*
  modules/functions.bicep
<<<<<<< HEAD
  Azure Functions (Consumption plan, Python 3.11) with Application Insights.
=======
  Azure Functions (Python 3.11) with Application Insights,
  Redis, Cosmos DB, and optional staging slot for blue-green deployment.
>>>>>>> origin/main
*/

@description('Short environment name used in resource naming.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

@description('Storage account name for the Functions host.')
param storageAccountName string

@description('Azure OpenAI deployment name.')
param aiDeploymentName string = 'gpt-4o'

<<<<<<< HEAD
var appName            = 'func-dont-lie-to-me-${environmentName}'
var appInsightsName    = 'appi-dont-lie-to-me-${environmentName}'
var hostingPlanName    = 'asp-dont-lie-to-me-${environmentName}'

// ── Application Insights ───────────────────────────────────────────────────
=======
@description('Azure Cache for Redis connection string.')
param redisConnectionString string = ''

@description('Cosmos DB connection string.')
param cosmosConnectionString string = ''

var appName         = 'func-dont-lie-to-me-${environmentName}'
var appInsightsName = 'appi-dont-lie-to-me-${environmentName}'
var hostingPlanName = 'asp-dont-lie-to-me-${environmentName}'

// -- Application Insights ---------------------------------------------------
>>>>>>> origin/main
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    RetentionInDays: 30
  }
}

<<<<<<< HEAD
// ── Consumption hosting plan ───────────────────────────────────────────────
=======
// -- Hosting plan -----------------------------------------------------------
// Use Consumption (Y1) for dev, ElasticPremium (EP1) for prod (supports slots)
>>>>>>> origin/main
resource hostingPlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: hostingPlanName
  location: location
  sku: {
<<<<<<< HEAD
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {}
}

// ── Reference the storage account ─────────────────────────────────────────
=======
    name: environmentName == 'prod' ? 'EP1' : 'Y1'
    tier: environmentName == 'prod' ? 'ElasticPremium' : 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

// -- Reference the storage account -----------------------------------------
>>>>>>> origin/main
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

<<<<<<< HEAD
// ── Function App ───────────────────────────────────────────────────────────
=======
// -- Function App -----------------------------------------------------------
>>>>>>> origin/main
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
    siteConfig: {
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
<<<<<<< HEAD
        // AZURE_AI_ENDPOINT and AZURE_AI_API_KEY are stored in Key Vault and
        // referenced here as Key Vault references once the vault is deployed.
        // e.g. @Microsoft.KeyVault(SecretUri=https://<vault>.vault.azure.net/secrets/AzureAIEndpoint/)
=======
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
>>>>>>> origin/main
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
  }
}

<<<<<<< HEAD
output functionAppUrl      string = 'https://${functionApp.properties.defaultHostName}'
output functionPrincipalId string = functionApp.identity.principalId
=======
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
    siteConfig: functionApp.properties.siteConfig
  }
}

// -- Outputs ----------------------------------------------------------------
output functionAppUrl      string = 'https://${functionApp.properties.defaultHostName}'
output functionPrincipalId string = functionApp.identity.principalId
output appInsightsId       string = appInsights.id
output functionAppId       string = functionApp.id
>>>>>>> origin/main
