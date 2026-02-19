/*
  modules/storage.bicep
  Azure Storage Account for Azure Functions host requirements and optional
  query logging (Blob container).
*/

@description('Short environment name used in resource naming.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

var storageAccountName = 'stdontlie${environmentName}${uniqueString(resourceGroup().id)}'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: take(storageAccountName, 24)
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    encryption: {
      services: {
        blob: { enabled: true }
        file: { enabled: true }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Blob container for optional query logs
resource queryLogsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  name: '${storageAccount.name}/default/query-logs'
  properties: {
    publicAccess: 'None'
  }
}

output storageAccountName string = storageAccount.name
output storageAccountId   string = storageAccount.id
