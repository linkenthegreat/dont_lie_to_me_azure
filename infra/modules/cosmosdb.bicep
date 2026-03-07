/*
  modules/cosmosdb.bicep
  Azure Cosmos DB account, database, and containers with optimized partitioning.
*/

@description('Short environment name.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

var cosmosAccountName = 'cosmos-dontlie-${environmentName}-${take(uniqueString(resourceGroup().id), 6)}'

resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
  name: cosmosAccountName
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    capabilities: [
      { name: 'EnableServerless' }
    ]
    backupPolicy: {
      type: 'Periodic'
      periodicModeProperties: {
        backupIntervalInMinutes: 240
        backupRetentionIntervalInHours: 720
        backupStorageRedundancy: 'Local'
      }
    }
  }
}

resource database 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2023-11-15' = {
  parent: cosmosAccount
  name: 'antiscam'
  properties: {
    resource: { id: 'antiscam' }
  }
}

resource analysesContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-11-15' = {
  parent: database
  name: 'analyses'
  properties: {
    resource: {
      id: 'analyses'
      partitionKey: {
        paths: ['/sessionId']
        kind: 'Hash'
      }
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
        includedPaths: [
          { path: '/timestamp/?' }
          { path: '/endpoint/?' }
          { path: '/result/classification/?' }
        ]
        excludedPaths: [
          { path: '/inputText/?' }
          { path: '/result/reasoning/?' }
          { path: '/"_etag"/?' }
        ]
      }
      defaultTtl: 7776000
    }
  }
}

output cosmosAccountName string = cosmosAccount.name
output cosmosEndpoint string = cosmosAccount.properties.documentEndpoint
output cosmosConnectionString string = cosmosAccount.listConnectionStrings().connectionStrings[0].connectionString
