/*
  modules/keyvault.bicep
  Azure Key Vault for storing secrets (API keys, connection strings).
  Grants the Function App's managed identity read access to secrets.
*/

@description('Short environment name used in resource naming.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

@description('Object/principal ID of the Function App managed identity.')
param functionPrincipalId string

var keyVaultName = 'kv-dontlie-${environmentName}-${take(uniqueString(resourceGroup().id), 6)}'

// ── Key Vault ──────────────────────────────────────────────────────────────
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// ── RBAC: grant the Function App "Key Vault Secrets User" ─────────────────
// Role definition ID for "Key Vault Secrets User": 4633458b-17de-408a-b874-0445c86b69e6
resource secretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionPrincipalId, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    )
    principalId: functionPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output keyVaultUrl  string = keyVault.properties.vaultUri
output keyVaultName string = keyVault.name
