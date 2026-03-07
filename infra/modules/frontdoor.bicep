/*
  modules/frontdoor.bicep
  Azure Front Door for multi-region load balancing.
*/

@description('Short environment name.')
param environmentName string

@description('Primary backend Function App URL.')
param primaryBackendUrl string

@description('Secondary backend Function App URL (optional).')
param secondaryBackendUrl string = ''

var frontDoorName = 'afd-dontlie-${environmentName}'

resource frontDoorProfile 'Microsoft.Cdn/profiles@2023-05-01' = {
  name: frontDoorName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
}

resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2023-05-01' = {
  parent: frontDoorProfile
  name: 'api-endpoint'
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2023-05-01' = {
  parent: frontDoorProfile
  name: 'api-origins'
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    healthProbeSettings: {
      probePath: '/api/health'
      probeRequestType: 'GET'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 30
    }
  }
}

resource primaryOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2023-05-01' = {
  parent: originGroup
  name: 'primary'
  properties: {
    hostName: replace(replace(primaryBackendUrl, 'https://', ''), '/', '')
    httpPort: 80
    httpsPort: 443
    originHostHeader: replace(replace(primaryBackendUrl, 'https://', ''), '/', '')
    priority: 1
    weight: 1000
  }
}

resource secondaryOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2023-05-01' = if (!empty(secondaryBackendUrl)) {
  parent: originGroup
  name: 'secondary'
  properties: {
    hostName: replace(replace(secondaryBackendUrl, 'https://', ''), '/', '')
    httpPort: 80
    httpsPort: 443
    originHostHeader: replace(replace(secondaryBackendUrl, 'https://', ''), '/', '')
    priority: 2
    weight: 1000
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-05-01' = {
  parent: endpoint
  name: 'api-route'
  properties: {
    originGroup: {
      id: originGroup.id
    }
    supportedProtocols: ['Https']
    patternsToMatch: ['/api/*']
    forwardingProtocol: 'HttpsOnly'
    httpsRedirect: 'Enabled'
  }
}

output frontDoorEndpoint string = endpoint.properties.hostName
output frontDoorProfileName string = frontDoorProfile.name
