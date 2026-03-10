/*
  modules/redis.bicep
  Azure Cache for Redis (Basic C0 for dev, Standard C1 for prod).
*/

@description('Short environment name.')
param environmentName string

@description('Azure region.')
param location string = resourceGroup().location

var redisCacheName = 'redis-dontlie-${environmentName}-${take(uniqueString(resourceGroup().id), 6)}'

resource redisCache 'Microsoft.Cache/redis@2023-08-01' = {
  name: redisCacheName
  location: location
  properties: {
    sku: {
      name: environmentName == 'prod' ? 'Standard' : 'Basic'
      family: 'C'
      capacity: environmentName == 'prod' ? 1 : 0
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    redisConfiguration: {}
  }
}

output redisHostName string = redisCache.properties.hostName
output redisCacheName string = redisCache.name
