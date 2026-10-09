targetScope = 'subscription'

@description('Object ID of the service principal, managed identity, or group used by GRC Lake.')
param principalId string

@description('Principal type for the GRC Lake identity.')
@allowed([
  'ServicePrincipal'
  'ManagedIdentity'
  'Group'
])
param principalType string = 'ServicePrincipal'

@description('Assign Reader for resource and policy inventory.')
param assignReader bool = true

var readerRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7'
)

resource readerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (assignReader) {
  name: guid(subscription().id, principalId, readerRoleDefinitionId, 'grc-lake-posture')
  scope: subscription()
  properties: {
    principalId: principalId
    principalType: principalType
    roleDefinitionId: readerRoleDefinitionId
  }
}

output readerRoleDefinitionId string = readerRoleDefinitionId
