<#
Update the variables with values for your environment, then run it in your powershell command prompt
with the initial dot to 'dot source' the variables into your session

. .\tenant-config.ps1

#>
$tenantID = "<tenant-guid>" 
$tenantName = "...your-name..."
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI (scope below)
$spClientSecret="<...client secret...>" # if signing in with client credentials

# The below settings are ONLY needed if you plan to Onboard a tenant via powershell
$SubscriptionId = "<azure-subscription-guid>"
$resourceGroupName = "<resource-group-name>"
$keyVaultName = "<your-keyvault>"
$keyVaultResourceID="/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.KeyVault/vaults/$keyVaultName"

$spVCServiceAdmin="6a8b4b39-c021-437c-b060-5a14a3fd65f3"
$scope = "$spVCServiceAdmin/full_access"
$spScope = "$spVCServiceAdmin/.default"
