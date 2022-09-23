<#
Update the variables with values for your environment, then run it in your powershell command prompt
with the initial dot to 'dot source' the variables into your session

. .\tenant-config.ps1

#>
$tenantID = "<tenant-guid>" 
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI (scope below)

# The below settings are ONLY needed if you plan to Onboard a tenant via powershell
$SubscriptionId = "<azure-subscription-guid>"
$resourceGroupName = "<resource-group-name>"
$keyVaultName = "<your-keyvault>"
