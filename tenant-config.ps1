$tenantID = "<tenant-guid>" 
<#
Update the variables with values for your environment, then run it in your powershell command prompt
with the initial dot to 'dot source' the variables into your session

. .\tenant-config.ps1

#>
$SubscriptionId = "<azure-subscription-guid>"
$Location = "West Europe"
$resourceGroupName = "<resource-group-name>"
$keyVaultName = "<your-keyvault>"
$storageAccountName = "<your-storageaccountname>"
$ContainerPath = "<your-storagecontainername>"
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI (scope below)
$scope = "6a8b4b39-c021-437c-b060-5a14a3fd65f3/full_access"
