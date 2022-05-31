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
$scope = "0135fd85-3010-4e73-a038-12560d2b58a9/full_access"
