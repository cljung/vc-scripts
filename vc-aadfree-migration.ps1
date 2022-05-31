<#
This scripts migrates and Azure AD P2 tenant with old AppIDs to the new 1st party AppIDs
introduced with the Azure AD Free preview
#>
param (
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$KeyVaultResourceGroupName,
    [Parameter(Mandatory=$true)][string]$KeyVaultName,
    [Parameter(Mandatory=$true)][string]$StorageResourceGroupName,
    [Parameter(Mandatory=$true)][string]$StorageAccountName,
    [Parameter(Mandatory=$true)][string]$StorageAccountContainerName
    )

if ((Get-Module -ListAvailable -Name "Az.Accounts") -eq $null) {  
  Install-Module -Name "Az.Accounts" -Scope CurrentUser 
}
if ((Get-Module -ListAvailable -Name "Az.Resources") -eq $null) {  
  Install-Module "Az.Resources" -Scope CurrentUser 
}

$ctx = Get-AzContext
if ( $null -eq $ctx -or ( $ctx.Subscription -and $ctx.Subscription.Id -ne $SubscriptionId ) ) {
    Connect-AzAccount -TenantId $TenantId -Subscription $SubscriptionId
    $ctx = Get-AzContext
}

function PrintMsg( $msg ) {  
  $buf = "".PadLeft(78,"*")
  write-host "`n$buf`n* $msg`n$buf"
}
##############################################################################################
# Constants

# old appIDs from the AAD P2 era
$appIdRequestAPI_old = "bbb94529-53a3-4be5-a069-7eaf2712b826"
$appIdVCService_old = "0135fd85-3010-4e73-a038-12560d2b58a9"
$appIdVCIssuingService_old = "603b8c59-ba28-40ff-83d1-408eee9a93e5"

# new appIDs from the AAD Free era
$appIdVCService = "bb2a64ee-5d29-4b07-a491-25806dc854d3"
$appIdAdmin = "6a8b4b39-c021-437c-b060-5a14a3fd65f3"
$appIdRequestAPI = "3db474b9-6a0c-4840-96ac-1fceb342124f"

$permissionNameVerifiableCredentialCreateAll = "VerifiableCredential.Create.All"
##############################################################################################
# get apps
$spRequestAPI_old = Get-AzADServicePrincipal -ApplicationId $appIdRequestAPI_old
$spVCIS_old = Get-AzADServicePrincipal -ApplicationId $appIdVCIssuingService_old

if ( $null -eq ($spVCS = Get-AzADServicePrincipal -ApplicationId $appIdVCService )) {
    $spVCS = New-AzADServicePrincipal -ApplicationId $appIdVCService
}
if ( $null -eq ($spAdmin = Get-AzADServicePrincipal -ApplicationId $appIdAdmin )) {
    $spAdmin = New-AzADServicePrincipal -ApplicationId $appIdAdmin
}
$idAdminAPIFullAccess = ($spAdmin.Oauth2PermissionScope | where {$_.AdminConsentDisplayName -eq "full_access"}).Id

if ( $null -eq ($spRequestAPI = Get-AzADServicePrincipal -ApplicationId $appIdRequestAPI )) {
    $spRequestAPI = New-AzADServicePrincipal -ApplicationId $appIdRequestAPI
}
$idVerifiableCredentialCreateAll = ($spRequestAPI.AppRole | where {$_.DisplayName -eq $permissionNameVerifiableCredentialCreateAll}).Id

##############################################################################################
# Convert all apps that has an API Permission of VerifiableCredential.Create.All to use the new AppId

PrintMsg "Updating Azure AD Apps that has API Permissions of $permissionNameVerifiableCredentialCreateAll"

$apps = Get-AzADApplication 
foreach( $app in $apps ) {
    if ( $app.RequiredResourceAccess.ResourceAppId -contains $appIdRequestAPI_old ) {
        write-host "$($app.DisplayName) ($($app.AppId)) has API Permission(s) for Client API " $appIdRequestAPI_old
        if ( $app.RequiredResourceAccess.ResourceAppId -contains $appIdRequestAPI ) {
            write-host "Already setup for new API Permission"
        } else {
            write-host "Adding new API Permission" $idVerifiableCredentialCreateAll " - remember to Grant permission in the portal"
            Add-AzADAppPermission -ObjectId $app.Id -ApiId $appIdRequestAPI -PermissionId $idVerifiableCredentialCreateAll -Type "Role"
        }
    }
}

##############################################################################################
# Convert KeyVault Access Policy to include Get,Sign for the new apps

PrintMsg "Updating KeyVault $keyVaultName Access Policy"

$kv = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -Name $keyVaultName
if ( !($kv.AccessPolicies.ObjectID -contains $spVCIS_old.Id -and $kv.AccessPolicies.ObjectID -contains $spRequestAPI_old.Id) ) {
    write-host "KeyVault $keyVaultName AccessPolicy does not contain old VC apps"
} else {
    write-host "KeyVault $keyVaultName AccessPolicy contains old VC apps"
    if ( !($kv.AccessPolicies.ObjectID -contains $spVCS.Id) ) {
        write-host "Adding $($spVCS.DisplayName) to AccessPolicy"
        Set-AzKeyVaultAccessPolicy -ResourceGroupName $KeyVaultResourceGroupName -VaultName $keyVaultName -ObjectId $spVCS.Id -PermissionsToKeys Get,Sign
    } else {
        write-host "$($spVCS.DisplayName) already in AccessPolicy"
    }
    if ( !($kv.AccessPolicies.ObjectID -contains $spRequestAPI.Id) ) {
        write-host "Adding $($spRequestAPI.DisplayName) to AccessPolicy"
        Set-AzKeyVaultAccessPolicy -ResourceGroupName $KeyVaultResourceGroupName -VaultName $keyVaultName -ObjectId $spRequestAPI.Id -PermissionsToKeys Get,Sign
    } else {
        write-host "$($spRequestAPI.DisplayName) already in AccessPolicy"
    }
}

##############################################################################################
# Convert Storage Account so that new VC Service can read blobs in container

$storageRoleBlobDataReaderName = "Storage Blob Data Reader"
PrintMsg "Assigning $storageRoleBlobDataReaderName roles to $($spVCS.DisplayName)"

$scope = "/subscriptions/$($ctx.Subscription.Id)/resourcegroups/$StorageResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default/containers/$StorageAccountContainerName"
$roles = Get-AzRoleAssignment -Scope $scope
if (!($roles | where {$_.RoleDefinitionName -eq $storageRoleBlobDataReaderName -and $_.objectId -eq $spVCS.Id})) {
    write-host "Adding $storageRoleName access to storage account $storageAccountName for $($spVCS.DisplayName)"
    New-AzRoleAssignment -ObjectId $spVCS.Id -RoleDefinitionName $storageRoleBlobDataReaderName -Scope $scope 
} else {
    write-host "$($spVCS.DisplayName) already has $storageRoleBlobDataReaderName access to storage account $storageAccountName"
}
