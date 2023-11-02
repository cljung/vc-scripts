<#
This script shows the tenantId and region based on a DID
#>
param (
    [Parameter(Mandatory=$true)][string]$DID
)

# ZeroConfig DIDs have the tenantId in the DID, others have it in the DID Document
if ( $DID.StartsWith("did:web:verifiedid.entra.microsoft.com") ) {
    $tenantID = $DID.Split(":")[3]
} else {
    $didDocument = invoke-restmethod -Uri "https://beta.discover.did.microsoft.com/1.0/identifiers/$DID"
    $hubUrl = ($didDocument.didDocument.service | where {$_.type -eq "IdentityHub"}).serviceEndpoint.instances[0]
    $tenantId = $hubUrl.Split("/")[4]
}

$tenantMetadata = invoke-restmethod -Uri "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
$tenantRegionScope = $tenantMetadata.tenant_region_scope # WW, NA, EU, AF, AS, OC, SA

write-host "DID      : $DID`nTenantId : $TenantId`nRegion   : $tenantRegionScope"