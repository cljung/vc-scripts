$AdminAPIScriptVersion = "2022-09-27"
<#
This file contains a Powershell module for the EntraVerifiedID Admin API
#>

<#
.SYNOPSIS
    Interactive Login to VC Admin API
.DESCRIPTION
    Interactive Login to get an access token that can be used for the VC Admin API
.PARAMETER TenantId
    Your Azure AD tenant id (guid)
.PARAMETER ClientId
    Your registered Azure AD AppID that has API Permissions to use the VC Admin API
.PARAMETER Scope
    The scope of the VC Admin API. "6a8b4b39-c021-437c-b060-5a14a3fd65f3/full_access"
.OUTPUTS
    On successful authentication, the MSAL.PS token cache has an access token 
.EXAMPLE
    Connect-EntraVerifiedID -TenantId $TenantId -ClientID $clientId
#>
function Connect-EntraVerifiedID {
    [cmdletbinding()]
    param( 
        [Parameter(Mandatory=$True)][Alias('c')][string]$ClientId,
        [Parameter(Mandatory=$True)][Alias('t')][string]$TenantId,
        [Parameter()][Alias('s')][string]$Scope = "6a8b4b39-c021-437c-b060-5a14a3fd65f3/full_access"
)

$msalParams = @{ ClientId = $clientId; TenantId = $tenantId; Scopes = $Scope }
$msalResp = Get-MsalToken @msalParams

$tenantMetadata = invoke-restmethod -Uri "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
$global:tenantRegionScope = $tenantMetadata.tenant_region_scope # WW, NA, EU, AF, AS, OC, SA
$global:tenantId = $tenantId
$global:clientId = $clientId
$global:scope = $scope
$global:VerifiedIDHostname = "https://verifiedid.did.msidentity.com"
}

################################################################################################################################################
# Helper functions
################################################################################################################################################
function Invoke-RestMethodWithMsal( [string]$httpMethod, [string]$path, [string]$body ) {
    if ( $path.StartsWith("https://")) {
        $url = $path
    } else {
        if ( $path.StartsWith("/") ) {
            $url="$global:VerifiedIDHostname$path"
        } else {
            $url="$global:VerifiedIDHostname/v1.0/verifiableCredentials/$path"
        }
    }
    $msalParams = @{ ClientId = $global:clientId; TenantId = $global:tenantId; Scopes = $global:scope }
    $msalResp = Get-MsalToken @msalParams
    $authHeader =@{ 'Content-Type'='application/json'; 'Authorization'=$msalResp.TokenType + ' ' + $msalResp.AccessToken }
    try {
        if ( $httpMethod -eq "GET" ) {
            write-verbose "$httpMethod $url`n$($authHeader | ConvertTo-json)" #$msalResp.AccessToken
            $resp = Invoke-RestMethod -Method "GET" -Headers $authHeader -Uri $url -ErrorAction Stop
        } else {
            write-verbose "$httpMethod $url`n$($authHeader | ConvertTo-json)`n$body" #$msalResp.AccessToken
            $resp = Invoke-RestMethod -Method $httpMethod -Uri $url -Headers $authHeader -Body $body -ContentType "application/json" -ErrorAction Stop
        }
    } catch {
        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $streamReader.BaseStream.Position = 0
        $streamReader.DiscardBufferedData()
        $errResp = $streamReader.ReadToEnd()
        $streamReader.Close()    
        write-host $errResp -ForegroundColor "Red" -BackgroundColor "Black"
    }
    return $resp    
}
function Invoke-AdminAPIGet( [string]$path ) {
    return Invoke-RestMethodWithMsal "GET" $path $null
}
function Invoke-AdminAPIPost( [string]$path, [string]$body ) {
    return Invoke-RestMethodWithMsal "POST" $path $body
}
function Invoke-AdminAPIPatch( [string]$path, [string]$body ) {
    return Invoke-RestMethodWithMsal "PATCH" $path $body
}

################################################################################################################################################
# Admin API
################################################################################################################################################
#-----------------------------------------------------------------------------------------------------------------------------------------------
# Onboard tenant & Out-out
#-----------------------------------------------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
    Gets Azure AD tenant details for Entra Verified ID
.DESCRIPTION
    Gets Azure AD tenant details for Entra Verified ID
.EXAMPLE
    Get-EntraVerifiedIDTenantSettings
#>
function Get-EntraVerifiedIDTenantSettings() {
    return Invoke-AdminAPIGet "organizationSettings"
}
<#
.SYNOPSIS
    Onboards the Azure AD tenant to Entra Verified ID
.DESCRIPTION
    Onboards the Azure AD tenant to Entra Verified ID
.EXAMPLE
    Enable-EntraVerifiedIDTenant
#>
function Enable-EntraVerifiedIDTenant() {
    return Invoke-AdminAPIPost "onboard" ""
}

function Enable-EntraVerifiedIDTenantQuick( [Parameter(Mandatory=$True)][string]$Name
                                          , [Parameter(Mandatory=$True)][string]$LinkedDomainUrl) {
$body = @"
{
    "name":"$Name",
    "linkedDomainUrl":"$LinkedDomainUrl"
}
"@
    return Invoke-AdminAPIPost "onboardZeroConfig" $body 
}
<#
.SYNOPSIS
    Opts-out Entra Verified ID for the Azure AD tenant
.DESCRIPTION
    Opts-out Entra Verified ID for the Azure AD tenant, destroying all authorities, cedential contracts and issued credentials
.PARAMETER Force
    If to not get the 'are you sure?' question
.EXAMPLE
    Remove-EntraVerifiedIDTenantOptOut
.EXAMPLE
    Remove-EntraVerifiedIDTenantOptOut -Force
#>
function Remove-EntraVerifiedIDTenantOptOut( [Parameter(Mandatory=$false)][switch]$Force = $False ) {
    if (!$Force ) {
        $answer = (Read-Host "Are you sure you want to Opt-out and delete all credentials? [Y]es or [N]o").ToLower()
        if ( !("yes","y" -contains $answer) ) {
            return
        }
    }
    return Invoke-AdminAPIPost "optout" ""
}
#-----------------------------------------------------------------------------------------------------------------------------------------------
# Issuer
#-----------------------------------------------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
    Creates a new Verifiable Credential authority in Entra Verified ID tenant
.DESCRIPTION
    Creates a new Verifiable Credential authority in Entra Verified ID, with it's unique DID
.PARAMETER OrganizationName
    Name of this instance of the Verified ID service, like Contoso, Fabrikam or Woodgrove
.PARAMETER Domain
    Domain linked to this DID, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.PARAMETER KeyVaultResourceID
    The Azure ResourceID of the Azure KeyVault instance to be used for signin and encryption keys
.EXAMPLE
    New-EntraVerifiedIDAuthority -Name "Contoso" -Domain "https://contoso.com" -KeyVaultResourceID $KeyVaultResourceID 
#>
function New-EntraVerifiedIDAuthority(  [Parameter(Mandatory=$True)][string]$Name, 
                                        [Parameter(Mandatory=$True)][string]$Domain, 
                                        [Parameter(Mandatory=$True)][string]$KeyVaultResourceID,
                                        [Parameter(Mandatory=$false)][string]$DidMethod = "web"
                                    )
{
    $kvparts=$KeyVaultResourceID.Split("/")
    if ( $kvparts.Count -ne 9 ) {
        write-error "Invalid KeyVault ResourceID"
        return
    }
    $subscriptionId=$kvparts[2]
    $resourceGroup=$kvparts[4]
    $kvName=$kvparts[8]
    $kvUrl="https://$kvName.vault.azure.net/"
    # "didMethod" : "web",
    $body = @"
{
    "name":"$Name",
    "linkedDomainUrl":"$Domain",
    "didMethod": "$($didMethod.ToLower())",
    "keyVaultMetadata":
    {
        "subscriptionId":"$subscriptionId",
        "resourceGroup":"$resourceGroup",
        "resourceName":"$kvName",
        "resourceUrl": "$kvUrl"
    }
}
"@
    return Invoke-AdminAPIPost "authorities" $body 
}
<#
.SYNOPSIS
    Updates an Authority
.DESCRIPTION
    Updates and Authority. Currently, you can only modify display name of the authority
.PARAMETER Id
    Id of the Authority. 
.OUTPUTS
    Returns the updated Authority object
.EXAMPLE
    Update-EntraVerifiedIDAuthority -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6" -Name "MyNewName"
#>
function Set-EntraVerifiedIDAuthority( [Parameter(Mandatory=$True)][string]$Id, [Parameter(Mandatory=$True)][string]$Name ) {
    $body = @"
{
    "name":"$Name"
}
"@
    return Invoke-AdminAPIPost  "authorities/$id" $body 
}
<#
.SYNOPSIS
    Rotate the Authority's signing keys
.DESCRIPTION
    Rotate the Authority's signing key, which means rotate in Azure Key Vault and update the Issuer object.
    You manually have to generate the new did document and publish it if the Issuer is using the did:web method
.PARAMETER Id
    Id of the Authority. 
.OUTPUTS
    Does not return any data
.EXAMPLE
    New-EntraVerifiedIDAuthoritySigningKey -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function New-EntraVerifiedIDAuthoritySigningKey( [Parameter(Mandatory=$True)][string]$AuthorityId ) {
    #return Invoke-AdminAPIPost  "authorities/$id/rotateSigningKey" 
    return Invoke-AdminAPIPost  "authorities/$Authorityid/didInfo/signingKeys/rotate"
}
<#
.SYNOPSIS
    Start using the new signing key for the Authority
.DESCRIPTION
    After you have created a new signing key, you must use this command to tell the Authority to start using it
.PARAMETER Id
    Id of the Authority. 
.OUTPUTS
    returns the Authority
.EXAMPLE
    New-EntraVerifiedIDAuthoritySigningKey -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Use-EntraVerifiedIDAuthoritySigningKey( [Parameter(Mandatory=$True)][string]$AuthorityId ) {
    return Invoke-AdminAPIPost  "authorities/$Authorityid/didInfo/synchronizeWithDidDocument"
}

<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Issuer instance. The domain names where originally set in the New-EntraVerifiedIDIssuer command
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-EntraVerifiedIDAuthority command
.PARAMETER Domains
    String array of domains, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.EXAMPLE
    Set-EntraVerifiedIDAuthorityLinkedDomains -Domains @( "https://contoso.com/", "https://vc.fabrikam.com/" )
.EXAMPLE
    Set-EntraVerifiedIDAuthorityLinkedDomains -Id $AuthorityId -Domains @( "https://contoso.com/", "https://vc.fabrikam.com/" )
#>
function Set-EntraVerifiedIDAuthorityLinkedDomains( [Parameter(Mandatory=$False)][string]$Id, 
                                                    [Parameter(Mandatory=$True)][string[]]$Domains
                                                  ) {
    if ( !$Id ) {
        $authorities = Get-EntraVerifiedIDAuthority
        $Id = $authorities[0].id
    }    
    $body = @"
{
    "domainUrls" : $($domains | ConvertTo-Json)
}
"@    
    return Invoke-AdminAPIPost "authorities/$Id/updateLinkedDomains" $body
}
<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Authority instance. The domain names where originally set in the New-EntraVerifiedIDAuthority command
.PARAMETER IssuerId
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthority command
.PARAMETER Domain
    Domain, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.OUTPUTS
    Returns the content that should be put in the <domain>/.well-known/did-configuration.json file to verify the linked domain
.EXAMPLE
    New-EntraVerifiedIDAuthorityWellKnownDidConfiguration -Domain "https://contoso.com/"
.EXAMPLE
    New-EntraVerifiedIDAuthorityWellKnownDidConfiguration -AuthorityId $AuthorityId -Domain "https://vc.fabrikam.com/"
#>
function New-EntraVerifiedIDAuthorityWellKnownDidConfiguration( [Parameter(Mandatory=$False)][string]$Id, 
                                                                [Parameter(Mandatory=$True)][string]$Domain 
                                                              ) {
    if ( !$Id ) {
        $authorities = Get-EntraVerifiedIDAuthority
        $Id = $authorities[0].id
    }    
    $body = @"
{
    "domainUrl": "$Domain"
}
"@    
    return Invoke-AdminAPIPost "authorities/$Id/generateWellknownDidConfiguration" $body
}
<#
.SYNOPSIS
    Gets Authorities by Id
.DESCRIPTION
    Gets Authorities by Id
.PARAMETER Id
    Id of the Authority
.OUTPUTS
    Returns the Authority object
.EXAMPLE
    Get-EntraVerifiedIDAuthority
.EXAMPLE
    Get-EntraVerifiedIDAuthority -Name "Contoso"
.EXAMPLE
    Get-EntraVerifiedIDAuthority -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Get-EntraVerifiedIDAuthority( [Parameter(Mandatory=$False)][string]$Id, [Parameter(Mandatory=$False)][string]$Name ) {
    if ( $Id ) {
        $authorities = Invoke-AdminAPIGet "authorities/$id" 
        return $authorities
    }
    $authorities = Invoke-AdminAPIGet "authorities" 
    if ( !$Name ) {
        return $authorities.value
    }
    return ($authorities.value | where {$_.name -eq $Name } )
}
<#
.SYNOPSIS
    Gets a new DID Document for an Authority by Id. Only supported by did:web
.DESCRIPTION
    Gets a new DID Document for an Authority by Id. Only supported by did:web
.PARAMETER Id
    Id of the Authority
.OUTPUTS
    Returns the DID Document
.EXAMPLE
    Get-EntraVerifiedIDDidDocument -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function New-EntraVerifiedIDDidDocument( [Parameter(Mandatory=$True)][string]$Id ) {
    return Invoke-AdminAPIPost "authorities/$id/generateDidDocument" 
}

<#
.SYNOPSIS
    Get Linked Domains did-configuration json metadata for an Authority
.DESCRIPTION
    Get Linked Domains did-configuration json metadata for an Authority.
    If -Raw switch is not passed, the decoded values to pay attention to are:
    - type == DomainLinkageCredential
    - credentialSubject.id == did for the Authority. Matches (Get-EntraVerifiedIDAuthority -Name "Contoso").didModel.did
    - credentialSubject.origin == matches the linked domain name
.PARAMETER Name
    Name or the Authority. If not specified, all Authority will be returned
.PARAMETER Raw
    Switch if to return the raw did-configuration or if to decode the JWT token
.OUTPUTS
    Returns one or all did-configuration metadata, decoded or raw
.EXAMPLE
    Get-EntraVerifiedIDAuthorityLinkedDomainDidConfiguration -Name "Contoso"
.EXAMPLE
    Get-EntraVerifiedIDAuthorityLinkedDomainDidConfiguration -Name "Contoso" -Raw
#>
function Get-EntraVerifiedIDAuthorityLinkedDomainDidConfiguration( [Parameter(Mandatory=$True)][string]$Name,
                                                                   [Parameter(Mandatory=$false)][switch]$Raw = $False ) {
    $authorities = Get-EntraVerifiedIDAuthority -Name $Name
    $didcfgs = @()
    foreach( $domain in $authorities.didModel.linkedDomainUrls ) {
        $url = "$domain.well-known/did-configuration.json"
        write-verbose "GET $url"
        $cfg = invoke-restmethod -Method "GET" -Uri $url
        $didcfgs += $cfg
    }
    if ( $Raw ) {
        return $didcfgs
    }
    $tokens = @()
    foreach( $cfg in $didcfgs ) {
        $token = $cfg.linked_dids.Split(".")[1]
        if ( ($token.Length % 4) -gt 0 ) {
            $token = $token + "".PadRight( 4-($token.Length % 4), "=")
        }
        $tokens += ([System.Text.Encoding]::ASCII.GetString( [System.Convert]::FromBase64String($token) ) | ConvertFrom-json)
    }
    return $tokens
}
#-----------------------------------------------------------------------------------------------------------------------------------------------
# Contracts (or Credentials as it is called in the portal)
#-----------------------------------------------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
    Gets a Credential contract by id
.DESCRIPTION
    Gets a Credential contract by id
.PARAMETER Id
    Id of the contract
.OUTPUTS
    Returns the contract objects
.EXAMPLE
    Get-EntraVerifiedIDContract -AuthorityId <guid>
.EXAMPLE
    Get-EntraVerifiedIDContract -AuthorityId <guid> -Id "OTg4NTQ1N2EtMjAy...lhbHRlc3Qx"
.EXAMPLE
    Get-EntraVerifiedIDContract -AuthorityId <guid> -Name "VerifiedCredentialExpert"
#>
function Get-EntraVerifiedIDContract( [Parameter(Mandatory=$True)][string]$AuthorityId,
                                      [Parameter(Mandatory=$False)][string]$Id,
                                      [Parameter(Mandatory=$False)][string]$Name
                                    ) {
    if ( $Id ) {
        return Invoke-AdminAPIGet "authorities/$AuthorityId/contracts/$Id"
    }                                        
    $contracts = Invoke-AdminAPIGet "authorities/$AuthorityId/contracts"
    if ( $Name ) {
        return ($contracts.value | where {$_.name -eq $Name } )
    }
    return $contracts.value    
}
<#
.SYNOPSIS
    Gets all or a named Credential contract
.DESCRIPTION
    Gets all or a named Credential contract from the Entra Verified ID configuration
.PARAMETER AuthorityId
    Id of the Authority.
.PARAMETER Name
    Name or the Credential contract. 
.PARAMETER Rules
    The rules definition
.PARAMETER Displays
    The display definition
.PARAMETER AvailableInVcDirectory
    If the credential contract should be visible in the Entra Verified ID Network
.PARAMETER issueNotificationAllowedToGroupOids
    Group directory object ids, if this is a contract of type "VerifiedEmployee"
.OUTPUTS
    Returns the newly created Credential contract object
.EXAMPLE
    New-EntraVerifiedIDContract -Name "ContosoEmployee" -StorageResourceID $StorageResourceID -RulesFileName "contosofterules.json" -DisplayFileName "contosoftedisplay.json"
.EXAMPLE
    New-EntraVerifiedIDContract -AuthorityId $AuthorityId -Name "ContosoEmployee" -StorageResourceID $StorageResourceID -RulesFileName "contosofterules.json" -DisplayFileName "contosoftedisplay.json"
#>
function New-EntraVerifiedIDContract( [Parameter(Mandatory=$False)][string]$AuthorityId,
                                      [Parameter(Mandatory=$True)][string]$Name, 
                                      [Parameter(Mandatory=$True)][string]$Rules, 
                                      [Parameter(Mandatory=$True)][string]$Displays,
                                      [Parameter(Mandatory=$False)][boolean]$AvailableInVcDirectory = $False
                                    ) {
    $body = $null
    $issueNotificationEnabled = $False
    $groupOids = "[]"
    if ( $issueNotificationAllowedToGroupOids.Length -gt 0 ) {
        $issueNotificationEnabled = $True
        $groupOids = ($issueNotificationAllowedToGroupOids | ConvertTo-json -Compress )
    }
    $body = @"
{
    "name": "$Name",
    "status":  "Enabled",
    "issueNotificationEnabled": $($issueNotificationEnabled.ToString().ToLower()),
    "availableInVcDirectory": $($availableInVcDirectory.ToString().ToLower()),
    "displays": [ $Displays ],
    "rules": $Rules
}
"@
    if ( !$AuthorityId ) {
        $authorities = Get-EntraVerifiedIDAuthority
        $AuthorityId = $authorities[0].id
    }        
    return Invoke-AdminAPIPost  "authorities/$AuthorityId/contracts" $body 
}
<#
.SYNOPSIS
    Updates a Credential contract
.DESCRIPTION
    Updates a Credential contract
.PARAMETER AuthorityId
    Id of the Authority.
.PARAMETER Id
    Id of the contract
.PARAMETER Body
    JSON payload of the contract
.OUTPUTS
    Returns the contract objects
.EXAMPLE
    Update-EntraVerifiedIDContract -AuthorityId $AuthorityId -Id $contracId -Body $jsonPayload
#>
function Set-EntraVerifiedIDContract( [Parameter(Mandatory=$True)][string]$AuthorityId,
                                         [Parameter(Mandatory=$True)][string]$Id,
                                         [Parameter(Mandatory=$True)]$Body
                                       ) {
    return Invoke-AdminAPIPatch "authorities/$AuthorityId/contracts/$Id" $Body
}
#-----------------------------------------------------------------------------------------------------------------------------------------------
# Credentials (ie what is issued to holders)
#-----------------------------------------------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
    Searches for issued credentials based on indexed claim value
.DESCRIPTION
    Searches for issued credentials based on indexed claim value
.PARAMETER ContractId
    Id of the Credential contract. Can be retrieved by the Get-EntraVerifiedIDContract command
.PARAMETER ClaimValue
    Value of the indexed claim
.OUTPUTS
    Returns all issued credentials that matches the indexed claim value
.EXAMPLE
    Get-EntraVerifiedIDCredentials -AuthorityId $AuthorityId -ContractId $contractId -ClaimValue "alice@contoso.com"
#>
function Get-EntraVerifiedIDCredentials( [Parameter(Mandatory=$true)][string]$AuthorityId,
                                         [Parameter(Mandatory=$true)][string]$ContractId,    
                                         [Parameter(Mandatory=$true)][string]$ClaimValue
                                       ) {
    $sha256 = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $inputasbytes = [System.Text.Encoding]::UTF8.GetBytes( $contractid + $claimvalue )
    $hashedsearchclaimvalue = [System.Convert]::ToBase64String($sha256.ComputeHash($inputasbytes))
    $qpValue = [System.Web.HTTPUtility]::UrlEncode( $hashedsearchclaimvalue )
    $url = "authorities/$AuthorityId/contracts/$contractid/credentials?filter=indexclaimhash eq $qpValue"
    $resp = Invoke-AdminAPIGet $url
    #$url = "https://beta.did.msidentity.com/$($global:tenantId)/api/portable/v1.0/admin/contracts/$ContractId/cards?filter=indexclaim eq $qpValue"
    return $resp.value
}
<#
.SYNOPSIS
    Revokes an issued credentials
.DESCRIPTION
    Revokes an issued credentials based on its id. This operation is irreversable
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-EntraVerifiedIDAuthority command
.PARAMETER ContractId
    Id of the Credential contract. Can be retrieved by the Get-EntraVerifiedIDContract command
.PARAMETER CredentialId
    Id of the issued credential
.PARAMETER Force
    If to not get the 'are you sure?' question
.EXAMPLE
    Revoke-EntraVerifiedIDCredential -AuthorityId $AuthorityId -ContractId $contractId -CardId $cardId
.EXAMPLE
    Revoke-EntraVerifiedIDCredential -AuthorityId $AuthorityId -ContractId $contractId -CardId $cardId -Force
#>
function Revoke-EntraVerifiedIDCredential( [Parameter(Mandatory=$false)][string]$AuthorityId,    
                                           [Parameter(Mandatory=$true)][string]$ContractId,    
                                           [Parameter(Mandatory=$true)][string]$CredentialId,
                                           [Parameter(Mandatory=$false)][switch]$Force = $False
                                         ) {
    if (!$Force ) {
        $answer = (Read-Host "Are you sure you want to Revoke the Credential $CardId? [Y]es or [N]o").ToLower()
        if ( !("yes","y" -contains $answer) ) {
            return
        }
    }
    if ( !$AuthorityId ) {
        $issuers = Get-EntraVerifiedIDAuthority
        $AuthorityId = $issuers[0].id
    }    
    return Invoke-AdminAPIPost  "authorities/$AuthorityId/contracts/$ContractId/credentials/$CredentialId/revoke" ""
}
################################################################################################################################################
# Status API
################################################################################################################################################
# '/v1.0/:tenantId/verifiableCredential/card/status'
# post a VC and get its status
################################################################################################################################################
# Contracts API
################################################################################################################################################
<#
.SYNOPSIS
    Gets a Credential Contract's manifest URL
.DESCRIPTION
    Gets a Credential Contract's manifest URL
.PARAMETER IssuerId
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthority command
.PARAMETER Name
    Name or the Credential contract. 
.OUTPUTS
    Returns one or all Credential contract objects
.EXAMPLE
    Get-EntraVerifiedIDContractManifestURL -Name "ContosoEmployee"
.EXAMPLE
    Get-EntraVerifiedIDContractManifestURL -Name "ContosoEmployee" -AuthorityId $issuer.id
#>
function Get-EntraVerifiedIDContractManifestURL( [Parameter(Mandatory=$False)][string]$AuthorityId,
                                                 [Parameter(Mandatory=$True)][string]$Name
                                               ) {
    $contract = Get-EntraVerifiedIDContract -AuthorityId $AuthorityId -Name $Name
    if ( !$contract ) {
        return $null
    }
    $url = $contract.manifestUrl
    # temp bugfix
    if ( !$url.StartsWith("https://verifiedid.did.msidentity.com/v1.0/tenants/")) {
        $url = $url.Replace( "https://verifiedid.did.msidentity.com/", "https://verifiedid.did.msidentity.com/v1.0/tenants/")
    }
    return $url
}
<#
.SYNOPSIS
    Gets a Credential Contract's manifest
.DESCRIPTION
    Gets a Credential Contract's manifest either signed as a JWT token or unsigned json data
.PARAMETER AuthorityId
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthority command
.PARAMETER Name
    Name or the Credential contract.
.PARAMETER Signed
    If to sign the manifest and return a JWT Token. This is what the Microsoft Authenticator does
    and it is also a test to see that your Azure KeyVault is set up correctly.
.OUTPUTS
    Returns the manifest as an unsigned json data structure or a signed JWT token
.EXAMPLE
    Get-EntraVerifiedIDContractManifest -Name "ContosoEmployee"
.EXAMPLE
    Get-EntraVerifiedIDContractManifest -Name "ContosoEmployee" -AuthorityId $issuer.id -Signed
#>
function Get-EntraVerifiedIDContractManifest( [Parameter(Mandatory=$False)][string]$AuthorityId,
                                              [Parameter(Mandatory=$True)][string]$Name,
                                              [Parameter(Mandatory=$false)][switch]$Signed = $False
                                            ) {
    $url = Get-EntraVerifiedIDContractManifestURL -AuthorityId $AuthorityId -Name $Name
    if ( !$url ) {
        return $null
    }
    write-verbose "GET $url"
    return invoke-restmethod -Method "GET" -Uri $url -Headers @{ "x-ms-sign-contract"="$($Signed.ToString().ToLower())"; }
}
################################################################################################################################################
# Discovery API
################################################################################################################################################
<#
.SYNOPSIS
    Gets a DID Document for an Authority
.DESCRIPTION
    Gets a DID Document for an Authority from the Entra Verified ID configuration
.PARAMETER Name
    Name or the Authority. If not specified, first authority will be used
.OUTPUTS
    Returns DID Document for an Authority
.EXAMPLE
    Get-EntraVerifiedIDDidExplorer
.EXAMPLE
    Get-EntraVerifiedIDDidExplorer -Name "Contoso"
#>
function Get-EntraVerifiedIDDidDocument( [Parameter(Mandatory=$False)][string]$AuthorityId
                                       , [Parameter(Mandatory=$False)][string]$Name
                                       , [Parameter(Mandatory=$False)][string]$did ) {
    if ( $AuthorityId ) {
        $authority = Get-EntraVerifiedIDAuthority -Id $AuthorityId
        $did = $authority.didModel.did
    } else {
        if ( $Name ) {
            $authority = Get-EntraVerifiedIDAuthority -Name $Name
            $did = $authority.didModel.did
        }
    }
    if ( $did ) {
        $url = "https://discover.did.msidentity.com/v1.0/identifiers/$did"
        write-verbose "GET $url"
        return invoke-restmethod -Method "GET" -Uri $url
    }
}
################################################################################################################################################
# VC Directory API
################################################################################################################################################
<#
.SYNOPSIS
    Gets all Issuers in the VC Directory
.DESCRIPTION
    Gets all Issuers that have opted-in to be visible in the VC Directory
.PARAMETER Name
    Name or the Issuer. If not specified, all Issuers will be returned
.OUTPUTS
    Returns one or all Issuer objects
.EXAMPLE
    Get-EntraVerifiedIDNetworkIssuers
#>
function Get-EntraVerifiedIDNetworkIssuers( [Parameter(Mandatory=$false)][string]$DomainSearch ) {
    if ( !$DomainSearch ) { $DomainSearch = "%20" }
    $resp = Invoke-AdminAPIGet "/v1.0/verifiableCredentialsNetwork/authorities?filter=linkeddomainurls like $DomainSearch"
    return $resp.value
}
<#
.SYNOPSIS
    Gets all contracts for an Issuers in the VC Directory
.DESCRIPTION
    Gets all contracts for an Issuers in the VC Directory
.PARAMETER TenantId
    Id of the tenant in the VC Directory. This is the normal Azure AD tenant id
.PARAMETER IssuerId
    Id of the Issuer in that tenant. You can retrieve this from Get-EntraVerifiedIDDirectoryIssuers command
.PARAMETER TenantRegion
    If you want to query a different region than your default region
.OUTPUTS
    Returns one or all contracts objects
.EXAMPLE
    Get-EntraVerifiedIDNetworkIssuerContracts
#>
function Get-EntraVerifiedIDNetworkIssuerContracts( [Parameter(Mandatory=$True)][string]$TenantId
                                            , [Parameter(Mandatory=$True)][string]$AuthorityId ) {
    $resp = Invoke-AdminAPIGet "/v1.0/tenants/$tenantId/verifiableCredentialsNetwork/authorities/$AuthorityId/contracts"
    return  $resp.value
}
