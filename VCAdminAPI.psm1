$AdminAPIScriptVersion = "2022-08-16"
<#
This file contains a Powershell module for the EntraVerifiedID Admin API
#>

<#
.SYNOPSIS
    Interactive Login using Device Code Flow
.DESCRIPTION
    Interactive Login using Device Code Flow to get an access token that can be used for the VC Admin API
.PARAMETER TenantId
    Your Azure AD tenant id (guid)
.PARAMETER ClientId
    Your registered Azure AD AppID that has API Permissions to use the VC Admin API
.PARAMETER Scope
    The scope of the VC Admin API. "0135fd85-3010-4e73-a038-12560d2b58a9/full_access"
.PARAMETER Edge
    If to launch the device code flow in Microsoft Egde browser (only works on Windows)
.PARAMETER Chrome
    If to launch the device code flow in Google Chrome browser (Only works on Windows)
.PARAMETER Firefox
    If to launch the device code flow in Firefox browser (only works on Windows)
.PARAMETER Incognito
    If to launch the device code flow in an incognito/inprivate window (only works on Windows)
.PARAMETER NewWindow
    If to launch the device code flow in a new browser window (only works on Windows)
.PARAMETER Timeout
    How many seconds the powershell command should wait for sign in completion
.OUTPUTS
    On successful authentication, the command sets global variable $global:authHeader that can be used for authenticating REST API calls
    $global:authHeader =@{ 'Content-Type'='application/json'; 'Authorization'=$retval.token_type + ' ' + $retval.access_token }
.EXAMPLE
    Connect-EntraVerifiedIDGraphDevicelogin -TenantId $TenantId -ClientID $clientId -Scope "0135fd85-3010-4e73-a038-12560d2b58a9/full_access"
.EXAMPLE
    Connect-EntraVerifiedIDGraphDevicelogin -TenantId $TenantId -ClientID $clientId -Scope "0135fd85-3010-4e73-a038-12560d2b58a9/full_access" -Edge -Incognito
#>
function Connect-EntraVerifiedIDGraphDevicelogin {
    [cmdletbinding()]
    param( 
        [Parameter(Mandatory=$True)][Alias('c')][string]$ClientId,
        [Parameter(Mandatory=$True)][Alias('t')][string]$TenantId,
        [Parameter()][Alias('s')][string]$Scope = "6a8b4b39-c021-437c-b060-5a14a3fd65f3/full_access",                
        [Parameter(DontShow)][int]$Timeout = 300, # Timeout in seconds to wait for user to complete sign in process
        # depending on in which browser you may already have a login session started, these switches might come in handy
        [Parameter(Mandatory=$false)][switch]$Chrome = $False,
        [Parameter(Mandatory=$false)][switch]$Edge = $False,
        [Parameter(Mandatory=$false)][switch]$Firefox = $False,
        [Parameter(Mandatory=$false)][switch]$Incognito = $True,
        [Parameter(Mandatory=$false)][switch]$NewWindow = $True
)

Function IIf($If, $Right, $Wrong) {If ($If) {$Right} Else {$Wrong}}

if ( !($Scope -imatch "offline_access") ) { $Scope += " offline_access"} # make sure we get a refresh token
$retVal = $null
$url = "https://microsoft.com/devicelogin"
$isMacOS = ($env:PATH -imatch "/usr/bin" )
$pgm = "chrome.exe"
$params = "--incognito --new-window"
if ( !$IsMacOS ) {
    $Browser = ""
    if ( $Chrome ) { $Browser = "Chrome" }
    if ( $Edge ) { $Browser = "Edge" }
    if ( $Firefox ) { $Browser = "Firefox" }
    if ( $browser -eq "") {
        $browser = (Get-ItemProperty HKCU:\Software\Microsoft\windows\Shell\Associations\UrlAssociations\http\UserChoice).ProgId
    }
    $browser = $browser.Replace("HTML", "").Replace("URL", "")
    switch( $browser.ToLower() ) {        
        "firefox" { 
            $pgm = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
            $params = (&{If($Incognito) {"-private "} Else {""}}) + (&{If($NewWindow) {"-new-window"} Else {""}})
        } 
        "chrome" { 
            $pgm = "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe"
            $params = (&{If($Incognito) {"--incognito "} Else {""}}) + (&{If($NewWindow) {"--new-window"} Else {""}})
        } 
        default { 
            $pgm = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
            $params = (&{If($Incognito) {"-InPrivate "} Else {""}}) + (&{If($NewWindow) {"-new-window"} Else {""}})
        } 
    }  
}

try {
    $DeviceCodeRequest = Invoke-RestMethod -Method "POST" -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
                                            -Body @{ client_id=$ClientId; scope=$scope; } -ContentType "application/x-www-form-urlencoded"
                                            # for endpoint != v2.0
                                            #-Body @{ client_id=$ClientId; resource="0135fd85-3010-4e73-a038-12560d2b58a9"; scope="full_access"; } -ContentType "application/x-www-form-urlencoded"
    #write-host $DeviceCodeRequest
    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow
    $url = $DeviceCodeRequest.verification_uri # url for endpoint != v2.0

    Set-Clipboard -Value $DeviceCodeRequest.user_code

    if ( $isMacOS ) {
        $ret = [System.Diagnostics.Process]::Start("/usr/bin/open","$url")
    } else {
        $ret = [System.Diagnostics.Process]::Start($pgm,"$params $url")
    }

    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($TokenRequest.access_token)) {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt $Timeout) {
            throw 'Login timed out, please try again.'
        }
        $TokenRequest = try {
            Invoke-RestMethod -Method "POST" -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                                -Body @{ grant_type="urn:ietf:params:oauth:grant-type:device_code"; code=$DeviceCodeRequest.device_code; client_id=$ClientId} `
                                -ErrorAction Stop
        }
        catch {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne "authorization_pending") {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    $retVal = $TokenRequest
}
finally {
    try {
        $TimeoutTimer.Stop()
    }
    catch {
        # We don't care about errors here
    }
}

$tenantMetadata = invoke-restmethod -Uri "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
$global:tenantRegionScope = $tenantMetadata.tenant_region_scope # WW, NA, EU, AF, AS, OC, SA

$global:tenantId = $tenantId
$global:tokens = $retval
$global:authHeader =@{ 'Content-Type'='application/json'; 'Authorization'=$retval.token_type + ' ' + $retval.access_token }
}

<#
.SYNOPSIS
    Refreshes the access token when needed.
.DESCRIPTION
    Refreshes the access token when needed. This function is called internally
.OUTPUTS
    Updates the global variables $global:tokens and $global:authHeader
.EXAMPLE
    Refresh-EntraVerifiedIDAccessToken
#>

function Refresh-EntraVerifiedIDAccessToken {
    $token = $global:tokens.access_token.Split(".")[1]
    if ( ($token.Length % 4) -gt 0 ) {
        $token = $token + "".PadRight( 4-($token.Length % 4), "=")
    }
    $tokenClaims = ([System.Text.Encoding]::ASCII.GetString( [System.Convert]::FromBase64String($token) ) | ConvertFrom-json)
    $exp = (get-date "1/1/1970").AddSeconds($tokenClaims.exp).ToLocalTime()    
    if ( ((get-date) -gt $exp) -and $global:tokens.refresh_token) {        
        $retval = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$($tokenClaims.tid)/oauth2/v2.0/token" `
                                -Body @{ grant_type="refresh_token"; client_id="$($tokenClaims.appid)"; refresh_token=$global:tokens.refresh_token; }
        $global:tokens = $retval
        $global:authHeader =@{ 'Content-Type'='application/json'; 'Authorization'=$retval.token_type + ' ' + $retval.access_token }
    }
}
################################################################################################################################################
# Helper functions
################################################################################################################################################
function Invoke-RestMethodWithRefresh( [string]$httpMethod, [string]$path, [string]$body, [string]$TenantRegion ) {
    if ( $path.StartsWith("/") ) {
        $url="https://verifiedid.did.msidentity.com$path"
    } else {
        #$url="https://verifiedid.did.msidentity.com/$($global:tenantID)/api/portable/v1.0/admin/$path"
        $url="https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/$path"
    }
    <#
    if ( !$TenantRegion ) { $TenantRegion = $global:tenantRegionScope }
    if ( $TenantRegion -eq "EU" ) {
        $url = $url.Replace("https://beta.did", "https://beta.eu.did")
    }
    #>
    write-verbose "$httpMethod $url"
    $needRefresh = $False
    do {
        $needRefresh = $False
        try {
            if ( $httpMethod -eq "GET" ) {
                $resp = Invoke-RestMethod -Method "GET" -Headers $global:authHeader -Uri $url -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $httpMethod -Uri $url -Headers $global:authHeader -Body $body -ContentType "application/json" -ErrorAction Stop
            }
        } catch {
            $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $streamReader.BaseStream.Position = 0
            $streamReader.DiscardBufferedData()
            $errResp = $streamReader.ReadToEnd()
            $streamReader.Close()    
            $needRefresh = $errResp -imatch "token_validation.expired"
            if ( $needRefresh ) {
                Refresh-EntraVerifiedIDAccessToken
            } else {
                write-host $errResp -ForegroundColor "Red" -BackgroundColor "Black"
            }
        }
    } while ($needRefresh)
    return $resp    
}
function Invoke-AdminAPIGet( [string]$path, [string]$TenantRegion ) {
    return Invoke-RestMethodWithRefresh "GET" $path $null $TenantRegion
}

function Invoke-AdminAPIUpdate( [string]$httpMethod, [string]$path, [string]$body, [string]$TenantRegion ) {
    return Invoke-RestMethodWithRefresh $httpMethod $path $body $TenantRegion
}

################################################################################################################################################
# Admin API
################################################################################################################################################
#-----------------------------------------------------------------------------------------------------------------------------------------------
# Onboard tenant & Out-out
#-----------------------------------------------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
    Onboards the Azure AD tenant to Verifiable Credentials
.DESCRIPTION
    Onboards the Azure AD tenant to Verifiable Credentials
.EXAMPLE
    Enable-EntraVerifiedIDTenant
#>
function Enable-EntraVerifiedIDTenant() {
    return Invoke-AdminAPIUpdate "POST"  "onboard" ""
}

<#
.SYNOPSIS
    Opts-out Verifiable Credentials for the Azure AD tenant
.DESCRIPTION
    Opts-out Verifiable Credentials for the Azure AD tenant, destroying all authorities, cedential contracts and issued credentials
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
    return Invoke-AdminAPIUpdate "POST"  "optout" ""
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
                                        [Parameter(Mandatory=$True)][string]$KeyVaultResourceID 
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
    "issuerName":"$nName",
    "linkedDomainUrl":"$Domain",
    "keyVaultUrl":"$kvUrl",
    "keyVaultMetadata":
    {
        "subscriptionId":"$subscriptionId",
        "resourceGroup":"$resourceGroup",
        "resourceName":"$kvName",
        "resourceUrl": "$kvUrl"
    }
}
"@
    return Invoke-AdminAPIUpdate "POST"  "authorities" $body 
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
function Update-EntraVerifiedIDAuthority( [Parameter(Mandatory=$True)][string]$Id, [Parameter(Mandatory=$True)][string]$Name ) {
    $body = @"
{
    "name":"$Name"
}
"@
    return Invoke-AdminAPIUpdate "POST" "authorities/$id" $body 
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
    Rotate-EntraVerifiedIDAuthoritySigningKey -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Rotate-EntraVerifiedIDAuthoritySigningKey( [Parameter(Mandatory=$True)][string]$Id ) {
    return Invoke-AdminAPIUpdate "POST" "authorities/$id/rotateSigningKey" 
}

<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Issuer instance. The domain names where originally set in the New-EntraVerifiedIDIssuer command
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-EntraVerifiedIDAuthorities command
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
        $authorities = Get-EntraVerifiedIDAuthorities
        $Id = $authorities[0].id
    }    
    $body = @"
{
    "domainUrls" : $($domains | ConvertTo-Json)
}
"@    
    return Invoke-AdminAPIUpdate "POST"  "authorities/$Id/updateLinkedDomains" $body
}
<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Authority instance. The domain names where originally set in the New-EntraVerifiedIDAuthority command
.PARAMETER IssuerId
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthorities command
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
        $authorities = Get-EntraVerifiedIDAuthorities
        $Id = $authorities[0].id
    }    
    $body = @"
{
    "domainUrl": "$Domain"
}
"@    
    return Invoke-AdminAPIUpdate "POST"  "authorities/$Id/generateWellknownDidConfiguration" $body
}
<#
.SYNOPSIS
    Gets all or a named Authorities
.DESCRIPTION
    Gets all or a named Authorities from the Entra Verified ID configuration
.PARAMETER Name
    Name or the Authority. If not specified, all Authorities will be returned
.OUTPUTS
    Returns one or all Authorities objects
.EXAMPLE
    Get-EntraVerifiedIDAuthorities
.EXAMPLE
    Get-EntraVerifiedIDAuthorities -Name "Contoso"
#>
function Get-EntraVerifiedIDAuthorities( [Parameter(Mandatory=$False)][string]$Name ) {
    $authorities = Invoke-AdminAPIGet "authorities" 
    if ( !$Name ) {
        return $authorities.value
    }
    return ($issuers.value | where {$_.name -eq $Name } )
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
    Get-EntraVerifiedIDAuthorities -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Get-EntraVerifiedIDAuthority( [Parameter(Mandatory=$True)][string]$Id ) {
    $authorities = Invoke-AdminAPIGet "authorities/$id" 
    return $authorities
}
function Get-EntraVerifiedIDDidDocument( [Parameter(Mandatory=$True)][string]$Id ) {
    return Invoke-AdminAPIUpdate "POST" "authorities/$id/generateDidDocument" 
}

<#
.SYNOPSIS
    Get Linked Domains did-configuration json metadata for an Authority
.DESCRIPTION
    Get Linked Domains did-configuration json metadata for an Authority.
    If -Raw switch is not passed, the decoded values to pay attention to are:
    - type == DomainLinkageCredential
    - credentialSubject.id == did for the Authority. Matches (Get-EntraVerifiedIDAuthorities -Name "Contoso").didModel.did
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
    $authorities = Get-EntraVerifiedIDAuthorities -Name $Name
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
    Gets all or a named Credential contract
.DESCRIPTION
    Gets all or a named Credential contract from the Entra Verified ID configuration
.PARAMETER AuthorityId
    Id of the Authority. 
.PARAMETER Name
    Name or the Credential contract. If not specified, all contracts will be returned
.OUTPUTS
    Returns one or all Credential contract objects
.EXAMPLE
    Get-EntraVerifiedIDContracts
.EXAMPLE
    Get-EntraVerifiedIDContracts -Name "ContosoEmployee"
#>
function Get-EntraVerifiedIDContracts( [Parameter(Mandatory=$True)][string]$AuthorityId,
                                       [Parameter(Mandatory=$False)][string]$Name
                                     ) {
    $contracts = Invoke-AdminAPIGet "authorities/$AuthorityId/contracts"
    if ( $Name.Length -gt 0 ) {
        return ($contracts.value | where {$_.name -eq $Name } )
    }
    return $contracts.value    
}
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
    Get-EntraVerifiedIDContract -Id "OTg4NTQ1N2EtMjAy...lhbHRlc3Qx"
#>
function Get-EntraVerifiedIDContract( [Parameter(Mandatory=$False)][string]$AuthorityId,
                                      [Parameter(Mandatory=$True)][string]$Id
                                    ) {
    return Invoke-AdminAPIGet "authorities/$AuthorityId/contracts/$Id"
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
                                      [Parameter(Mandatory=$False)][boolean]$AvailableInVcDirectory = $False,
                                      [Parameter(Mandatory=$False)][array]$issueNotificationAllowedToGroupOids = @()
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
    "issueNotificationAllowedToGroupOids": $groupOids,
    "availableInVcDirectory": $($availableInVcDirectory.ToString().ToLower()),
    "displays": [ $Displays ],
    "rules": $Rules
}
"@

    if ( !$AuthorityId ) {
        $authorities = Get-EntraVerifiedIDAuthorities
        $AuthorityId = $authorities[0].id
    }        
    return Invoke-AdminAPIUpdate "POST" "authorities/$AuthorityId/contracts" $body 
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
function Update-EntraVerifiedIDContract( [Parameter(Mandatory=$True)][string]$AuthorityId,
                                         [Parameter(Mandatory=$True)][string]$Id,
                                         [Parameter(Mandatory=$True)]$Body
                                       ) {
    return Invoke-AdminAPIUpdate "PATCH" "authorities/$AuthorityId/contracts/$Id" $Body
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
    Id of the Credential contract. Can be retrieved by the Get-EntraVerifiedIDContracts command
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
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ContractId + $ClaimValue))   
    $hashedsearchclaimvalue = [System.Web.HttpUtility]::UrlEncode( [Convert]::ToBase64String($hash) )
    return Invoke-AdminAPIGet "authorities/$AuthorityId/contracts/$contractid/credentials?filter=indexclaim eq $hashedsearchclaimvalue"
}
<#
.SYNOPSIS
    Revokes an issued credentials
.DESCRIPTION
    Revokes an issued credentials based on its id. This operation is irreversable
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-EntraVerifiedIDAuthorities command
.PARAMETER ContractId
    Id of the Credential contract. Can be retrieved by the Get-EntraVerifiedIDContracts command
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
        $issuers = Get-EntraVerifiedIDAuthorities
        $AuthorityId = $issuers[0].id
    }    
    return Invoke-AdminAPIUpdate "POST" "authorities/$AuthorityId/contracts/$ContractId/credentials/$CredentialId/revoke" ""
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
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthorities command
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
    $contract = Get-EntraVerifiedIDContracts -AuthorityId $AuthorityId -Name $Name
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
    Id of the Authority. If omitted, the first authority will be used via the Get-EntraVerifiedIDAuthorities command
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
function Get-EntraVerifiedIDDidExplorer( [Parameter(Mandatory=$False)][string]$Name, [Parameter(Mandatory=$False)][string]$did ) {
    if ( $Name ) {
        $issuer = Get-EntraVerifiedIDAuthorities -Name $Name
        $did = $issuer.didModel.did
    }
    if ( $did ) {
        $url = "https://beta.discover.did.microsoft.com/1.0/identifiers/$did"
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
function Get-EntraVerifiedIDNetworkIssuers( [Parameter(Mandatory=$false)][string]$DomainSearch,
                                            [Parameter(Mandatory=$False)][string]$TenantRegion 
                                          ) {
    if ( !$DomainSearch ) { $DomainSearch = "%20" }
    $resp = Invoke-AdminAPIGet "/v1.0/verifiableCredentialsNetwork/authorities?filter=linkeddomainurls like $DomainSearch" $TenantRegion
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
                                            , [Parameter(Mandatory=$True)][string]$AuthorityId
                                            , [Parameter(Mandatory=$False)][string]$TenantRegion ) {
    $resp = Invoke-AdminAPIGet "/v1.0/tenants/$tenantId/verifiableCredentialsNetwork/authorities/$AuthorityId/contracts" $TenantRegion
    return  $resp.value
}
