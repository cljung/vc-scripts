$AdminAPIScriptVersion = "2022-05-31"
<#
This file contains a Powershell module for the Azure AD Verifiable Credentials Admin API
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
    Connect-AzADVCGraphDevicelogin -TenantId $TenantId -ClientID $clientId -Scope "0135fd85-3010-4e73-a038-12560d2b58a9/full_access"
.EXAMPLE
    Connect-AzADVCGraphDevicelogin -TenantId $TenantId -ClientID $clientId -Scope "0135fd85-3010-4e73-a038-12560d2b58a9/full_access" -Edge -Incognito
#>
function Connect-AzADVCGraphDevicelogin {
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
    Refresh-AzADVCAccessToken
#>

function Refresh-AzADVCAccessToken {
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
        $url="https://beta.did.msidentity.com$path"
    } else {
        $url="https://beta.did.msidentity.com/$($global:tenantID)/api/portable/v1.0/admin/$path"
    }
    if ( !$TenantRegion ) { $TenantRegion = $global:tenantRegionScope }
    if ( $TenantRegion -eq "EU" ) {
        $url = $url.Replace("https://beta.did", "https://beta.eu.did")
    }
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
                Refresh-AzADVCAccessToken
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
    Enable-AzADVCTenant
#>
function Enable-AzADVCTenant() {
    return Invoke-AdminAPIUpdate "POST"  "onboard" ""
}

<#
.SYNOPSIS
    Gets the status if Azure AD tenant is enabled for Verifiable Credentials
.DESCRIPTION
    Gets the status if Azure AD tenant is enabled for Verifiable Credentials.
.EXAMPLE
    Get-AzADVCTenantStatus
.EXAMPLE
    $ret = Get-AzADVCTenantStatus
    if ( $ret.status -eq "Enabled" ) {
        Get-AzADServicePrincipal -Id $ret.servicePrincipal
    }
#>
function Get-AzADVCTenantStatus() {
    return Invoke-AdminAPIGet "tenants"
}
<#
.SYNOPSIS
    Opts-out Verifiable Credentials for the Azure AD tenant
.DESCRIPTION
    Opts-out Verifiable Credentials for the Azure AD tenant, destroying all issuers, cedential contracts and issued credentials
.PARAMETER Force
    If to not get the 'are you sure?' question
.EXAMPLE
    Remove-AzADVCTenantOptOut
.EXAMPLE
    Remove-AzADVCTenantOptOut -Force
#>
function Remove-AzADVCTenantOptOut( [Parameter(Mandatory=$false)][switch]$Force = $False ) {
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
    Creates a new Verifiable Credential Issuer in the Azure AD tenant
.DESCRIPTION
    Creates a new Verifiable Credential Issuer in the Azure AD tenant, with it's unique DID
.PARAMETER OrganizationName
    Name of your issuer organization, like Contoso, Fabrikam or Woodgrove
.PARAMETER Domain
    Domain of your issuer, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.PARAMETER KeyVaultResourceID
    The Azure ResourceID of the Azure KeyVault instance to be used for signin and encryption keys
.EXAMPLE
    New-AzADVCIssuer -OrganizationName "Contoso" -Domain "https://contoso.com" -KeyVaultResourceID $KeyVaultResourceID 
#>
function New-AzADVCIssuer(  [Parameter(Mandatory=$True)][string]$OrganizationName, 
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
    "issuerName":"$OrganizationName",
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
    return Invoke-AdminAPIUpdate "POST"  "issuers" $body 
}
<#
.SYNOPSIS
    Updates an Issuer
.DESCRIPTION
    Updates and Issuer. Currently, you can only modify what is called 'Organization' in the portal, ie, the name
.PARAMETER Id
    Id of the Issuer. 
.OUTPUTS
    Returns the updated Issuer object
.EXAMPLE
    Update-AzADVCIssuer -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6" -Name "MyNewName"
#>
function Update-AzADVCIssuer( [Parameter(Mandatory=$True)][string]$Id, [Parameter(Mandatory=$True)][string]$OrganizationName ) {
    $issuer = Invoke-AdminAPIGet "issuers/$id" 
    if ( !$issuer ) {
        return $null
    }
    $body = @"
{
    "issuerName":"$OrganizationName"
}
"@
    return Invoke-AdminAPIUpdate "PUT" "issuers/$id" $body 
}
<#
.SYNOPSIS
    Rotate the Issuers signing keys
.DESCRIPTION
    Rotate the Issuers signing key, which means rotate in Azure Key Vault and update the Issuer object.
    You manually have to generate the new did document and publish it if the Issuer is using the did:web method
.PARAMETER Id
    Id of the Issuer. 
.OUTPUTS
    Does not return any data
.EXAMPLE
    Rotate-AzADVCIssuerSigningKey -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Rotate-AzADVCIssuerSigningKey( [Parameter(Mandatory=$True)][string]$Id ) {
    return Invoke-AdminAPIUpdate "POST" "issuers/$id/rotateSigningKey" 
}

<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Issuer instance. The domain names where originally set in the New-AzADVCIssuer command
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Domains
    String array of domains, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.EXAMPLE
    Set-AzADVCLinkedDomains -Domains @( "https://contoso.com/", "https://vc.fabrikam.com/" )
.EXAMPLE
    Set-AzADVCLinkedDomains -IssuerId $issuerId -Domains @( "https://contoso.com/", "https://vc.fabrikam.com/" )
#>
function Set-AzADVCLinkedDomains( [Parameter(Mandatory=$False)][string]$IssuerId, [Parameter(Mandatory=$True)][string[]]$Domains ) {
    if ( !$IssuerId ) {
        $issuers = Get-AzADVCIssuers
        $IssuerId = $issuers[0].id
    }    
    $body = @"
{
    "domains" : $($domains | ConvertTo-Json)
}
"@    
    return Invoke-AdminAPIUpdate "POST"  "issuers/$IssuerId/update-linked-domains" $body
}
<#
.SYNOPSIS
    Updates the domain name(s)
.DESCRIPTION
    Update the domain name(s) that is the verified domain for the Issuer instance. The domain names where originally set in the New-AzADVCIssuer command
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Domain
    Domain, like https://contoso.com/, https://vc.fabrikam.com/ or https://did.woodgrove.com/
.OUTPUTS
    Returns the content that should be put in the <domain>/.well-known/did-configuration.json file to verify the linked domain
.EXAMPLE
    New-AzADVCWellKnownDidConfiguration -Domain "https://contoso.com/"
.EXAMPLE
    New-AzADVCWellKnownDidConfiguration -IssuerId $issuerId -Domain "https://vc.fabrikam.com/"
#>
function New-AzADVCWellKnownDidConfiguration( [Parameter(Mandatory=$False)][string]$IssuerId, [Parameter(Mandatory=$True)][string]$Domain ) {
    if ( !$IssuerId ) {
        $issuers = Get-AzADVCIssuers
        $IssuerId = $issuers[0].id
    }    
    $body = @"
{
    "domainUrl":"$Domain"
}
"@    
    return Invoke-AdminAPIUpdate "POST"  "issuers/$IssuerId/well-known-did-configuration" $body
}
<#
.SYNOPSIS
    Gets all or a named Issuer
.DESCRIPTION
    Gets all or a named Issuer from the Azure AD Verifiable Credentials configuration
.PARAMETER Name
    Name or the Issuer. If not specified, all Issuers will be returned
.OUTPUTS
    Returns one or all Issuer objects
.EXAMPLE
    Get-AzADVCIssuers
.EXAMPLE
    Get-AzADVCIssuers -Name "Contoso"
#>
function Get-AzADVCIssuers( [Parameter(Mandatory=$False)][string]$Name ) {
    $issuers = Invoke-AdminAPIGet "issuers" 
    if ( !$Name ) {
        return $issuers
    }
    return ($issuers | where {$_.issuerName -eq $Name } )
}
<#
.SYNOPSIS
    Gets Issuer by Id
.DESCRIPTION
    Gets Issuer by Id
.PARAMETER Id
    Id of the issuer
.OUTPUTS
    Returns the Issuer object
.EXAMPLE
    Get-AzADVCIssuers -Id "8d3f8247-535f-412d-81d7-3d4d77074ab6"
#>
function Get-AzADVCIssuer( [Parameter(Mandatory=$True)][string]$Id ) {
    $issuer = Invoke-AdminAPIGet "issuers/$id" 
    return $issuer
}
function Get-AzADVCDidDocument( [Parameter(Mandatory=$True)][string]$Id ) {
    return Invoke-AdminAPIUpdate "POST" "issuers/$id/generateDidDocument" 
}

<#
.SYNOPSIS
    Get Linked Domains did-configuration json metadata for an Issuer
.DESCRIPTION
    Get Linked Domains did-configuration json metadata for an Issuer.
    If -Raw switch is not passed, the decoded values to pay attention to are:
    - type == DomainLinkageCredential
    - credentialSubject.id == did for the Issuer. Matches (Get-AzADVCIssuers -Name "Contoso").didModel.did
    - credentialSubject.origin == matches the linked domain name
.PARAMETER Name
    Name or the Issuer. If not specified, all Issuers will be returned
.PARAMETER Raw
    Switch if to return the raw did-configuration or if to decode the JWT token
.OUTPUTS
    Returns one or all did-configuration metadata, decoded or raw
.EXAMPLE
    Get-AzADVCIssuerLinkedDomainDidConfiguration -Name "Contoso"
.EXAMPLE
    Get-AzADVCIssuerLinkedDomainDidConfiguration -Name "Contoso" -Raw
#>
function Get-AzADVCIssuerLinkedDomainDidConfiguration( [Parameter(Mandatory=$True)][string]$Name,
                                                       [Parameter(Mandatory=$false)][switch]$Raw = $False )
{
    $issuer = Get-AzADVCIssuers -Name $Name
    $didcfgs = @()
    foreach( $domain in $issuer.didModel.linkedDomainUrls ) {
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
    Gets all or a named Credential contract from the Azure AD Verifiable Credentials configuration
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Name
    Name or the Credential contract. If not specified, all Issuers will be returned
.OUTPUTS
    Returns one or all Credential contract objects
.EXAMPLE
    Get-AzADVCContracts
.EXAMPLE
    Get-AzADVCContracts -Name "ContosoEmployee"
#>
function Get-AzADVCContracts([Parameter(Mandatory=$False)][string]$IssuerId,
                             [Parameter(Mandatory=$False)][string]$Name
                             )
{
    $contracts = Invoke-AdminAPIGet "contracts"
    if ( $Name.Length -gt 0 ) {
        return ($contracts | where {$_.contractName -eq $Name } )
    }
    if ( $IssuerId.Length -gt 0 ) {
        return ($contracts | where {$_.issuerId -eq $IssuerId } )    
    }
    return $contracts    
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
    Get-AzADVCContract -Id "OTg4NTQ1N2EtMjAy...lhbHRlc3Qx"
#>
function Get-AzADVCContract([Parameter(Mandatory=$True)][string]$Id
                             )
{
    return Invoke-AdminAPIGet "contracts/$Id"
}
<#
.SYNOPSIS
    Updates a Credential contract by id
.DESCRIPTION
    Updates a Credential contract by id
.PARAMETER Id
    Id of the contract
.PARAMETER Body
    JSON payload of the contract
.OUTPUTS
    Returns the contract objects
.EXAMPLE
    Update-AzADVCContract -Id "OTg4NTQ1N2EtMjAy...lhbHRlc3Qx" -Body $jsonPayload
#>
function Update-AzADVCContract([Parameter(Mandatory=$True)][string]$Id,
                                [Parameter(Mandatory=$True)]$Body
                             )
{
    return Invoke-AdminAPIUpdate "PUT" "contracts/$Id" $Body
}

<#
.SYNOPSIS
    Gets all or a named Credential contract
.DESCRIPTION
    Gets all or a named Credential contract from the Azure AD Verifiable Credentials configuration
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Name
    Name or the Credential contract. If not specified, all Issuers will be returned
.PARAMETER StorageResourceID
    StorageResourceID for where the Display and the Rules files will be stored
.PARAMETER StorageContainerName
    Storage container name for where the Display and the Rules files will be stored
.PARAMETER RulesFileName
    The filename of the Rules file as it is named in the storage container
.PARAMETER DisplayFileName
    The filename of the Display file as it is named in the storage container
.OUTPUTS
    Returns the newly created Credential contract object
.EXAMPLE
    New-AzADVCContract -Name "ContosoEmployee" -StorageResourceID $StorageResourceID -RulesFileName "contosofterules.json" -DisplayFileName "contosoftedisplay.json"
.EXAMPLE
    New-AzADVCContract -IssuerId $issuerId -Name "ContosoEmployee" -StorageResourceID $StorageResourceID -RulesFileName "contosofterules.json" -DisplayFileName "contosoftedisplay.json"
#>
function New-AzADVCContract([Parameter(Mandatory=$False)][string]$IssuerId,
                            [Parameter(Mandatory=$True)][string]$Name, 
                            [Parameter(Mandatory=$False)][string]$StorageResourceID,
                            [Parameter(Mandatory=$False)][string]$StorageContainerName, 
                            [Parameter(Mandatory=$False)][string]$RulesFileName, 
                            [Parameter(Mandatory=$False)][string]$DisplayFileName,
                            [Parameter(Mandatory=$False)][string]$Rules, 
                            [Parameter(Mandatory=$False)][string]$Displays,
                            [Parameter(Mandatory=$False)][boolean]$AvailableInVcDirectory = $False,
                            [Parameter(Mandatory=$False)][array]$issueNotificationAllowedToGroupOids = @()
                        )
{
    $body = $null

    # we must either have (Rules + Display) or (Storage* + RulesFileName + DisplayFileName)

    if ( $StorageResourceID -and $StorageContainerName -and $RulesFileName -and $DisplayFileName ) {
        $stgparts=$StorageResourceID.Split("/")
        if ( $stgparts.Count -ne 9 ) {
            write-error "Invalid Storage ResourceID"
            return
        }
        $RulesFileName = Split-Path $RulesFileName -leaf
        $DisplayFileName = Split-Path $DisplayFileName -leaf
        $subscriptionId=$stgparts[2]
        $resourceGroup=$stgparts[4]
        $stgName=$stgparts[8]
        $stgPath="https://$stgName.blob.core.windows.net/$StorageContainerName"
        $body = @"
{
    "contractName": "$Name",
    "rulesFile": "$stgPath/$RulesFileName",
    "displayFile": "$stgPath/$DisplayFileName",
    "rulesFileContainerMetadata": {
        "subscriptionId": "$subscriptionId",
        "resourceGroup": "$resourceGroup",
        "resourceName": "$stgName",
        "container": "$StorageContainerName",
        "resourceUrl": "$stgPath/$RulesFileName"
    },
    "displayFileContainerMetadata": {
        "subscriptionId": "$subscriptionId",
        "resourceGroup": "$resourceGroup",
        "resourceName": "$stgName",
        "container": "$StorageContainerName",
        "resourceUrl": "$stgPath/$DisplayFileName"
    }
}
"@
    }

    if ( $Rules -and $Displays ) {
        $groupOids = "[]"
        $issueNotificationEnabled = $False
        if ( $issueNotificationAllowedToGroupOids.Length -gt 0 ) {
            $issueNotificationEnabled = $True
            $groupOids = ($issueNotificationAllowedToGroupOids | ConvertTo-json -Compress )
        }
        $body = @"
{
    "contractName": "$Name",
    "tenantId": "$($global:tenantId)",
    "status":  "Enabled",
    "issueNotificationEnabled": $($issueNotificationEnabled.ToString().ToLower()),
    "issueNotificationAllowedToGroupOids": $groupOids,
    "availableInVcDirectory": $($availableInVcDirectory.ToString().ToLower()),
    "rules": $Rules,
    "displays": $Displays
}
"@
    }

    if ( $null -eq $body ) {
        write-error "Wrong parameter combination. Specify either Rules+Displays or Storage+Files"
        return
    }

    if ( !$IssuerId ) {
        $issuers = Get-AzADVCIssuers
        $IssuerId = $issuers[0].id
    }        
    return Invoke-AdminAPIUpdate "POST" "issuers/$IssuerId/contracts" $body 
}
<#
.SYNOPSIS
    Uploads a local file to an Azure Storage blob
.DESCRIPTION
    Uploads a local file to an Azure Storage blob
.PARAMETER LocalFile
    Full path to the local file. The filename.ext will be used as the blob name
.PARAMETER StorageAccountName
    Name or the Credential contract. If not specified, all Issuers will be returned
.PARAMETER ContainerPath
    Name of the container and possibly an additional path, like "containername" or "containername/path2" 
.PARAMETER AccessKey
    The access key to the Azure Storage Account
.EXAMPLE
    Import-AzADVCFileToStorage -LocalFile "C:\mydir\myrulesfile.json" -StorageAccountName "mystgaccount" -ContainerPath "vccontracts" -AccessKey $key
#>
function Import-AzADVCFileToStorage (
    [Parameter(Mandatory=$true)][string]$LocalFile,
    [Parameter(Mandatory=$true)][string]$StorageAccountName,
    [Parameter(Mandatory=$true)][string]$ContainerPath,
    [Parameter(Mandatory=$true)][string]$AccessKey
    )
{
    $body = (Get-Content $LocalFile)
    $FileName = Split-Path $LocalFile -leaf
    $Url = "https://$StorageAccountName.blob.core.windows.net/$ContainerPath/$Filename"
    $uri = New-Object System.Uri -ArgumentList $url
    $bytes = ([System.Text.Encoding]::UTF8.GetBytes($body))
    $contentLength = $bytes.length
    $headers = @{"x-ms-version"="2014-02-14"}
    $headers.Add("x-ms-date", $(([DateTime]::UtcNow.ToString('r')).ToString()) )
    $headers.Add("Content-Length","$contentLength")
    $headers.Add("x-ms-blob-type","BlockBlob")
    $signatureString = "PUT`n`n`n$contentLength`n`n`n`n`n`n`n`n`n"
    $signatureString += "x-ms-blob-type:$($headers["x-ms-blob-type"])`nx-ms-date:$($headers["x-ms-date"])`nx-ms-version:$($headers["x-ms-version"])`n/$StorageAccountName$($uri.AbsolutePath)"
    $dataToMac = [System.Text.Encoding]::UTF8.GetBytes($signatureString)
    $accountKeyBytes = [System.Convert]::FromBase64String($AccessKey)
    $hmac = new-object System.Security.Cryptography.HMACSHA256((,$accountKeyBytes))
    $signature = [System.Convert]::ToBase64String($hmac.ComputeHash($dataToMac))
    $headers.Add("Authorization", "SharedKey " + $StorageAccountName + ":" + $signature);

    write-host "PUT $LocalFile ==> $Url`r`n$contentLength byte(s)"
    $resp = Invoke-RestMethod -Uri $Url -Method "PUT" -headers $headers -Body $body
    $resp
}
<#
.SYNOPSIS
    Downloads an Azure Storage blob file 
.DESCRIPTION
    Downloads an Azure Storage blob file
.PARAMETER ResourceUrl
    THe url to the Azure Storage blob file
.PARAMETER AccessKey
    The access key to the Azure Storage Account
.EXAMPLE
    Get-AzADVCFileFromStorage -ResourceUrl "https://myaccount.blob.core.windows.net/didstg/displayfile.json" -AccessKey $key
#>
function Get-AzADVCFileFromStorage (
    [Parameter(Mandatory=$true)][string]$ResourceUrl,
    [Parameter(Mandatory=$true)][string]$AccessKey
    )
{
    $uri = New-Object System.Uri -ArgumentList $resourceUrl
    $StorageAccountName = $resourceUrl.Split("/")[2].Split(".")[0]
    $headers = @{"x-ms-version"="2014-02-14"}
    $headers.Add("x-ms-date", $(([DateTime]::UtcNow.ToString('r')).ToString()) )
    $signatureString = "GET`n`n`n`n`n`n`n`n`n`n`n`n"
    $signatureString += "x-ms-date:$($headers["x-ms-date"])`nx-ms-version:$($headers["x-ms-version"])`n/$StorageAccountName$($uri.AbsolutePath)"
    $dataToMac = [System.Text.Encoding]::UTF8.GetBytes($signatureString)
    $hmac = new-object System.Security.Cryptography.HMACSHA256((,[System.Convert]::FromBase64String($AccessKey)))
    $signature = [System.Convert]::ToBase64String($hmac.ComputeHash($dataToMac))   
    $headers.Add("Authorization", "SharedKey " + $StorageAccountName + ":" + $signature);
    return Invoke-RestMethod -Uri $ResourceUrl -Method "GET" -headers $headers
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
    Id of the Credential contract. Can be retrieved by the Get-AzADVCContracts command
.PARAMETER ClaimValue
    Value of the indexed claim
.OUTPUTS
    Returns all issued credentials that matches the indexed claim value
.EXAMPLE
    Get-AzADVCCredential -ContractId $contractId -ClaimValue "alice@contoso.com"
#>
function Get-AzADVCCredential(
    [Parameter(Mandatory=$true)][string]$ContractId,    
    [Parameter(Mandatory=$true)][string]$ClaimValue
) 
{
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ContractId + $ClaimValue))   
    $hashedsearchclaimvalue = [System.Web.HttpUtility]::UrlEncode( [Convert]::ToBase64String($hash) )
    return Invoke-AdminAPIGet "contracts/$contractid/cards?filter=indexclaim eq $hashedsearchclaimvalue"
}
<#
.SYNOPSIS
    Revokes an issued credentials
.DESCRIPTION
    Revokes an issued credentials based on its id. This operation is irreversable
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER ContractId
    Id of the Credential contract. Can be retrieved by the Get-AzADVCContracts command
.PARAMETER CardId
    Id of the issued credential
.PARAMETER Force
    If to not get the 'are you sure?' question
.EXAMPLE
    Revoke-AzADVCCredential -IssuerId $issuerId -ContractId $contractId -CardId $cardId
.EXAMPLE
    Revoke-AzADVCCredential -IssuerId $issuerId -ContractId $contractId -CardId $cardId -Force
#>
function Revoke-AzADVCCredential(
    [Parameter(Mandatory=$false)][string]$IssuerId,    
    [Parameter(Mandatory=$true)][string]$ContractId,    
    [Parameter(Mandatory=$true)][string]$CardId,
    [Parameter(Mandatory=$false)][switch]$Force = $False
) 
{
    if (!$Force ) {
        $answer = (Read-Host "Are you sure you want to Revoke the Credential $CardId? [Y]es or [N]o").ToLower()
        if ( !("yes","y" -contains $answer) ) {
            return
        }
    }
    if ( !$IssuerId ) {
        $issuers = Get-AzADVCIssuers
        $IssuerId = $issuers[0].id
    }    
    return Invoke-AdminAPIUpdate "POST" "issuers/$IssuerId/contracts/$ContractId/cards/$CardId/revoke" ""
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
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Name
    Name or the Credential contract. If not specified, all Issuers will be returned
.OUTPUTS
    Returns one or all Credential contract objects
.EXAMPLE
    Get-AzADVCContractManifestURL -Name "ContosoEmployee"
.EXAMPLE
    Get-AzADVCContractManifestURL -Name "ContosoEmployee" -IssuerId $issuer.id
#>
function Get-AzADVCContractManifestURL([Parameter(Mandatory=$False)][string]$IssuerId,
                                       [Parameter(Mandatory=$True)][string]$Name
                                      )
{
    $contracts = Invoke-AdminAPIGet "contracts"
    $contract = ($contracts | where {$_.contractName -eq $Name } )
    if ( !$contract ) {
        return $null
    }
    $url = "https://beta.did.msidentity.com/v1.0/$($contract.tenantId)/verifiableCredential/contracts/$($contract.contractName)"
    if ( $global:tenantRegionScope -eq "EU" ) {
        $url = $url.Replace("https://beta.did", "https://beta.eu.did")
    }
    return $url
}
<#
.SYNOPSIS
    Gets a Credential Contract's manifest
.DESCRIPTION
    Gets a Credential Contract's manifest either signed as a JWT token or unsigned json data
.PARAMETER IssuerId
    Id of the issuer. If omitted, the first issuer will be used via the Get-AzADVCIssuers command
.PARAMETER Name
    Name or the Credential contract. If not specified, all Issuers will be returned
.PARAMETER Signed
    If to sign the manifest and return a JWT Token. This is what the Microsoft Authenticator does
    and it is also a test to see that your Azure KeyVault is set up correctly.
.OUTPUTS
    Returns the manifest as an unsigned json data structure or a signed JWT token
.EXAMPLE
    Get-AzADVCContractManifest -Name "ContosoEmployee"
.EXAMPLE
    Get-AzADVCContractManifest -Name "ContosoEmployee" -IssuerId $issuer.id -Signed
#>
function Get-AzADVCContractManifest([Parameter(Mandatory=$False)][string]$IssuerId,
                                    [Parameter(Mandatory=$True)][string]$Name,
                                    [Parameter(Mandatory=$false)][switch]$Signed = $False
                                    )
{
    $contracts = Invoke-AdminAPIGet "contracts"
    $contract = ($contracts | where {$_.contractName -eq $Name } )
    if ( !$contract ) {
        return $null
    }
    $url = "https://beta.did.msidentity.com/v1.0/$($contract.tenantId)/verifiableCredential/contracts/$($contract.contractName)"
    if ( $global:tenantRegionScope -eq "EU" ) {
        $url = $url.Replace("https://beta.did", "https://beta.eu.did")
    }
    write-verbose "GET $url"
    if ( $Signed ) {
        return invoke-restmethod -Method "GET" -Uri $url -Headers @{ 'x-ms-sign-contract'='true'; }
    } else {
        return invoke-restmethod -Method "GET" -Uri $url
    }
}
################################################################################################################################################
# Discovery API
################################################################################################################################################
<#
.SYNOPSIS
    Gets all or a named Issuer
.DESCRIPTION
    Gets all or a named Issuer from the Azure AD Verifiable Credentials configuration
.PARAMETER Name
    Name or the Issuer. If not specified, all Issuers will be returned
.OUTPUTS
    Returns one or all Issuer objects
.EXAMPLE
    Get-AzADVCDidExplorer
.EXAMPLE
    Get-AzADVCDidExplorer -Name "Contoso"
#>
function Get-AzADVCDidExplorer( [Parameter(Mandatory=$False)][string]$Name, [Parameter(Mandatory=$False)][string]$did ) {
    if ( $Name ) {
        $issuers = Invoke-AdminAPIGet "issuers" 
        $issuer = ($issuers | where {$_.issuerName -eq $Name } )
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
    Get-AzADVCDirectoryIssuers
#>
function Get-AzADVCDirectoryIssuers( [Parameter(Mandatory=$false)][string]$DomainSearch
                                    , [Parameter(Mandatory=$False)][string]$TenantRegion ) {
    if ( !$DomainSearch ) { $DomainSearch = "%20" }
    return Invoke-AdminAPIGet "/v1.0/vcDirectory/issuers?filter=linkeddomainurls like $DomainSearch" $TenantRegion
}
<#
.SYNOPSIS
    Gets all contracts for an Issuers in the VC Directory
.DESCRIPTION
    Gets all contracts for an Issuers in the VC Directory
.PARAMETER TenantId
    Id of the tenant in the VC Directory. This is the normal Azure AD tenant id
.PARAMETER IssuerId
    Id of the Issuer in that tenant. You can retrieve this from Get-AzADVCDirectoryIssuers command
.PARAMETER TenantRegion
    If you want to query a different region than your default region
.OUTPUTS
    Returns one or all contracts objects
.EXAMPLE
    Get-AzADVCDirectoryIssuerContracts
#>
function Get-AzADVCDirectoryIssuerContracts( [Parameter(Mandatory=$True)][string]$TenantId
                                            , [Parameter(Mandatory=$True)][string]$IssuerId
                                            , [Parameter(Mandatory=$False)][string]$TenantRegion ) {
    return Invoke-AdminAPIGet "/v1.0/vcDirectory/$TenantId/issuers/$IssuerId/contracts" $TenantRegion
}
