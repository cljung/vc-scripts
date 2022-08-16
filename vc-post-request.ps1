<#
This script makes a request to the VC Request Service API and creates the file qrcode.html 
that the vc-mini-webserver.ps1 can display so you can scan the QR code

./vc-post-request.ps1 -DID "did:ion:EiDR..." `
  -VcType "VerifiedEmployee" ``
  -VcManifest "https://beta.eu.did.msidentity.com/v1.0/...tenantId.../verifiableCredential/contracts/Verified%20employee%201" `
  -CallbackHostname "https://5237-2001-8a0-7753-7200-5545-d28-1df-e74a.ngrok.io" `
  -TenantId "...guid..." ``
  -AppId "...AppId..." `
  -AppKey "...AppKey..." 
#>
param (
    [Parameter(Mandatory=$false)][switch]$Issue = $False, # else Present
    [Parameter(Mandatory=$true)][string]$DID,
    [Parameter(Mandatory=$true)][string]$VcType,
    [Parameter(Mandatory=$true)][string]$VcManifest,
    [Parameter(Mandatory=$true)][string]$CallbackHostname,
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$AppId,
    [Parameter(Mandatory=$true)][string]$AppKey,
    [Parameter(Mandatory=$false)][string]$Scope = "3db474b9-6a0c-4840-96ac-1fceb342124f/.default"
)
<#
write-host "Getting Tenant Region..."
$tenantMetadata = invoke-restmethod -Uri "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
$tenantRegionScope = $tenantMetadata.tenant_region_scope 
#>
write-host "Acquiring Access Token..."
$oauth = Invoke-RestMethod -Method Post -Uri "https://login.microsoft.com/$tenantID/oauth2/v2.0//token?api-version=1.0" `
    -Body @{grant_type="client_credentials";client_id=$AppID;client_secret=$AppKey;scope=$Scope}

if ( !$oauth.access_token ) {
  exit 1
}

# common for both Issuance and Presentation
$common = @"
"authority": "$DID",
  "includeQRCode": true,
  "registration": {
    "clientName": "Powershell test driver",
    "purpose": "To test VC presentation"
  },
  "callback": {
    "url": "$CallbackHostname/api/request-callback",
    "state": "$((New-Guid).Guid.ToString())",
    "headers": {
      "api-key": "$((New-Guid).Guid.ToString())"
    }
  }
"@

# create issuance or presentation request
if ( $Issue ) {
  $url="https://beta.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest"
$request = @"
{
  $common,
  "type": "$VcType",
  "manifest": "$VcManifest"
}
"@
} else { # Presentation Request
  $url="https://beta.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest"
$request = @"
{
  $common,
  "includeReceipt": true,
  "requestedCredentials": [
    {
      "type": "$VcType",
      "manifest": "$VcManifest",
      "purpose": "the purpose why the verifier asks for a VC",
      "acceptedIssuers": [ "$DID" ]
    }
  ],
  "configuration": {
    "validation": {
      "allowRevoked": true,
      "validateLinkedDomain": true
    }
  }
}
"@
}

write-host "Calling Request API with a presentation request...`nPOST $url`n$request"
$resp = Invoke-RestMethod -Method "POST" -Uri $url  -ContentType "application/json" -Body $request `
            -Headers @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"} 

write-host "Writing QR code to qrcode.html file..."
$html = "<!DOCTYPE html><html><head><title>Powershell VC</title></head><body><h1>VC QR Code</h1><p>Scan this QR code with the Authenticator</p><img src=`"$($resp.qrCode)`" alt=`"$($resp.url)`"/></body></html>"
Set-Content -Path ./qrcode.html -Value $html