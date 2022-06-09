<#
This script uses the VCAdminAPI.psm1 module and generates the Request Service API payloads for a given Issuer/Contract
#>
param (
    [Parameter(Mandatory=$true)][string]$ContractName
)

$contract = Get-AzADVCContracts -Name $ContractName
$issuer = Get-AzADVCIssuer -Id $contract.issuerId  
$manifestUrl = Get-AzADVCContractManifestURL -IssuerId $issuer.id -Name $contract.contractName
$manifest = Invoke-RestMethod -Uri $manifestUrl

function SaveToFile( [string]$Path, [string]$Value) {
  write-host "Generating file $Path"
  Set-Content -Path $Path -Value $Value
}

##########################################################################################################
# Create the issunce payload
##########################################################################################################

# if it's an idTokenHint flow, then we should add the claims to the issuance payload
# we just add the pin code. If you don't want it, remove it
$idTokenHintJson = ""
if ( $manifest.input.attestations.idTokens -and $manifest.input.attestations.idTokens[0].configuration -eq "https://self-issued.me") {  
  $idTokenHintJson = ",`n      `"pin`": {`n        `"value`": `"1234`",`n        `"length`": 4`n        },`n      `"claims`": {"
  $sep = ""
  foreach( $claim in $manifest.input.attestations.idTokens[0].claims.claim ) {
    $claimName = $claim.Replace("$.", "")
    $idTokenHintJson += "$sep`n        `"$claimName`": `"PLACEHOLDER`""
    $sep = ", "
  }
  $idTokenHintJson += "`n      }`n"
}

$issuancePayload = @"
{
    "authority": "$($issuer.didModel.did)",
    "includeQRCode": false,
    "registration": {
      "clientName": "...set at runtime...",
      "purpose": "You will be issued with a wonderful VC"
    },
    "callback": {
      "url": "...set at runtime...",
      "state": "...set at runtime...",
      "headers": {
        "api-key": "blabla"
      }
    },
    "issuance": {
      "type": "$($contract.contractName)",
      "manifest": "$manifestUrl"$idTokenHintJson
    }
}
"@
SaveToFile -Path ".\issuance_payload_$($contract.contractName).json" -Value $issuancePayload

##########################################################################################################
# Create the presentation payload
##########################################################################################################
$presentationPayload = @"
{
    "authority": "$($issuer.didModel.did)",
    "includeQRCode": false,
    "registration": {
      "clientName": "...set at runtime...",
      "purpose": "Sign away all your posessions by pressing Allow. Transaction id {0}"
    },
    "callback": {
      "url": "...set at runtime...",
      "state": "...set at runtime...",
      "headers": {
        "api-key": "blabla"
      }
    },
    "presentation": {
      "includeReceipt": true,
      "requestedCredentials": [
        {
          "type": "$($contract.contractName)",
          "manifest": "$manifestUrl",
          "purpose": "the purpose why the verifier asks for a VC",
          "acceptedIssuers": [ "$($issuer.didModel.did)" ]
        }
      ]
    }
  }
"@
SaveToFile -Path ".\presentation_payload_$($contract.contractName).json" -Value $presentationPayload

##########################################################################################################
# Create/update the config.json that node/python sample uses
##########################################################################################################

# update file if it exist (don't overwrite) or create it if it doesn't exist
$configFile = ".\config_$($contract.contractName).json"
if ( Test-Path $configFile ) {
  $config = (Get-Content $configFile | ConvertFrom-json)
  $config.AzTenantId = $contract.tenantId
  $config.IssuerAuthority = $issuer.didModel.did
  $config.VerifierAuthority = $issuer.didModel.did
  $config.CredentialManifest = $manifestUrl
  $configJson = ($config | ConvertTo-json)
} else {
$configJson = @"
{
  "azTenantId": "$($contract.tenantId)",
  "azClientId": "<YOUR-AAD-CLIENTID-FOR-KEYVAULT-ACCESS>",
  "azClientSecret": "<YOUR-AAD-CLIENTSECRET-FOR-KEYVAULT-ACCESS>",
  "azCertificateName" : "",
  "azCertificateLocation": "",
  "azCertificatePrivateKeyLocation": "",
  "CredentialManifest": "$manifest",
  "IssuerAuthority": "$($issuer.didModel.did)",
  "VerifierAuthority": "$($issuer.didModel.did)"
}
"@
}
SaveToFile -Path $configFile -Value $configJson

##########################################################################################################
# Create/update the appsettings.json that dotnet sample uses
##########################################################################################################
$uri = New-Object System.Uri -ArgumentList $manifestUrl
$endpoint = "https://$($uri.Host)/v1.0/{0}/verifiablecredentials/request"

# update file if it exist (don't overwrite) or create it if it doesn't exist
$appsettingsFile = ".\appsettings.$($contract.contractName).json"
if ( Test-Path $appsettingsFile ) {
  $appsettings = (Get-Content $appsettingsFile | ConvertFrom-json)
  $appsettings.AppSettings.TenantId = $contract.tenantId
  $appsettings.AppSettings.IssuerAuthority = $issuer.didModel.did
  $appsettings.AppSettings.VerifierAuthority = $issuer.didModel.did
  $appsettings.AppSettings.CredentialManifest = $manifestUrl
  $appsettings.AppSettings.Endpoint = $endpoint
  $appSettingsJson = ($appsettings | ConvertTo-json)
} else {
$appSettingsJson = @"
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "AppSettings": {
    "Endpoint": "$endpoint",
    "VCServiceScope": "3db474b9-6a0c-4840-96ac-1fceb342124f/.default",
    "Instance": "https://login.microsoftonline.com/{0}",

    "TenantId": "$($contract.tenantId)",
    "ClientId": "APPLICATION CLIENT ID",
    "ClientSecret": "[client secret or instead use the prefered certificate in the next entry]",
    "CertificateName": "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]",
    "IssuerAuthority": "$($issuer.didModel.did)",
    "VerifierAuthority": "$($issuer.didModel.did)",
    "CredentialManifest": "$manifestUrl"
  }
}
"@
}
SaveToFile -Path $appsettingsFile -Value $appSettingsJson
