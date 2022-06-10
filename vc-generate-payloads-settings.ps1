<#
This script uses the VCAdminAPI.psm1 module and generates the Request Service API payloads for a given Issuer/Contract
and the appsettings.json/config.json + run.cmd/sh and docker-run.cmd/sh for the VC Samples
#>
param (
    [Parameter(Mandatory=$true)][string]$ContractName,      # VC Credential Contract Name
    [Parameter(Mandatory=$true)][string]$ClientId,          # AppReg that has scope VerifiableCredentials.Create.All
    [Parameter(Mandatory=$true)][string]$ClientSecret,      # key for app 
    [Parameter(Mandatory=$false)][string]$Path = ".",        # Path to store the generated files
    [Parameter(Mandatory=$false)][switch]$Dotnet = $False,
    [Parameter(Mandatory=$false)][switch]$Node = $False,
    [Parameter(Mandatory=$false)][switch]$Java = $False,
    [Parameter(Mandatory=$false)][switch]$Python = $False
)

$contract = Get-AzADVCContracts -Name $ContractName
$issuer = Get-AzADVCIssuer -Id $contract.issuerId  
$manifestUrl = Get-AzADVCContractManifestURL -IssuerId $issuer.id -Name $contract.contractName
$manifest = Invoke-RestMethod -Uri $manifestUrl

# this is to check that Azure key Vault is set up correctly. If this failes, you will not be able to issue/verify
$manifestSigned = Get-AzADVCContractManifest -IssuerId $issuer.id -Name $contract.contractName -Signed

$uri = New-Object System.Uri -ArgumentList $manifestUrl
$RequestAPIEndpoint = "https://$($uri.Host)/v1.0/$($contract.tenantId)/verifiablecredentials/request"

$dirsep = [IO.Path]::DirectorySeparatorChar # to handle Windows/Mac/Linux
if ( !($Path.EndsWith("/") -or $Path.EndsWith("\")) ) {
  $Path = "$Path$dirsep"
}

# generated files have .tenantId.contractName. as part of their name to make them unique
$filePattern = "$($contract.contractName).$($contract.tenantId)"
function SaveToFile( [string]$Filename, [string]$Value) {
  $TargetPath = "$Path$Filename"
  write-host "Generating file $Filename"
  Set-Content -Path $TargetPath -Value $Value
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
$issuancePayloadFile = "issuance_request_payload.$filePattern.json"
SaveToFile -Filename $issuancePayloadFile -Value $issuancePayload

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
$presentationPayloadFile = "presentation_request_payload.$filePattern.json"
SaveToFile -Filename $presentationPayloadFile -Value $presentationPayload

##########################################################################################################
# Create/update the config.json that node/python sample uses
##########################################################################################################
$configFile = "config.$filePattern.json"

if ( $Node -or $Python ) {
  # update file if it exist (don't overwrite) or create it if it doesn't exist
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
  "azClientId": "$ClientId",
  "azClientSecret": "$ClientSecret",
  "azCertificateName" : "",
  "azCertificateLocation": "",
  "azCertificatePrivateKeyLocation": "",
  "CredentialManifest": "$manifestUrl",
  "IssuerAuthority": "$($issuer.didModel.did)",
  "VerifierAuthority": "$($issuer.didModel.did)"
}
"@
  }
  SaveToFile -Filename $configFile -Value $configJson
}

##########################################################################################################
# Create/update the appsettings.json that dotnet sample uses
##########################################################################################################

if ( $Dotnet ) {
  # update file if it exist (don't overwrite) or create it if it doesn't exist
  $appsettingsFile = ".$($dirsep)appsettings.$filePattern.json"
  if ( Test-Path $appsettingsFile ) {
    $appsettings = (Get-Content $appsettingsFile | ConvertFrom-json)
    $appsettings.AppSettings.TenantId = $contract.tenantId
    $appsettings.AppSettings.ClientId = $ClientId
    $appsettings.AppSettings.ClientSecret = $ClientSecret
    $appsettings.AppSettings.IssuerAuthority = $issuer.didModel.did
    $appsettings.AppSettings.VerifierAuthority = $issuer.didModel.did
    $appsettings.AppSettings.CredentialManifest = $manifestUrl
    $appsettings.AppSettings.Endpoint = $RequestAPIEndpoint
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
    "Endpoint": "$RequestAPIEndpoint",
    "VCServiceScope": "3db474b9-6a0c-4840-96ac-1fceb342124f/.default",
    "Instance": "https://login.microsoftonline.com/{0}",

    "TenantId": "$($contract.tenantId)",
    "ClientId": "$ClientId",
    "ClientSecret": "$ClientSecret",
    "CertificateName": "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]",
    "IssuerAuthority": "$($issuer.didModel.did)",
    "VerifierAuthority": "$($issuer.didModel.did)",
    "CredentialManifest": "$manifestUrl"
  }
}
"@
  }
  SaveToFile -Filename $appsettingsFile -Value $appSettingsJson
}

##########################################################################################################
# Create run.cmd/sh and docker-run.cmd/sh
##########################################################################################################
$runTarget = $null
$dockerTarget = $null
if ( $Node ) {
  $runTarget = "node app.js"
  $dockerTarget = "node-aadvc-api-idtokenhint:latest"
}
if ( $Python ) {
  $runTarget = "python app.py"
  $dockerTarget = "python-aadvc-api-idtokenhint:latest"
}

if ( $runTarget ) {
  SaveToFile "run.$filePattern.cmd" "$runTarget .$dirsep$configFile .$dirsep$issuancePayloadFile .$dirsep$presentationPayloadFile"
  SaveToFile "run.$filePattern.sh" "#!/bin/bash`n$runTarget ./$configFile ./$issuancePayloadFile ./$presentationPayloadFile"
}

if ( $dockerTarget  ) {
  $dockerRunCmd= @"
docker run --rm -it -p 8080:8080 ^
  -e CONFIGFILE=./$configFile ^
  -e ISSUANCEFILE=./$issuancePayloadFile ^
  -e PRESENTATIONFILE=./$presentationPayloadFile ^
  $dockerTarget
"@
  SaveToFile "docker-run.$filePattern.cmd" $dockerRunCmd

  $dockerRunSh = @"
#!/bin/bash
docker run --rm -it -p 8080:8080 \
  -e CONFIGFILE=./$configFile \
  -e ISSUANCEFILE=./$issuancePayloadFile \
  -e PRESENTATIONFILE=./$presentationPayloadFile \
  $dockerTarget  
"@
  SaveToFile "docker-run.$filePattern.sh" $dockerRunSh
}

# Java is special since there is no config.json. Everything i pqassed as envvars to what is defined in application.properties
if ( $Java ) {
  $runCmd = @"
set AADVC_TenantId=$($contract.tenantId)
set AADVC_ClientID=$ClientId
set AADVC_ClientSecret=$ClientSecret
set AADVC_CertName=not_used_if_secret_is_set
set AADVC_CertLocation=%cd%\AppCreationScripts\aadappcert.crt
set AADVC_CertKeyLocation=%cd%\AppCreationScripts\aadappcert.key
set AADVC_ApiKey=$((New-Guid).Guid.ToString())
set AADVC_ISSUERAUTHORITY=$($issuer.didModel.did)
set AADVC_VERIFIERAUTHORITY=$($issuer.didModel.did)
set AADVC_PRESENTATIONFILE=%cd%\$presentationPayloadFile
set AADVC_ISSUANCEFILE=%cd%\$issuancePayloadFile
set AADVC_ApiEndpoint=$RequestAPIEndpoint
set AADVC_CREDENTIALMANIFEST=$manifestUrl

java -jar .\target\java-aadvc-api-idtokenhint-0.0.1-SNAPSHOT.jar
"@  
  SaveToFile "run.$filePattern.cmd" $runCmd

  $runSh = @"
#!/bin/bash
export AADVC_TenantId=$($contract.tenantId)
export AADVC_ClientID=$ClientId
export AADVC_ClientSecret=$ClientSecret
export AADVC_CertName=not_used_if_secret_is_set
export AADVC_CertLocation=`$(pwd)/AppCreationScripts/aadappcert.crt
export AADVC_CertKeyLocation=`$(pwd)/AppCreationScripts/aadappcert.key
export AADVC_ApiKey=$((New-Guid).Guid.ToString())
export AADVC_ISSUERAUTHORITY=$($issuer.didModel.did)
export AADVC_VERIFIERAUTHORITY=$($issuer.didModel.did)
export AADVC_PRESENTATIONFILE=`$(pwd)/$presentationPayloadFile
export AADVC_ISSUANCEFILE=`$(pwd)/$issuancePayloadFile
export AADVC_ApiEndpoint=$RequestAPIEndpoint
export AADVC_CREDENTIALMANIFEST=$manifestUrl

java -jar ./target/java-aadvc-api-idtokenhint-0.0.1-SNAPSHOT.jar
"@  
  SaveToFile "run.$filePattern.sh" $runSh

  $dockerRunCmd = @"
docker run --rm -it -p 8080:8080 ^
    -e AADVC_TenantId=$($contract.tenantId) ^
    -e AADVC_ClientID=$ClientId ^
    -e AADVC_ClientSecret=$ClientSecret ^
    -e AADVC_CertName=not_used_if_secret_is_set ^
    -e AADVC_CertLocation=/usr/local/lib/aadappcert.crt ^
    -e AADVC_CertKeyLocation=/usr/local/lib/aadappcert.key ^
    -e AADVC_ApiKey=$((New-Guid).Guid.ToString()) ^
    -e AADVC_CREDENTIALMANIFEST=$manifestUrl ^
    -e AADVC_ISSUERAUTHORITY=$($issuer.didModel.did) ^
    -e AADVC_VERIFIERAUTHORITY=$($issuer.didModel.did) ^
    -e AADVC_PRESENTATIONFILE=/usr/local/lib/$presentationPayloadFile ^
    -e AADVC_ISSUANCEFILE=/usr/local/lib/$issuancePayloadFile ^
    java-aadvc-api-idtokenhint:latest
"@
  SaveToFile "docker-run.$filePattern.cmd" $dockerRunCmd

  $dockerRunSh = @"
docker run --rm -it -p 8080:8080 \
  -e AADVC_TenantId=$($contract.tenantId) \
  -e AADVC_ClientID=$ClientId \
  -e AADVC_ClientSecret=$ClientSecret \
  -e AADVC_CertName=not_used_if_secret_is_set \
  -e AADVC_CertLocation=/usr/local/lib/aadappcert.crt \
  -e AADVC_CertKeyLocation=/usr/local/lib/aadappcert.key \
  -e AADVC_ApiEndpoint=$RequestAPIEndpoint \
  -e AADVC_ApiKey=$((New-Guid).Guid.ToString()) \
  -e AADVC_CREDENTIALMANIFEST=$manifestUrl \
  -e AADVC_ISSUERAUTHORITY=$($issuer.didModel.did) \
  -e AADVC_VERIFIERAUTHORITY=$($issuer.didModel.did) \
  -e AADVC_PRESENTATIONFILE=/usr/local/lib/$presentationPayloadFile \
  -e AADVC_ISSUANCEFILE=/usr/local/lib/$issuancePayloadFile \
  java-aadvc-api-idtokenhint:latest
"@
  SaveToFile "docker-run.$filePattern.sh" $dockerRunSh
}
