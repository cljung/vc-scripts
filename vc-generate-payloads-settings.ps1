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
    [Parameter(Mandatory=$false)][switch]$Python = $False,
    [Parameter(Mandatory=$false)][switch]$OutputToConsole = $False
)

$authority = Get-EntraVerifiedIDAuthorities
$contract = Get-EntraVerifiedIDContracts -AuthorityId $authority.id -Name $ContractName
$manifestUrl = Get-EntraVerifiedIDContractManifestURL -AuthorityId $authority.id -Name $contract.name
$tenantId = $manifestUrl.Split("/")[5]
$manifest = Get-EntraVerifiedIDContractManifest -AuthorityId $authority.id -Name $contract.name
# this is to check that Azure key Vault is set up correctly. If this failes, you will not be able to issue/verify
$manifestSigned = Get-EntraVerifiedIDContractManifest -AuthorityId $authority.id -Name $contract.name -Signed

$uri = New-Object System.Uri -ArgumentList $manifestUrl
$RequestAPIEndpoint = "https://$($uri.Host)/v1.0/" # The rest goes in code

$dirsep = [IO.Path]::DirectorySeparatorChar # to handle Windows/Mac/Linux
if ( !($Path.EndsWith("/") -or $Path.EndsWith("\")) ) {
  $Path = "$Path$dirsep"
}

# generated files have .tenantId.contractName. as part of their name to make them unique
$filePattern = "$tenantId.$($contract.name)"
function SaveToFile( [string]$Filename, [string]$Value) {
  $TargetPath = "$Path$Filename"
  if ( $OutputToConsole ) {
    $banner = "".PadLeft($Filename.Length+4,"*")
    write-host "`n$banner`n* $Filename *`n$banner`n"
    write-host $Value
  } else {
      write-host "Generating file $Filename"
      Set-Content -Path $TargetPath -Value $Value
  }
}

##########################################################################################################
# Create the issunce payload
##########################################################################################################

# if it's an idTokenHint flow, then we should add the claims to the issuance payload
# we just add the pin code. If you don't want it, remove it
$idTokenHintJson = ""
$claims = $null
if ( $manifest.input.attestations.idTokenHints ) {
  $claims = $manifest.input.attestations.idTokenHints[0].claims
}
if ( $manifest.input.attestations.idTokens -and $manifest.input.attestations.idTokens[0].configuration -eq "https://self-issued.me")  {
  $claims = $manifest.input.attestations.idTokens[0].claims
}
if ( $claims ) {  
  $idTokenHintJson = ",`n  `"pin`": {`n    `"value`": `"1234`",`n    `"length`": 4`n  },`n  `"claims`": {"
  $sep = ""
  foreach( $claim in $claims.claim ) {
    $claimName = $claim.Replace("$.", "")
    $idTokenHintJson += "$sep`n    `"$claimName`": `"PLACEHOLDER`""
    $sep = ", "
  }
  $idTokenHintJson += "`n  }`n"
}

$issuancePayload = @"
{
  "includeQRCode": false,
  "authority": "$($authority.didModel.did)",
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
  "type": "$($contract.rules.vc.type)",
  "manifestUrl": "$manifestUrl"$idTokenHintJson
}
"@
$issuancePayloadFile = "issuance_request_payload.$filePattern.json"
SaveToFile -Filename $issuancePayloadFile -Value $issuancePayload

##########################################################################################################
# Create the presentation payload
##########################################################################################################
$presentationPayload = @"
{
  "includeQRCode": false,
  "includeReceipt": true,
  "authority": "$($issuer.didModel.did)",
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
  "requestedCredentials": [
    {
      "type": "$($contract.rules.vc.type)",
      "manifestUrl": "$manifestUrl",
      "purpose": "the purpose why the verifier asks for a VC",
      "acceptedIssuers": [ "$($authority.didModel.did)" ],
      "configuration": {
        "validation": {
          "allowRevoked": true,
          "validateLinkedDomain": true
        }
      }  
    }
  ]
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
    $config.AzTenantId = $tenantId
    $config.IssuerAuthority = $authority.didModel.did
    $config.VerifierAuthority = $authority.didModel.did
    $config.CredentialManifest = $manifestUrl
    $configJson = ($config | ConvertTo-json)
  } else {
  $configJson = @"
{
  "azTenantId": "$tenantId",
  "azClientId": "$ClientId",
  "azClientSecret": "$ClientSecret",
  "azCertificateName" : "",
  "azCertificateLocation": "",
  "azCertificatePrivateKeyLocation": "",
  "CredentialManifest": "$manifestUrl",
  "IssuerAuthority": "$($authority.didModel.did)",
  "VerifierAuthority": "$($authority.didModel.did)"
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
    $appsettings.AppSettings.TenantId = $tenantId
    $appsettings.AppSettings.ClientId = $ClientId
    $appsettings.AppSettings.ClientSecret = $ClientSecret
    $appsettings.AppSettings.IssuerAuthority = $authority.didModel.did
    $appsettings.AppSettings.VerifierAuthority = $authority.didModel.did
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

    "TenantId": "$tenantId",
    "ClientId": "$ClientId",
    "ClientSecret": "$ClientSecret",
    "CertificateName": "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]",
    "IssuerAuthority": "$($authority.didModel.did)",
    "VerifierAuthority": "$($authority.didModel.did)",
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
set AADVC_TenantId=$tenantId
set AADVC_ClientID=$ClientId
set AADVC_ClientSecret=$ClientSecret
set AADVC_CertName=not_used_if_secret_is_set
set AADVC_CertLocation=%cd%\AppCreationScripts\aadappcert.crt
set AADVC_CertKeyLocation=%cd%\AppCreationScripts\aadappcert.key
set AADVC_ApiKey=$((New-Guid).Guid.ToString())
set AADVC_ISSUERAUTHORITY=$($authority.didModel.did)
set AADVC_VERIFIERAUTHORITY=$($authority.didModel.did)
set AADVC_PRESENTATIONFILE=%cd%\$presentationPayloadFile
set AADVC_ISSUANCEFILE=%cd%\$issuancePayloadFile
set AADVC_ApiEndpoint=$RequestAPIEndpoint
set AADVC_CREDENTIALMANIFEST=$manifestUrl

java -jar .\target\java-aadvc-api-idtokenhint-0.0.1-SNAPSHOT.jar
"@  
  SaveToFile "run.$filePattern.cmd" $runCmd

  $runSh = @"
#!/bin/bash
export AADVC_TenantId=$tenantId
export AADVC_ClientID=$ClientId
export AADVC_ClientSecret=$ClientSecret
export AADVC_CertName=not_used_if_secret_is_set
export AADVC_CertLocation=`$(pwd)/AppCreationScripts/aadappcert.crt
export AADVC_CertKeyLocation=`$(pwd)/AppCreationScripts/aadappcert.key
export AADVC_ApiKey=$((New-Guid).Guid.ToString())
export AADVC_ISSUERAUTHORITY=$($authority.didModel.did)
export AADVC_VERIFIERAUTHORITY=$($authority.didModel.did)
export AADVC_PRESENTATIONFILE=`$(pwd)/$presentationPayloadFile
export AADVC_ISSUANCEFILE=`$(pwd)/$issuancePayloadFile
export AADVC_ApiEndpoint=$RequestAPIEndpoint
export AADVC_CREDENTIALMANIFEST=$manifestUrl

java -jar ./target/java-aadvc-api-idtokenhint-0.0.1-SNAPSHOT.jar
"@  
  SaveToFile "run.$filePattern.sh" $runSh

  $dockerRunCmd = @"
docker run --rm -it -p 8080:8080 ^
    -e AADVC_TenantId=$tenantId ^
    -e AADVC_ClientID=$ClientId ^
    -e AADVC_ClientSecret=$ClientSecret ^
    -e AADVC_CertName=not_used_if_secret_is_set ^
    -e AADVC_CertLocation=/usr/local/lib/aadappcert.crt ^
    -e AADVC_CertKeyLocation=/usr/local/lib/aadappcert.key ^
    -e AADVC_ApiKey=$((New-Guid).Guid.ToString()) ^
    -e AADVC_CREDENTIALMANIFEST=$manifestUrl ^
    -e AADVC_ISSUERAUTHORITY=$($authority.didModel.did) ^
    -e AADVC_VERIFIERAUTHORITY=$($authority.didModel.did) ^
    -e AADVC_PRESENTATIONFILE=/usr/local/lib/$presentationPayloadFile ^
    -e AADVC_ISSUANCEFILE=/usr/local/lib/$issuancePayloadFile ^
    java-aadvc-api-idtokenhint:latest
"@
  SaveToFile "docker-run.$filePattern.cmd" $dockerRunCmd

  $dockerRunSh = @"
docker run --rm -it -p 8080:8080 \
  -e AADVC_TenantId=$tenantId \
  -e AADVC_ClientID=$ClientId \
  -e AADVC_ClientSecret=$ClientSecret \
  -e AADVC_CertName=not_used_if_secret_is_set \
  -e AADVC_CertLocation=/usr/local/lib/aadappcert.crt \
  -e AADVC_CertKeyLocation=/usr/local/lib/aadappcert.key \
  -e AADVC_ApiEndpoint=$RequestAPIEndpoint \
  -e AADVC_ApiKey=$((New-Guid).Guid.ToString()) \
  -e AADVC_CREDENTIALMANIFEST=$manifestUrl \
  -e AADVC_ISSUERAUTHORITY=$($authority.didModel.did) \
  -e AADVC_VERIFIERAUTHORITY=$($authority.didModel.did) \
  -e AADVC_PRESENTATIONFILE=/usr/local/lib/$presentationPayloadFile \
  -e AADVC_ISSUANCEFILE=/usr/local/lib/$issuancePayloadFile \
  java-aadvc-api-idtokenhint:latest
"@
  SaveToFile "docker-run.$filePattern.sh" $dockerRunSh
}
