<#
This script migrates Credential Contracts off from Azure Storage to the new model.
#>

import-module .\VCAdminAPI.psm1

###############################################################################################################
### MODIFY THESE THREE LINES BEFORE YOU RUN THE SCRIPT ###
$tenantID = "<tenant-guid>"                                 # Your Azure AD tenant id
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI
$AccessKey = ""                                             # Azure Storage Access Keys - get this from portal
### IMPORTANT !!!
# Uncomment the last line (Update-AzADVCContract) if you want to update the credential contracts. 
# It is commented out so you can test run this script without making any chages
###############################################################################################################

Connect-AzADVCGraphDevicelogin -TenantId $tenantId -ClientId $clientId

if ( !$global:authHeader ) {
    write-error "Authentication failed"
    exit 1
}

if ( !$AccessKey ) {
    write-error "Please set `$AccessKey variable for storage"
    exit 1
}

write-host "Retrieving VC Credential Contracts for tenant $tenantId..."
$contracts = Get-AzADVCContracts

function PrintMsg($msg) {
    $banner = "".PadLeft(78,"*")
    write-host "`n$banner`n* $msg`n$banner"
}

function MigrateClaimsMapping( $claimsMapping ) {
    $mapping = ""
    foreach( $claims in $claimsMapping ) {
        $sep = ""
        foreach ($claim in $claims.PSObject.Properties) { 
            $indexed = "false"
            if ( $claim.Value.indexed -eq $True ) { $indexed = "true"}
            $mapping += "$sep{ `"outputClaim`": `"$($claim.Name)`", `"required`": true, `"inputClaim`": `"$($claim.Value.claim)`", `"indexed`": $indexed }"
            $sep = ",`n              "
        }
    }
    return $mapping
}
foreach( $contract in $contracts ) {
    # only process old contracts that uses Azure Storage for display & rules files
    if ( !($contract.rulesFile -and $contract.displayFile) ) {
        PrintMsg "$($contract.contractName) - already good"
        continue
    }

    PrintMsg "$($contract.contractName) - converting..."

    write-host "Downloading " $contract.rulesFile
    $rules = Get-AzADVCFileFromStorage -ResourceUrl $contract.rulesFile -AccessKey $AccessKey
    write-host "Downloading " $contract.displayFile
    $display = Get-AzADVCFileFromStorage -ResourceUrl $contract.displayFile -AccessKey $AccessKey

    if ( !$rules -or !$display ) {
        write-host "Failed to get display & rules files"
        continue
    }

    write-host "Converting display definitions..."
    $sep = ""
    $displayClaims = ""
    foreach( $claim in $display.default.claims.PSObject.Properties ) {
        $displayClaims += "$sep{ `"claim`": `"$($claim.Name)`", `"label`": `"$($claim.Value.label)`", `"type`": `"$($claim.Value.type)`" }"
        $sep = ",`n"
    }
    $newDisplay = @"
"displays": [
    {
    "locale": "$($display.default.locale)",
    "card": $($display.default.card | ConvertTo-Json),
    "consent": $($display.default.consent | ConvertTo-json),
    "claims": [
        $displayClaims
    ]
    }
  ]
"@

    write-host "Converting rules definitions..."
    if ( $rules.attestations.idTokens ) {
        $newRules = "`"idTokens`": ["
        foreach( $idToken in $rules.attestations.idTokens ) {
            $sep = ""
            $clientId = $idToken.client_id
            $configuration = $idToken.configuration
            $redirectUri = $idToken.redirect_uri
            $scope = $idToken.scope
            if ( $configuration -eq "https://self-issued.me" ) {
                $clientId = "ignore"
                $redirectUri = "ignore"
                $scope = "ignore"
            }
            $mapping = MigrateClaimsMapping $idToken.mapping
            $newRules += "$sep{ `"clientId`": `"$clientId`",`"configuration`": `"$configuration`", `"redirectUri`": `"$redirectUri`", `"scope`": `"$scope`", `"mapping`": [ $mapping ], `"required`": false }"
            $sep = ",`n"
        }
        $newRules += "]"
    }

    if ( $rules.attestations.presentations ) {
        foreach( $presentation in $rules.attestations.presentations ) {
            $mapping = MigrateClaimsMapping $presentation.mapping
            $presentation.mapping = ("{ `"mapping`": [ $mapping ] }" | ConvertFrom-json).mapping
        }
        $newRules = ($rules.attestations | ConvertTo-json -Depth 15)
        $newRules = $newRules.Substring(1, $newRules.Length-2)
    }

    if ( $rules.attestations.accessTokens ) {
        $newRules = "`"accessTokens`": ["
        foreach( $accessToken in $rules.attestations.accessTokens ) {
            $sep = ""
            $mapping = MigrateClaimsMapping $accessToken.mapping
            $newRules += "$sep{ `"mapping`": [ $mapping ], `"required`": true }"
            $sep = ",`n"
        }
        $newRules += "]"
    }

    if ( $rules.attestations.selfIssued ) {
        $mapping = MigrateClaimsMapping $rules.attestations.selfIssued.mapping
        $newRules = "`"selfIssued`": { `"mapping`": [ $mapping ] }"
    }
      
    $newContract = @"
{
  "id": "$($contract.id)",
  "tenantId": "$($contract.tenantId)",
  "contractName": "$($contract.contractName)",
  "issuerId": "$($contract.issuerId)",
  "status": "$($contract.status)",
  "issueNotificationEnabled": $($contract.issueNotificationEnabled.ToString().ToLower()),
  "issueNotificationAllowedToGroupOids": [],
  "availableInVcDirectory": $($contract.availableInVcDirectory.ToString().ToLower()),
  "rules": {
    "attestations": {
        $newRules
    }
  },
  $newDisplay
}
"@
    write-host "New Contract..."
    write-host ($newContract | ConvertFrom-json | ConvertTo-json -Depth 15 )

    write-host "Updating Contract..."
    $newContract = ($newContract | ConvertFrom-json | ConvertTo-json -Depth 15 -Compress)
#    Update-AzADVCContract -Id $contract.Id -Body $newContract
} # foreach
