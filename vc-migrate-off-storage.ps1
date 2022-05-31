<#
This script migrates Credential Contracts off from Azure Storage to the new model.
#>
import-module .\VCAdminAPI.psm1

###############################################################################################################
### MODIFY THESE THREE LINES BEFORE YOU RUN THE SCRIPT ###
$tenantID = "<tenant-guid>"                                 # Your Azure AD tenant id
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI
$AccessKey = ""                                             # Azure Storage Access Keys - get this from portal
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
        $sep = ",`n          "
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
    foreach( $idToken in $rules.attestations.idTokens ) {
        $clientId = $idToken.client_id
        $configuration = $idToken.configuration
        $redirectUri = $idToken.redirect_uri
        $scope = $idToken.scope
        if ( $configuration -eq "https://self-issued.me" ) {
            $clientId = "ignore"
            $redirectUri = "ignore"
            $scope = "ignore"
        }
        $mapping = ""
        foreach( $claims in $idToken.mapping ) {
            $sep = ""
            foreach ($claim in $claims.PSObject.Properties) { 
                $indexed = "false"
                if ( $claim.Value.indexed -eq $True ) { $indexed = "true"}
                $mapping += "$sep{ `"outputClaim`": `"$($claim.Name)`", `"required`": true, `"inputClaim`": `"$($claim.Value.claim)`", `"indexed`": $indexed }"
                $sep = ",`n              "
            }
        }
    }
    $newRules = @"
"rules": {
    "attestations": {
    "idTokens": [
        {
        "clientId": "$clientId",
        "configuration": "$configuration",
        "redirectUri": "$redirectUri",
        "scope": "$scope",
        "mapping": [ 
            $mapping
        ],
        "required": false
        }
    ]
    }
  }
"@
      
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
  $newRules,
  $newDisplay
}
"@
    write-host "New Contract..."
    write-host $newContract

    write-host "Updating Contract..."
#    Update-AzADVCContract -Id $contract.Id -Body $newContract -Verbose
} # foreach
