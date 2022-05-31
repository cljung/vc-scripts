<#
This script uses the VCAdminAPI.psm1 module and generates the Request Service API payloads for a given Issuer/Contract
#>
$manifest = Get-AzADVCContractManifestURL -IssuerId $issuer.id -Name $contract.contractName

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
      "manifest": "$manifest"
    }
}
"@

$issuanceFile = ".\issuance_payload_$($contract.contractName).json"
write-host "Generating file $issuanceFile"
Set-Content -Path $issuanceFile -Value $issuancePayload

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
          "manifest": "$manifest",
          "purpose": "the purpose why the verifier asks for a VC",
          "acceptedIssuers": [ "$($issuer.didModel.did)" ]
        }
      ]
    }
  }
"@

$presentationFile = ".\presentation_payload_$($contract.contractName).json"
write-host "Generating file $presentationFile"
Set-Content -Path $presentationFile -Value $presentationPayload
