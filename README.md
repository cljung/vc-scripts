# vc-scripts
Github repo for sundry Microsoft Entra Verified ID powershell scripts

## Scripts

| Sample | Description |
|------|--------|
| tenant-config.ps1 | Your tenant configuration variables |
| VCAdminAPI.psm1 | Admin API powershell module |
| vc-admin-loging.ps1 | shortcut to login in to your tenant |
| vc-aadfree-migration.ps1 | Script to migrate an Azure AD tenant to the new 1st party AppIDs |
| vc-mini-webserver.ps1 | Mini webserver in powershell to test issuance and presentation |
| vc-post-request.ps1 | Script to create an issuance or presentation request |
| vc-generate-payloads.ps1 | Script to generate a request Service API payload based on Issuer/Contract |

## MSAL.PS
You need to install **MSAL.PS** in order for this powershell module to work. Authentication and acquiring of access tokens are handled by MSAL.PS.

```powershell
Install-Module -Name MSAL.PS
```
 
## App Registration
You need to create a new App Registration in your tenant and grant that application the `API Permission` to `Verifiable Credential Service Admin` with permission `full_access`. Under `Authentication` the app needs `Allow public client flows` enabled and you also need to check `https://login.microsoftonline.com/common/oauth2/nativeclient` before you save.

## Usage
You need to edit the file [tenant-config.ps1](tenat-config.ps1) and set the id's of your tenant, subscription, etc. The $clientId is the AppId of the app you registered above.

```powershell
$tenantId = "<aad-tenantid-guid>"
$SubscriptionId = "<azure-subscription-guid>"
$resourceGroupName = "<resource-group-name>"
$keyVaultName = "<your-keyvault>"
$clientId="<AppId of the app that has AdminAPI permission>" # App that has API Permission to AdminAPI (scope below)
```

Then, to create a session where you can invoke requests to the Admin API, you run the following commands which will set the environment and sign you in and get an access token. The sign in uses the device code flow and if you are already signed into portal.azure.com for your tenant, you should only need to paste the code to sign in.

```powershell
import-module .\VCAdminAPI.psm1
. .\tenant-config.ps1
.\vc-admin-login.ps1
``` 

The powershell module then contains the following commands

*** Signin ***
- Connect-EntraVerifiedID

*** Tenant ***
- Enable-EntraVerifiedIDTenant
- Remove-EntraVerifiedIDTenantOptOut

*** Authorities ***
- Get-EntraVerifiedIDAuthority
- New-EntraVerifiedIDAuthority
- Set-EntraVerifiedIDAuthority
- Get-EntraVerifiedIDAuthorityLinkedDomainDidConfiguration
- New-EntraVerifiedIDAuthorityWellKnownDidConfiguration
- Set-EntraVerifiedIDAuthorityLinkedDomains
- New-EntraVerifiedIDAuthoritySigningKey
- New-EntraVerifiedIDDidDocument
- Get-EntraVerifiedIDDidDocument

*** Credential Contracts ***
- Get-EntraVerifiedIDContract
- New-EntraVerifiedIDContract
- Set-EntraVerifiedIDContract
- Get-EntraVerifiedIDContractManifest
- Get-EntraVerifiedIDContractManifestURL

*** Credentials ***
- Get-EntraVerifiedIDCredentials
- Revoke-EntraVerifiedIDCredential

*** VC Network ***
- Get-EntraVerifiedIDNetworkIssuers
- Get-EntraVerifiedIDNetworkIssuerContracts

## Test VC Issuance and Presentation using Powershell
You can test issuance and presentation using just powershell. The two scripts `vc-mini-webserver.ps1` and `vc-post-request.ps1` helps your with that. 

First you run the `vc-post-request.ps1` script to create a request and get a QR code. This scripts creates the local file `qrcode.html` with the QR code and the deep link the Authenticator needs.

```powershell
.\vc-post-request.ps1 -DID "did:ion:EiDR..." `
  -VcType "VerifiedEmployee" ``
  -VcManifest "https://beta.eu.did.msidentity.com/v1.0/...tenantId.../verifiableCredential/contracts/Verified%20employee%201" `
  -CallbackHostname "https://5237-2001-8a0-7753-7200-5545-d28-1df-e74a.ngrok.io" `
  -TenantId "...guid..." ``
  -AppId "...AppId..." `
  -AppKey "...AppKey..." 
``` 
Then you run the `vc-mini-webserver.ps1` script which starts a little mini-webserver. Open the browser and navigate to `http://localhost:8080/qrcode.html` to view and scan the QR code. Note that you must have started `ngrok` just as you do when you use the other [samples](https://github.com/Azure-Samples/active-directory-verifiable-credentials). You must also have followed the instructions in the samples for how to do an App Registration that has access to your Azure Key Vault.

## Generate Request Service API Payloads
If you want to generate JSON payloads for the Request Service APIs that work with the [samples](https://github.com/Azure-Samples/active-directory-verifiable-credentials) that are based on the Issuer/Contract details in your tenant, you can use the `vc-generate-payloads-settings.ps1` script. If you have imported the VCAdminAPI.psm1 module and signed in, you can auto-generate the `config.json`, `appsettings.json`, `issuance_request_payload.json` and `presentation_request_payload.json` files by running the below command. 

```powershell
.\vc-generate-payloads-settings.ps1 -ContractName "VerifiedCredentialExpert" -Node -ClientId $AppId -ClientSecret $AppKey

Generating file .\issuance_request_payload.<tenantId>.VerifiedCredentialExpert.json
Generating file .\presentation_payload.<tenantId>.VerifiedCredentialExpert.json
Generating file .\config.<tenantId>.VerifiedCredentialExpert.json
Generating file .\run.<tenantId>.VerifiedCredentialExpert.cmd
Generating file .\run.<tenantId>.VerifiedCredentialExpert.sh
Generating file .\docker-run.<tenantId>.VerifiedCredentialExpert.cmd
Generating file .\docker-run.<tenantId>.VerifiedCredentialExpert.sh
```

The generated files will have the the credential contract name as part of the file name so you can have files for multiple contracts on your dev machine. The config*.json and appsettings*.json files will just be updated if they already exists, and updates you have made in between runs will be preserved.

Unless you want to use a client certificate instead of a client secret, you are good to go. For example, the `run.<tenantId>.VerifiedCredentialExpert.cmd` will look like this:

```cmd
node app.js .\config.<tenantId>.VerifiedCredentialExpert.json .\issuance_request_payload.<tenantId>.VerifiedCredentialExpert.json .\presentation_payload.<tenantId>.VerifiedCredentialExpert.json
```

During the genration, the manifest is downloaded and if you are using the id_token_hint flow, the claims defined in the rules section will be part of the generated `issuance_request_payload.<tenantId>.VerifiedCredentialExpert.json` file. 

```json
{
    "authority": "did:web:example.com",
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
    "type": "VerifiedCredentialExpert",
    "manifest": "https://beta.eu.did.msidentity.com/v1.0/...your-tenant-id.../verifiableCredential/contracts/VerifiedCredentialExpert",
    "pin": {
      "value": "1234",
      "length": 4
      },
    "claims": {
      "given_name": "PLACEHOLDER", 
      "family_name": "PLACEHOLDER"
    }
}
```

## Migrate Off Storage
Please refer to [this](https://github.com/Azure-Samples/active-directory-verifiable-credentials/tree/main/scripts/contractmigration) script for migrating off storage.

## New 1st party apps AppID migration
With the support for Azure AD Free for Verifiable Credentials, new AppIDs were introduced. Azure AD tenants that were used for POC/Pilots before this happened need to migrate their configuration. The script `vc-aadfree-migration.ps1` script will help you do that.