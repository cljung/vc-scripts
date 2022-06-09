# vc-scripts
Github repo for sundry Azure AD Verifiable Credentials powershell scripts

## Scripts

| Sample | Description |
|------|--------|
| tenat-config.ps1 | Your tenant configuration variables |
| VCAdminAPI.psm1 | Admin API powershell module |
| vc-admin-loging.ps1 | shortcut to login in to your tenant |
| vc-aadfree-migration.ps1 | Script to migrate an Azure AD tenant to the new 1st party AppIDs |
| vc-mini-webserver.ps1 | Mini webserver in powershell to test issuance and presentation |
| vc-post-request.ps1 | Script to create an issuance or presentation request |
| vc-generate-payloads.ps1 | Script to generate a request Service API payload based on Issuer/Contract |

## App Registration
You need to create a new App Registration in your tenant and grant that application the `API Permission` to `Verifiable Credential Service Admin` with permission `full_access`. The app needs `Allow public client flows` enabled under `Authentication`.

## Usage
You need to edit the file [tenat-config.ps1](tenat-config.ps1) and set the id's of your tenant, subscription, etc. The $clientId is the AppId of the app you registered above.

```powershell
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
- Connect-AzADVCGraphDevicelogin

*** Tenant ***
- Enable-AzADVCTenant
- Remove-AzADVCTenantOptOut
- Get-AzADVCTenantStatus
- Rotate-AzADVCIssuerSigningKey

*** Issuers ***
- Get-AzADVCIssuer
- Get-AzADVCIssuers
- New-AzADVCIssuer
- Update-AzADVCIssuer
- New-AzADVCWellKnownDidConfiguration
- Get-AzADVCIssuerLinkedDomainDidConfiguration
- Set-AzADVCLinkedDomains
- Get-AzADVCDidDocument
- Get-AzADVCDidExplorer

*** Credential Contracts ***
- Get-AzADVCContracts
- Get-AzADVCContract
- New-AzADVCContract
- Update-AzADVCContract
- Get-AzADVCContractManifest
- Get-AzADVCContractManifestURL
- Get-AzADVCFileFromStorage
- Import-AzADVCFileToStorage

*** Credentials ***
- Get-AzADVCCredential
- Revoke-AzADVCCredential

*** VC Network ***
- Get-AzADVCDirectoryIssuers
- Get-AzADVCDirectoryIssuerContracts

## Migrate Off Storage
Old Credential Contracts uses Azure Storage to stor the display and rules json files while new contracts, created via the QuickStarts, store them internally together with the rest of the contract definition. In order to migrate a contract off storage, you need to update the contract definition. The steps to do that is to get the contract (using the Admin API), get the json files from storage, then change the json definition and finally updating the new contract definition (using the Admin API). The script [vc-migrate-off-storage.ps1](vc-migrate-off-storage.ps1) does this for all your contracts i  your tenant. 

This script is written to be executed standalone and you do not need VCAdminAPI.psm1. The script takes three parameters, which are: 
- **TenantId** - is the guid for your tenant
- **AccessToken** - an access token that has the `scp` (scope) claim of `full_access ` and the `aud` (audience) claim of `6a8b4b39-c021-437c-b060-5a14a3fd65f3`, which is the `Verifiable Credentials Service Admin`.
- **StorageAccessKey** - Azure Storage Access Key to your storage. This can be copied from portal.azure.com.

Also, please not that the actual Update command is commented out so you can test run without making changes. If you are ready to migrate, uncomment the last part and run again.

```Powershell
.\vc-migrate-off-storage.ps1 -TenantId $TenantId -AccessToken $access_token -StorageAccessKey $StorageAccessKey
```

How do I get an access token? Here are two ways:
1. In portal.azure.com, go to the VC blade for your tenant. Bring up the network view in the developer tools in your browser (F12 in Edge/Chrome), then click on something VC related and find a call to *.msidentity.com. In the request section, you will find the Authorization http header. Copy the base64 value (not including the 'Bearer ' prefix) and set it as a powershell variable you pass to the script. Note - this is a Q&D hack. 
1. Use the VCAdminAPI.psm1 module, follow the steps above, and login. After a successful login you will have an access token in the global variable `$global:tokens.access_token`  

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
If you want to generate JSON payloads for the Request Service APIs that work with the [samples](https://github.com/Azure-Samples/active-directory-verifiable-credentials) that are based on the Issuer/Contract details in your tenant, you can use the `vc-generate-payloads-settings.ps1` script. If you have imported the VCAdminAPI.psm1 module and signed in, you can auto-generate the `config.json`, `appsettings.json`, `issuance_request_payload.json` and `presentation_request_payload.json` files by running the following command:

```powershell
.\vc-generate-payloads-settings.ps1 -ContractName "VerifiedCredentialExpert"
```

The generated files will have the the credential contract name as part of the file name so you can have files for multiple contracts on your dev machine. The config.json and appsettings.json files will just be updated if they already exists, and updates you have made inbetween runs will be preserved.

- config_VerifiedCredentialExpert.json
- appsettings.VerifiedCredentialExpert.json
- issuance_payload_VerifiedCredentialExpert.json
- presentation_payload_VerifiedCredentialExpert.json


## New 1st party apps AppID migration
With the support for Azure AD Free for Verifiable Credentials, new AppIDs were introduced. Azure AD tenants that were used for POC/Pilots before this happened need to migrate their configuration. The script `vc-aadfree-migration.ps1` script will help you do that.