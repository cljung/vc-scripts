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
. .\tenant-config.ps1
.\vc-admin-login.ps1
``` 

## Migrate Off Storage
Old Credential Contracts uses Azure Storage to stor the display and rules json files while new contracts, created via the QuickStarts, store them internally together with the rest of the contract definition. In order to migrate a contract off storage, you need to update the contract definition. The steps to do that is to get the contract (using the Admin API), get the json files from storage, then change the json definition and finally updating the new contract definition (using the Admin API). The script [vc-aadfree-migration.ps1](vc-aadfree-migration.ps1) does this for all your contracts i  your tenant. You need to have a signed in session for the Admin API and you also need to set the powershell variable `$AccessKey` to the shared access key of your Azure Storage account.

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
If you want to generate JSON payloads for the Request Service APIs that work with the [samples](https://github.com/Azure-Samples/active-directory-verifiable-credentials) that are based on the Issuer/Contract details in your tenant, you can use the `vc-generate-payloads.ps1` script.

## New 1st party apps AppID migration
With the support for Azure AD Free for Verifiable Credentials, new AppIDs were introduced. Azure AD tenants that were used for POC/Pilots before this happened need to migrate their configuration. The script `vc-aadfree-migration.ps1` script will help you do that.