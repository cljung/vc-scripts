<#
You need to set the tenant environment config first via running the tenant-config.ps1 file,
then run this file to login
#>
import-module MSAL.PS
Connect-EntraVerifiedID -TenantId $tenantId -ClientId $clientId