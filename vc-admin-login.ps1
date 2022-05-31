<#
You need to set the tenant environment config first via running the tenant-config.ps1 file,
then run this file to login
#>
Connect-AzADVCGraphDevicelogin -TenantId $tenantId -ClientId $clientId