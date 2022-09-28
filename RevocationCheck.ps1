<#
.SYNOPSIS
    Checks is a Entra Verified ID VC is revoked by the issuer
.DESCRIPTION
    Checks is a Entra Verified ID VC is revoked by the issuer using StatusList2021
.PARAMETER vpToken
    VerifiablePresentation token passed to the verifier relying party app
.OUTPUTS
    Echoes progress to console for demo purposes
.EXAMPLE
    .\RevocationCheck.ps1 -vpToken $vpToken
#>
param (
    [Parameter(Mandatory=$true)][string]$vpToken
)

<#
Function for fixing up base64 strings though some of them lack padding, etc
#>
function base64Fixup( [string]$base64string ) {
    $base64string = $base64string.Replace("-", "+").Replace("_", "/").Replace("*", "=")
    if ( ($base64string.Length % 4) -gt 0 ) {
        $base64string = $base64string + "".PadRight( 4-($base64string.Length % 4), "=")
    }
    return $base64string
}
<#
GZIP decompress function
#>
function gzipDecompress( [byte[]]$byteArray ) {
    $msIn = New-Object System.IO.MemoryStream( , $byteArray )
    $msOut = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $msIn, ([IO.Compression.CompressionMode]::Decompress)
    $gzipStream.CopyTo( $msOut )
    $gzipStream.Close()
    $msIn.Close()
    [byte[]]$retval = $msOut.ToArray()    
    $msOut.Close()
    return $retval
}

<#
The vp token being presented is a JWT token and contains the following claims:
- aud : issuer's DID
- vp.type : Must be 'VerifiablePresentation' or we have the wrong type of token
#>
if ( $vpToken.Contains(".")) {
    $vpToken = $vpToken.Split(".")[1]
}
$vpToken = base64Fixup $vpToken
$vpClaims = ( [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $vpToken )) | ConvertFrom-json)
if ( !($vpClaims.vp.type.Contains("VerifiablePresentation") )) {
    write-error "Wrong vp.type: [$($vcClaims.vc.type -Join " ," )]. Must contain 'VerifiablePresentation'"
    exit 1
}
<#
In the vp token, there is a vp.cerifiableCredential claim that is the VC the holder presented (in JWT token format)
The vc token should have a claim of 'vc.credentialStatus.type == 'RevocationList2021Status'. If it doesn't, we
don't have data to check if this VC is revoked.
The claim vc.credentialStatus.statusListCredential contains this:  'did:method:<id>?service=IdentityHub&queries=<base64string>'
The service gives us the type name to look for a matching service in the issuer's did document.
The queries gives is the 'descriptor' of how to query for the correct data (see JSON below)
#>
$vc = base64Fixup $vpClaims.vp.verifiableCredential.Split(".")[1]
$vcClaims = ( [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $vc )) | ConvertFrom-json)
if ( $vcClaims.vc.credentialStatus.type -ne "RevocationList2021Status" ) {
    write-error "Wrong credentialStatus.type: $($vcClaims.vc.credentialStatus.type). Must be 'RevocationList2021Status'"
    exit 1
}
write-host "VC Type  :" $vcClaims.vc.type[1] "`nVC Claims: " $vcClaims.vc.credentialSubject "`nDID      :" $vcClaims.sub "`n"

$qpParams = $vcClaims.vc.credentialStatus.statusListCredential.Split("?")[1].Split("&")
$serviceType = ($qpParams | where {$_.StartsWith("service")}).Split("=")[1]
$queries = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( ($qpParams | where {$_.StartsWith("queries")}).Split("=")[1] ))
$bodyReq = @"
{
    "requestId": "$((new-Guid).Guid.ToString())",
    "target": "$($vpClaims.aud)",
    "messages": [
        {
            "descriptor": $(($queries | ConvertFrom-json) | ConvertTo-json)
        }
    ]
}
"@
<#
We need to resolve the issuer's DID in order to find out the endpoint for checking status.
- didDocument.service : should contain and entry where type == 'IdentityHub' (matching VCs $serviceType) where the serviceEndpoint is the URL for getting statusList2021 data
#>
write-host "Resolving issuers DID Document..."
$did = Invoke-RestMethod -Method "GET" -Uri "https://discover.did.msidentity.com/v1.0/identifiers/$($vpClaims.aud)"

$hubEndpoint = ($did.didDocument.service | where {$_.type -eq $serviceType}).serviceEndpoint.instances[0]
$linkedDomains = ($did.didDocument.service | where {$_.type -eq "LinkedDomains"}).serviceEndpoint.origins
write-host "VC Issuer: " $vpClaims.aud "`nDomains  : " $linkedDomains "`n"

<#
Query the serviceEndpoint for the revocation list data
#>
write-host "Retriving StatusList2021 from Hub Endpoint $hubEndpoint ..."
$resp = Invoke-RestMethod -Method "POST" -Uri $hubEndpoint -ContentType "application/json" -Body $bodyReq

<#
The JSON response is structured like this. You will only have 1 entry in each collection and the 'data' claim contains the data
    replies[0].entries[0].data
The 'data' claim is base64 encoded and after you've base64Decoded the data you would get this ($hubClaims below)
  vc.type == StatusList2021Credential
In the vc.credentialSubject.encodedList claim is created like this: base64Encode(gzipCompress(encodedList))  
Since the statusList is a bit array, gzip compressing it means that continuous zeros will be heavily compressed and a 130K block
may be compressed to under 100 bytes.
#>
write-host "Decompressing status list and checking revocation..."
$data = ( [System.Text.Encoding]::UTF8.GetString( [System.Convert]::FromBase64String( $resp.replies[0].entries[0].data ) ) ).Split(".")[1].Replace("_","/")
$data = base64Fixup $data
$hubClaims = ( [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( $data )) | ConvertFrom-json)
if ( !($hubClaims.vc.type.Contains( "StatusList2021Credential" ) ) ){
    write-error "Wrong type in revocation list: [$($hubClaims.vc.type -Join ", ")]. Must contain 'StatusList2021Credential'"
    exit 1
}
<#
 base64Decode and then gzipDecompress the data
#>
$encodedList = base64Fixup $hubClaims.vc.credentialSubject.encodedList
[byte[]]$byteArray = [System.Convert]::FromBase64String($encodedList)
$revocationList = gzipDecompress $byteArray
<#
In the VC the holder presented, there is a claim 'statusListIndex' that is an index to this VCs bit in the array
#>
$isRevoked = ($revocationList[$vcClaims.vc.credentialStatus.statusListIndex] -eq 1)

write-host "StatusList entries: " $revocationList.Count "`nVC Index          : " $vcClaims.vc.credentialStatus.statusListIndex "`nIs revoked?       : " $isRevoked
