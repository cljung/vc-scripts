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
    [Parameter(Mandatory=$true)][string]$vpToken,
    [Parameter(Mandatory=$false)][switch]$ReverseOrderBitCheck = $True
)

# ############################################################################
# Helper functions to bring clarity to the logic in revocation check logic
# ############################################################################

# Function for fixing up base64 strings though some of them lack padding, etc
function base64Fixup( [string]$base64 ) {
    $base64 = $base64.Replace("-", "+").Replace("_", "/").Replace("*", "=")
    if ( ($base64.Length % 4) -gt 0 ) {
        $base64 = $base64 + "".PadRight( 4-($base64.Length % 4), "=")
    }
    return $base64
}
# Function to decode a base64 to byte array
function decodeBase64( [string]$base64 ) {
    return [System.Convert]::FromBase64String( $(base64Fixup $base64) )
}
# Function to decode a base64 string
function decodeBase64ToString( [string]$base64 ) {
    return [System.Text.Encoding]::UTF8.GetString( ( $(decodeBase64 $base64) )) 
}
# Function to convert a base64 string, containing JSON, to a JSON object
function base64ToJSON( [string]$base64 ) {
    return ( $(decodeBase64ToString $base64) | ConvertFrom-json)    
}
# Function to contain a JWT Token's claims to JSON
function jwtTokenToJSON( [string]$jwtToken ) {
    return base64ToJSON $jwtToken.Split(".")[1]
}

function getQueryStringParameter( [string]$params, [string]$name ) {    
    return ( ($params.Split("?")[1].Split("&")) | where {$_.StartsWith($name)}).Split("=")[1]
}
# GZIP decompress function
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

# ############################################################################
# Revocation Check logic
# ############################################################################

<#
We accept a VC of type VerifiablePresentation (which contains a VerifiableCredential) or a VerifiableCredential
#>
$vpClaims = $null
$vcClaims = $null
$token = jwtTokenToJSON $vpToken
if ( $token.vp -and $token.vp.type.Contains("VerifiablePresentation") ) {
    $vpClaims = $token
    $vcClaims = jwtTokenToJSON $vpClaims.vp.verifiableCredential
}
if ( $token.vc -and $token.vc.type.Contains("VerifiableCredential") ) {
    $vcClaims = $token
}
if ( $null -eq $vcClaims ) {
    write-error "Wrong vp.type: [$($token.vc.type -Join " ," )]. Must contain 'VerifiablePresentation' or 'VerifiableCredential'"
    exit 1
}

<#
We support a VC with vc.credentialStatus.type == 'RevocationList2021Status' or 'StatusList2021Entry' 
#>
if ( !($vcClaims.vc.credentialStatus.type -eq "RevocationList2021Status" `
   -or $vcClaims.vc.credentialStatus.type -eq "StatusList2021Entry" )) {
    write-error "Wrong credentialStatus.type: $($vcClaims.vc.credentialStatus.type). Must be 'RevocationList2021Status' or 'StatusList2021Entry'"
    exit 1
}

write-host "VC Type       :" $vcClaims.vc.type[1]
write-host "VC Claims     :" $vcClaims.vc.credentialSubject
write-host "VC Status Type:" $vcClaims.vc.credentialStatus.type
write-host "VC DID        :" $vcClaims.sub "`n"

<#
Resolve the Issuer's DID Document. 
For type StatusList2021Entry, this is not needed, but we do it anyway here so we can show the linked domain. 
For type RevocationList2021Status, we need did.didDocument.service since it is the URL to get the revocation list from
#>
write-host "Resolving issuers DID Document..."
$did = Invoke-RestMethod -Method "GET" -Uri "https://discover.did.msidentity.com/v1.0/identifiers/$($vcClaims.iss)"
$linkedDomains = ($did.didDocument.service | where {$_.type -eq "LinkedDomains"}).serviceEndpoint
if ( $linkedDomains.origins ) {
    $linkedDomains = $linkedDomains.origins
}
write-host "VC Issuer: " $vcClaims.iss "`nDomains  : " $linkedDomains "`n"

# ----------------------------------------------------------------------------
# RevocationList2021Status
# The claim vc.credentialStatus.statusListCredential contains this:
#    'did:method:<id>?service=IdentityHub&queries=<base64string>'
# - service : the type name to look for a matching service in the issuer's did document.
# - queries : the 'descriptor' of how to query for the correct data (see JSON below)
# ----------------------------------------------------------------------------
if ( $vcClaims.vc.credentialStatus.type -eq "RevocationList2021Status" -and $vcClaims.vc.credentialStatus.statusListCredential.StartsWith("https://") -eq $false ) {
    $queries = decodeBase64ToString $(getQueryStringParameter $vcClaims.vc.credentialStatus.statusListCredential "queries")
    $serviceType = getQueryStringParameter $vcClaims.vc.credentialStatus.statusListCredential "service"
    $hubEndpoint = ($did.didDocument.service | where {$_.type -eq $serviceType}).serviceEndpoint.instances[0]
    write-host "Retriving StatusList2021 from $serviceType $hubEndpoint..."
    $vcRevocationJwt = Invoke-RestMethod -Method "POST" -Uri $hubEndpoint -ContentType "application/json" -Body @"
{
    "requestId": "$((new-Guid).Guid.ToString())",
    "target": "$($vcClaims.iss)",
    "messages": [
        {
            "descriptor": $(($queries | ConvertFrom-json) | ConvertTo-json)
        }
    ]
}
"@
    <#
    The JSON response is structured like this: replies[0].entries[0].data
    There will only be 1 entry of replies and entries. The 'data' is a VC containing the revocation list
      #>
    $vcRevocation = jwtTokenToJSON (decodeBase64ToString $vcRevocationJwt.replies[0].entries[0].data)
} 

if ( $vcClaims.vc.credentialStatus.type -eq "RevocationList2021Status" -and $vcClaims.vc.credentialStatus.statusListCredential.StartsWith("https://")) {
    write-host "Retriving RevocationList2021Status from $($vcClaims.vc.credentialStatus.statusListCredential) ..."
    $vcRevocationJwt = Invoke-RestMethod -Method "GET" -Uri $vcClaims.vc.credentialStatus.statusListCredential 
    $vcRevocation = jwtTokenToJSON $vcRevocationJwt
}

# ----------------------------------------------------------------------------
# StatusList2021Entry. 
# The statusListCredential is a URL that gives us the revocation list in a VC
# ----------------------------------------------------------------------------
if ( $vcClaims.vc.credentialStatus.type -eq "StatusList2021Entry" ) {
    write-host "Retriving StatusList2021 from $($vcClaims.vc.credentialStatus.statusListCredential) ..."
    $vcRevocationJwt = Invoke-RestMethod -Method "GET" -Uri $vcClaims.vc.credentialStatus.statusListCredential 
    $vcRevocation = jwtTokenToJSON $vcRevocationJwt
}

if ( $null -eq $vcRevocation ) {
    write-error "Couldn't retrieve the status list"
    exit 1
}
# ----------------------------------------------------------------------------
# Common to RevocationList2021Status + StatusList2021Entry. 
# ----------------------------------------------------------------------------
# Check that the revocation list is of the correct type
if ( !($vcRevocation.vc.type.Contains( "StatusList2021Credential" ) ) ){
    write-error "Wrong type in revocation list: [$($vcRevocation.vc.type -Join ", ")]. Must contain 'StatusList2021Credential'"
    exit 1
}
write-host "VC StatusList     : " $vcRevocationJwt

<#
The revocation list data is in the encodedList claim. It is GZIP compressed and in base64 format.
Once base64 decoded and gzip uncompressed, it is an array of bits where the holders VC's statusListIndex
tells us what bit to check for revocation status.
#>
write-host "Decompressing status list and checking revocation...`n"
$revocationList = gzipDecompress (decodeBase64 $vcRevocation.vc.credentialSubject.encodedList)
$statusListIndex = $vcClaims.vc.credentialStatus.statusListIndex
# create an index to the byte and the bit within the byte
$byteIndex=[int]($statusListIndex/8)
$bitIndex=($statusListIndex%8)

# create array of mask bits from 0x00000001...0x10000000
[byte[]]$maskBits = @( 1, 2, 4, 8, 16, 32, 64, 128, 128 )
if ( $ReverseOrderBitCheck ) {
    # create array of mask bits from 0x10000000...0x00000001
    [byte[]]$maskBits = @( 128, 64, 32, 16, 8, 4, 2, 1 )
}
$isRevoked = ($revocationList[$byteIndex] -bAnd $maskBits[$bitIndex]) ? $True : $False
# convert the byte to a bit string and pad with leading zeroes
$revocationByteMask = [convert]::ToString($revocationList[$byteIndex],2).PadLeft(8, "0")
# create a label to point to the bit in question
$label = "^".PadLeft($bitIndex+1, "-").PadRight(8,"-")

write-host "StatusList entries: " ($revocationList.Count * 8)
write-host "VC Index          : " $vcClaims.vc.credentialStatus.statusListIndex
write-host "Is revoked?       : " $isRevoked
write-host "Revocation Byte   : " $revocationByteMask
write-host "                    " $label
write-host "Byte index [0..N] : " $byteIndex
write-host "Bit index [0..7]  : " $bitIndex

write-host "`nBitString"
for ( $i = 0; $i -le ($statusListIndex/8); $i++ ) {
    write-host -NoNewLine ([convert]::ToString($revocationList[$i],2).PadLeft(8, "0").PadRight(9, " "))
}

#write-host "`n$revocationList"
<#
# for testing and dumping out how the maskBits look like
for ( $i = 0; $i -lt $maskBits.Count; $i++ ) {
    write-host -NoNewLine ([convert]::ToString($maskBits[$i],2).PadLeft(8, "0").PadRight(9, " "))
}
#>
