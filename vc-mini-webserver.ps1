<#
This file is a mini webserver in Powershell code. Start this script, run the vc-post-request.ps1 in a separate window,
then browse to http://localhost:8080/qrcode.html to scan the QR Code
#>
$url = "http://localhost:8080/"

function ReadRequestBody( $context ) {
    return [System.IO.StreamReader]::new($context.Request.InputStream).ReadToEnd()
}
function WriteResponse( $context, [int]$statusCode, [string]$contentType, [string]$response ) {
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
    $context.Response.ContentLength64 = $buffer.Length
    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $context.Response.StatusCode = $statusCode
    $context.Response.ContentType = $contentType
    $context.Response.OutputStream.Close() 
}
function CreateHtmlDoc( [string]$htmlBody ){
    return "<!DOCTYPE html><html><head><title>Powershell VC</title></head><body><h1>A Powershell Webserver</h1>$htmlBody</body></html>"
}
$http = [System.Net.HttpListener]::new() 
$http.Prefixes.Add($url)
$http.Start()
if ($http.IsListening) {
    write-host "Listening to $($http.Prefixes)" -f 'y'
    write-host "Ctrl+C will not work. To stop webserver, make a GET request to $($http.Prefixes)exit" -f 'y'
}
while ($http.IsListening) {
    $requestHandled = $False
    $context = $http.GetContext()
    write-host "$($context.Request.UserHostAddress)  =>  $($context.Request.HttpMethod) $($context.Request.Url)" -f 'gre'
    # GET /stop 
    if ($context.Request.HttpMethod -eq 'GET' -and $context.Request.RawUrl -eq '/stop') {
        write-host "Exiting webserver..."
        WriteResponse $context 200 "text/plain" "Webservr stopped"
        $http.Stop()
        break
    }
    #  GET /
    if ($context.Request.HttpMethod -eq 'GET' ) {
        if ( $context.Request.RawUrl -eq '/') {
            $requestHandled = $True
            $html = CreateHtmlDoc "<p>home page</p><a href=`"/stop`">Click here to stop the webserver</a><br/><br/><a href=`"/qrcode.html`">Click here when you have the QR code</a>"
            WriteResponse $context 200 "text/html" $html                
        } else { # try and see if there is a file with this name we can serve
            try {
                $file = $context.Request.RawUrl.Substring(1)
                if (Test-Path -Path $file -PathType Leaf ) {
                    $requestHandled = $True
                    $buf = Get-Content -Path $file
                    WriteResponse $context 200 "text/html" $buf
                }
            } catch {}
        }
    }
    # POST /api/*
    if ($context.Request.HttpMethod -eq 'POST' ) { # -and $context.Request.RawUrl.StartsWith('/api')) {
        $requestHandled = $True
        $body = ReadRequestBody $context
        Write-Host "ContentType: $($context.Request.ContentType)`nContentLength: $($body.Length)`n$body" -f 'Yellow'
        WriteResponse $context 201 $resp "application/json" "{}"
    }
    # else, 404 Not Found
    if ( !$requestHandled ){
        WriteResponse $context 404 "text/plain" "Not Found"
    }
} 
