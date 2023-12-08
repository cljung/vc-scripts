param (
    [Parameter(Mandatory=$true)][string]$AppSettingsFilename
)

$appsettings = (Get-Content $AppSettingsFilename | ConvertFrom-json)

$buf = "["
$topLevel = $appsettings.PSObject.Properties | select Name
foreach( $name in $topLevel.Name) {
    $subLevel = ($appsettings | select $name).PSObject.Properties.Value | Get-Member | Where {$_.MemberType -eq "NoteProperty"} |Select Name
    foreach( $n2 in $subLevel.Name) {
        if ( $appsettings.$name.$n2.GetType().Name -eq "String" ) {
            $value = $appsettings.$name.$n2
            $buf += "{ `"name`": `"" + $name + "__" + $n2 + "`", `"value`": `"" + $value + "`", `"slotSetting`": false},"
        }
    }
}
$buf = $buf.Substring(0, $buf.Length-1) + "]"
$buf = ($buf | ConvertTo-Json | ConvertFrom-Json)
$buf
