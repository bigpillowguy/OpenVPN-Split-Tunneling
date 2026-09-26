# No installs, VPN processes or network requests. Uses the verified cached MSI.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\dependencies.ps1"
$script:sourcePackage = Join-Path $PSScriptRoot "deps\$OpenVpnMsiName"
Assert-OpenVpnPackage $script:sourcePackage
# Read-only Windows Installer metadata: no msiexec/install/custom actions.
$windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
$database = $windowsInstaller.OpenDatabase($script:sourcePackage, 0)
$view = $database.OpenView('SELECT `Feature` FROM `Feature`')
$view.Execute()
$features = @()
while ($record = $view.Fetch()) { $features += $record.StringData(1) }
$setup = Get-Content -LiteralPath "$PSScriptRoot\VpnClient.iss" -Raw
$setupVersion = [regex]::Match($setup, '#define\s+OpenVpnVersion\s+"([^"]+)"').Groups[1].Value
if ($setupVersion -ne $OpenVpnVersion) { throw 'Inno Setup and downloader disagree on the OpenVPN package version.' }
$requested = [regex]::Match($setup, 'ADDLOCAL=([A-Za-z0-9.,]+)').Groups[1].Value.Split(',')
foreach ($feature in $requested) {
    if ($feature -notin $features) { throw "Setup requests an absent MSI feature: $feature" }
}
if ('OpenVPN' -notin $requested) { throw 'Setup does not request OpenVPN core binaries.' }
$view.Close()
foreach ($comObject in @($record, $view, $database, $windowsInstaller)) {
    if ($null -ne $comObject) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject) }
}
$script:downloads = 0
$script:badDownload = $false
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    $script:downloads++
    if ($script:badDownload) {
        [IO.File]::WriteAllText($OutFile, 'incomplete MSI')
    } else {
        Copy-Item -LiteralPath $script:sourcePackage -Destination $OutFile
    }
}
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) "vpnclient-package-test-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$destination = Join-Path $testDirectory 'OpenVPN.msi'
try {
    Get-OpenVpnPackage $destination
    Assert-OpenVpnPackage $destination
    Get-OpenVpnPackage $destination
    if ($script:downloads -ne 1) { throw 'A valid cache triggered another download.' }
    [IO.File]::WriteAllText($destination, 'corrupt cached MSI')
    Get-OpenVpnPackage $destination
    Assert-OpenVpnPackage $destination
    if ($script:downloads -ne 2) { throw 'A corrupted cache was not replaced.' }
    [IO.File]::WriteAllText($destination, 'preserve until replacement is validated')
    $script:badDownload = $true
    $rejected = $false
    try { Get-OpenVpnPackage $destination } catch { $rejected = $true }
    if (-not $rejected) { throw 'A corrupt download was accepted.' }
    if ([IO.File]::ReadAllText($destination) -ne 'preserve until replacement is validated') {
        throw 'A failed download modified the existing cache.'
    }
    if (@(Get-ChildItem -LiteralPath $testDirectory -Filter '*.download').Count -ne 0) {
        throw 'Temporary download files leaked.'
    }
    Write-Host 'PASS: MSI features, valid cache, corrupted cache replacement, rejected download, atomic publication and cleanup.'
} finally {
    # Only the flat temporary test directory created above is touched.
    Get-ChildItem -LiteralPath $testDirectory -File | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
    Remove-Item -LiteralPath $testDirectory
}
