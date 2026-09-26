[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'out'))
$ErrorActionPreference = 'Stop'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$version = '10.0.26100.0'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC x64 build tools are required.' }
$msvc = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$toolBin = Join-Path $msvc.FullName 'bin\Hostx64\x64'
$sdkBin = Join-Path $sdk "bin\$version\x64"
foreach ($required in @((Join-Path $toolBin 'cl.exe'), (Join-Path $sdkBin 'makeappx.exe'), (Join-Path $sdk "Include\$version\cppwinrt\winrt\Windows.Networking.Vpn.h"))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Missing build prerequisite: $required" }
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$package = Join-Path $output 'package'
New-Item -ItemType Directory -Path (Join-Path $package 'Assets') -Force | Out-Null
$savedPath = $env:Path; $savedInclude = $env:INCLUDE; $savedLib = $env:LIB
try {
    $env:Path = "$toolBin;$env:Path"
    $env:INCLUDE = @((Join-Path $msvc.FullName 'include'), (Join-Path $sdk "Include\$version\ucrt"), (Join-Path $sdk "Include\$version\shared"), (Join-Path $sdk "Include\$version\um"), (Join-Path $sdk "Include\$version\winrt"), (Join-Path $sdk "Include\$version\cppwinrt")) -join ';'
    $env:LIB = @((Join-Path $msvc.FullName 'lib\x64'), (Join-Path $sdk "Lib\$version\ucrt\x64"), (Join-Path $sdk "Lib\$version\um\x64")) -join ';'
    Push-Location $output
    try {
        $common = @('/nologo', '/std:c++20', '/EHsc', '/O2', '/MT', '/W4', '/DUNICODE', '/D_UNICODE')
        & cl.exe @common (Join-Path $PSScriptRoot 'FixtureTests.cpp') '/Fe:FixtureTests.exe'
        if ($LASTEXITCODE) { throw 'Fixture tests did not compile.' }
        & (Join-Path $output 'FixtureTests.exe')
        if ($LASTEXITCODE) { throw 'Offline fixture tests failed.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'ProfileTests.cpp') '/Fe:ProfileTests.exe' '/link' 'windowsapp.lib'
        if ($LASTEXITCODE) { throw 'Offline profile tests did not compile.' }
        & (Join-Path $output 'ProfileTests.exe')
        if ($LASTEXITCODE) { throw 'Offline profile object tests failed.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'ProfileActivate.cpp') '/Fe:ProfileActivate.exe' '/link' 'windowsapp.lib' 'ole32.lib'
        if ($LASTEXITCODE) { throw 'VM-only profile activation helper did not compile.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'ProfileProvision.cpp') '/Fe:package\VpnPlatformProvision.exe' '/link' '/SUBSYSTEM:WINDOWS' '/APPCONTAINER' 'windowsapp.lib'
        if ($LASTEXITCODE) { throw 'Packaged profile provisioning app did not compile.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'ResolverProbe.cpp') '/Fe:Selected.exe' '/link' 'dnsapi.lib' 'ws2_32.lib'
        if ($LASTEXITCODE) { throw 'Resolver probe did not compile.' }
        Copy-Item -LiteralPath (Join-Path $output 'Selected.exe') -Destination (Join-Path $output 'Unselected.exe') -Force
        & cl.exe @common (Join-Path $PSScriptRoot 'LabDnsServer.cpp') '/Fe:LabDnsServer.exe' '/link' 'ws2_32.lib'
        if ($LASTEXITCODE) { throw 'Lab DNS control did not compile.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'VpnProbeHost.cpp') '/Fe:package\VpnPlatformProbe.exe' '/link' '/SUBSYSTEM:WINDOWS' '/APPCONTAINER' 'windowsapp.lib'
        if ($LASTEXITCODE) { throw 'VPN platform host did not compile.' }
        & cl.exe @common '/LD' '/DPROBE_DLL' (Join-Path $PSScriptRoot 'VpnProbeHost.cpp') '/Fe:package\VpnPlatformProbe.dll' '/link' ('/DEF:' + (Join-Path $PSScriptRoot 'VpnProbe.def')) '/APPCONTAINER' 'windowsapp.lib'
        if ($LASTEXITCODE) { throw 'VPN platform activation DLL did not compile.' }
        & cl.exe @common (Join-Path $PSScriptRoot 'ActivationTests.cpp') '/Fe:ActivationTests.exe' '/link' 'windowsapp.lib'
        if ($LASTEXITCODE) { throw 'Activation tests did not compile.' }
        & (Join-Path $output 'ActivationTests.exe') (Join-Path $package 'VpnPlatformProbe.dll')
        if ($LASTEXITCODE) { throw 'Local activation factory tests failed.' }
    } finally { Pop-Location }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'AppxManifest.xml') -Destination (Join-Path $package 'AppxManifest.xml') -Force
    # Plain placeholder package assets, generated locally. No external images.
    Add-Type -AssemblyName System.Drawing
    foreach ($asset in @(@('StoreLogo.png', 50), @('Logo.png', 150), @('SmallLogo.png', 44))) {
        $bitmap = New-Object Drawing.Bitmap($asset[1], $asset[1])
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try { $graphics.Clear([Drawing.Color]::FromArgb(51, 51, 51)); $bitmap.Save((Join-Path $package ('Assets\' + $asset[0])), [Drawing.Imaging.ImageFormat]::Png) }
        finally { $graphics.Dispose(); $bitmap.Dispose() }
    }
    $mapping = @('[Files]')
    foreach ($relative in @('AppxManifest.xml', 'VpnPlatformProbe.exe', 'VpnPlatformProbe.dll', 'VpnPlatformProvision.exe', 'Assets\StoreLogo.png', 'Assets\Logo.png', 'Assets\SmallLogo.png')) {
        $mapping += '"' + (Join-Path $package $relative) + '" "' + $relative + '"'
    }
    $mappingPath = Join-Path $output 'package-files.txt'
    $mapping | Set-Content -LiteralPath $mappingPath -Encoding UTF8
    & (Join-Path $sdkBin 'makeappx.exe') pack /f $mappingPath /p (Join-Path $output 'VpnPlatformResearch-unsigned.appx') /o
    if ($LASTEXITCODE) { throw 'MakeAppx validation/packing failed.' }
    Write-Output "Built unsigned VM research package at $output. Nothing installed; no VPN or DNS responder started."
} finally { $env:Path = $savedPath; $env:INCLUDE = $savedInclude; $env:LIB = $savedLib }
