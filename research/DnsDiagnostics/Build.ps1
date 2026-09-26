[CmdletBinding()]
param([string]$OutputDirectory, [switch]$RunCodecTests)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $PSScriptRoot '..\..\target\dns-diagnostics' }
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$version = '10.0.26100.0'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC x64 build tools are required.' }
$msvc = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$toolBin = Join-Path $msvc.FullName 'bin\Hostx64\x64'
foreach ($path in @((Join-Path $toolBin 'cl.exe'), (Join-Path $sdk "Include\$version\um\windns.h"))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing build prerequisite: $path" }
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$savedPath = $env:Path; $savedInclude = $env:INCLUDE; $savedLib = $env:LIB
try {
    $env:Path = "$toolBin;$env:Path"
    $env:INCLUDE = @((Join-Path $msvc.FullName 'include'), (Join-Path $sdk "Include\$version\ucrt"), (Join-Path $sdk "Include\$version\shared"), (Join-Path $sdk "Include\$version\um")) -join ';'
    $env:LIB = @((Join-Path $msvc.FullName 'lib\x64'), (Join-Path $sdk "Lib\$version\ucrt\x64"), (Join-Path $sdk "Lib\$version\um\x64")) -join ';'
    Push-Location $output
    try {
        & cl.exe /nologo /std:c++20 /EHsc /O2 /MT /W4 /WX /DUNICODE /D_UNICODE (Join-Path $PSScriptRoot 'DnsProbe.cpp') /Fe:DnsProbe.exe /link dnsapi.lib ws2_32.lib bcrypt.lib
        if ($LASTEXITCODE) { throw 'DNS diagnostic probe compilation failed.' }
        if ($RunCodecTests) {
            & cl.exe /nologo /std:c++20 /EHsc /O2 /MT /W4 /WX /DUNICODE /D_UNICODE (Join-Path $PSScriptRoot 'TestCodec.cpp') /Fe:TestCodec.exe /link dnsapi.lib ws2_32.lib bcrypt.lib
            if ($LASTEXITCODE) { throw 'Offline DNS codec test compilation failed.' }
            & (Join-Path $output 'TestCodec.exe')
            if ($LASTEXITCODE) { throw 'Offline DNS codec tests failed.' }
        }
    } finally { Pop-Location }
    Write-Output (Join-Path $output 'DnsProbe.exe')
} finally { $env:Path = $savedPath; $env:INCLUDE = $savedInclude; $env:LIB = $savedLib }
