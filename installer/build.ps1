# Build from any working directory. This only compiles/packages; it never installs.
param([switch]$SkipBuild)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot\dependencies.ps1"
$originalPath = $env:Path
Push-Location -LiteralPath $root
try {
    $rustupBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path -LiteralPath $rustupBin) { $env:Path = "$rustupBin;$env:Path" }
    $iscc = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $iscc) { throw 'Install Inno Setup 6.7 or newer: https://jrsoftware.org/isdl.php' }

    if (-not $SkipBuild) {
        foreach ($command in @('rustup', 'cargo', 'rustc', 'dotnet')) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required build tool missing: $command" }
        }
        $rustInfo = & rustc -vV
        if ($LASTEXITCODE -ne 0 -or $rustInfo -notcontains 'host: x86_64-pc-windows-msvc') {
            throw 'Use the x86_64-pc-windows-msvc Rust toolchain from rust-toolchain.toml.'
        }
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio Build Tools with Desktop development with C++ and a Windows SDK.' }
        $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $vs) { throw 'Visual Studio MSVC x64/x86 build tools were not found.' }
        & dotnet --version
        if ($LASTEXITCODE -ne 0) { throw 'Install the .NET SDK required by global.json.' }
        Write-Host '[1/4] Building redirector' -ForegroundColor Cyan
        $cargoOutput = & cargo build --locked --release --manifest-path redirector/Cargo.toml --message-format=json-render-diagnostics
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed (check MSVC and Windows SDK installation)' }
        $artifact = $cargoOutput | ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'redirector' -and $_.executable } |
            Select-Object -Last 1
        $expectedBinary = Join-Path $root 'target\release\redirector.exe'
        if (-not $artifact -or [IO.Path]::GetFullPath($artifact.executable) -ne $expectedBinary) {
            throw 'Cargo output was redirected by a target or target-dir override. Remove that override before packaging; no previous target/release binary will be packaged.'
        }
        Write-Host '[2/4] Publishing UI' -ForegroundColor Cyan
        $uiPublish = Join-Path $root 'dotnet\VpnClient.Ui\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish'
        & dotnet restore dotnet/VpnClient.Ui/VpnClient.Ui.csproj --locked-mode
        if ($LASTEXITCODE -ne 0) { throw 'Locked NuGet restore failed; review the package references and lockfile.' }
        & dotnet publish dotnet/VpnClient.Ui/VpnClient.Ui.csproj -c Release --nologo --no-restore -o $uiPublish
        if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }
        Write-Host '[3/4] Publishing DNS recovery service' -ForegroundColor Cyan
        $guardPublish = Join-Path $root 'dotnet\VpnClient.DnsGuard\bin\Release\net8.0-windows\win-x64\publish'
        & dotnet restore dotnet/VpnClient.DnsGuard/VpnClient.DnsGuard.csproj --locked-mode
        if ($LASTEXITCODE -ne 0) { throw 'Locked DNS guard restore failed.' }
        & dotnet publish dotnet/VpnClient.DnsGuard/VpnClient.DnsGuard.csproj -c Release --nologo --no-restore -o $guardPublish
        if ($LASTEXITCODE -ne 0) { throw 'DNS guard publish failed.' }
    }

    # Do not package stale native dependencies even when -SkipBuild is used.
    foreach ($name in @('WinDivert.dll', 'WinDivert64.sys')) {
        $vendor = Join-Path $root "vendor\windivert\$name"
        $built = Join-Path $root "target\release\$name"
        if (-not (Test-Path -LiteralPath $built) -or
            (Get-FileHash -LiteralPath $vendor).Hash -ne (Get-FileHash -LiteralPath $built).Hash) {
            throw "Missing or stale $name in target/release. Rebuild redirector before packaging."
        }
    }
    Get-OpenVpnPackage (Join-Path $PSScriptRoot "deps\$OpenVpnMsiName")
    Write-Host '[4/4] Compiling installer' -ForegroundColor Cyan
    & $iscc "$PSScriptRoot\VpnClient.iss"
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed' }
    Write-Host 'Installer built in installer/Output.' -ForegroundColor Green
} finally {
    $env:Path = $originalPath
    Pop-Location
}
