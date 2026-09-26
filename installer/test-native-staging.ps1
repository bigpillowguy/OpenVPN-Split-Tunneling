# Exercise build.rs as a file-copy helper. No redirector, DLL or driver is loaded.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$testDirectory = Join-Path $root "target\native-staging-test-$([guid]::NewGuid().ToString('N'))"
$output = Join-Path $testDirectory 'release\build\redirector-test\out'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$oldPath = $env:Path
$oldManifest = $env:CARGO_MANIFEST_DIR
$oldOutput = $env:OUT_DIR
Push-Location -LiteralPath $root
try {
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    $helper = Join-Path $testDirectory 'build-script.exe'
    & rustc --edition=2021 redirector/build.rs -o $helper
    if ($LASTEXITCODE -ne 0) { throw 'Could not compile native staging helper.' }
    $env:CARGO_MANIFEST_DIR = Join-Path $root 'redirector'
    $env:OUT_DIR = $output
    & $helper | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Initial native staging failed.' }
    foreach ($name in @('WinDivert.dll', 'WinDivert64.sys')) {
        [IO.File]::WriteAllText((Join-Path $testDirectory "release\$name"), 'stale output')
    }
    & $helper | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Incremental native staging failed.' }
    foreach ($name in @('WinDivert.dll', 'WinDivert64.sys')) {
        $expected = (Get-FileHash -LiteralPath (Join-Path $root "vendor\windivert\$name")).Hash
        $actual = (Get-FileHash -LiteralPath (Join-Path $testDirectory "release\$name")).Hash
        if ($actual -ne $expected) { throw "Incremental build retained stale $name." }
    }
    Write-Host 'PASS: build.rs replaces stale DLL and SYS outputs with vendored content.'
} finally {
    $env:Path = $oldPath
    $env:CARGO_MANIFEST_DIR = $oldManifest
    $env:OUT_DIR = $oldOutput
    Pop-Location
    # Keep test output under ignored target/ for inspection; no recursive deletion.
}
