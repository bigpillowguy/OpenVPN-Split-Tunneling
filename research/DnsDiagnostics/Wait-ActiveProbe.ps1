#requires -Version 7.0
# Bounded, read-only foreground watcher for one user-controlled activation.
param(
    [Parameter(Mandatory)][System.Net.IPAddress]$DnsServer,
    [ValidateRange(10, 300)][int]$WaitSeconds = 180
)
$ErrorActionPreference = 'Stop'
if ($DnsServer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'An explicit IPv4 DNS server is required.' }
$probeExecutable = Join-Path $PSScriptRoot '..\..\target\dns-diagnostics\DnsProbe.exe'
if (-not (Test-Path -LiteralPath $probeExecutable -PathType Leaf)) { throw 'Build DnsProbe.exe with Build.ps1 first.' }
$startedUtc = [DateTimeOffset]::UtcNow
Write-Host ("Waiting for a user-controlled activation: {0:o} through {1:o}." -f $startedUtc, $startedUtc.AddSeconds($WaitSeconds))
$deadline = [Diagnostics.Stopwatch]::StartNew()
$stableSince = $null
$stablePid = 0
$previousObservation = $null
while ($deadline.Elapsed.TotalSeconds -lt $WaitSeconds) {
    $services = @(Get-CimInstance Win32_Service -Filter "Name='Dnscache' OR Name='VpnClientDnsGuard'")
    $cache = $services | Where-Object Name -eq 'Dnscache'
    $guard = $services | Where-Object Name -eq 'VpnClientDnsGuard'
    $stub = $false
    $processName = $null
    $processReadError = $null
    if ($cache.State -eq 'Running' -and $guard.State -eq 'Running' -and $cache.ProcessId -gt 0) {
        $process = $null
        try {
            $process = [Diagnostics.Process]::GetProcessById([int]$cache.ProcessId)
            $processName = $process.ProcessName
            $stub = $processName -eq 'VpnClient.DnsGuard'
        } catch [ArgumentException] { $processReadError = 'process_exited' }
        catch [InvalidOperationException] { $processReadError = 'process_unavailable' }
        catch [ComponentModel.Win32Exception] { $processReadError = 'win32_' + $_.Exception.NativeErrorCode }
        finally { if ($null -ne $process) { $process.Dispose() } }
    }
    $observation = [ordered]@{
        cacheState = $cache.State; cachePid = $cache.ProcessId
        guardState = $guard.State; guardPid = $guard.ProcessId
        processName = $processName; processReadError = $processReadError
    } | ConvertTo-Json -Compress
    if ($observation -ne $previousObservation) {
        Write-Host ("{0:o} {1}" -f [DateTimeOffset]::UtcNow, $observation)
        $previousObservation = $observation
    }
    if ($stub) {
        if ($stablePid -ne $cache.ProcessId -or $null -eq $stableSince) {
            $stablePid = $cache.ProcessId
            $stableSince = $deadline.Elapsed.TotalSeconds
        } elseif ($deadline.Elapsed.TotalSeconds - $stableSince -ge 1) {
            Write-Host 'Observed DNS stub and guardian running. Starting one bounded comparison.'
            & (Join-Path $PSScriptRoot 'Invoke-Probe.ps1') -DnsServer $DnsServer -Label active-observed
            Write-Host 'Comparison finished. Experimental DNS can be turned off now.'
            exit 0
        }
    } else {
        $stableSince = $null
        $stablePid = 0
    }
    Start-Sleep -Milliseconds 500
}
Write-Host ("{0:o} No stable active DNS stub observed before the local deadline. No probe run." -f [DateTimeOffset]::UtcNow)
exit 2
