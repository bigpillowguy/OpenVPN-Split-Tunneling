#requires -Version 7.0
# Bounded, read-only watcher for one user-controlled activation.
param(
    [Parameter(Mandatory)][System.Net.IPAddress]$DnsServer,
    [ValidateRange(10, 1800)][int]$WaitSeconds = 180,
    [string]$AttemptDirectory
)
$ErrorActionPreference = 'Stop'
$startedUtc = [DateTimeOffset]::UtcNow
if ([string]::IsNullOrWhiteSpace($AttemptDirectory)) {
    $AttemptDirectory = Join-Path $PSScriptRoot ('..\..\target\dns-diagnostics\watch-' + [Guid]::NewGuid().ToString('N'))
}
$AttemptDirectory = [IO.Path]::GetFullPath($AttemptDirectory)
$null = New-Item -ItemType Directory -Path $AttemptDirectory -Force
$statusPath = Join-Path $AttemptDirectory 'status.json'
$status = [ordered]@{
    version = 1; pid = $PID; state = 'starting'; startedUtc = $startedUtc
    deadlineUtc = $startedUtc.AddSeconds($WaitSeconds); updatedUtc = $startedUtc
    observation = $null; reportPath = $null; serviceMode = $null; error = $null
}
function Save-WatchStatus([string]$State) {
    $status.state = $State
    $status.updatedUtc = [DateTimeOffset]::UtcNow
    $pendingPath = $statusPath + '.tmp'
    [IO.File]::WriteAllText($pendingPath, ($status | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $pendingPath -Destination $statusPath -Force
}
Save-WatchStatus 'starting'
$transcriptStarted = $false
try {
    $null = Start-Transcript -LiteralPath (Join-Path $AttemptDirectory 'watch.log') -ErrorAction Stop
    $transcriptStarted = $true
if ($DnsServer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'An explicit IPv4 DNS server is required.' }
$probeExecutable = Join-Path $PSScriptRoot '..\..\target\dns-diagnostics\DnsProbe.exe'
if (-not (Test-Path -LiteralPath $probeExecutable -PathType Leaf)) { throw 'Build DnsProbe.exe with Build.ps1 first.' }
Write-Host ("Waiting for a user-controlled activation: {0:o} through {1:o}." -f $startedUtc, $status.deadlineUtc)
$deadline = [Diagnostics.Stopwatch]::StartNew()
$stableSince = $null
$stablePid = 0
$previousObservation = $null
while ($deadline.Elapsed.TotalSeconds -lt $WaitSeconds) {
    $services = @(Get-CimInstance Win32_Service -OperationTimeoutSec 2 -Filter "Name='Dnscache' OR Name='VpnClientDnsGuard'")
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
        $status.observation = $observation | ConvertFrom-Json
        Save-WatchStatus 'waiting'
    }
    if ($stub) {
        if ($stablePid -ne $cache.ProcessId -or $null -eq $stableSince) {
            $stablePid = $cache.ProcessId
            $stableSince = $deadline.Elapsed.TotalSeconds
        } elseif ($deadline.Elapsed.TotalSeconds - $stableSince -ge 1) {
            Write-Host 'Observed DNS stub and guardian running. Starting one bounded comparison.'
            Save-WatchStatus 'measuring'
            $reportJson = & (Join-Path $PSScriptRoot 'Invoke-Probe.ps1') -DnsServer $DnsServer -Label active-observed
            $report = $reportJson | ConvertFrom-Json -ErrorAction Stop
            $status.reportPath = Join-Path $AttemptDirectory 'probe.json'
            [IO.File]::WriteAllText($status.reportPath, ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
            $status.serviceMode = $report.serviceObservation.mode
            Save-WatchStatus 'complete'
            Write-Host 'Comparison finished. Experimental DNS can be turned off now.'
            exit 0
        }
    } else {
        $stableSince = $null
        $stablePid = 0
    }
    Start-Sleep -Milliseconds 500
}
Save-WatchStatus 'timeout'
Write-Host ("{0:o} No stable active DNS stub observed before the local deadline. No probe run." -f [DateTimeOffset]::UtcNow)
exit 2
} catch {
    $status.error = $_.Exception.GetType().Name + ': ' + $_.Exception.Message
    Save-WatchStatus 'failed'
    throw
} finally {
    if ($transcriptStarted) { $null = Stop-Transcript }
}
