#requires -Version 7.0
# Read-only DNS probes. Does not activate VPN, modify services or capture packets.
param(
    [Parameter(Mandatory)][System.Net.IPAddress]$DnsServer,
    [ValidateSet('browserleaks.com', 'example.com')][string]$Query = 'browserleaks.com',
    [ValidatePattern('^[a-zA-Z0-9_-]{1,32}$')][string]$Label = 'manual'
)

$ErrorActionPreference = 'Stop'
$probeRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$probeOutput = Join-Path $probeRoot 'target\dns-diagnostics'
$probeExecutable = Join-Path $probeOutput 'DnsProbe.exe'
if ($DnsServer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'An explicit IPv4 DNS server is required.' }
if (-not (Test-Path -LiteralPath $probeExecutable -PathType Leaf)) { throw 'Build DnsProbe.exe with build.ps1 first.' }

# Async continuations execute managed code only, never PowerShell without a runspace.
# Every child gets its own timer immediately; awaiting results later cannot postpone its kill.
if (-not ('VpnClient.DnsDiagnostics.ChildDeadline' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
namespace VpnClient.DnsDiagnostics {
    public static class ChildDeadline {
        public static async Task<bool> MonitorAsync(Process child, int milliseconds) {
            using (var deadline = new CancellationTokenSource(milliseconds)) {
                try {
                    await child.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
                    return false;
                } catch (OperationCanceledException) when (deadline.IsCancellationRequested) {
                    // The retained Process was created by this invocation; no name/PID lookup.
                    try { child.Kill(); }
                    catch (InvalidOperationException) when (child.HasExited) { }
                    using (var cleanup = new CancellationTokenSource(2000)) {
                        await child.WaitForExitAsync(cleanup.Token).ConfigureAwait(false);
                    }
                    return true;
                }
            }
        }
    }
}
'@
}

function Get-ProbeServiceState {
    @(Get-CimInstance Win32_Service -Filter "Name='Dnscache' OR Name='VpnClientDnsGuard'" | ForEach-Object {
        $service = $_
        $processName = $null
        if ($service.ProcessId -gt 0) {
            $serviceProcess = $null
            try { $serviceProcess = [Diagnostics.Process]::GetProcessById([int]$service.ProcessId); $processName = $serviceProcess.ProcessName }
            catch [ArgumentException] { }
            catch [ComponentModel.Win32Exception] { }
            catch [InvalidOperationException] { }
            finally { if ($null -ne $serviceProcess) { $serviceProcess.Dispose() } }
        }
        [pscustomobject]@{ Name=$service.Name; State=$service.State; ProcessId=$service.ProcessId; ProcessName=$processName; ExitCode=$service.ExitCode }
    })
}

function Get-ProbeServiceClassification([object[]]$Services) {
    $cache = @($Services | Where-Object Name -eq 'Dnscache')
    $guard = @($Services | Where-Object Name -eq 'VpnClientDnsGuard')
    if ($cache.Count -ne 1 -or $guard.Count -ne 1) { return 'transitionOrUnknown' }
    if ($cache[0].State -ne 'Running' -or $cache[0].ProcessId -le 0) { return 'transitionOrUnknown' }
    if ($cache[0].ProcessName -eq 'VpnClient.DnsGuard' -and $guard[0].State -eq 'Running' -and
        $guard[0].ProcessId -gt 0 -and $guard[0].ProcessName -eq 'VpnClient.DnsGuard') { return 'observedStub' }
    if ($cache[0].ProcessName -eq 'svchost' -and $guard[0].State -eq 'Stopped' -and
        $guard[0].ProcessId -eq 0) { return 'observedOff' }
    return 'transitionOrUnknown'
}

function Get-ProbeServiceObservation([object[]]$Before, [object[]]$After) {
    $beforeClass = Get-ProbeServiceClassification $Before
    $afterClass = Get-ProbeServiceClassification $After
    $samePids = $true
    foreach ($name in @('Dnscache', 'VpnClientDnsGuard')) {
        $first = @($Before | Where-Object Name -eq $name)
        $last = @($After | Where-Object Name -eq $name)
        if ($first.Count -ne 1 -or $last.Count -ne 1 -or $first[0].ProcessId -ne $last[0].ProcessId) { $samePids = $false }
    }
    $mode = 'transitionOrUnknown'
    if ($samePids -and $beforeClass -eq $afterClass) { $mode = $beforeClass }
    [pscustomobject]@{ before=$beforeClass; after=$afterClass; processIdsConsistent=$samePids; mode=$mode }
}

$startedUtc = [DateTimeOffset]::UtcNow
$before = Get-ProbeServiceState
$children = [Collections.Generic.List[object]]::new()
$results = [Collections.Generic.List[object]]::new()
try {
    foreach ($mode in @('getaddrinfo', 'dns-standard', 'dns-wire', 'udp', 'tcp')) {
        $startInfo = [Diagnostics.ProcessStartInfo]::new($probeExecutable)
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.ArgumentList.Add($mode)
        $startInfo.ArgumentList.Add($Query)
        if ($mode -in @('udp', 'tcp')) { $startInfo.ArgumentList.Add($DnsServer.ToString()) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        $childTimer = [Diagnostics.Stopwatch]::StartNew()
        if (-not $process.Start()) { $process.Dispose(); throw "Could not start $mode probe." }
        $child = [pscustomobject]@{
            Mode = $mode; Process = $process; Pid = $process.Id
            StartedUtc = [DateTimeOffset]::UtcNow
            Deadline = $null
            Stdout = $process.StandardOutput.ReadToEndAsync()
            Stderr = $process.StandardError.ReadToEndAsync()
        }
        $children.Add($child)
        $remaining = [int][Math]::Max(1, 6000 - $childTimer.ElapsedMilliseconds)
        $child.Deadline = [VpnClient.DnsDiagnostics.ChildDeadline]::MonitorAsync($process, $remaining)
    }
    foreach ($child in $children) {
        $timedOut = $child.Deadline.GetAwaiter().GetResult()
        $stdout = $child.Stdout.GetAwaiter().GetResult()
        $stderr = $child.Stderr.GetAwaiter().GetResult()
        $parsed = $null
        $parseError = $null
        if (-not $timedOut) {
            try { $parsed = $stdout | ConvertFrom-Json -ErrorAction Stop }
            catch { $parseError = 'invalid_probe_output' }
        }
        $results.Add([pscustomobject]@{
            mode = $child.Mode; pid = $child.Pid; startedUtc = $child.StartedUtc
            deadlineExceeded = $timedOut; exitCode = $child.Process.ExitCode
            result = $parsed; parseError = $parseError
            stderr = $stderr.Substring(0, [Math]::Min(1024, $stderr.Length))
        })
    }
} finally {
    foreach ($child in $children) {
        if (-not $child.Process.HasExited) {
            try { $child.Process.Kill(); $null = $child.Process.WaitForExit(2000) } catch [InvalidOperationException] { }
        }
        # Settle managed continuations before disposing the retained Process they access.
        if ($null -ne $child.Deadline) {
            try { $null = $child.Deadline.GetAwaiter().GetResult() }
            catch { Write-Warning ('Owned DNS probe cleanup failed: ' + $_.Exception.GetType().Name) }
        }
        $child.Process.Dispose()
    }
}

$after = Get-ProbeServiceState
$report = [pscustomobject]@{
    version = 1; label = $Label; startedUtc = $startedUtc; finishedUtc = [DateTimeOffset]::UtcNow
    query = $Query; directDnsServer = $DnsServer.ToString()
    servicesBefore = $before; servicesAfter = $after
    serviceObservation = Get-ProbeServiceObservation $before $after
    results = $results.ToArray()
}
$reportPath = Join-Path $probeOutput ($Label + '-' + $startedUtc.ToString('yyyyMMdd-HHmmss-fff') + '.json')
$reportJson = $report | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($reportPath, $reportJson, [Text.UTF8Encoding]::new($false))
Write-Output $reportJson
Write-Host "Saved diagnostic report: $reportPath"
