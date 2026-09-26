[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch]$InsideDisposableVm,
    [Parameter(Mandatory)][ValidateSet('NoVpn', 'All', 'Selected')][string]$Stage,
    [Parameter(Mandatory)][ValidateSet('None', 'Runtime', 'Profile')][string]$AssignmentSource,
    [ValidateSet('.vpn-probe.test', '.')][string]$Namespace = '.vpn-probe.test',
    [string]$BinaryDirectory,
    [string]$ResultPath
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($BinaryDirectory)) { $BinaryDirectory = Join-Path $PSScriptRoot 'out' }
if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $PSScriptRoot ('result-' + $Stage + '.json') }
if (-not $InsideDisposableVm) { throw 'This matrix sends DNS queries. Run it only inside the prepared disposable VM.' }
if (($Stage -eq 'NoVpn') -ne ($AssignmentSource -eq 'None')) { throw 'Use source None only for NoVpn; otherwise explicitly identify Runtime or Profile.' }
if ((Get-Service Dnscache).Status -ne 'Running') { throw 'Dnscache must remain running.' }
function Start-Probe([string]$app, [string]$name, [string]$type, [string]$api, [long]$start = 0) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = [IO.Path]::GetFullPath((Join-Path $BinaryDirectory ($app + '.exe')))
    $info.Arguments = "$name $type $api" + $(if ($start) { " $start" } else { '' })
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Could not start owned resolver probe.' }
    return $process
}
function Finish-Probe($process, [string]$app, [string]$phase, [string]$type, [string]$api, [string]$name) {
    try {
        if (-not $process.WaitForExit(20000)) { $process.Kill(); $process.WaitForExit(); throw 'Owned resolver probe timed out.' }
        $stdout = $process.StandardOutput.ReadToEnd().Trim(); $stderr = $process.StandardError.ReadToEnd().Trim()
        $marker = if ($Stage -eq 'All' -or ($Stage -eq 'Selected' -and $app -eq 'Selected')) { 10 } else { 20 }
        $expected = if ($type -eq 'A') { '203.0.113.' + $marker } else { '2001:db8::' + $marker.ToString('x') }
        $addresses = @([regex]::Matches($stdout, 'answer=(\S+)') | ForEach-Object { $_.Groups[1].Value })
        $ok = $process.ExitCode -eq 0 -and $addresses.Count -gt 0 -and @($addresses | Where-Object { $_ -ne $expected }).Count -eq 0
        if ($api -eq 'direct' -and $Stage -eq 'Selected' -and $app -eq 'Unselected') {
            # Only concrete Winsock network denial/unreachable/timeout failures
            # qualify; bad arguments, startup failure and invalid replies do not.
            $statusMatch = [regex]::Match($stdout, ' status=(\d+)$')
            $networkFailures = @(10013, 10051, 10054, 10060, 10065)
            $expected = 'blocked'
            $ok = $process.ExitCode -eq 1 -and $addresses.Count -eq 0 -and
                $statusMatch.Success -and [int]$statusMatch.Groups[1].Value -in $networkFailures
        }
        [pscustomobject]@{ App=$app; Phase=$phase; Api=$api; Type=$type; Name=$name; Expected=$expected; Passed=$ok; Stdout=$stdout; Stderr=$stderr; ExitCode=$process.ExitCode }
    } finally { $process.Dispose() }
}
$rows = @()
if ($Stage -ne 'NoVpn') {
    foreach ($app in @('Selected', 'Unselected')) {
        $name = 'gate' + [guid]::NewGuid().ToString('N') + '.vpn-probe.test'
        $rows += Finish-Probe (Start-Probe $app $name 'A' 'direct') $app 'direct-filter-gate' 'A' 'direct' $name
    }
}
foreach ($api in @('dnsapi', 'winsock')) {
    foreach ($type in @('A', 'AAAA')) {
        foreach ($order in @(@('Selected','Unselected'), @('Unselected','Selected'))) {
            $name = 'p' + [guid]::NewGuid().ToString('N') + '.vpn-probe.test'
            foreach ($app in $order) {
                $rows += Finish-Probe (Start-Probe $app $name $type $api) $app ('warm-order-' + ($order -join '-')) $type $api $name
            }
        }
        $name = 'p' + [guid]::NewGuid().ToString('N') + '.vpn-probe.test'
        $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 1500
        $selected = Start-Probe 'Selected' $name $type $api $start
        $unselected = Start-Probe 'Unselected' $name $type $api $start
        $rows += Finish-Probe $selected 'Selected' 'cold-concurrent' $type $api $name
        $rows += Finish-Probe $unselected 'Unselected' 'cold-concurrent' $type $api $name
    }
}
$report = [pscustomobject]@{
    Stage=$Stage; AssignmentSource=$AssignmentSource; Namespace=$Namespace
    OsVersion=[Environment]::OSVersion.Version.ToString(); Dnscache=(Get-Service Dnscache).Status.ToString()
    FilterGatePassed=@($rows | Where-Object { $_.Api -eq 'direct' -and -not $_.Passed }).Count -eq 0
    Passed=@($rows | Where-Object { -not $_.Passed }).Count -eq 0; Results=$rows
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
$rows | Format-Table App, Phase, Api, Type, Passed
if (-not $report.Passed) { exit 1 }
