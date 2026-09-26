# Disposable Windows 11 VM runbook

**Not executed.** All deployment, trust, VPN and NIC commands below belong only
inside a disposable Windows 11 x64 VM with a snapshot. Do not run them on the
development host. This is an experimental package, not the shipping VPN client.

## Stage the payload

Copy `out/`, `Run-Matrix.ps1` and this file to `C:\VpnPlatformLab` in the VM.
The example layout puts binaries directly in `C:\VpnPlatformLab\out`. Record
the OS build. Keep Dnscache running throughout. The manifest requires build22000+.
Take a clean snapshot; revert it after exporting test evidence.

Signing needs a copy of the Windows SDK SignTool inside the VM. In an elevated
**Windows PowerShell 5.1** session inside the VM:

```powershell
Set-Location C:\VpnPlatformLab
$labCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=VpnPlatformResearch' -CertStoreLocation Cert:\CurrentUser\My
Export-Certificate -Cert $labCert -FilePath .\VpnPlatformResearch.cer
Import-Certificate -FilePath .\VpnPlatformResearch.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
# Use the copied SignTool path; do not download a signing utility from another source.
& .\signtool.exe sign /fd SHA256 /sha1 $labCert.Thumbprint .\out\VpnPlatformResearch-unsigned.appx
if ($LASTEXITCODE) { throw 'Signing failed' }
Add-AppxPackage -Path .\out\VpnPlatformResearch-unsigned.appx
Get-AppxPackage -Name VpnPlatformResearch | Select-Object Name, PackageFamilyName, InstallLocation
```

If package registration or capability authorization fails, stop and record the
deployment error. Do not classify it as a DNS result. Package signing/activation
have not been tested by the host-side offline checks.

## Establish a distinguishable control resolver

Choose the VM NIC explicitly. Save its configuration and the clean snapshot.
The lab resolver only answers the test suffix, so other DNS may fail in the VM
until the snapshot is restored. Do not use the machine for unrelated work.

```powershell
Get-NetAdapter
$labNic = 7 # REPLACE with this VM's intended NIC index after inspection.
Get-DnsClientServerAddress -InterfaceIndex $labNic | ConvertTo-Json -Depth 4 | Set-Content .\original-dns.json
Set-DnsClientServerAddress -InterfaceIndex $labNic -ServerAddresses 127.0.0.53
Get-Service Dnscache
```

In a second VM terminal, run `out\LabDnsServer.exe --serve-vm-control` and retain
its output. Its exclusive UDP bind must succeed. It never changes NIC settings
itself. If the VM has other enabled NICs/resolvers, document and isolate them in
the VM before testing; hidden fallback makes the results ambiguous.

```powershell
.\Run-Matrix.ps1 -InsideDisposableVm -Stage NoVpn -AssignmentSource None -ResultPath .\no-vpn.json
```

Require every row to pass. A/AAAA answers are .20 / ::14. Do not flush the global
cache; each matrix phase supplies a new GUID name.

## Add and connect the baseline platform profile

Use a literal IPv4 address on the VM's lab network for the outer UDP transport,
such as the VM's gateway. The fixture sends no encapsulated traffic or keepalive;
it fabricates its DNS response through VPN receive buffers. Still, verify actual
platform activation before drawing any conclusions.

```powershell
$labTransportIp = '192.168.77.2' # REPLACE with this VM lab network's actual address.
$labPackage = Get-AppxPackage -Name VpnPlatformResearch
$labExe = (Resolve-Path .\out\Selected.exe).Path
$labConfig = New-Object Xml.XmlDocument
$labConfig.LoadXml('<Probe><AssignmentSource>runtime</AssignmentSource><Mode>all</Mode><Namespace>.vpn-probe.test</Namespace><SelectedExe/><TransportIp/></Probe>')
$labConfig.Probe.SelectedExe = $labExe
$labConfig.Probe.TransportIp = $labTransportIp
Add-VpnConnection -Name 'VpnPlatformLab' -ServerAddress $labTransportIp -PlugInApplicationID $labPackage.PackageFamilyName -CustomConfiguration $labConfig -SplitTunneling
```

Connect **VpnPlatformLab** through the VM's Windows VPN settings. This exact
background activation is a live gate; if it fails, retain deployment/RasClient
events and the package log before debugging setup. Do not treat it as DNS failure.

The log is `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\vpn-probe.log`.
Require `CONNECTED mode=all`, the synthetic /32 route, unchanged Dnscache service
state and successful All-stage replies below. Capture effective NRPT output as
evidence, but do not assume every platform connection policy must appear there;
an empty NRPT listing alone is not a negative DNS result. Capture:

```powershell
Get-VpnConnection -Name VpnPlatformLab | Format-List *
Get-NetRoute -DestinationPrefix '198.18.0.53/32'
Get-DnsClientNrptPolicy -Effective | Format-List *
Get-Service Dnscache
.\Run-Matrix.ps1 -InsideDisposableVm -Stage All -AssignmentSource Runtime -ResultPath .\runtime-all.json
```

Require every row to pass with .10 / ::a. Both direct-UDP probes must also pass.
If platform setup works but the in-plugin receive injection fails, repair the
fixture before proceeding. That failure says nothing about DNS application scope.

## Select exactly one EXE

Disconnect the lab VPN in VM settings, then:

```powershell
$labConfig.Probe.Mode = 'selected'
Set-VpnConnection -Name VpnPlatformLab -CustomConfiguration $labConfig
```

Reconnect and capture route/NRPT/profile/log again. Compare configured SelectedExe
with the `exe=` path recorded by the probes. Run:

```powershell
.\Run-Matrix.ps1 -InsideDisposableVm -Stage Selected -AssignmentSource Runtime -ResultPath .\runtime-selected-suffix.json
```

The direct-filter gate is mandatory: Selected reaches synthetic VPN DNS, while
Unselected cannot. If it fails, all DNS architecture findings are inconclusive.
The two direct probes use distinct names. Require Selected's name in the VPN
log and absence of Unselected's name there; a timeout by itself does not prove
its request was excluded. The matrix accepts only Winsock access denied (10013),
network/host unreachable (10051/10065), connection reset (10054, for example from
an ICMP rejection), or timeout (10060) as a provisional negative network result.
Startup/argument errors and malformed received datagrams fail the gate. Confirm
the log evidence before accepting `FilterGatePassed` as architectural evidence.
If it passes, inspect ordinary DNS rows: Selected must return .10 / ::a and
Unselected .20 / ::14 for the identical name, including reversed warmup order.
Inspect both resolver logs. A selected-only fresh query must never reach control
DNS, and an unselected-only fresh query must never be answered by the VPN fixture.

The coordinated cold launch records API-call timestamps. A shared scheduled start
is not a guaranteed DNS-responder barrier: do not claim demonstrated overlapping
in-flight queries from this alone. Add a controlled two-responder hold/release
barrier before making that stronger claim.

## Compare profile-provisioned policy

This additional variant uses the public packaged management API. It places DNS
namespace and EXE filters in `VpnPlugInProfile` before connection. The plug-in
then calls `StartWithMainTransport` without assigning runtime DNS/filter policy.
The synthetic /32 route, assigned address and packet responder remain identical.
Disconnect **every other lab VPN** first; simultaneous profiles contaminate the
comparison. Keep Dnscache running and retain both resolver logs.

The helper is outside the package, but the management call runs inside the
capability-bearing packaged `Provision` entry point. Invoke only in the VM:

```powershell
$labPackage = Get-AppxPackage -Name VpnPlatformResearch
$labExe = (Resolve-Path .\out\Selected.exe).Path
# Reuse the VM's verified literal lab transport address, not a public VPN server.
.\out\ProfileActivate.exe --inside-disposable-vm $labPackage.PackageFamilyName profile all .vpn-probe.test $labExe $labTransportIp
$labResult = Join-Path $env:LOCALAPPDATA ('Packages\' + $labPackage.PackageFamilyName + '\LocalState\profile-provision.txt')
Get-Content -LiteralPath $labResult
```

Activation prints a fresh `request={GUID}`. Wait for that **same request ID** and
`CREATED_AND_VERIFIED VpnPlatformLab-profile-all-suffix` in the result. An older
file, missing file, `SETUP_ERROR`, or created-profile readback mismatch fails the
setup gate. Do not proceed based on helper exit zero alone. The helper refuses an
existing name and never replaces/deletes it; use a fresh snapshot when repeating
profile creation. Readback checks exact EXE identity, split routing, namespace,
single synthetic DNS server, and absence of AppTriggers/proxies/default routes.

Connect **VpnPlatformLab-profile-all-suffix** in the VM's Windows VPN settings.
Require `CONNECTED mode=all source=profile namespace=.vpn-probe.test` in the log,
capture profile/route/NRPT evidence, then run:

```powershell
.\Run-Matrix.ps1 -InsideDisposableVm -Stage All -AssignmentSource Profile -ResultPath .\profile-all-suffix.json
```

After All passes, disconnect it, provision the selected variant and inspect the
fresh matching-ID result using the same steps:

```powershell
.\out\ProfileActivate.exe --inside-disposable-vm $labPackage.PackageFamilyName profile selected .vpn-probe.test $labExe $labTransportIp
Get-Content -LiteralPath $labResult
```

Connect only **VpnPlatformLab-profile-selected-suffix**. Require the corresponding
`CONNECTED mode=selected source=profile` log and run the same matrix:

```powershell
.\Run-Matrix.ps1 -InsideDisposableVm -Stage Selected -AssignmentSource Profile -ResultPath .\profile-selected-suffix.json
```

All direct-filter and DNS/cache gates above apply unchanged. A profile creation
success is not evidence that the platform applied the filter at connection.
For the strict comparison, repeat these provisioning steps with source `runtime`
and names `VpnPlatformLab-runtime-all-suffix` / `VpnPlatformLab-runtime-selected-suffix`.
That holds the management API constant and varies only where policy is assigned.

Repeat each source with namespace `.`; the corresponding names end in `-root`.
Pass `-Namespace .` to the matrix and use separate result files. The in-memory
root object test is already covered, but actual all-domain semantics remain a
live VM gate. Root namespace may disrupt unrelated VM resolution; keep the VM
dedicated to this experiment and restore its snapshot afterwards.

## Required extensions before adoption

- Disconnect, set `Namespace` to `.`, reconnect, rerun All and Selected with new
  result files. A suffix-only pass is not an all-domain pass. The test responder
  still answers only the lab suffix; ordinary VM name resolution may stop.
- Carry an identical name across connect/disconnect/reconnect, in both warmup
  orders. The stock stage matrices regenerate names and do not cover that case.
- Complete the profile-provisioned versus runtime comparison above, recording
  which path Windows accepted. AppTrigger provisioning remains a separate
  untested extension; neither implemented variant auto-connects the VPN.
- Add a selected app-only cold-query phase, controlled resolver loss, TCP fallback,
  IPv6 transport, out-of-namespace controls and brokered service callers. Current
  AAAA testing is over IPv4 UDP, not IPv6 routing.
- For a DNS-only sidecar, verify actual provider-DNS forwarding via the owned
  OpenVPN interface/session, including failure/reconnect. The synthetic resolver
  proves no real provider forwarding or OpenVPN integration.
- App-owned DoH/DoT is a separate unresolved requirement; a pass of Windows DNS
  APIs must not be presented as universal enforcement for it.

Export all JSON results, raw resolver logs, profile/route/NRPT evidence and OS
build. Disconnect the lab VPN and revert the VM snapshot. Reverting the snapshot
removes only this disposable environment's test package/certificate/NIC changes;
no host cleanup should be necessary.

Primary command/API references:
[Add-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/add-vpnconnection?view=windowsserver2025-ps),
[Set-VpnConnection](https://learn.microsoft.com/en-us/powershell/module/vpnclient/set-vpnconnection?view=windowsserver2025-ps),
[VpnChannel](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel?view=winrt-26100).
