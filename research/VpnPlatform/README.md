# Windows VPN Platform: per-EXE DNS scope investigation

Status, 2026-09-26: **paused while the PIA-style alternative is implemented; no live VPN-platform verdict**.
The user selected the previously reserved DNS Client replacement approach.
This fixture is retained for future investigation; its offline results do not
establish a runtime success or failure. The disposable VM did not reach a verified
desktop/Tools/baseline snapshot and its VMX/VMDK subsequently disappeared from
the prepared directory. No package or VPN profile was activated there.
This directory is independent of the shipping UI, redirector and installer.
CI builds and validates it offline; CI never registers or connects the VPN.
No package was registered, no certificate was created/trusted, and no VPN/DNS
listener or system-setting mutation was performed on the development host.

The question is precise: with Dnscache running, two ordinary EXEs resolve the
**same name**. Selected.exe must use the VPN resolver; Unselected.exe must keep
using its original resolver, including when one answer is already cached.

## Current verdict

- Windows VPN Platform exposes per-EXE traffic filters and VPN DNS namespace
  assignment. That is enough to build a falsifiable experiment, not enough to
  certify per-EXE DNS semantics.
- Absence of AppId from `VpnDomainNameInfo`/VPNv2 DNS rules is **not proof** that
  Windows DNS cannot carry application context internally. A newly inspected
  SDK declaration explicitly contains that context; details below.
- No primary source found establishes the required same-name/two-EXE behavior.
  It has neither been demonstrated nor ruled out by the local offline tests.
- A literal guarantee covering every app's own DNS implementation is already
  outside the NRPT contract: Microsoft explicitly says applications with their
  own DNS implementation bypass those policies. Routing an app-owned HTTPS
  resolver connection through a VPN also does not turn it into a query to the
  VPN provider's DNS server. [VPNv2 CSP, DomainNameInformationList](https://learn.microsoft.com/en-us/windows/client-management/mdm/vpnv2-csp#deviceprofilename-domainnameinformationlist).

## Evidence and its limits

### Two independently assigned policy variants

The same packet fixture and resolver matrix now support these explicit variants:

| Source | DNS and EXE policy | Channel start |
| --- | --- | --- |
| `runtime` | Constructed in the plug-in at Connect | `StartWithTrafficFilter` for Selected; `StartWithMainTransport` for All |
| `profile` | `VpnPlugInProfile.DomainNameInfoList` and `TrafficFilters`, saved before Connect | `StartWithMainTransport`, with no runtime DNS/filter assignment |

`ProfileActivate.exe` activates this package's separate provisioning application
only with `--inside-disposable-vm`. The packaged application has the documented
`networkingVpnProvider` capability and calls `VpnManagementAgent.AddProfileFromObjectAsync`.
It never connects the profile. It refuses an existing name, performs no profile
replacement/deletion, and verifies the saved policy by reading it back. A setup
result carries a fresh request ID, so a previous successful result cannot satisfy
a later activation. A missing/different result or capability error is a setup
failure, not a negative DNS-isolation result.

The helper can provision both sources through the same management API. Use that
pair for a controlled comparison; the older `Add-VpnConnection` runtime recipe
is also retained. No `AppTrigger`, SYSTEM/Dnscache exception, proxy, or default
route is added. Only one lab profile may be connected during each matrix run.

`ProfileTests.exe` checks eight combinations of source, mode and namespace plus
negative policy cases using real WinRT objects in memory. It does not instantiate
`VpnManagementAgent`. These tests exposed a setup bug before VM deployment:
the WinRT suffix constructor rejects `.vpn-probe.test` with `E_INVALIDARG` on the
tested Windows build. It requires `vpn-probe.test` with type `Suffix`; the shared
builder now performs that conversion. Special root `.` is accepted, but its
`DomainName` getter is null, which readback validation handles explicitly. This
observation establishes object construction only, not root-policy behavior.

Primary contracts: [VpnPlugInProfile](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnpluginprofile?view=winrt-26100),
[TrafficFilters](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnpluginprofile.trafficfilters?view=winrt-26100),
[DomainNameInfoList](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnpluginprofile.domainnameinfolist?view=winrt-26100),
[AddProfileFromObjectAsync](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnmanagementagent.addprofilefromobjectasync?view=winrt-26100).

### Microsoft implementation sample, pinned

Inspected Microsoft/UwpVpnPluginSample commit
`d589fe0f57af13e052c44c662ade5fb1da2bcbb0`:

- [CustomConfiguration.cs:343](https://github.com/microsoft/UwpVpnPluginSample/blob/d589fe0f57af13e052c44c662ade5fb1da2bcbb0/CSharp/TestVpnPluginAppBg/CustomConfiguration.cs#L343)
  constructs traffic filters from separate application identifiers.
- [CustomConfiguration.cs:822](https://github.com/microsoft/UwpVpnPluginSample/blob/d589fe0f57af13e052c44c662ade5fb1da2bcbb0/CSharp/TestVpnPluginAppBg/CustomConfiguration.cs#L822)
  constructs DNS namespace entries independently, using suffix and server lists.
- [VpnPlugin.cs:514](https://github.com/microsoft/UwpVpnPluginSample/blob/d589fe0f57af13e052c44c662ade5fb1da2bcbb0/CSharp/TestVpnPluginAppBg/VpnPlugin.cs#L514)
  passes both assignments to `StartWithTrafficFilter`.
- [Background task](https://github.com/microsoft/UwpVpnPluginSample/blob/d589fe0f57af13e052c44c662ade5fb1da2bcbb0/CppWinRT/TestVpnPluginAppBg/TestVpnPluginAppBgTask.cpp#L10)
  retains one plug-in instance and dispatches platform events with
  `VpnChannel.ProcessEventAsync`.

The sample demonstrates the public boundary; Windows' DNS service/connection
manager implementation is not supplied by this sample. It contains no two-app
DNS isolation test. Its configuration layout alone cannot answer the question.

There is a documentation/source discrepancy worth preserving: the API page says
the transport supplied to Start should be unconnected, while the pinned sample
explicitly associates/connects its transport before Start. This fixture follows
the sample. Successful `All`-mode activation, route creation and DNS replies are
mandatory before interpreting any selected-app failure.
[StartWithTrafficFilter documentation](https://learn.microsoft.com/en-us/uwp/api/windows.networking.vpn.vpnchannel.startwithtrafficfilter?view=winrt-26100).

### New AppId-bearing DNS connection-policy lead

The installed SDK 10.0.26100.0 and Microsoft/win32metadata commit
`5c5efbc01d4c87f6830ec304d42777991d533154` declare:

- `DNS_CONNECTION_POLICY_ENTRY`: host, application ID, application SID,
  connection-name list and flags.
- `DNS_CONNECTION_POLICY_ENTRY_ONDEMAND`, and policy tags named DEFAULT,
  CONNECTION_MANAGER and WWWPT.
- `DnsConnectionSetPolicyEntries`, deletion by policy tag, and
  `DnsConnectionUpdateIfIndexTable` to relate connection names to interfaces.

Primary source: [WinDNS.h:1558](https://github.com/microsoft/win32metadata/blob/5c5efbc01d4c87f6830ec304d42777991d533154/generation/WinSDK/RecompiledIdlHeaders/um/WinDNS.h#L1558).

These declarations demonstrate an AppId-aware policy representation. They do
**not** document whether ordinary DnsQuery/GetAddrInfo queries consult it, whether
it selects DNS servers rather than activating connections/selecting proxies,
what zero versus ONDEMAND means, the accepted desktop AppId syntax, cache keys,
or ownership/restore semantics. No supported behavioral contract or Microsoft
sample using these setters was located. No setter was called.

Read-only PE inspection confirmed SetPolicyEntries, UpdateIfIndexTable and the
private policy exports exist in the host's dnsapi.dll. The setter is not simply
a one-instruction error stub; it validates inputs and delegates. This still
does not establish its effect on DNS queries. Recorded binary:

- file version: `10.0.26100.9278 (WinBuild.160101.0800)`;
- SHA-256: `717EED809C8B79DF7258C51E46C8FBB876F29F4CF35EA2875AE19FC35C2C69A4`.

Treat direct use of these setters as a separate VM research path. In particular,
deletion by a shared tag is not an adequate proven ownership/rollback model.
Do not infer that ONDEMAND makes the API irrelevant, or that AppId makes it a
supported arbitrary-EXE resolver override. Both claims require more evidence.

### Existing implementations do not settle the missing experiment

- The independent WireGuard UWP implementation at commit
  `328e622fb613d611bb022874a6535e2846ac6640` installs namespace rules, then calls
  the older `Start` API without per-app filters. Its wildcard DNS behavior does
  not prove what `StartWithTrafficFilter` does.
  [plugin.rs:154](https://github.com/luqmana/wireguard-uwp-rs/blob/328e622fb613d611bb022874a6535e2846ac6640/plugin/src/plugin.rs#L154).
- Omnissa's Windows Tunnel 25.11 notes describe DNS configuration across all
  interfaces by default; 25.08 stopped using NRPT and documented cross-app
  domain-lockdown effects. These are useful counterexamples to equating the
  product label “per-app VPN” with our DNS guarantee, not proof about the
  implementation of Microsoft's plug-in platform.
  [Vendor release notes](https://docs.omnissa.com/Workspace_ONE_Tunnel_Windows-RN/Tunnel-Windows-ReleaseNotes).

## Build and host-side validation

Requires MSVC x64 and Windows SDK **10.0.26100.0** already installed. It uses
C++/WinRT headers directly, with no NuGet dependency, UWP/XAML workload, signing
key, package deployment or driver. The package intentionally requires **Windows
11 x64 / build 22000+**; it uses newer packet append/flush methods and makes no
Windows 10 compatibility claim.

```powershell
./research/VpnPlatform/build.ps1
```

The build compiles the native clients, control responder, VPN host/activation
module and profile provisioning helpers, runs offline codec, profile-object and local COM-factory tests, then validates and packs an
**unsigned** Appx using MakeAppx. The COM test creates IBackgroundTask but never
calls Run. It proves local ABI/factory behavior, not package activation by the
VPN broker. Only the build/offline tests were run on the host.
The [saved build evidence](BUILD-EVIDENCE.md) records versions, check results
and the unsigned package checksum; runtime status remains **NOT RUN**.

Files in `out/` are ignored by Git. Copy that folder plus Run-Matrix.ps1 and
the [VM runbook](VM-RUNBOOK.md) into the disposable VM. No .NET runtime is needed.

## The experiment

The plug-in creates only a synthetic IPv4 resolver route (`198.18.0.53/32`) and
an assigned address (`198.18.0.2`). It answers laboratory A/AAAA requests inside
the plug-in; no commercial VPN account or real VPN server is needed. An outer
UDP socket is associated with a literal VM-lab address as required by the
platform; no external response is trusted or forwarded. Actual broker/channel
activation remains a live-test prerequisite, not an offline-test result.

- Control DNS: `127.0.0.53:53`, answer `203.0.113.20` or `2001:db8::14`.
- Synthetic VPN DNS: `198.18.0.53:53`, answer `203.0.113.10` or `2001:db8::a`.
- Both use TTL 60, so an incorrect shared cache can be detected.
- Only `*.vpn-probe.test` is answered. Other data is dropped, never forwarded.
- Selected.exe and Unselected.exe are copies of the same native probe. Ordinary
  tests use DnsQuery_W with standard flags or GetAddrInfoW, with no custom-server
  API. A separate direct-UDP mode validates the actual EXE traffic filter.

The first namespace is `.vpn-probe.test`. A separate **VM-only** `Namespace=.`
variant is required before making any all-domain claim. Profile connection,
disconnect, namespace changes and VM system-DNS setup are not automated by build.

Interpretation gates:

1. `NoVpn`: both EXEs return control answers.
2. `All`: both return VPN answers, including direct UDP. This proves the test
   channel/namespace/packet fixture actually work.
3. `Selected`: direct UDP by Selected.exe succeeds; Unselected.exe is excluded.
   Exact launched EXE paths are recorded. A failure here makes DNS conclusions
   **inconclusive**, rather than demonstrating loss of DNS-client identity.
4. Only after those gates: same-name queries in both warm-cache orders and a
   coordinated fresh-name launch must return the correct per-EXE answers.

Run-Matrix records mandatory `AssignmentSource` and the chosen `Namespace` in
each result; they must agree with the connected profile and plug-in log. These
labels are operator assertions, not automatic proof of the active configuration.
Run-Matrix coordinates the launch timestamp but has no responder barrier; this
does **not** guarantee overlapping in-flight DNS queries. The baseline does not
test TCP DNS, IPv6 transport, retained cache across reconnect, out-of-namespace
effects, loss/fallback, brokered requests, or app-owned encrypted DNS. AAAA tests
still use IPv4 UDP transport. The runbook contains the further required cases.

A failure after valid gates refutes this exact configuration/OS build. It does
not rule out the other policy source. Both `runtime` and `profile` must pass their
own All/Selected gates; adding AppTriggers is still a separate untested variant.

## Conditional integration: DNS-only sidecar

If native Windows DNS passes the app/context/cache tests, the platform need not
necessarily replace OpenVPN's entire data plane. A second VPN-channel adapter
could own only the synthetic DNS address; its DNS packets could be serviced by
an authenticated local broker that sends requests to provider DNS through the
existing OpenVPN-owned DCO interface. This keeps OpenVPN.exe and the main packet
backend. It is a hypothesis enabled by the API shape, not an implemented fix.

Before adopting it, prove provider resolver capture, broker egress on the exact
current OpenVPN lease, loop prevention/WinDivert exclusions, DNS-only filters,
package-to-broker IPC permissions, TCP fallback, reconnect revocation, and no
effect on unselected apps. Packet inspection after Dnscache cannot invent an
AppId the platform did not preserve. Adding an explicit blanket Dnscache allow
rule to make this test pass would invalidate the selected-app requirement.

The hard blocker to a runtime verdict is a disposable, accessible Windows 11 VM
with permission to register the package and change **that VM's** test DNS/VPN
state. The development host is not that test environment. An unsigned build,
source inspection or ordinary process-local DNS tests cannot substitute for it.
