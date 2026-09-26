# Experimental DNS recovery guard

This is an original implementation; no PIA/GPL source is incorporated. It is a recovery component for the explicitly enabled experimental DNS mode, not a DNS resolver or a claim that all application DNS is protected.

## Build and validation

`dotnet restore dotnet/VpnClient.DnsGuard/VpnClient.DnsGuard.csproj --locked-mode`

`dotnet publish dotnet/VpnClient.DnsGuard/VpnClient.DnsGuard.csproj -c Release --no-restore`

The default output is a Windows x64 self-contained **directory**, with `PublishSingleFile=false`: `bin/Release/net8.0-windows/win-x64/publish`. Install the complete directory as `{app}/DnsGuard` under protected Program Files. Runtime DLLs, configuration, executable and all their ancestor paths must have trusted ownership, no unprivileged write permissions and no reparse points. No LocalSystem single-file extraction is used.

`dotnet restore dotnet/VpnClient.DnsGuard.Tests/VpnClient.DnsGuard.Tests.csproj --locked-mode`

`dotnet test dotnet/VpnClient.DnsGuard.Tests/VpnClient.DnsGuard.Tests.csproj -c Release --no-restore`

Tests target the installed .NET 10 test runtime and link the exact production engine/protocol/recovery-policy/transition sources. They never invoke SCM or registry mutation. The 62 tests cover every observed activation crash boundary, sustained journal write failure, foreign registry/process conflicts, ownership death/cancellation, partial writes, failed restart, maintenance ownership, interrupted service installation, release after rejected acquisition, missed STOPPED intervals and owned-stub shutdown races. Live acceptance of the 1.3.1 transition fix, boot recovery and provider DNS traffic is **NOT RUN**. Build/unit success does not validate SCM behavior on a particular Windows build.

The user installed an intermediate 1.3.0 and observed `service_timeout`. Read-only SCM logs show Dnscache terminating at 21:28:22/21:28:33 and 21:30:00/21:30:10, with a configured one-second automatic restart; afterward the original Dnscache was RUNNING and the guard STOPPED. A missed transient STOPPED interval is consistent with that evidence; the old phase was not independently recovered from the protected journal. Version 1.3.1 fixes the demonstrable state-machine race: transitions accept a verified already-running target, including automatic restart, and timeout reasons identify `stub_start`, `original_restore` or the guardian operation. Restoration first requests a graceful STOP for an exact owned stub when the existing Dnscache ACL permits it; otherwise it may terminate only that retained stub. No Dnscache ACL or failure actions are changed.

## Command contract (version 1)

All ordinary commands print one JSON result with `version`, `status`, nullable `lease`, controlled `reason`, and nullable `message`. Statuses are `off`, `preparing`, `active`, `restoring`, `unsupported`, `recoveryRequired`, or `busy`. Exit codes: 0 normal result, 2 unsupported, 3 busy, 4 recovery required/error. Raw exception detail is not emitted.

* `inspect`: read-only; creates no store, service or synchronization object. An executable outside its protected installed location reports `unsupported/unsafe_install_location`.
* `acquire --lease GUID --owner-pid PID --owner-created FILETIME --backend-pid PID --backend-created FILETIME`: validates the exact installed UI/backend images, user/session and process identities; waits up to 30 seconds for confirmed activation. Helpers must not be put in the UI Job.
* `release --lease GUID`: refuses another pending/active lease, stops/recoveries its own lease, and acknowledges the requested GUID when off, even if an older completed journal remains.
* `recover`: refuses a live owner/backend pair; otherwise restores stale state through the verified recovery service.
* `uninstall --maintenance-owner PID`: records the setup process's actual PID/FILETIME under machine-wide serialization, refuses a live foreign maintenance owner or live DNS lease, restores stale state, stops and deletes only the verified guard service.
* `maintenance-complete --maintenance-owner PID`: removes only the matching setup marker. A stale marker is discarded on later acquisition. Custom-directory installs that never created any guard registration, unfinished journal or marker can uninstall through a read-only no-op path.
* `service` and `stub-service --lease GUID`: SCM-only roles requiring LocalSystem and NetworkService respectively.

## Recovery and refusal rules

`VpnClientDnsGuard` is installed only during explicit acquisition, as an automatic LocalSystem service. Its base configuration and restart policy are verified; a partially installed existing service is repaired before acquisition. Service starts without the one-shot acquisition GUID (boot/restart) **only restore**. They never activate the experiment. The guardian holds exact UI/backend kernel process handles throughout the lease and restores on owner death, backend death or STOP.

Before modifying Dnscache, a write-through journal containing the original `ImagePath` and `Type` is atomically replaced and flushed in the protected `%ProgramData%/VpnClient.DnsGuard` directory. Only those two values change. `ObjectName`, `Start` and `ServiceDll` are untouched. The original registry values are restored immediately after the replacement stub is confirmed RUNNING; only then may the lease become active. Recovery uses the immutable original state even when subsequent journal writes fail; inability to persist completion still reports `recoveryRequired`.

Supported original configurations are the known NetworkService System32 svchost command, type `SERVICE_WIN32_SHARE_PROCESS` or `SERVICE_WIN32_OWN_PROCESS`, running under NetworkService. Both require the trusted Microsoft Windows-signed executable, retained process identity and complete service peer visibility. Shared-process type additionally requires an explicit `-s Dnscache` process command. Own-process type may omit that argument. Status access denied for any registered service, a peer sharing the PID, transient service visibility, an unknown command, signature uncertainty or incompatible service SID configuration causes refusal. No fallback kills other NetworkService processes.

Recovery terminates only a retained process whose image, command (including lease) and current Dnscache PID identify this guard's stub. Unknown registry changes are preserved and reported as conflicts. Registry checks are optimistic comparisons under our machine-wide ownership; Windows does not provide a multi-value registry compare-and-swap that excludes unrelated administrative editors. Concurrent privileged tampering remains outside the guarantee.

The approach still changes DNS Client service behavior for the machine. The separate redirector is responsible for deciding which selected applications' supported DNS packets use the VPN provider. DoH, unsupported resolver behavior, reboot ordering, Windows protection restrictions and actual installed service transitions require live acceptance before a production reliability claim.

## Primary Windows API references

* [Service process types](https://learn.microsoft.com/en-us/windows/win32/services/service-programs)
* [ChangeServiceConfig2W](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w): restart actions require `SERVICE_START`; queued restarts may survive a manual stop.
* [EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw): inaccessible services can be silently omitted, so an empty enumerated peer list alone is insufficient.
* [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex): PID validity depends on state.
* [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess): termination is asynchronous and the retained process must be waited on.
