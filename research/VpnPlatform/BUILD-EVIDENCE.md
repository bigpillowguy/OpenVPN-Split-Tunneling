# Offline build evidence

Recorded 2026-09-26 at 17:06 UTC. **VPN platform runtime status: NOT RUN.**

Environment:

- Windows 11 Pro for Workstations, version 25H2, build 26200.9457, x64.
- MSVC toolset 14.51.36231, x64 compiler/linker.
- Windows SDK headers/libraries 10.0.26100.0.
- MakeAppx file/tool version 10.0.26100.8249.
- Manifest minimum: Windows 11 build 22000, x64.

Command from the repository root:

```powershell
./research/VpnPlatform/build.ps1
```

Observed successful output from the final build:

```text
52 offline fixture checks passed. No sockets or VPN opened.
51 offline profile checks passed. No management agent, profile registration or network opened.
Activation factory checks passed; background task Run was not called.
Packing 7 file(s) ...
Package creation succeeded.
Built unsigned VM research package ... Nothing installed; no VPN or DNS responder started.
```

All native sources compiled at `/W4` with no compiler/linker warning or error
in the final output. Both PowerShell scripts parsed with zero AST errors.
A previously recorded in-memory check invoked only the extracted `Finish-Probe` function
with fake process/readers: all ten direct-negative-gate cases passed. Accepted
exit/status pairs were exit 1 with status 10013, 10051, 10054, 10060 or 10065;
exit 1/status 13 or 0, and exit 2, 3 or 0/status 10060 were rejected. This test
started no resolver probe and opened no socket.

Generated local artifacts, excluded from Git by `out/`:

| Artifact | Evidence |
| --- | --- |
| `out/VpnPlatformResearch-unsigned.appx` | 326503 bytes; Authenticode status `NotSigned` |
| Package SHA-256 | `3B8FBEA27C7638E4CF846B475E05FFCC76ABF178B56EF315CC10BB9841A78BCA` |
| `out/build-output.txt` SHA-256 | `17C2CCB3D781B3BCA33AB8E94A2CA99B6337DB015FA02F932ED33CA4F1A17ABF` |

The package checksum identifies this particular build, not a reproducible-build
guarantee; a rebuild can change timestamps/checksum. `git check-ignore` confirmed
that the unsigned package is excluded.

The new profile checks construct real `VpnPlugInProfile`, `VpnTrafficFilter` and
`VpnDomainNameInfo` objects in memory for eight runtime/profile, all/selected and
suffix/root combinations. They check serialization, exact policy shape, wrong EXE,
extra DNS server, incorrect URI scheme/port, and invalid/duplicate input fields.
The shared namespace builder uses bare `vpn-probe.test` with type `Suffix`:
passing `.vpn-probe.test` to that WinRT constructor produced `E_INVALIDARG` during
development. Root `.` constructs successfully and exposes a null `DomainName`;
the test validates it without dereferencing null. This is object/API evidence,
not evidence of effective DNS policy or cache isolation.

`ProfileActivate.exe` and the packaged `VpnPlatformProvision.exe` compiled, but
were not activated. In particular, no `VpnManagementAgent` instance was created
and no profile was added/read back on the host. Their explicit VM provisioning,
capability authorization and saved-policy readback remain live setup gates.

The offline factory test loads the local activation DLL and creates its
`IBackgroundTask`. It never calls `Run`; it therefore does **not** validate
package registration, capability authorization, VPN-broker activation, channel
creation, packet receive injection, application filtering or DNS isolation.

Not run: signing, certificate creation/trust, package deployment, VPN profile
creation/connection, DNS responder, resolver matrix, NIC/DNS/route mutation,
or any live VM stage. See [the VM runbook](VM-RUNBOOK.md) for the independent
setup and EXE-filter gates required before drawing a runtime conclusion.
