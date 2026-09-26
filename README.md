# OpenVPN Split Tunneling Client

Choose Windows executable files whose IPv4 TCP and UDP traffic should use your
OpenVPN connection. The WPF application starts OpenVPN and a Rust redirector;
the redirector captures packets with WinDivert and forwards selected traffic
through bridge sockets bound to the VPN interface.

This is a community client, not a VPN provider. Supply your own trusted `.ovpn`
profile and any credentials required by your provider.

## Supported behavior and limits

- Selection matches an executable path. Add each executable you want to tunnel,
  including games or helper programs launched by a selected launcher. Child
  processes with different paths are not automatically selected.
- Only IPv4 TCP/UDP are captured. IPv6 and other protocols can use the normal
  connection. Disabling IPv6 on the VPN profile alone does not stop IPv6 on the
  physical interface.
- The client is **fail-open**: when the VPN is unavailable, selected applications
  may use the default route. This is not a kill switch or an anonymity boundary.
- **DNS remains unchanged:** selecting an EXE does not isolate its DNS queries.
  Local and server-pushed DNS/DHCP settings are excluded from the runtime profile.
  System DNS configuration and the Windows DNS Client service remain unchanged.
  Per-application VPN DNS is being investigated with Windows VPN Platform;
  it is not enabled in the client. See [DNS-RESEARCH.md](DNS-RESEARCH.md).
- Each connection uses a temporary profile that suppresses local/pushed routes,
  including `redirect-gateway` and IPv4 `/1` routes. The stored profile is preserved.
  OpenVPN still configures its tunnel interface; the redirector prepares a route
  through that interface with the session's reported gateway. Readiness requires
  that preparation to succeed. Cleanup removes only an unchanged route created
  by this redirector. Interface configuration can still create connected routes.
- The target is the interface reported by this client's OpenVPN process, checked
  against its process creation time, interface GUID/index and assigned IPv4 address.
  Other active VPN adapters are not selected as a fallback. Reconnects revoke old
  flows even when the new interface address and index are unchanged.
- An application's existing connections may need to reconnect when policy or
  VPN state changes. Select apps before starting their network activity.
- Anti-cheat compatibility, packet reinjection behavior across Windows versions,
  and gaming latency require testing with the actual application. Compatibility
  with EAC, Vanguard or BattlEye is not guaranteed.

The unit tests and build pipeline do not replace install/upgrade/uninstall and
packet-capture acceptance tests on a disposable Windows machine. See
[REVIEW.md](REVIEW.md) and [TODO.md](TODO.md) for the audit and verification plan.

## Install and use

The package targets **native x64 Windows 10 version 2004 (build 19041) or newer**,
including Windows 11. ARM64 and 32-bit Windows are not supported by the bundled
WinDivert driver. Use a Windows version still receiving security updates.
Administrator rights are required for installation and application launch.

1. Obtain `VpnClientSetup-<version>.exe` from this fork's
   [Releases](../../releases), when available. The application/installer is
   currently unsigned; only run a build whose origin you trust.
2. Install the application into Program Files. If a compatible native OpenVPN
   installation with a DCO or TAP driver is missing, setup installs the bundled
   OpenVPN Community 2.7.4-I001 prerequisite. Setup reports MSI failures and
   requests a reboot when required.
3. Launch the client, import a trusted profile through VPN settings, and enter
   credentials if required. Supported external certificates and keys are copied
   into a private folder with the profile. Stored credentials use Windows DPAPI
   for the user.
4. Add executable paths under **Manage**, then connect and start the selected
   applications. The main window displays VPN state and traffic statistics.

OpenVPN 2.7 uses DCO/TAP; Wintun was removed upstream. This client lets OpenVPN
choose a compatible driver. An old `windows-driver wintun` option is ignored by
OpenVPN 2.7, rather than providing Wintun support. See the
[OpenVPN 2.7.4 changes](https://github.com/OpenVPN/openvpn/blob/v2.7.4/Changes.rst).

If the window reports **routing unavailable**, inspect the redirector failure
and diagnostic path displayed below the connection state. Each launch keeps
`redirector.log` under `%LOCALAPPDATA%\VpnClient\runtime\<launch-id>\` with one
rotated `.1` archive (up to 2 MiB each). Logs survive normal client shutdown;
the session binding and temporary profile containing keys are removed.
Version 1.2.0 preserves ordinary application startup and DNS while Windows VPN
Platform is tested separately.

Close this client's session before upgrading or uninstalling. Setup uses file
ownership and Windows Restart Manager for in-use application files; it does not
kill all `openvpn.exe` processes or delete a shared WinDivert service. A locked
driver may require a restart. OpenVPN is a separate installed prerequisite and
is not removed when this client is uninstalled.

### Profile import

The importer reads quoted paths and inline blocks, expands nested `config`
files, and copies `ca`, `cert`, `key`, `pkcs12`, `tls-auth`, `tls-crypt`,
`tls-crypt-v2`, `extra-certs`, `crl-verify` files and `dh` dependencies.
Relative paths, including paths inside nested configs, are resolved from the
top-level source profile's directory. Missing files, include cycles, unsupported
directives and oversized inputs are reported before a profile is saved.

Executable hooks/plugins, management overrides, `cd`/`chroot`, external password
files and inline username/password blocks are unsupported. For username/password
authentication use a bare `auth-user-pass` directive and save credentials in the
UI. Encrypted private-key prompts and MFA/challenges remain unsupported.
Imports use a separate directory per profile, so equal filenames do not overwrite
another profile. Imported material is private to the current Windows user;
temporary runtime profiles containing inline keys are removed at session cleanup.

## Architecture

```text
WPF UI (elevated)
  |-- OpenVPN process ------------ VPN interface configuration
  |-- private session binding ---- process identity + interface + gateway
  |-- redirector process --------- WinDivert + smoltcp + bridge sockets
  |-- config.json ---------------- selected executable paths
  `-- status named pipe <--------- VPN and application statistics
```

The UI assigns its OpenVPN/redirector processes to a Windows Job Object before
they run. Normal shutdown signals the redirector to release its network handles
and owned route before closing the Job; the Job provides process cleanup when
the UI exits unexpectedly. Forced termination cannot guarantee route cleanup.

The production redirector does not expose the experimental policy pipe. The
status pipe permits the launching Windows user and SYSTEM, and the UI checks that
the server PID belongs to the redirector process it started. These checks are
implemented in code; cross-user IPC acceptance tests still require a Windows
test environment.

The redirector resolves socket ownership and executable paths, tracks process
identity rather than trusting a reused PID, and periodically reloads selected
paths from `%APPDATA%\VpnClient\config.json`. Policy revisions revoke flows
admitted under an old selection rather than retaining stale PID membership.
TCP streams terminate in smoltcp and bridge to a new Windows socket; UDP uses
per-flow bridge sockets. `IP_UNICAST_IF` binds those sockets to a VPN interface.

OpenVPN 2.7's authenticated `management-up-down` events provide the interface
index and gateway. The UI publishes them only after a matching `CONNECTED` event,
and revokes the binding on reconnect, disconnect or process exit. The redirector
requires this binding (`observe --session-file <path>`) and revalidates it every
250 ms. Authenticated management PUSH metadata supplies DNS separately, without
applying it to the system. `route-noexec` and `route-nopull` enforce the route/DNS policy; a nonexecuted
route supplies OpenVPN's gateway metadata. See the
[OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html).

`supervisor/` is an experimental command-line launcher, not part of the WPF
workflow or installer. Rust `ui/` is a placeholder. Messages declared in the
protobuf schema do not imply that every command/event is implemented.

## Build from source

Use native x64 Windows with:

- Rust **1.98.1 MSVC**, installed with rustup. `rust-toolchain.toml` selects the
  release toolchain. The supported minimum is Rust 1.98; the largest declared
  dependency requirement in the current lockfile is smoltcp 0.13.1's Rust 1.91,
  but older toolchains are not part of this project's supported build baseline.
- Visual Studio Build Tools with **Desktop development with C++**, MSVC x64/x86
  tools and a Windows SDK. The GNU Rust toolchain is not supported here.
- .NET SDK **10.0.400**, selected exactly by `global.json` so servicing SDKs cannot
  silently change the implicit packages required by the committed lockfile.
  The application targets .NET 8 and ships its runtime in the self-contained
  publish output; no separate .NET installation is required on the target PC.
- Inno Setup **6.7 or newer** for installer packaging.

From any directory, supply the absolute path to the script:

```powershell
powershell -ExecutionPolicy Bypass -File C:\path\to\OpenVPN-Split-Tunneling\installer\build.ps1
```

The script enters the repository root, puts rustup before any older system Rust
installation, checks MSVC, builds with `Cargo.lock`, publishes the UI, verifies
NuGet dependencies against `packages.lock.json`, checks the WinDivert staging
files, and compiles setup. It **never executes the setup**.
The output is `installer/Output/VpnClientSetup-1.2.0.exe`.

The bundled OpenVPN download is pinned by SHA-256 and requires a valid OpenVPN
Authenticode signature. Every cached use is checked; downloads are verified
before atomically replacing the cache. `-SkipBuild` packages existing build
outputs but still checks the native files and the prerequisite MSI.

For development, run these commands from the repository root:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./research/VpnPlatform/build.ps1 # offline checks and unsigned VM package only
dotnet restore dotnet/VpnClient.Tests/VpnClient.Tests.csproj --locked-mode
dotnet test dotnet/VpnClient.Tests/VpnClient.Tests.csproj -c Release --nologo --no-restore
cargo build --locked --release -p redirector
dotnet restore dotnet/VpnClient.Ui/VpnClient.Ui.csproj --locked-mode
dotnet publish dotnet/VpnClient.Ui/VpnClient.Ui.csproj -c Release --no-restore
./installer/test-native-staging.ps1
./installer/test-legacy-retirement.ps1
./installer/test-dependencies.ps1  # requires the verified MSI cache from build.ps1
```

Keep `redirector.exe`, `WinDivert.dll` and `WinDivert64.sys` together when running
a built client. Do not rely on a hard-coded developer checkout path.

Both .NET projects keep NuGet lockfiles in source control. When intentionally
updating a package reference, run `dotnet restore <project> --force-evaluate`,
review the lockfile diff and rerun tests. CI and packaging use locked restores
and fail if the package graph disagrees with the committed lockfile.

Windows CI is configured to check formatting, clippy and tests, and produce an
unsigned installer artifact without installing OpenVPN or starting VPN/driver
processes. Product/setup version
`1.2.0` and internal Rust workspace crate version `0.1.0` are separate identifiers.

## Source layout and licenses

| Directory | Purpose |
| --- | --- |
| `dotnet/VpnClient.Ui/` | WPF UI and VPN process management |
| `redirector/` | Rust packet redirector |
| `research/VpnPlatform/` | Windows VPN Platform per-application DNS experiment |
| `ipc/` | Protobuf definitions and framing |
| `installer/` | Build, prerequisite validation, setup, licenses |
| `vendor/windivert/` | WinDivert 2.2.2 binaries and upstream license |
| `vendor/windivert-rs/` | Patched Rust wrapper: metadata-only events and safe overlapped cancellation |
| `supervisor/`, `ui/` | Experimental Rust tools |

This project's own Rust, C# and C++ source is [MIT licensed](LICENSE). Third-party
components retain their own licenses. Setup includes the client license,
WinDivert's LGPLv3/GPL texts and OpenVPN's GPLv2 text and linking exceptions
under `licenses/`. See [third-party notices](installer/licenses/THIRD-PARTY-NOTICES.txt)
for component origins and source links. OpenVPN remains a separate installation.
