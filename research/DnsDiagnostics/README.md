# Windows DNS diagnostic probe

This isolated research executable compares Windows resolver APIs with direct DNS transport. It changes no DNS settings, services, registry entries, routes, or capture configuration. It does not activate the experimental mode. Each invocation makes one A lookup for `browserleaks.com` or `example.com` and prints one JSON object, without returned addresses or other RDATA.

## Build and run

Requirements: Windows x64, installed MSVC x64 C++ tools, Windows SDK `10.0.26100.0`. The build uses the static C++ runtime and installs nothing.

```powershell
& .\research\DnsDiagnostics\Build.ps1
# Output: target\dns-diagnostics\DnsProbe.exe

# CI/offline: compile both executables and run 12 artificial-packet checks, with no DNS/network calls.
& .\research\DnsDiagnostics\Build.ps1 -RunCodecTests

# Recommended: supervised comparison, using the actual resolver under investigation.
pwsh -File .\research\DnsDiagnostics\Invoke-Probe.ps1 -DnsServer 192.168.1.1 -Query browserleaks.com -Label off-baseline

# One bounded comparison at the next user-controlled activation (no automatic activation/restoration):
pwsh -File .\research\DnsDiagnostics\Wait-ActiveProbe.ps1 -DnsServer 192.168.1.1 -WaitSeconds 180

# Run the API modes only through a process supervisor with a deadline:
DnsProbe.exe getaddrinfo browserleaks.com
DnsProbe.exe dns-standard browserleaks.com
DnsProbe.exe dns-wire browserleaks.com

# Replace the address with the actual resolver being investigated; no fallback is chosen.
DnsProbe.exe udp browserleaks.com 192.168.1.1
DnsProbe.exe tcp browserleaks.com 192.168.1.1
```

`Invoke-Probe.ps1` is the supervising runner: each mode uses a fresh child, with a six-second process deadline. A blocked Windows resolver API has no in-process timeout here; do not invoke those modes without supervision. Raw UDP/TCP uses a single two-second nonblocking socket deadline for connect, send, and receive. TCP does not silently substitute UDP or vice versa. Only the supervising runner can terminate its own timed-out child.

`Wait-ActiveProbe.ps1` polls only SCM/process metadata for up to the supplied deadline.
It triggers once after both the guardian and a Dnscache process named
`VpnClient.DnsGuard` remain running for one second. This avoids relying on a chat
reply arriving while system DNS is broken. The user controls activation and
restoration; the script does neither. The result still records service state
before and after the probes, which must be checked before treating it as Active.
The watcher prints its UTC start/deadline and changes in the observed SCM/process
state. A process-metadata read failure is reported rather than silently treated
as proof that the original DNS service is running.

`TestCodec.cpp` compiles the production parser in a separate test executable. Its 12 offline checks cover positive A/CNAME answers, NODATA/NXDOMAIN, missing records, truncated CNAME data, alias cycles, trailing bytes, invalid A length, a mismatched question, and unrelated A records. It never invokes the probe CLI or a networking API. These checks validate decoding; they do not replace live socket/API comparisons.

The raw resolver argument must be an IPv4 literal; the port is always 53. Zero, broadcast, multicast, and reserved high address ranges are rejected. Private and loopback resolvers are allowed when explicitly supplied. The source does not contain a public resolver fallback.

## Result contract

All JSON values are metadata. `statusKind` identifies the meaning of `status`: `gai` (GetAddrInfoW), `dns` (DNS_STATUS), `winsock`, `win32`, or `input`. Exit codes are 0 for a positive A result, 1 for a diagnostic failure, and 2 for invalid arguments. The runner must also retain the child exit code and timeout result.

The runner's `label` is only a filename tag. Its `serviceObservation` separately
classifies both service snapshots as `observedStub`, `observedOff`, or
`transitionOrUnknown`. The combined mode requires matching classes and unchanged
Dnscache/guardian PIDs before and after the probes. `observedStub` means the stub
and guardian were running at those two observations; it does not certify backend
readiness, continuous state between snapshots, or successful DNS isolation.

| Field | Meaning |
| --- | --- |
| `version`, `mode`, `query` | Schema version 1 and the whitelisted invocation. Invalid arguments are not echoed. |
| `elapsedMs` | Whole invocation duration measured with GetTickCount64. |
| `rcode` | Raw response's base four-bit DNS RCODE, otherwise null; not inferred from API status. |
| `answerCount` | Raw DNS header ANCOUNT, or the number of returned API record/address nodes. These are different representations. |
| `idValid` | Raw response transaction-ID equality, otherwise null. |
| `responseValid` | Raw header/question, RR boundaries, A-record length, and answer CNAME-chain validation. Null when no complete response was obtained, or for API modes. |
| `addressCount` | Raw answer-section A records reachable from the requested name through CNAMEs; for API modes, returned A/address nodes. No address values are printed. |
| `truncated` | Raw TC flag, otherwise null. UDP does not automatically retry TCP. |
| `ok` | Status zero, no nonzero raw RCODE, a positive A/address count, and no raw TC flag. |

A raw NXDOMAIN response therefore has transport status 0, RCODE 3, and `ok: false`. Valid NOERROR/NODATA also has `ok: false`. An incomplete/malformed raw message has Win32 `ERROR_INVALID_DATA` (13); available header metadata remains visible. Nonblocking TCP connection errors are obtained with `SO_ERROR` after readiness in either write or exception sets, so connection refusal is not deliberately converted into a timeout. Validation is structural and query-correlated, not DNSSEC verification or comprehensive validation of unknown RR payloads.

## Interpreting the comparison

The modes are deliberately different:

- `getaddrinfo`: GetAddrInfoW, AF_INET, SOCK_STREAM.
- `dns-standard`: DnsQuery_W, type A, DNS_QUERY_STANDARD.
- `dns-wire`: DnsQuery_W, type A, DNS_QUERY_WIRE_ONLY | DNS_QUERY_TREAT_AS_FQDN.
- `udp` / `tcp`: a native Winsock query to the explicit peer, random transaction ID, A/IN question, no Windows DNS API call.

WIRE_ONLY bypasses local information according to Microsoft; it does **not** establish that the DNS Client service's RPC path is bypassed. Direct UDP/TCP is the independent transport control. Standard API success can come from cache. Parallel API runs can share and populate the machine cache, so successful API results do not prove that each invocation sent a packet.

API failures with successful raw transport identify a useful separation between the Windows API path and the tested transport path. They do not, by themselves, identify a particular DLL, RPC endpoint, service-stub defect, or browser failure. A raw reply also does not prove that another process used the same resolver or route. An Off baseline does not test Active service-stub compatibility; the mode and service state must be recorded for every comparison. Browser `DNS_PROBE_FINISHED_NXDOMAIN` is not a substitute for an observed DNS RCODE.

This probe is not shipped in the installer and is not a production DNS health check. The source and build may be reviewed offline; any later Active comparison must be separately coordinated with the user. No part of the probe toggles the experimental mode.

## Primary API references

- [DnsQuery_W](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsquery_w)
- [DNS query option constants](https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants)
- [GetAddrInfoW](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfow)
- [Winsock select, including nonblocking connect failure](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select)
