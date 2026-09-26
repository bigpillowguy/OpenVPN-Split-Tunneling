using Vpnclient.Status;

namespace VpnClient.Ui;

internal static class ExperimentalDnsReadiness
{
    internal static DnsEligibility? Evaluate(bool connected, bool splitDnsMode, Snapshot? snapshot,
        VpnSessionBinding? binding, DnsProcessIdentity? backend)
    {
        if (!connected || !splitDnsMode || backend is null || binding is null || snapshot is null || !SnapshotValidator.IsValid(snapshot) ||
            snapshot.Vpn?.Up != true || snapshot.SplitDns is not { Enabled: true, Ready: true } state ||
            binding.Dns is not { Status: "ready" } dns || dns.Servers.Count == 0 ||
            state.SessionId != binding.SessionId.ToString("N") || state.Generation != dns.Generation.ToString("N") ||
            snapshot.Vpn.AdapterIp != binding.Ipv4) return null;
        return new(binding.SessionId, dns.Generation, backend);
    }
}

internal static class ExperimentalDnsDiagnostics
{
    internal static string Format(SplitDnsState? state, bool active, bool fresh)
    {
        if (!active || !fresh || state is not { Enabled: true } || (state.Dropped == 0 && state.Fault.Length == 0)) return "";
        var reason = state.Fault switch
        {
            "unknown_owner" => "application owner unavailable",
            "ambiguous_owner" => "socket has ambiguous ownership",
            "unavailable_policy" => "application policy unavailable",
            "unavailable_session" => "current VPN DNS unavailable",
            "unsupported_transport" => "unsupported DNS transport",
            "invalid_packet" => "unclassifiable packet",
            "revoked" => "session or application changed",
            "" => "",
            _ => "DNS routing error",
        };
        // Only fixed labels and a counter reach the UI; never display arbitrary backend data.
        return $" Blocked packets: {state.Dropped}" + (reason.Length == 0 ? "." : $" ({reason}).");
    }
}
