using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnClient.Ui;

internal sealed record VpnDnsServer(string Address, int Port = 53);

internal sealed record VpnDnsSnapshot(string Status, Guid Generation, IReadOnlyList<VpnDnsServer> Servers,
    string? Reason = null);

/// <summary>
/// A bounded projection of authenticated realtime management LOG messages. Raw PUSH
/// options are never retained. Format verified against OpenVPN v2.7.4/v2.6.14 push.c.
/// Only pushed legacy IPv4 DNS endpoints are supported; no resolver is inferred.
/// </summary>
internal sealed class OpenVpnDnsMetadata
{
    private const string PushLog = "PUSH: Received control message: '";
    private readonly bool _localDns;
    private readonly List<VpnDnsServer> _servers = new();
    private bool _continuing, _complete, _connected, _blocked;
    private int _fragments, _bytes, _options;
    private string? _problemStatus, _problemReason;
    public VpnDnsSnapshot Current { get; private set; }

    public OpenVpnDnsMetadata(bool hasLocalDns = false)
    {
        _localDns = hasLocalDns;
        Current = Empty("unknown", "awaiting_push");
        Reset();
    }

    public static bool HasLocalDns(OvpnDocument document) => document.Nodes.Any(node =>
        node.Kind == OvpnNodeKind.Directive && (node.Name == "dns" ||
        (node.Name == "dhcp-option" && node.Tokens.Count > 1 &&
         (node.Tokens[1].StartsWith("DNS", StringComparison.OrdinalIgnoreCase) ||
          node.Tokens[1].StartsWith("DOMAIN", StringComparison.OrdinalIgnoreCase)))));

    public void Reset()
    {
        _servers.Clear();
        _continuing = _complete = _connected = _blocked = false;
        _fragments = _bytes = _options = 0;
        _problemStatus = _problemReason = null;
        Current = _localDns ? Empty("unsupported", "local_dns_unsupported") : Empty("unknown", "awaiting_push");
    }

    public VpnDnsSnapshot OnConnected()
    {
        _connected = true;
        if (!_blocked)
        {
            if (_continuing) Block("invalid", "incomplete_push");
            else if (_complete) PublishComplete();
        }
        return Current;
    }

    /// <returns>True only when the public DNS policy/generation changed.</returns>
    public bool Consume(string line)
    {
        var generation = Current.Generation;
        if (!line.StartsWith(">LOG:", StringComparison.Ordinal)) return false;
        // Management framing is separately bounded in bytes, including auth/ACK frames.
        if (Encoding.UTF8.GetByteCount(line) > ManagementProtocol.MaximumFrameBytes)
        { Block("invalid", "metadata_limit"); return Current.Generation != generation; }
        var comma = line.IndexOf(',', 5);
        var second = comma < 0 ? -1 : line.IndexOf(',', comma + 1);
        if (second < 0 || !ulong.TryParse(line.AsSpan(5, comma - 5), NumberStyles.None,
                CultureInfo.InvariantCulture, out _))
        { Block("unknown", "unknown_log_format"); return Current.Generation != generation; }
        var message = line[(second + 1)..];
        if (!message.StartsWith("PUSH:", StringComparison.Ordinal)) return false;
        if (!message.StartsWith(PushLog, StringComparison.Ordinal) || !message.EndsWith("'", StringComparison.Ordinal))
        { Block("unknown", "unknown_push_format"); return Current.Generation != generation; }
        var payload = message[PushLog.Length..^1];
        if (payload == "PUSH_UPDATE" || payload.StartsWith("PUSH_UPDATE,", StringComparison.Ordinal))
        { Block("unsupported", "push_update_unsupported"); return Current.Generation != generation; }
        if (_blocked) return false;
        if (payload != "PUSH_REPLY" && !payload.StartsWith("PUSH_REPLY,", StringComparison.Ordinal))
        { Block("unknown", "unknown_push_message"); return Current.Generation != generation; }
        ParseReply(payload);
        return Current.Generation != generation;
    }

    private void ParseReply(string payload)
    {
        // Connected token-refresh messages are independent bounded messages,
        // not continuations of the initial PUSH sequence.
        if (_connected) _fragments = _bytes = _options = 0;
        var priorFragments = _fragments;
        var priorBytes = _bytes;
        var priorOptions = _options;
        if (++_fragments > 32 || (_bytes += Encoding.UTF8.GetByteCount(payload)) > 65536)
        { Block("invalid", "metadata_limit"); return; }
        // Upstream push_option_ex rejects commas in options; apply_push_options
        // splits on every comma before option tokenization (also inside quotes).
        var options = payload.Length == 10 ? Array.Empty<string>() : payload[11..].Split(',');
        var continuation = 0;
        var continuationSeen = false;
        var tokenRefreshOnly = options.Length > 0;
        foreach (var option in options)
        {
            if (++_options > 512) { Block("invalid", "metadata_limit"); return; }
            IReadOnlyList<string> tokens;
            try { tokens = OvpnDocument.Tokenize(option); }
            catch (InvalidDataException) { Block("invalid", "malformed_push"); return; }
            if (tokens.Count == 0) { Block("invalid", "malformed_push"); return; }
            var name = tokens[0].StartsWith("--", StringComparison.Ordinal) ? tokens[0][2..] : tokens[0];
            tokenRefreshOnly &= name is "auth-token" or "auth-token-user";
            if (name == "push-continuation")
            {
                if (continuationSeen || tokens.Count != 2 || tokens[1] is not ("1" or "2"))
                { Block("invalid", "malformed_continuation"); return; }
                continuationSeen = true;
                continuation = tokens[1] == "1" ? 1 : 2;
            }
            else if (name == "dns") Problem("unsupported", "dns_options_unsupported");
            else if (name == "dhcp-option") ParseDhcp(tokens);
        }
        // OpenVPN can renew an auth token with a minimal PUSH_REPLY on a live
        // connection. It carries no new DNS policy and must not erase the old one.
        if (_connected && tokenRefreshOnly)
        {
            _fragments = priorFragments;
            _bytes = priorBytes;
            _options = priorOptions;
            return;
        }
        if (_connected || _complete) { Block("unsupported", "repeated_push_unsupported"); return; }
        if ((_continuing && continuation == 0) || (!_continuing && continuation == 1))
        { Block("invalid", "malformed_continuation"); return; }
        _continuing = continuation == 2;
        if (_continuing) { Set("unknown", "incomplete_push"); return; }
        _complete = true;
        Set(_localDns ? "unsupported" : "unknown", _localDns ? "local_dns_unsupported" : "awaiting_connection");
    }

    private void ParseDhcp(IReadOnlyList<string> tokens)
    {
        if (tokens.Count < 2) { Problem("invalid", "malformed_dns"); return; }
        var kind = tokens[1];
        if (kind == "DNS")
        {
            if (tokens.Count != 3) { Problem("invalid", "malformed_dns"); return; }
            var text = tokens[2];
            if (IPAddress.TryParse(text, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6)
            { Problem("unsupported", "ipv6_dns_unsupported"); return; }
            if (text.Contains(':')) { Problem("unsupported", "dns_endpoint_unsupported"); return; }
            try { OpenVpnTunnelMetadata.ParseIpv4(text); }
            catch (InvalidDataException) { Problem("invalid", "invalid_dns_address"); return; }
            if (_servers.Any(server => server.Address == text)) return;
            if (_servers.Count == 4) { Problem("unsupported", "too_many_dns_servers"); return; }
            _servers.Add(new(text));
        }
        else if (kind.StartsWith("DNS", StringComparison.Ordinal)) Problem("unsupported", "dns_option_unsupported");
        else if (kind.StartsWith("DOMAIN", StringComparison.Ordinal)) Problem("unsupported", "dns_domains_unsupported");
    }

    private void Problem(string status, string reason)
    {
        if (_problemStatus == "invalid") return;
        _problemStatus = status;
        _problemReason = reason;
    }

    private void PublishComplete()
    {
        if (_problemStatus is not null) Set(_problemStatus, _problemReason);
        else if (_localDns) Set("unsupported", "local_dns_unsupported");
        else if (_servers.Count == 0) Set("not-provided", "no_provider_dns");
        else Set("ready", null, _servers);
    }

    private void Block(string status, string reason)
    {
        _blocked = true;
        _servers.Clear();
        Set(status, reason);
    }

    private void Set(string status, string? reason, IEnumerable<VpnDnsServer>? servers = null)
    {
        var values = (servers ?? Array.Empty<VpnDnsServer>()).ToArray();
        if (Current.Status == status && Current.Reason == reason && Current.Servers.SequenceEqual(values)) return;
        Current = new(status, Guid.NewGuid(), Array.AsReadOnly(values), reason);
    }

    private static VpnDnsSnapshot Empty(string status, string reason) =>
        new(status, Guid.NewGuid(), Array.AsReadOnly(Array.Empty<VpnDnsServer>()), reason);
}
