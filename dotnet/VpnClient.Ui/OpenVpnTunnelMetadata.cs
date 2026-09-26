using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace VpnClient.Ui;

internal sealed record OpenVpnTunnel(Guid SessionId, uint InterfaceIndex, string Device,
    IPAddress Ipv4, IPAddress Gateway);

/// <summary>Parses the native --management-up-down environment, never a log or adapter-name guess.</summary>
internal sealed class OpenVpnTunnelMetadata
{
    private Dictionary<string, string>? _environment;
    private int _bytes;
    private int _entries;
    public OpenVpnTunnel? Current { get; private set; }

    public void Reset() { _environment = null; Current = null; _bytes = 0; _entries = 0; }

    public void Consume(string line)
    {
        if (line == ">UPDOWN:UP")
        {
            Reset();
            _environment = new(StringComparer.Ordinal);
            return;
        }
        if (line == ">UPDOWN:DOWN") { Reset(); return; }
        const string prefix = ">UPDOWN:ENV,";
        if (!line.StartsWith(prefix, StringComparison.Ordinal))
            throw new InvalidDataException("Unexpected OpenVPN tunnel metadata message.");
        // DOWN also carries an environment block. Its values must never authorize a tunnel.
        if (_environment is null) return;
        _bytes = checked(_bytes + line.Length);
        if (_bytes > 65536 || ++_entries > 256)
            throw new InvalidDataException("OpenVPN tunnel metadata exceeds the supported limit.");
        var value = line[prefix.Length..];
        if (value == "END")
        {
            var indexText = Required("dev_idx");
            if (!uint.TryParse(indexText, NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index == 0)
                throw new InvalidDataException("OpenVPN did not report a valid tunnel interface index.");
            var device = Required("dev");
            if (device.Length > 256 || device.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                throw new InvalidDataException("OpenVPN reported an invalid tunnel device.");
            var ipv4 = ParseIpv4(Required("ifconfig_local"));
            // OpenVPN emits ifconfig_remote only for point-to-point/net30 topology;
            // a subnet mask must never be interpreted as a next hop.
            var gatewayText = _environment.GetValueOrDefault("route_vpn_gateway")
                ?? (!_environment.ContainsKey("ifconfig_netmask") ? _environment.GetValueOrDefault("ifconfig_remote") : null);
            if (gatewayText is null)
                throw new InvalidDataException("OpenVPN did not report an IPv4 tunnel gateway.");
            var gateway = ParseIpv4(gatewayText);
            if (gateway.Equals(ipv4)) throw new InvalidDataException("OpenVPN reported its local address as the tunnel gateway.");
            Current = new(Guid.NewGuid(), index, device, ipv4, gateway);
            _environment = null;
            return;
        }
        var equals = value.IndexOf('=');
        if (equals <= 0) throw new InvalidDataException("Malformed OpenVPN tunnel environment.");
        var key = value[..equals];
        if (key is "dev_idx" or "dev" or "ifconfig_local" or "ifconfig_remote" or "ifconfig_netmask" or "route_vpn_gateway")
        {
            if (!_environment.TryAdd(key, value[(equals + 1)..]))
                throw new InvalidDataException("Duplicate OpenVPN tunnel identity field.");
        }
    }

    private string Required(string name) => _environment!.TryGetValue(name, out var value) && value.Length > 0
        ? value : throw new InvalidDataException("OpenVPN tunnel identity is incomplete: " + name);

    internal static IPAddress ParseIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            ip.ToString() != value || ip.GetAddressBytes()[0] is 0 or 127 or >= 224 ||
            (ip.GetAddressBytes()[0] == 169 && ip.GetAddressBytes()[1] == 254))
            throw new InvalidDataException("OpenVPN reported an invalid unicast IPv4 address.");
        return ip;
    }
}
