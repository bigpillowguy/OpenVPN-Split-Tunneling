using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace VpnClient.Ui;

internal sealed record VpnAdapter(Guid Guid, uint Index, string Name, bool IsUp, IReadOnlyList<IPAddress> Addresses);

internal static class WindowsVpnAdapter
{
    // Tentative confirms address assignment without blocking management/DOWN processing.
    // Rust independently requires Preferred before it installs routes or forwards traffic.
    internal static bool IsUsableIdentityAddress(DuplicateAddressDetectionState state) =>
        state is DuplicateAddressDetectionState.Preferred or DuplicateAddressDetectionState.Tentative;

    public static VpnAdapter Resolve(OpenVpnTunnel tunnel, IPAddress connectedAddress) =>
        Resolve(tunnel, connectedAddress, ReadAdapters());

    internal static VpnAdapter Resolve(OpenVpnTunnel tunnel, IPAddress connectedAddress, IEnumerable<VpnAdapter> adapters)
    {
        if (!tunnel.Ipv4.Equals(connectedAddress))
            throw new InvalidDataException("OpenVPN CONNECTED address disagrees with its tunnel metadata.");
        // The index is supplied by our authenticated OpenVPN process, not selected by address/name.
        var exact = adapters.Where(a => a.Index == tunnel.InterfaceIndex).ToArray();
        if (exact.Length != 1 || exact[0].Guid == Guid.Empty || !exact[0].IsUp ||
            !exact[0].Addresses.Contains(tunnel.Ipv4))
            throw new InvalidOperationException("The OpenVPN session's exact tunnel adapter is not ready.");
        var adapter = exact[0];
        if (Guid.TryParse(tunnel.Device, out var deviceGuid)
            ? deviceGuid != adapter.Guid
            : !string.Equals(tunnel.Device, adapter.Name, StringComparison.Ordinal))
            throw new InvalidOperationException("The OpenVPN session's adapter identity changed.");
        return adapter;
    }

    internal static IReadOnlyList<VpnAdapter> ReadAdapters()
    {
        var result = new List<VpnAdapter>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (!Guid.TryParse(adapter.Id, out var guid) || !adapter.Supports(NetworkInterfaceComponent.IPv4)) continue;
                var properties = adapter.GetIPProperties();
                var ipv4 = properties.GetIPv4Properties();
                if (ipv4 is null || ipv4.Index <= 0) continue;
                result.Add(new(guid, (uint)ipv4.Index, adapter.Name, adapter.OperationalStatus == OperationalStatus.Up,
                    properties.UnicastAddresses.Where(a => IsUsableIdentityAddress(a.DuplicateAddressDetectionState))
                        .Select(a => a.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray()));
            }
            catch (NetworkInformationException) { } // An unrelated adapter can disappear during enumeration.
            catch (NotSupportedException) { } // Some virtual adapters expose no IPv4 properties.
        }
        return result;
    }
}
