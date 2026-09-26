using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace VpnClient.Ui;

/// <summary>Prepare a per-session profile without applying profile/server routes or DNS to Windows.</summary>
public static class OvpnRuntimeProfile
{
    private static readonly HashSet<string> Removed = new(StringComparer.OrdinalIgnoreCase)
    {
        "route", "route-ipv6", "redirect-gateway", "redirect-private", "route-metric", "route-table",
        "dhcp-option", "dns", "block-outside-dns", "register-dns", "block-ipv6",
        "route-noexec", "route-nopull", "persist-tun", "pull-filter"
    };

    public static string Create(string sourcePath, string sessionDirectory)
    {
        var document = OvpnProfileImporter.LoadExpanded(sourcePath);
        var path = Path.Combine(sessionDirectory, "runtime.ovpn");
        // The caller owns a freshly created, current-user-only SessionSecrets directory.
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(output, new UTF8Encoding(false));
        writer.Write(Prepare(document).Render());
        return path;
    }

    public static OvpnDocument Prepare(OvpnDocument document)
    {
        var retained = document.Nodes.Where(node => node.Kind != OvpnNodeKind.Directive || !Removed.Contains(node.Name)).ToList();
        // Enforce the policy before custom filters (first match wins). route-nopull is
        // the actual pushed option permission boundary in OpenVPN 2.7, including DNS;
        // filters alone can be bypassed with alternate whitespace in PUSH_REPLY.
        var policy = OvpnDocument.Parse("""
            # Managed split-tunnel policy. DNS remains with the operating system.
            route-noexec
            route-nopull
            pull-filter ignore redirect-gateway
            pull-filter ignore redirect-private
            pull-filter ignore "route "
            pull-filter ignore route-ipv6
            pull-filter ignore dhcp-option
            pull-filter ignore dns
            pull-filter ignore block-outside-dns
            pull-filter ignore register-dns
            pull-filter ignore block-ipv6
            pull-filter ignore persist-tun
            pull-filter ignore setenv
            # Populate authenticated UPDOWN route_vpn_gateway metadata; route-noexec
            # prevents OpenVPN from installing this or any other requested route.
            route 0.0.0.0 0.0.0.0 vpn_gateway
            """);
        // Preserve tunnel addressing (ifconfig/topology/route-gateway), transport,
        // authentication, inline data and the user's remaining custom pull filters.
        var filters = document.Nodes.Where(node => node.Kind == OvpnNodeKind.Directive && node.Name == "pull-filter");
        return new OvpnDocument(policy.Nodes.Concat(retained).Concat(filters), document.BaseDirectory);
    }
}
