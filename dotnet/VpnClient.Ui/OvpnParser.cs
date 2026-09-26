using System;
using System.IO;
using System.Linq;

namespace VpnClient.Ui;

public static class OvpnParser
{
    /// <summary>
    /// Pulls the first `remote &lt;host&gt; [&lt;port&gt;]` line out of an .ovpn config and
    /// returns the hostname only (matches OpenVPN Connect's display convention).
    /// Returns null if no remote line found.
    /// </summary>
    public static string? ParseRemote(string filePath)
    {
        try
        {
            return OvpnProfileImporter.LoadExpanded(filePath, validateSupported: false).Nodes
                .FirstOrDefault(node => node.Kind == OvpnNodeKind.Directive && node.Name == "remote" && node.Tokens.Count >= 2)?.Tokens[1];
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or System.Text.DecoderFallbackException)
        {
            // fall through
        }
        return null;
    }

    public static bool RequiresUserPassword(string filePath)
    {
        // Metadata detection remains separate from the import/runtime safety validation.
        return OvpnProfileImporter.LoadExpanded(filePath, validateSupported: false).Nodes.Any(node => node.Name == "auth-user-pass");
    }
}
