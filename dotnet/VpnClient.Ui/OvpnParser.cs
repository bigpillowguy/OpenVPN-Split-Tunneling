using System;
using System.IO;

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
            foreach (var raw in File.ReadAllLines(filePath))
            {
                var line = raw.Trim();
                if (line.StartsWith("#") || line.StartsWith(";")) continue;
                if (!line.StartsWith("remote ", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = line.Split(
                    (char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries
                );
                if (parts.Length >= 2) return parts[1];
            }
        }
        catch
        {
            // fall through
        }
        return null;
    }
}
