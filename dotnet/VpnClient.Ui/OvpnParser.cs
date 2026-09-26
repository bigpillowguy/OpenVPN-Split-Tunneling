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
                var parts = line.Split(
                    (char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries
                );
                if (parts.Length >= 2 && parts[0].Equals("remote", StringComparison.OrdinalIgnoreCase))
                    return parts[1].Trim('"', '\'');
            }
        }
        catch
        {
            // fall through
        }
        return null;
    }

    public static bool RequiresUserPassword(string filePath)
    {
        foreach (var raw in File.ReadLines(filePath))
        {
            var line = raw.Trim();
            if (line.StartsWith('#') || line.StartsWith(';')) continue;
            var directive = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (directive.Length == 0) continue;
            if (directive[0].Equals("auth-user-pass", StringComparison.OrdinalIgnoreCase) ||
                directive[0].Equals("<auth-user-pass>", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
