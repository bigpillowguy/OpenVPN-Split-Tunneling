using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

public static class ManagementProtocol
{
    public static string Quote(string value)
    {
        if (value.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
            throw new ArgumentException("OpenVPN credentials cannot contain line breaks or NUL characters.");
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    // The password prompt has no newline. Read it before switching to line frames.
    public static async Task AuthenticateAsync(StreamReader reader, StreamWriter writer, string secret, CancellationToken ct)
    {
        const string prompt = "ENTER PASSWORD:";
        var prefix = "";
        var one = new char[1];
        while (!prefix.EndsWith(prompt, StringComparison.Ordinal))
        {
            if (prefix.Length >= 4096) throw new InvalidDataException("Unexpected OpenVPN management greeting.");
            if (await reader.ReadAsync(one.AsMemory(), ct).ConfigureAwait(false) == 0)
                throw new EndOfStreamException("OpenVPN management closed before authentication.");
            prefix += one[0];
        }
        await writer.WriteLineAsync(secret.AsMemory(), ct).ConfigureAwait(false);
        for (var i = 0; i < 16; i++)
        {
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false)
                ?? throw new EndOfStreamException("OpenVPN management authentication ended unexpectedly.");
            if (line.Contains("SUCCESS: password is correct", StringComparison.Ordinal)) return;
            if (line.StartsWith("ERROR:", StringComparison.Ordinal))
                throw new InvalidOperationException("OpenVPN management authentication was rejected.");
        }
        throw new InvalidDataException("OpenVPN did not acknowledge management authentication.");
    }
}
