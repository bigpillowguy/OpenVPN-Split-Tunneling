using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

public static class ManagementProtocol
{
    public const int MaximumFrameBytes = 16 * 1024;

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
            var line = await ReadLineAsync(reader, ct).ConfigureAwait(false)
                ?? throw new EndOfStreamException("OpenVPN management authentication ended unexpectedly.");
            if (line.Contains("SUCCESS: password is correct", StringComparison.Ordinal)) return;
            if (line.StartsWith("ERROR:", StringComparison.Ordinal))
                throw new InvalidOperationException("OpenVPN management authentication was rejected.");
        }
        throw new InvalidDataException("OpenVPN did not acknowledge management authentication.");
    }

    // The process is still held. Never request cached log history: only fresh,
    // authenticated messages are a DNS source for this process/connection.
    public static async Task EnableRealtimeLogAsync(StreamReader reader, StreamWriter writer,
        Action<string> notification, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await writer.WriteLineAsync("log on".AsMemory(), deadline.Token).ConfigureAwait(false);
        for (var i = 0; i < 128; i++)
        {
            var line = await ReadLineAsync(reader, deadline.Token).ConfigureAwait(false)
                ?? throw new EndOfStreamException("OpenVPN closed before acknowledging realtime metadata.");
            if (line == "SUCCESS: real-time log notification set to ON") return;
            if (line.StartsWith(">LOG:", StringComparison.Ordinal)) notification(line);
            else if (line.StartsWith("ERROR:", StringComparison.Ordinal) || line.StartsWith(">FATAL:", StringComparison.Ordinal))
                throw new InvalidOperationException("OpenVPN could not enable realtime metadata.");
            else if (line.Length > 0 && !line.StartsWith(">INFO:", StringComparison.Ordinal) &&
                     !line.StartsWith(">HOLD:", StringComparison.Ordinal))
                throw new InvalidDataException("OpenVPN returned an unexpected metadata acknowledgement.");
        }
        throw new InvalidDataException("OpenVPN did not acknowledge realtime metadata within the supported limit.");
    }

    public static async Task<string?> ReadLineAsync(StreamReader reader, CancellationToken ct)
    {
        var line = new StringBuilder();
        var one = new char[1];
        var bytes = 0;
        var highSurrogate = false;
        try
        {
            while (await reader.ReadAsync(one.AsMemory(), ct).ConfigureAwait(false) != 0)
            {
                var character = one[0];
                if (character == '\n')
                {
                    if (highSurrogate) throw new InvalidDataException("OpenVPN management encoding is invalid.");
                    return line.ToString().TrimEnd('\r');
                }
                if (character == '\0' || (highSurrogate && !char.IsLowSurrogate(character)) ||
                    (!highSurrogate && char.IsLowSurrogate(character)))
                    throw new InvalidDataException("OpenVPN management encoding is invalid.");
                bytes += highSurrogate ? 0 : char.IsHighSurrogate(character) ? 4 : character <= 0x7f ? 1 : character <= 0x7ff ? 2 : 3;
                highSurrogate = char.IsHighSurrogate(character);
                if (bytes > MaximumFrameBytes)
                    throw new InvalidDataException("OpenVPN management frame exceeds the supported limit.");
                line.Append(character);
            }
        }
        catch (DecoderFallbackException) { throw new InvalidDataException("OpenVPN management encoding is invalid."); }
        return line.Length == 0 ? null : throw new EndOfStreamException("OpenVPN management frame was truncated.");
    }
}
