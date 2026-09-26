using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace VpnClient.Ui;

internal sealed class DnsGuardClient : IDnsGuardClient
{
    private readonly string _path;
    public DnsGuardClient(string directory) => _path = Path.Combine(directory, "DnsGuard", "VpnClient.DnsGuard.exe");
    public Task<DnsGuardReply> RecoverAsync() => RunAsync(new[] { "recover" });
    public Task<DnsGuardReply> InspectAsync() => RunAsync(new[] { "inspect" });
    public Task<DnsGuardReply> ReleaseAsync(Guid lease) => RunAsync(new[] { "release", "--lease", lease.ToString("D") });
    public Task<DnsGuardReply> AcquireAsync(Guid lease, DnsProcessIdentity owner, DnsProcessIdentity backend)
        => RunAsync(AcquireArguments(lease, owner, backend));

    internal static IReadOnlyList<string> AcquireArguments(Guid lease, DnsProcessIdentity owner, DnsProcessIdentity backend)
    {
        if (lease == Guid.Empty || owner.Pid == 0 || owner.Created == 0 || backend.Pid == 0 || backend.Created == 0)
            throw new ArgumentException("Guard ownership must identify live process instances.");
        return new[] { "acquire", "--lease", lease.ToString("D"), "--owner-pid", owner.Pid.ToString(CultureInfo.InvariantCulture),
            "--owner-created", owner.Created.ToString(CultureInfo.InvariantCulture), "--backend-pid", backend.Pid.ToString(CultureInfo.InvariantCulture),
            "--backend-created", backend.Created.ToString(CultureInfo.InvariantCulture) };
    }

    private async Task<DnsGuardReply> RunAsync(IReadOnlyList<string> arguments)
    {
        if (!File.Exists(_path)) throw new NotSupportedException("DNS guard executable is missing.");
        var start = new ProcessStartInfo(_path) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_path), RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in arguments) start.ArgumentList.Add(arg);
        // Deliberately outside JobManager: guardian lifetime must survive UI/backend failure.
        using var process = Process.Start(start) ?? throw new IOException("DNS guard did not start.");
        var output = ReadBoundedAsync(process.StandardOutput);
        var error = ReadBoundedAsync(process.StandardError);
        var completion = Task.WhenAll(process.WaitForExitAsync(), output, error);
        try { await completion.WaitAsync(TimeSpan.FromSeconds(40)).ConfigureAwait(false); }
        catch
        {
            // Only this CLI child is terminated. Its independent service owns pending recovery.
            try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { }
            try { await completion.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch { }
            throw;
        }
        return ParseReply(await output.ConfigureAwait(false), process.ExitCode);
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var text = new StringBuilder(); var buffer = new char[1024];
        while (true)
        {
            var count = await reader.ReadAsync(buffer).ConfigureAwait(false);
            if (count == 0) return text.ToString();
            if (text.Length + count > 16384) throw new InvalidDataException("DNS guard output exceeded its limit.");
            text.Append(buffer, 0, count);
        }
    }

    internal static DnsGuardReply ParseReply(string text, int exitCode)
    {
        if (text.Length > 16384) throw new InvalidDataException("Oversized guard response.");
        using var json = JsonDocument.Parse(text);
        var root = json.RootElement;
        var version = root.GetProperty("version").GetInt32();
        var status = root.GetProperty("status").GetString();
        var reason = root.GetProperty("reason").GetString() ?? "unknown";
        if (version != 1 || reason.Length > 128 || status is not ("off" or "preparing" or "active" or "restoring" or "unsupported" or "recoveryRequired" or "busy"))
            throw new InvalidDataException("Unknown guard protocol response.");
        if (exitCode != (status == "unsupported" ? 2 : status == "busy" ? 3 : status == "recoveryRequired" ? 4 : 0))
            throw new InvalidDataException("Guard exit status disagrees with its response.");
        Guid? lease = null;
        if (root.TryGetProperty("lease", out var value) && value.ValueKind != JsonValueKind.Null)
        {
            if (!Guid.TryParse(value.GetString(), out var parsed) || parsed == Guid.Empty) throw new InvalidDataException("Invalid guard lease.");
            lease = parsed;
        }
        if (status == "active" && lease is null) throw new InvalidDataException("Active guard response lacks ownership.");
        return new(version, status!, lease, reason);
    }
}
