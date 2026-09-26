using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

internal sealed class OpenVpnSession : IVpnSession
{
    private readonly OvpnEntry _profile;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _writes = new(1, 1);
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Process? _process;
    private SessionSecrets? _secrets;
    private TcpClient? _tcp;
    private StreamWriter? _writer;
    private Task? _readerTask;
    private bool _stopping;
    public string? Failure { get; private set; }
    public Task Completion => _completion.Task;
    public event EventHandler<bool>? ConnectionChanged;

    public OpenVpnSession(OvpnEntry profile) => _profile = profile;

    public async Task StartAsync(CancellationToken ct)
    {
        var executable = VpnConnector.FindOpenVpn() ?? throw new FileNotFoundException("Install OpenVPN Community before connecting.");
        if (!File.Exists(_profile.FilePath)) throw new FileNotFoundException("The imported OpenVPN profile is missing.", _profile.FilePath);
        if (!string.IsNullOrWhiteSpace(_profile.ServerOverride))
            throw new NotSupportedException("Server override is not supported yet. Clear it or edit the remote in the imported profile.");
        var requiresAuth = OvpnParser.RequiresUserPassword(_profile.FilePath);
        if (requiresAuth && (string.IsNullOrWhiteSpace(_profile.Username) || string.IsNullOrEmpty(_profile.GetPassword())))
            throw new InvalidOperationException("This profile requires a saved username and password.");
        ManagementProtocol.Quote(_profile.Username);
        ManagementProtocol.Quote(_profile.GetPassword());
        ct.ThrowIfCancellationRequested();
        _secrets = new SessionSecrets();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var psi = new ProcessStartInfo(executable)
        {
            WorkingDirectory = Path.GetDirectoryName(_profile.FilePath), UseShellExecute = false, CreateNoWindow = true,
        };
        foreach (var argument in new[] { "--config", _profile.FilePath, "--management", "127.0.0.1", port.ToString(),
                     _secrets.PasswordFile, "--management-query-passwords", "--management-hold", "--management-signal",
                     "--pull-filter", "ignore", "redirect-gateway", "--pull-filter", "ignore", "block-outside-dns",
                     "--log", Path.Combine(_secrets.DirectoryPath, "openvpn.log"), "--verb", "3" })
            psi.ArgumentList.Add(argument);
        if (requiresAuth) psi.ArgumentList.Add("--auth-user-pass");
        // OpenVPN 2.7 selects DCO/TAP itself; --windows-driver wintun is obsolete.
        _process = JobManager.Start(psi);
        _ = WatchProcessAsync(_process);
        using var startup = CancellationTokenSource.CreateLinkedTokenSource(ct, _lifetime.Token);
        while (true)
        {
            startup.Token.ThrowIfCancellationRequested();
            if (_process.HasExited) throw new InvalidOperationException(Failure ?? "OpenVPN exited during startup. Inspect the session log.");
            var client = new TcpClient();
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port, startup.Token).ConfigureAwait(false);
                _tcp = client;
                break;
            }
            catch (SocketException) { client.Dispose(); await Task.Delay(100, startup.Token).ConfigureAwait(false); }
            catch { client.Dispose(); throw; }
        }
        var stream = _tcp.GetStream();
        if (!LoopbackPeer.IsOwnedBy(_tcp, _process.Id))
            throw new InvalidOperationException("The management connection does not belong to the OpenVPN process we started.");
        var reader = new StreamReader(stream, Encoding.UTF8, false, 4096, leaveOpen: true);
        _writer = new StreamWriter(stream, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
        await ManagementProtocol.AuthenticateAsync(reader, _writer, _secrets.Password, startup.Token).ConfigureAwait(false);
        _secrets.ReleasePasswordFile();
        _readerTask = ReadManagementAsync(reader, _lifetime.Token);
        await SendAsync("state on", startup.Token).ConfigureAwait(false);
        await SendAsync("hold release", startup.Token).ConfigureAwait(false);
        await _connected.Task.WaitAsync(startup.Token).ConfigureAwait(false);
    }

    private async Task ReadManagementAsync(StreamReader reader, CancellationToken ct)
    {
        try
        {
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                if (line.StartsWith(">PASSWORD:Need 'Auth'", StringComparison.Ordinal) && !line.Contains("SC:", StringComparison.Ordinal))
                {
                    await SendAsync("username \"Auth\" " + ManagementProtocol.Quote(_profile.Username), ct).ConfigureAwait(false);
                    await SendAsync("password \"Auth\" " + ManagementProtocol.Quote(_profile.GetPassword()), ct).ConfigureAwait(false);
                }
                else if (line.StartsWith(">PASSWORD:Need", StringComparison.Ordinal) || line.StartsWith(">PASSWORD:Verification Failed", StringComparison.Ordinal))
                    throw new InvalidOperationException("OpenVPN authentication failed or requires an unsupported private-key password/challenge. Check the profile and credentials.");
                else if (line.StartsWith(">STATE:", StringComparison.Ordinal))
                {
                    var fields = line[7..].Split(',');
                    if (fields.Length > 2 && fields[1] == "CONNECTED" && fields[2] == "SUCCESS")
                    {
                        _connected.TrySetResult();
                        ConnectionChanged?.Invoke(this, true);
                    }
                    else if (fields.Length > 1 && fields[1] == "RECONNECTING") ConnectionChanged?.Invoke(this, false);
                }
                else if (line.StartsWith(">FATAL:", StringComparison.Ordinal))
                    throw new InvalidOperationException("OpenVPN reported a fatal error. Inspect the session log.");
            }
            if (!_stopping) throw new EndOfStreamException("OpenVPN management disconnected.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!_stopping)
            {
                Failure = ex.Message;
                _connected.TrySetException(ex);
                _completion.TrySetResult(); // The controller stops the still-owned process.
            }
        }
        finally { reader.Dispose(); }
    }

    private async Task WatchProcessAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync().ConfigureAwait(false);
            if (!_stopping)
            {
                Failure ??= $"OpenVPN exited with code {process.ExitCode}. Inspect the session log.";
                _connected.TrySetException(new InvalidOperationException(Failure));
            }
        }
        finally { _completion.TrySetResult(); }
    }

    private async Task SendAsync(string command, CancellationToken ct)
    {
        await _writes.WaitAsync(ct).ConfigureAwait(false);
        try { await _writer!.WriteLineAsync(command.AsMemory(), ct).ConfigureAwait(false); }
        finally { _writes.Release(); }
    }

    public async Task StopAsync()
    {
        _stopping = true;
        if (_process is { HasExited: false } process)
        {
            using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                if (_writer is not null) await SendAsync("signal SIGTERM", grace.Token).ConfigureAwait(false);
                await process.WaitForExitAsync(grace.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                }
            }
        }
        _lifetime.Cancel();
        _tcp?.Dispose();
        if (_readerTask is not null) await _readerTask.ConfigureAwait(false);
        _secrets?.Dispose();
        _secrets = null;
    }

    public void Dispose()
    {
        _lifetime.Dispose();
        _writer?.Dispose();
        _tcp?.Dispose();
        _process?.Dispose();
        _secrets?.Dispose();
    }
}
