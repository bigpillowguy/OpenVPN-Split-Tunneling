using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace VpnClient.Ui;

/// <summary>
/// Launches openvpn.exe with the active profile and exposes stop via
/// OpenVPN's --management TCP interface, with Process.Kill as fallback.
/// </summary>
public class VpnConnector
{
    public string? ActiveProfileId { get; private set; }
    public int ManagementPort { get; private set; }
    private Process? _process;

    public event EventHandler? StateChanged;

    private static readonly string[] OpenVpnPaths =
    {
        @"C:\Program Files\OpenVPN\bin\openvpn.exe",
        @"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
    };

    public static bool OpenVpnInstalled() => FindOpenVpn() is not null;

    public static string? FindOpenVpn()
    {
        foreach (var p in OpenVpnPaths)
            if (File.Exists(p)) return p;
        return null;
    }

    public async Task ConnectAsync(OvpnEntry profile)
    {
        var openvpn = FindOpenVpn()
            ?? throw new FileNotFoundException(
                "openvpn.exe not found. Install the OpenVPN Community client from openvpn.net.");

        var runtimeDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "VpnClient", "runtime");
        Directory.CreateDirectory(runtimeDir);

        var authFile = Path.Combine(runtimeDir, "auth.txt");
        await File.WriteAllTextAsync(
            authFile,
            $"{profile.Username}\n{profile.GetPassword()}\n");

        var logFile = Path.Combine(runtimeDir, "openvpn.log");
        ManagementPort = GetFreePort();

        // --windows-driver wintun bypasses the TAP-Windows6 DHCP path that
        // sometimes leaves the adapter stuck on 169.254.x.x even after
        // "Initialization Sequence Completed". Wintun does its own IP
        // configuration via SetIpInterfaceEntry.
        //
        // --pull-filter ignore redirect-gateway tells openvpn to drop the
        // server-pushed "default route via VPN" directive. Without it the
        // tunnel acts as a full-system VPN even for processes we don't want
        // to route through it. The redirector pins tunneled processes to
        // the VPN adapter via IP_UNICAST_IF, so they egress through the
        // tunnel without us hijacking the default route.
        var args =
            $"--config \"{profile.FilePath}\" " +
            $"--auth-user-pass \"{authFile}\" " +
            $"--management 127.0.0.1 {ManagementPort} " +
            $"--windows-driver wintun " +
            $"--pull-filter ignore \"redirect-gateway\" " +
            $"--pull-filter ignore \"block-outside-dns\" " +
            $"--log \"{logFile}\" " +
            $"--verb 3";

        var psi = new ProcessStartInfo
        {
            FileName = openvpn,
            Arguments = args,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true,
        };

        _process = Process.Start(psi);
        if (_process is not null)
        {
            // Lift openvpn into the UI's Job Object so it dies when we do.
            JobManager.Assign(_process);
        }
        ActiveProfileId = profile.Id;
        StateChanged?.Invoke(this, EventArgs.Empty);

        await Task.CompletedTask;
    }

    public async Task DisconnectAsync()
    {
        // Graceful via management socket first; fall through to Kill if that
        // doesn't take openvpn down within ~1.5s.
        if (ManagementPort != 0)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync("127.0.0.1", ManagementPort);
                using var stream = tcp.GetStream();
                var sig = Encoding.ASCII.GetBytes("signal SIGTERM\n");
                await stream.WriteAsync(sig);
                await stream.FlushAsync();
                await Task.Delay(1500);
            }
            catch { }
        }

        if (_process is { HasExited: false })
        {
            try
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(2000);
            }
            catch { }
        }

        _process?.Dispose();
        _process = null;
        ManagementPort = 0;
        ActiveProfileId = null;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
