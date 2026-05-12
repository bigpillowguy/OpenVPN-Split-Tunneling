using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace VpnClient.Ui;

/// <summary>
/// Best-effort launcher for the Rust redirector. The UI runs elevated, so
/// the spawned redirector inherits admin rights (which it needs to load
/// the WinDivert driver and create the SYSTEM-friendly named pipes).
/// </summary>
public static class Redirector
{
    public static bool IsRunning()
    {
        try { return Process.GetProcessesByName("redirector").Any(); }
        catch { return false; }
    }

    /// <summary>
    /// Kill stray redirector/openvpn processes left over from a previous
    /// UI session that exited before the Job Object teardown could fire.
    /// </summary>
    public static void KillOrphans()
    {
        foreach (var name in new[] { "redirector", "openvpn" })
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try { p.Kill(entireProcessTree: true); p.WaitForExit(2000); }
                catch { }
                finally { p.Dispose(); }
            }
        }
    }

    public static bool TryStart()
    {
        var path = FindBinary();
        if (path is null) return false;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = path,
                Arguments = "observe",
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Path.GetDirectoryName(path),
            };
            var proc = Process.Start(psi);
            if (proc is not null)
            {
                JobManager.Assign(proc);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? FindBinary()
    {
        // 1. Same directory as the UI exe (production / packaged install)
        var here = Path.GetDirectoryName(Environment.ProcessPath);
        if (here is not null)
        {
            var candidate = Path.Combine(here, "redirector.exe");
            if (File.Exists(candidate)) return candidate;
        }
        // 2. Workspace builds, release first (that's what we ship out of CI)
        foreach (var dev in new[]
        {
            @"C:\Projects\vpn\target\release\redirector.exe",
            @"C:\Projects\vpn\target\debug\redirector.exe",
        })
        {
            if (File.Exists(dev)) return dev;
        }
        return null;
    }
}
