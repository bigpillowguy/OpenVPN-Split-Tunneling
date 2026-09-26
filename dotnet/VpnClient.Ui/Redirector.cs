using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

public static class Redirector
{
    private static Process? _process;
    private static EventWaitHandle? _shutdown;

    public static bool IsOwnedServer(uint pid) => _process is { HasExited: false } process && (uint)process.Id == pid;

    public static void Start()
    {
        var path = FindBinary(AppContext.BaseDirectory)
            ?? throw new FileNotFoundException("redirector.exe was not found beside the UI or in the repository target/release or target/debug directory. Build the redirector first.");
        var start = new ProcessStartInfo(path)
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(path),
        };
        start.ArgumentList.Add("observe");
        var eventName = @"Local\VpnClient-" + Guid.NewGuid().ToString("N");
        _shutdown = new EventWaitHandle(false, EventResetMode.ManualReset, eventName);
        start.ArgumentList.Add("--shutdown-event");
        start.ArgumentList.Add(eventName);
        _process = JobManager.Start(start);
    }

    public static string? FindBinary(string baseDirectory)
    {
        var adjacent = Path.Combine(baseDirectory, "redirector.exe");
        if (File.Exists(adjacent)) return adjacent;
        // Only recognize an actual checkout ancestor, not an arbitrary target directory.
        for (var parent = new DirectoryInfo(baseDirectory); parent is not null; parent = parent.Parent)
        {
            if (!File.Exists(Path.Combine(parent.FullName, "Cargo.toml")) ||
                !File.Exists(Path.Combine(parent.FullName, "redirector", "Cargo.toml"))) continue;
            foreach (var configuration in new[] { "release", "debug" })
            {
                var candidate = Path.Combine(parent.FullName, "target", configuration, "redirector.exe");
                if (File.Exists(candidate)) return candidate;
            }
        }
        return null;
    }

    public static async Task StopAsync()
    {
        _shutdown?.Set();
        if (_process is { HasExited: false } process)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync(timeout.Token);
        }
    }

    public static void Dispose()
    {
        _shutdown?.Dispose(); _shutdown = null;
        _process?.Dispose(); _process = null;
    }
}
