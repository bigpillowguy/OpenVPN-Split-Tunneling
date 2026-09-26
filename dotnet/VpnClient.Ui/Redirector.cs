using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

public static class Redirector
{
    private static Process? _process;
    private static EventWaitHandle? _shutdown;
    private static VpnSessionBindingStore? _sessionBindings;
    private static Task? _exitWatch;
    private static volatile bool _stopping;
    private static volatile string? _failure;

    public static string? Failure => _failure;
    public static string? LogPath { get; private set; }
    public static event EventHandler? StateChanged;
    public static bool IsRunning
    {
        get
        {
            try { return _process is { HasExited: false }; }
            catch (InvalidOperationException) { return false; } // Shutdown may have disposed the retained handle.
        }
    }

    internal static VpnSessionBindingStore.Lease BeginSessionBinding()
    {
        if (!IsRunning || _sessionBindings is null)
            throw new InvalidOperationException(Failure ?? "The VPN backend is not running. Restart the client and inspect its redirector log.");
        return _sessionBindings.Begin();
    }

    public static bool IsOwnedServer(uint pid)
    {
        try { return _process is { HasExited: false } process && (uint)process.Id == pid; }
        catch (InvalidOperationException) { return false; }
    }

    public static void Start()
    {
        _stopping = false;
        _failure = null;
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
        _sessionBindings = new VpnSessionBindingStore();
        start.ArgumentList.Add("--session-file");
        start.ArgumentList.Add(_sessionBindings.FilePath);
        LogPath = Path.Combine(Path.GetDirectoryName(_sessionBindings.FilePath)!, "redirector.log");
        start.ArgumentList.Add("--log-file");
        start.ArgumentList.Add(LogPath);
        WriteLifecycleLog("starting redirector");
        try
        {
            _process = JobManager.Start(start);
            _exitWatch = ObserveExitAsync(_process);
            StateChanged?.Invoke(null, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            _failure = "The VPN backend could not start: " + ex.Message + ". Diagnostics: " + LogPath;
            WriteLifecycleLog("process creation failed: " + ex.GetType().Name + " (HRESULT 0x" + ex.HResult.ToString("X8") + ")");
            _sessionBindings.Dispose(); _sessionBindings = null;
            throw new InvalidOperationException(_failure, ex);
        }
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
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        if (_process is { HasExited: false } process)
        {
            _stopping = true;
            _shutdown?.Set();
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        // WaitForExit has independent continuations. Preserve the exit code/log before
        // OnExit disposes the Process handle and the launch directory.
        if (_exitWatch is { } watch) await watch.WaitAsync(timeout.Token).ConfigureAwait(false);
    }

    public static void Dispose()
    {
        _stopping = true;
        _sessionBindings?.Dispose(); _sessionBindings = null;
        _shutdown?.Dispose(); _shutdown = null;
        _process?.Dispose(); _process = null;
    }

    private static async Task ObserveExitAsync(Process process)
    {
        try
        {
            await process.WaitForExitAsync().ConfigureAwait(false);
            if (!ReferenceEquals(_process, process)) return;
            var code = process.ExitCode;
            WriteLifecycleLog($"redirector exited; code={code} (0x{unchecked((uint)code):X8}); requestedStop={_stopping}");
            if (!_stopping) _failure = DescribeUnexpectedExit(code, LogPath);
            StateChanged?.Invoke(null, EventArgs.Empty);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            if (!_stopping && ReferenceEquals(_process, process))
            {
                _failure = "The VPN backend could not be monitored. Diagnostics: " + LogPath;
                WriteLifecycleLog("process monitoring failed: " + ex.GetType().Name + " (HRESULT 0x" + ex.HResult.ToString("X8") + ")");
                StateChanged?.Invoke(null, EventArgs.Empty);
            }
        }
    }

    internal static string DescribeUnexpectedExit(int code, string? logPath) =>
        $"Redirector stopped unexpectedly (exit code {code}, 0x{unchecked((uint)code):X8}). Restart the client. Diagnostics: {logPath}";

    private static void WriteLifecycleLog(string message)
    {
        if (LogPath is not { } path) return;
        // Only controlled lifecycle fields, never arguments, profile contents or management traffic.
        try { File.AppendAllText(path, $"{DateTimeOffset.UtcNow:O} UI: {message}{Environment.NewLine}", new UTF8Encoding(false)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
