using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Vpnclient.Status;

namespace VpnClient.Ui;

internal interface IDnsControlClient
{
    Task ArmAsync(Guid lease, DnsEligibility target);
    Task DisarmAsync(Guid lease, DnsEligibility target);
    bool IsArmed(Guid lease, DnsEligibility target);
}

internal sealed record DnsControlRequest(int Version, ulong Revision, Guid Lease, bool Armed,
    uint OwnerPid, ulong OwnerCreationTime, uint BackendPid, ulong BackendCreationTime, Guid SessionId, Guid Generation);

/// <summary>Private per-backend control; only an exact fresh acknowledgement completes an operation.</summary>
internal sealed class DnsControlFile : IDisposable
{
    private readonly string _path;
    private readonly DnsProcessIdentity _owner, _backend;
    private readonly Func<bool> _backendAlive;
    private readonly TimeSpan _timeout;
    private readonly object _sync = new();
    private readonly SemaphoreSlim _operations = new(1, 1);
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private ulong _revision;
    private DnsControlRequest? _request;
    private SplitDnsState? _observed;
    private long _observedAt;
    private bool _disposed;
    internal string FilePath => _path;

    internal DnsControlFile(string path, DnsProcessIdentity owner, DnsProcessIdentity backend, Func<bool> backendAlive, TimeSpan? timeout = null)
    { _path = path; _owner = owner; _backend = backend; _backendAlive = backendAlive; _timeout = timeout ?? TimeSpan.FromSeconds(8); }

    internal void Observe(Snapshot snapshot, long receivedAt)
    {
        if (!SnapshotValidator.IsValid(snapshot)) return;
        lock (_sync)
        {
            if (_disposed) return;
            _observed = snapshot.SplitDns?.Clone();
            _observedAt = receivedAt;
        }
    }

    internal bool IsArmed(Guid lease, DnsEligibility target)
    {
        lock (_sync) return !_disposed && _backendAlive() && target.Backend == _backend &&
            _request is { Armed: true } request && request.Lease == lease && request.SessionId == target.SessionId &&
            request.Generation == target.Generation && Matches(request);
    }

    internal async Task ApplyAsync(Guid lease, DnsEligibility target, bool armed)
    {
        if (lease == Guid.Empty || target.SessionId == Guid.Empty || target.Generation == Guid.Empty || target.Backend != _backend)
            throw new InvalidOperationException("DNS control belongs to another backend or VPN session.");
        await _operations.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (_sync) ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_backendAlive())
            {
                if (!armed) return; // Its capture handles died with this exact retained process.
                throw new IOException("The DNS backend exited before activation.");
            }
            DnsControlRequest request;
            lock (_sync)
            {
                if (_request is { Armed: true } prior && prior.Lease != lease)
                    throw new InvalidOperationException("Another DNS control lease has not been deactivated.");
                request = new(1, checked(++_revision), lease, armed, _owner.Pid, _owner.Created,
                    _backend.Pid, _backend.Created, target.SessionId, target.Generation);
                // Record ownership before a write can fail after atomic replacement.
                _request = request;
            }
            Write(request);
            var timer = Stopwatch.StartNew();
            while (true)
            {
                lock (_sync)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    if (Matches(request)) return;
                }
                if (!_backendAlive())
                {
                    if (!armed) return;
                    throw new IOException("The DNS backend exited before its acknowledgement.");
                }
                if (timer.Elapsed >= _timeout) throw new IOException(armed
                    ? "The DNS backend did not acknowledge activation."
                    : "The DNS backend did not acknowledge deactivation.");
                await Task.Delay(50).ConfigureAwait(false);
            }
        }
        finally { _operations.Release(); }
    }

    private bool Matches(DnsControlRequest request) => _observed is { Enabled: true } state &&
        Stopwatch.GetElapsedTime(_observedAt) <= TimeSpan.FromSeconds(2) && state.ControlError.Length == 0 &&
        state.Armed == request.Armed && state.ControlRevision == request.Revision && state.ControlLease == request.Lease.ToString("N");

    private void Write(DnsControlRequest request)
    {
        string temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { WriteRequest(file, request); file.Flush(true); }
            File.Move(temporary, _path, true);
        }
        finally { File.Delete(temporary); }
    }

    internal static void WriteRequest(Stream destination, DnsControlRequest request) => JsonSerializer.Serialize(destination, request, Json);

    public void Dispose()
    {
        // Never delete an armed intent as a substitute for acknowledged restoration.
        // The runtime directory is unique, so no later backend consumes this file.
        lock (_sync) _disposed = true;
    }
}

internal sealed class RedirectorDnsControlClient : IDnsControlClient
{
    public Task ArmAsync(Guid lease, DnsEligibility target) => Redirector.ApplyDnsControlAsync(lease, target, true);
    public Task DisarmAsync(Guid lease, DnsEligibility target) => Redirector.ApplyDnsControlAsync(lease, target, false);
    public bool IsArmed(Guid lease, DnsEligibility target) => Redirector.IsDnsArmed(lease, target);
}
