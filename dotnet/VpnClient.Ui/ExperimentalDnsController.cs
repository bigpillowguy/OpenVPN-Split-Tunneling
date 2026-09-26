using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

internal enum ExperimentalDnsState { Off, Preparing, Active, Restoring, Unsupported, RecoveryRequired }
internal sealed record DnsProcessIdentity(uint Pid, ulong Created);
internal sealed record DnsEligibility(Guid SessionId, Guid Generation, DnsProcessIdentity Backend);
internal sealed record DnsGuardReply(int Version, string Status, Guid? Lease, string Reason);
internal interface IDnsGuardClient
{
    Task<DnsGuardReply> RecoverAsync();
    Task<DnsGuardReply> InspectAsync();
    Task<DnsGuardReply> AcquireAsync(Guid lease, DnsProcessIdentity owner, DnsProcessIdentity backend);
    Task<DnsGuardReply> ReleaseAsync(Guid lease);
}

/// <summary>Serializes global DNS changes. A pending acquisition remains owned until release is confirmed.</summary>
internal sealed class ExperimentalDnsController
{
    private readonly IDnsGuardClient _guard;
    private readonly DnsProcessIdentity _owner;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _sync = new();
    private readonly Func<DateTimeOffset> _now;
    private DnsEligibility? _desired, _leaseTarget, _rejected;
    private DateTimeOffset _observed;
    private DateTimeOffset _inspected;
    private string _rejectionDetail = "DNS activation was not confirmed. Reconnect to retry.";
    private ExperimentalDnsState _rejectionState = ExperimentalDnsState.RecoveryRequired;
    private Guid? _lease;
    private bool _enabled, _paused, _initialized;
    private ExperimentalDnsState _state;
    private string _detail = "Experimental split DNS is off.";
    public ExperimentalDnsState State { get { lock (_sync) return _state; } }
    public string Detail { get { lock (_sync) return _detail; } }
    public event EventHandler? StateChanged;

    public ExperimentalDnsController(IDnsGuardClient guard, DnsProcessIdentity owner, Func<DateTimeOffset>? now = null)
    {
        _guard = guard;
        _owner = owner;
        var origin = DateTimeOffset.UtcNow;
        var started = Stopwatch.GetTimestamp();
        // Preserve an injectable clock while making production deadlines immune to wall-clock changes.
        _now = now ?? (() => origin + Stopwatch.GetElapsedTime(started));
    }

    public async Task InitializeAsync(bool enabled)
    {
        lock (_sync) _enabled = enabled;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            // The helper alone decides whether a journal is stale. Never release a foreign lease.
            var result = await _guard.RecoverAsync().ConfigureAwait(false);
            if (result.Version != 1 || result.Status != "off")
            {
                SetState(result.Status == "unsupported" ? ExperimentalDnsState.Unsupported : ExperimentalDnsState.RecoveryRequired,
                    result.Status == "busy" ? "Another live DNS session owns the guard. This client will not change it." : "DNS recovery could not be confirmed. " + result.Reason);
                return;
            }
            lock (_sync) _initialized = true;
        }
        catch (Exception ex) { SetFailure(ex); }
        finally { _gate.Release(); }
        await ReconcileAsync().ConfigureAwait(false);
    }

    public Task SetEnabledAsync(bool enabled)
    {
        lock (_sync) { _enabled = enabled; _rejected = null; if (!enabled) _desired = null; }
        return ReconcileAsync();
    }

    public Task ObserveAsync(DnsEligibility? eligibility)
    {
        lock (_sync) { _desired = eligibility; _observed = _now(); }
        return ReconcileAsync();
    }

    public async Task PauseAsync()
    {
        lock (_sync) { _paused = true; _desired = null; }
        await ReconcileAsync().ConfigureAwait(false);
        lock (_sync)
            if (_lease is not null) throw new InvalidOperationException("DNS restoration is not confirmed. Keep the backend running and retry; the independent guard also recovers after this client exits.");
    }

    public Task ResumeAsync()
    { lock (_sync) { _paused = false; _rejected = null; } return ReconcileAsync(); }

    // Called by the UI timer even when status frames stop arriving.
    public async Task CheckFreshnessAsync()
    {
        await ReconcileAsync().ConfigureAwait(false);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_lease is not { } lease || State != ExperimentalDnsState.Active || _now() - _inspected < TimeSpan.FromSeconds(3)) return;
            _inspected = _now();
            var result = await _guard.InspectAsync().ConfigureAwait(false);
            if (result.Version != 1 || result.Status != "active" || result.Lease != lease)
                RejectCurrentLease("The guard no longer confirms this DNS lease. Reconnect after restoration to retry.");
        }
        catch (Exception) { RejectCurrentLease("The active DNS guard could not be verified. Reconnect after restoration to retry."); }
        finally { _gate.Release(); }
        await ReconcileAsync().ConfigureAwait(false);
    }

    private void RejectCurrentLease(string detail)
    {
        lock (_sync) { _rejected = _leaseTarget; _rejectionState = ExperimentalDnsState.RecoveryRequired; _rejectionDetail = detail; }
        SetState(ExperimentalDnsState.RecoveryRequired, detail);
    }

    private DnsEligibility? EffectiveTarget()
    {
        lock (_sync)
            return _initialized && _enabled && !_paused && _now() - _observed <= TimeSpan.FromSeconds(2)
                ? _desired : null;
    }

    private async Task ReconcileAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            while (true)
            {
                var target = EffectiveTarget();
                if (_lease is { } lease && (target != _leaseTarget || State == ExperimentalDnsState.RecoveryRequired))
                {
                    SetState(ExperimentalDnsState.Restoring, "Restoring the shared Windows DNS Client service…");
                    DnsGuardReply restored;
                    try { restored = await _guard.ReleaseAsync(lease).ConfigureAwait(false); }
                    catch (Exception) { SetState(ExperimentalDnsState.RecoveryRequired, "The guard has not confirmed DNS restoration. Retry before stopping the backend."); return; }
                    if (restored.Version != 1 || restored.Status != "off" || (restored.Lease is { } other && other != lease))
                    { SetState(ExperimentalDnsState.RecoveryRequired, "The guard has not confirmed this lease was restored. " + restored.Reason); return; }
                    lock (_sync) { _lease = null; _leaseTarget = null; }
                    continue;
                }
                if (_lease is not null) return;
                if (!_initialized) return; // Preserve startup recovery/unsupported result.
                if (target is null)
                {
                    bool waiting;
                    lock (_sync) waiting = _enabled && !_paused;
                    SetState(ExperimentalDnsState.Off, waiting ? "Waiting for current provider DNS and a ready VPN backend. System DNS is unchanged." : "Experimental split DNS is off. System DNS is restored.");
                    return;
                }
                if (target == _rejected) { SetState(_rejectionState, _rejectionDetail); return; }
                var acquiredLease = Guid.NewGuid();
                lock (_sync) { _lease = acquiredLease; _leaseTarget = target; }
                SetState(ExperimentalDnsState.Preparing, "Preparing the shared Windows DNS Client service…");
                DnsGuardReply reply;
                try { reply = await _guard.AcquireAsync(acquiredLease, _owner, target.Backend).ConfigureAwait(false); }
                catch (Exception)
                {
                    lock (_sync) { _rejected = target; _rejectionState = ExperimentalDnsState.RecoveryRequired; _rejectionDetail = "DNS activation was not confirmed. Reconnect to retry."; }
                    SetState(ExperimentalDnsState.RecoveryRequired, "DNS activation was not confirmed; restoring the pending lease.");
                    continue;
                }
                if (reply.Version == 1 && reply.Status == "active" && reply.Lease == acquiredLease && EffectiveTarget() == target)
                {
                    _inspected = _now();
                    SetState(ExperimentalDnsState.Active, "Experimental split DNS is active for ordinary IPv4 DNS on port 53. The shared Dnscache service is temporarily replaced; DoH/DoT is not replaced.");
                    return;
                }
                // A stale success must be released before the next generation can acquire.
                lock (_sync) _rejected = target;
                var terminal = reply.Status == "unsupported" ? ExperimentalDnsState.Unsupported : ExperimentalDnsState.RecoveryRequired;
                _rejectionState = terminal;
                _rejectionDetail = reply.Status == "unsupported" ? "This Windows configuration does not support the experimental DNS guard. " + reply.Reason : "DNS activation could not be confirmed. " + reply.Reason;
                SetState(ExperimentalDnsState.RecoveryRequired, "Restoring an unconfirmed or superseded DNS lease.");
                var cleanup = await _guard.ReleaseAsync(acquiredLease).ConfigureAwait(false);
                if (cleanup.Version != 1 || cleanup.Status != "off" || (cleanup.Lease is { } returned && returned != acquiredLease))
                { SetState(ExperimentalDnsState.RecoveryRequired, "DNS restoration needs attention. " + cleanup.Reason); return; }
                lock (_sync) { _lease = null; _leaseTarget = null; }
                if (EffectiveTarget() != target) continue;
                SetState(terminal, _rejectionDetail);
                return;
            }
        }
        catch (Exception ex) { SetFailure(ex); }
        finally { _gate.Release(); }
    }

    private void SetFailure(Exception ex) => SetState(ex is NotSupportedException && _lease is null ? ExperimentalDnsState.Unsupported : ExperimentalDnsState.RecoveryRequired,
        ex is NotSupportedException && _lease is null ? "The DNS guard is not installed or supported. Experimental mode cannot start." : "The DNS guard could not confirm recovery. Restart the client or inspect the guard diagnostics.");

    private void SetState(ExperimentalDnsState state, string detail)
    {
        lock (_sync)
        {
            if (_state == state && _detail == detail) return;
            _state = state; _detail = detail;
        }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
}
