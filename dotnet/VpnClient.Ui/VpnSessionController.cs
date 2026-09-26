using System;
using System.Threading;
using System.Threading.Tasks;

namespace VpnClient.Ui;

public enum VpnConnectionState { Disconnected, Connecting, Connected, Disconnecting, Failed }

/// <summary>A session owns one child and retains ownership until it exits.</summary>
public interface IVpnSession : IDisposable
{
    event EventHandler<bool>? ConnectionChanged;
    Task Completion { get; }
    string? Failure { get; }
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync();
}

public class VpnSessionController
{
    private readonly Func<OvpnEntry, IVpnSession> _createSession;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _requestLock = new();
    private readonly object _stateLock = new();
    private bool? _latestConnection;
    private CancellationTokenSource? _attempt;
    private long _request;
    private IVpnSession? _session;
    private readonly TimeSpan _connectionTimeout;
    private readonly Func<Task>? _beforeSessionStop;

    public VpnSessionController(Func<OvpnEntry, IVpnSession> createSession, TimeSpan? connectionTimeout = null, Func<Task>? beforeSessionStop = null)
    {
        _createSession = createSession;
        _connectionTimeout = connectionTimeout ?? TimeSpan.FromSeconds(30);
        _beforeSessionStop = beforeSessionStop;
    }
    public VpnConnectionState State { get; private set; }
    public string? ActiveProfileId { get; private set; }
    public string? LastError { get; private set; }
    public bool HasSession => _session is not null;
    public event EventHandler? StateChanged;

    private long NewRequest()
    {
        lock (_requestLock)
        {
            var request = ++_request;
            _attempt?.Cancel();
            return request;
        }
    }

    public async Task ConnectAsync(OvpnEntry profile)
    {
        var request = NewRequest();
        await _gate.WaitAsync().ConfigureAwait(false);
        CancellationTokenSource? attempt = null;
        try
        {
            if (request != Interlocked.Read(ref _request)) return;
            await StopOwnedSessionAsync().ConfigureAwait(false);
            lock (_requestLock)
            {
                if (request != _request) return;
                _attempt = attempt = new CancellationTokenSource(_connectionTimeout);
            }
            ActiveProfileId = profile.Id;
            SetState(VpnConnectionState.Connecting);
            var session = _createSession(profile);
            lock (_stateLock) { _session = session; _latestConnection = null; }
            session.ConnectionChanged += OnSessionConnectionChanged;
            await session.StartAsync(attempt.Token).ConfigureAwait(false);
            attempt.Token.ThrowIfCancellationRequested();
            lock (_stateLock)
            {
                // A RECONNECTING notification may arrive after the first successful handshake
                // but before the StartAsync continuation runs. Preserve the newest notification.
                State = _latestConnection == false ? VpnConnectionState.Connecting : VpnConnectionState.Connected;
                LastError = null;
            }
            StateChanged?.Invoke(this, EventArgs.Empty);
            _ = ObserveExitAsync(session);
        }
        catch (OperationCanceledException)
        {
            try
            {
                await StopOwnedSessionAsync().ConfigureAwait(false);
                if (request == Interlocked.Read(ref _request))
                    SetState(VpnConnectionState.Failed, "OpenVPN did not connect within 30 seconds. Check the profile and server, then retry.");
                else SetState(VpnConnectionState.Disconnected);
            }
            catch (Exception ex) { SetState(VpnConnectionState.Failed, ex.Message); throw; }
        }
        catch (Exception ex)
        {
            var error = ex.Message;
            try { await StopOwnedSessionAsync().ConfigureAwait(false); }
            catch (Exception stopError) { error += " Stop failed: " + stopError.Message; }
            SetState(VpnConnectionState.Failed, error);
            throw new InvalidOperationException(error, ex);
        }
        finally
        {
            lock (_requestLock)
            {
                if (ReferenceEquals(_attempt, attempt)) _attempt = null;
                attempt?.Dispose();
            }
            _gate.Release();
        }
    }

    public async Task DisconnectAsync()
    {
        NewRequest();
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            SetState(VpnConnectionState.Disconnecting);
            await StopOwnedSessionAsync().ConfigureAwait(false);
            SetState(VpnConnectionState.Disconnected);
        }
        catch (Exception ex) { SetState(VpnConnectionState.Failed, ex.Message); throw; }
        finally { _gate.Release(); }
    }

    private async Task StopOwnedSessionAsync()
    {
        if (_session is not { } session) { ActiveProfileId = null; return; }
        if (_beforeSessionStop is not null) await _beforeSessionStop().ConfigureAwait(false);
        // Retain a session when stop fails: Retry/Stop must still own its process.
        await session.StopAsync().ConfigureAwait(false);
        session.ConnectionChanged -= OnSessionConnectionChanged;
        session.Dispose();
        lock (_stateLock) { _session = null; _latestConnection = null; }
        ActiveProfileId = null;
    }

    private async Task ObserveExitAsync(IVpnSession session)
    {
        try { await session.Completion.ConfigureAwait(false); }
        catch { }
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(session, _session)) return;
            var failure = session.Failure ?? "OpenVPN exited. Reconnect to start a new session.";
            await StopOwnedSessionAsync().ConfigureAwait(false);
            SetState(VpnConnectionState.Failed, failure);
        }
        catch (Exception ex) { SetState(VpnConnectionState.Failed, ex.Message); }
        finally { _gate.Release(); }
    }

    private void OnSessionConnectionChanged(object? sender, bool connected)
    {
        lock (_stateLock)
        {
            if (!ReferenceEquals(sender, _session) || State is not (VpnConnectionState.Connected or VpnConnectionState.Connecting)) return;
            _latestConnection = connected;
            State = connected ? VpnConnectionState.Connected : VpnConnectionState.Connecting;
            LastError = null;
        }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private void SetState(VpnConnectionState state, string? error = null)
    {
        lock (_stateLock) { State = state; LastError = error; }
        StateChanged?.Invoke(this, EventArgs.Empty);
    }
}
