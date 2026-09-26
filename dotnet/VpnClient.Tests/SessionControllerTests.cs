using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public class SessionControllerTests
{
    [Fact]
    public async Task ReconnectingNotificationDuringStartupIsNotOverwritten()
    {
        var session = new FakeSession { ReconnectBeforeStartReturns = true };
        var controller = new VpnSessionController(_ => session);
        await controller.ConnectAsync(new OvpnEntry());
        Assert.Equal(VpnConnectionState.Connecting, controller.State);
        await controller.DisconnectAsync();
    }

    [Fact]
    public async Task CancelDuringHandshakeStopsAndDisposesOwnedSession()
    {
        var session = new FakeSession { WaitForCancellation = true };
        var controller = new VpnSessionController(_ => session);
        var connecting = controller.ConnectAsync(new OvpnEntry());
        await session.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await controller.DisconnectAsync();
        await connecting;
        Assert.Equal(VpnConnectionState.Disconnected, controller.State);
        Assert.False(controller.HasSession);
        Assert.True(session.Disposed);
        Assert.Equal(1, session.Stops);
    }

    [Fact]
    public async Task ReplacementWaitsForPreviousProcessExit()
    {
        var active = 0;
        var maximum = 0;
        var first = new FakeSession { WaitForCancellation = true };
        var second = new FakeSession();
        foreach (var session in new[] { first, second })
        {
            session.OnStart = () => { active++; maximum = Math.Max(maximum, active); };
            session.OnStop = () => active--;
        }
        var controller = new VpnSessionController(profile => profile.Id == "a" ? first : second);
        var connecting = controller.ConnectAsync(new OvpnEntry { Id = "a" });
        await first.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await controller.ConnectAsync(new OvpnEntry { Id = "b" });
        await connecting;
        Assert.Equal(1, maximum);
        Assert.True(first.Disposed);
        Assert.Equal("b", controller.ActiveProfileId);
        Assert.Equal(VpnConnectionState.Connected, controller.State);
        await controller.DisconnectAsync();
        Assert.Equal(0, active);
    }

    [Fact]
    public async Task StopFailureRetainsOwnershipAndPreventsReplacement()
    {
        var session = new FakeSession();
        var creations = 0;
        var controller = new VpnSessionController(_ => { creations++; return session; });
        await controller.ConnectAsync(new OvpnEntry());
        session.StopFailure = new IOException("cannot stop");
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ConnectAsync(new OvpnEntry()));
        Assert.True(controller.HasSession);
        Assert.False(session.Disposed);
        Assert.Equal(1, creations);
        session.StopFailure = null;
        await controller.DisconnectAsync();
        Assert.True(session.Disposed);
    }

    [Fact]
    public async Task FailedStartCleansOwnedSessionAndAllowsRetry()
    {
        var bad = new FakeSession { StartFailure = new IOException("AUTH_FAILED") };
        var good = new FakeSession();
        var count = 0;
        var controller = new VpnSessionController(_ => ++count == 1 ? bad : good);
        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.ConnectAsync(new OvpnEntry()));
        Assert.True(bad.Disposed);
        Assert.False(controller.HasSession);
        Assert.Contains("AUTH_FAILED", controller.LastError);
        await controller.ConnectAsync(new OvpnEntry());
        Assert.Equal(VpnConnectionState.Connected, controller.State);
        await controller.DisconnectAsync();
    }

    [Fact]
    public async Task TimeoutStopsAttemptBeforeRetry()
    {
        var slow = new FakeSession { WaitForCancellation = true };
        var controller = new VpnSessionController(_ => slow, TimeSpan.FromMilliseconds(100));
        await controller.ConnectAsync(new OvpnEntry());
        Assert.Equal(VpnConnectionState.Failed, controller.State);
        Assert.False(controller.HasSession);
        Assert.True(slow.Disposed);
    }

    [Fact]
    public async Task UnexpectedExitChangesStateWithoutRedirectorTelemetry()
    {
        var session = new FakeSession();
        var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var controller = new VpnSessionController(_ => session);
        controller.StateChanged += (_, _) => { if (controller.State == VpnConnectionState.Failed) failed.TrySetResult(); };
        await controller.ConnectAsync(new OvpnEntry());
        session.Exit("connection lost");
        await failed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("connection lost", controller.LastError);
        Assert.False(controller.HasSession);
    }

    [Fact]
    public async Task LateOldSessionExitCannotClearReplacement()
    {
        var first = new FakeSession();
        var second = new FakeSession();
        var controller = new VpnSessionController(profile => profile.Id == "a" ? first : second);
        await controller.ConnectAsync(new OvpnEntry { Id = "a" });
        await controller.ConnectAsync(new OvpnEntry { Id = "b" });
        first.Exit("old exit");
        await controller.DisconnectAsync();
        Assert.True(second.Disposed);
        Assert.Equal(VpnConnectionState.Disconnected, controller.State);
    }

    private sealed class FakeSession : IVpnSession
    {
        public event EventHandler<bool>? ConnectionChanged;
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task Completion => _exit.Task;
        public string? Failure { get; private set; }
        public bool WaitForCancellation, Disposed, ReconnectBeforeStartReturns;
        public int Stops;
        public Exception? StartFailure, StopFailure;
        public Action? OnStart, OnStop;
        public async Task StartAsync(CancellationToken ct)
        {
            OnStart?.Invoke();
            Started.TrySetResult();
            if (StartFailure is not null) throw StartFailure;
            if (WaitForCancellation) await Task.Delay(Timeout.Infinite, ct);
            ConnectionChanged?.Invoke(this, true);
            if (ReconnectBeforeStartReturns) ConnectionChanged?.Invoke(this, false);
        }
        public Task StopAsync()
        {
            if (StopFailure is not null) throw StopFailure;
            Stops++;
            OnStop?.Invoke();
            return Task.CompletedTask;
        }
        public void Exit(string reason) { Failure = reason; _exit.TrySetResult(); }
        public void Dispose() => Disposed = true;
    }
}
