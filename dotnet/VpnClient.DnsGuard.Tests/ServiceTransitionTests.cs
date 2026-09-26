using Xunit;

namespace VpnClient.DnsGuard.Tests;

public sealed class ServiceTransitionTests
{
    [Theory]
    [InlineData("stub_start")]
    [InlineData("original_restore")]
    public void AutorestartAlreadyAtExpectedIdentityDoesNotRequireObservingStopped(string stage)
    {
        var fixture = new Transition(ServiceTransitionState.ExpectedRunning);
        fixture.Run(stage);
        Assert.Equal(0, fixture.Starts);
        Assert.Equal(0, fixture.Stops);
    }

    [Theory]
    [InlineData("stub_start")]
    [InlineData("original_restore")]
    public void StaleDepartedPidAndPendingCanGoDirectlyToExpectedRunning(string stage)
    {
        var fixture = new Transition(ServiceTransitionState.Pending, ServiceTransitionState.Pending, ServiceTransitionState.ExpectedRunning);
        fixture.Run(stage);
        Assert.Equal(0, fixture.Starts);
    }

    [Fact]
    public void ExplicitStartIsIssuedOnceAfterObservedStopped()
    {
        var fixture = new Transition(ServiceTransitionState.Pending, ServiceTransitionState.Stopped,
            ServiceTransitionState.Pending, ServiceTransitionState.ExpectedRunning);
        fixture.Run();
        Assert.Equal(1, fixture.Starts);
    }

    [Fact]
    public void RestoreStopsOnlyIdentifiedOwnedStubAndAcceptsDirectAutorestart()
    {
        var fixture = new Transition(ServiceTransitionState.OwnedReplacementRunning,
            ServiceTransitionState.OwnedReplacementRunning, ServiceTransitionState.ExpectedRunning);
        fixture.Run("original_restore", allowStop: true);
        Assert.Equal(1, fixture.Stops);
        Assert.Equal(0, fixture.Starts);
    }

    [Fact]
    public void StubThatFinishesStartingDuringRecoveryIsStoppedBeforeOriginalStart()
    {
        var fixture = new Transition(ServiceTransitionState.Pending, ServiceTransitionState.OwnedReplacementRunning,
            ServiceTransitionState.Pending, ServiceTransitionState.Stopped, ServiceTransitionState.Pending, ServiceTransitionState.ExpectedRunning);
        fixture.Run("original_restore", allowStop: true);
        Assert.Equal(1, fixture.Stops);
        Assert.Equal(1, fixture.Starts);
    }

    [Fact]
    public void UnexpectedLiveProcessNeverTriggersStartOrStop()
    {
        var fixture = new Transition(ServiceTransitionState.UnexpectedRunning);
        Assert.Equal("original_restore_identity_mismatch", Assert.Throws<GuardException>(() => fixture.Run("original_restore", true)).Reason);
        Assert.Equal(0, fixture.Starts);
        Assert.Equal(0, fixture.Stops);
    }

    [Fact]
    public void StartFailureReturningStoppedIsReportedWithoutRestartLoop()
    {
        var fixture = new Transition(ServiceTransitionState.Stopped, ServiceTransitionState.Pending, ServiceTransitionState.Stopped);
        Assert.Equal("stub_start_stopped", Assert.Throws<GuardException>(() => fixture.Run()).Reason);
        Assert.Equal(1, fixture.Starts);
    }

    [Theory]
    [InlineData("stub_start")]
    [InlineData("original_restore")]
    public void PendingTimeoutIdentifiesStageAndIsBounded(string stage)
    {
        var fixture = new Transition(ServiceTransitionState.Pending);
        Assert.Equal(stage + "_timeout", Assert.Throws<GuardException>(() => fixture.Run(stage)).Reason);
        Assert.Equal(TimeSpan.FromSeconds(1), fixture.Elapsed);
        Assert.Equal(0, fixture.Starts);
    }

    [Fact]
    public void GracefulStopTimeoutDoesNotRepeatedlyStopOrKill()
    {
        var fixture = new Transition(ServiceTransitionState.OwnedReplacementRunning);
        Assert.Equal("original_restore_timeout", Assert.Throws<GuardException>(() => fixture.Run("original_restore", true)).Reason);
        Assert.Equal(1, fixture.Stops);
    }

    [Fact]
    public void LostOwnedIdentityBeforeStopRetriesObservationWithoutClaimingStopSucceeded()
    {
        var fixture = new Transition(ServiceTransitionState.OwnedReplacementRunning,
            ServiceTransitionState.OwnedReplacementRunning, ServiceTransitionState.ExpectedRunning) { StopResult = false };
        fixture.Run("original_restore", true);
        Assert.Equal(2, fixture.Stops);
        Assert.Equal(0, fixture.Starts);
    }

    private sealed class Transition(params ServiceTransitionState[] states)
    {
        internal int Starts, Stops;
        internal TimeSpan Elapsed;
        internal bool StopResult = true;
        private int _index;
        internal void Run(string stage = "stub_start", bool allowStop = false) => ServiceTransition.EnsureRunning(
            () => states[Math.Min(_index++, states.Length - 1)], () => Starts++,
            () => Elapsed += TimeSpan.FromMilliseconds(100), () => Elapsed,
            stage, TimeSpan.FromSeconds(1), allowStop ? () => { Stops++; return StopResult; } : null);
    }
}
