using Xunit;

namespace VpnClient.DnsGuard.Tests;

public sealed class ProtocolTests
{
    [Fact]
    public void ReleaseAfterRejectedNewAcquireAcknowledgesNewLeaseNotCompletedHistoricalLease()
    {
        Guid oldLease = Guid.NewGuid(), requested = Guid.NewGuid();
        var result = GuardProtocol.ReleaseResult(requested, GuardResult.Of("off", oldLease));
        Assert.Equal("off", result.Status);
        Assert.Equal(requested, result.Lease);
        Assert.Equal(0, result.ExitCode);
    }
    [Theory]
    [InlineData("busy")]
    [InlineData("recoveryRequired")]
    public void ReleaseDoesNotHideForeignOrUnrestoredLease(string status)
    {
        var original = GuardResult.Of(status, Guid.NewGuid());
        Assert.Equal(original, GuardProtocol.ReleaseResult(Guid.NewGuid(), original));
    }
    [Fact]
    public void LiveForeignInstallerCannotBeOverwrittenEvenWhenPidWasReused()
    {
        var marker = new ProcessIdentity(123, 1000);
        Assert.False(GuardProtocol.MaintenanceAllowed(marker, new(123, 2000), _ => true));
        Assert.True(GuardProtocol.MaintenanceAllowed(marker, marker, _ => true));
        Assert.True(GuardProtocol.MaintenanceAllowed(marker, new(456, 2000), _ => false));
        Assert.False(GuardProtocol.MaintenanceAllowed(marker, null, _ => true));
    }
    [Fact]
    public void CustomInstallNoOpRequiresNoServiceNoUnfinishedJournalAndNoMaintenance()
    {
        var journal = new GuardJournal(1, new(Guid.NewGuid(), new(1, 2), new(3, 4)), new("original", 0x20), "stub", "complete");
        Assert.True(GuardProtocol.UninstalledNoOp(false, null, null));
        Assert.True(GuardProtocol.UninstalledNoOp(false, journal, null));
        Assert.False(GuardProtocol.UninstalledNoOp(true, null, null));
        Assert.False(GuardProtocol.UninstalledNoOp(false, journal with { Phase = "prepared" }, null));
        Assert.False(GuardProtocol.UninstalledNoOp(false, null, new(1, 2)));
    }
    [Fact]
    public void ExistingServiceMissingFailureActionsAfterInterruptedInstallIsRepairedAndVerified()
    {
        var service = new Settings();
        RecoveryPolicy.Ensure(service);
        Assert.Equal(1, service.Configured);
        Assert.True(service.Value.Required);
        Assert.Equal(new[] { "verify", "read", "configure", "verify", "read" }, service.Events);
        RecoveryPolicy.Ensure(service);
        Assert.Equal(1, service.Configured);
    }
    [Fact]
    public void ForeignServiceIsNeverReconfigured()
    {
        var service = new Settings { Owned = false };
        Assert.Throws<GuardException>(() => RecoveryPolicy.Ensure(service));
        Assert.Equal(0, service.Configured);
    }
    [Fact]
    public void FailedRecoveryPolicyRoundTripRefusesAcquisition()
    {
        var service = new Settings { Persist = false };
        Assert.Throws<GuardException>(() => RecoveryPolicy.Ensure(service));
    }
    private sealed class Settings : IRecoverySettings
    {
        internal readonly List<string> Events = new();
        internal bool Owned = true, Persist = true;
        internal int Configured;
        internal RecoverySettings Value = new(0, Array.Empty<RestartAction>(), false);
        public void VerifyOwnership() { Events.Add("verify"); if (!Owned) throw new GuardException("guardian_configuration_conflict"); }
        public RecoverySettings Read() { Events.Add("read"); return Value; }
        public void ConfigureRequired()
        {
            Events.Add("configure"); Configured++;
            if (Persist) Value = new(86400, new[] { new RestartAction(1, 1000), new RestartAction(1, 60000), new RestartAction(1, 60000) }, true);
        }
    }
}
