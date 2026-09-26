using VpnClient.DnsGuard;
using Xunit;

namespace VpnClient.DnsGuard.Tests;

public sealed class GuardEngineTests
{
    private static readonly RegistryState Original = new("original-command", 0x20);
    private static LeaseRequest Request() => new(Guid.NewGuid(), new(101, 1001), new(102, 1002));

    [Fact]
    public void ActiveRequiresStubAndAlreadyRestoredRegistry()
    {
        var fixture = new Fixture();
        var result = fixture.Engine.Activate(fixture.Request, () => false);
        Assert.Equal("active", result.Status);
        Assert.Equal(Original, fixture.Platform.Registry);
        Assert.Equal("stub", fixture.Platform.Service);
        Assert.Equal("active", fixture.Store.Value!.Phase);
        Assert.True(fixture.Events.IndexOf("save:prepared") < fixture.Events.IndexOf("image:stub"));
        Assert.True(fixture.Events.IndexOf("image:original") < fixture.Events.IndexOf("save:active"));
        Assert.Equal("active", fixture.Engine.Inspect().Status);
    }

    [Fact]
    public void EveryObservedCrashPointCanRecoverWithoutUi()
    {
        var first = new Fixture();
        Assert.Equal("active", first.Engine.Activate(first.Request, () => false).Status);
        Assert.True(first.Snapshots.Count >= 12);
        foreach (var snapshot in first.Snapshots.Where(s => s.Journal is not null))
        {
            var restarted = new Fixture(first.Request);
            restarted.Store.Value = snapshot.Journal;
            restarted.Platform.Registry = snapshot.Registry;
            restarted.Platform.Service = snapshot.Service;
            restarted.Platform.OwnerAlive = false;
            restarted.Platform.BackendAlive = false;
            Assert.Equal("off", restarted.Engine.Restore().Status);
            Assert.Equal(Original, restarted.Platform.Registry);
            Assert.Equal("original", restarted.Platform.Service);
            Assert.Equal("complete", restarted.Store.Value!.Phase);
            Assert.DoesNotContain("terminate-original", restarted.Events);
        }
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("backend")]
    [InlineData("inspect")]
    [InlineData("save:prepared")]
    [InlineData("image:stub")]
    [InlineData("save:image_changed")]
    [InlineData("type:16")]
    [InlineData("save:configuration_changed")]
    [InlineData("recheck")]
    [InlineData("terminate-original")]
    [InlineData("save:original_exited")]
    [InlineData("start-stub")]
    [InlineData("save:stub_running")]
    [InlineData("image:original")]
    [InlineData("save:registry_restored")]
    [InlineData("confirm-stub")]
    [InlineData("save:active")]
    public void SingleOperationFailureDoesNotLeaveReplacementConfiguration(string failAt)
    {
        var fixture = new Fixture { FailOnce = failAt };
        var result = fixture.Engine.Activate(fixture.Request, () => false);
        Assert.NotEqual("active", result.Status);
        Assert.Equal(Original, fixture.Platform.Registry);
        Assert.Equal("original", fixture.Platform.Service);
        Assert.Equal(0, fixture.Platform.ForeignTerminations);
    }

    [Fact]
    public void FailedDurablePrepareHasNoMachineSideEffects()
    {
        var fixture = new Fixture { FailOnce = "save:prepared" };
        fixture.Engine.Activate(fixture.Request, () => false);
        Assert.DoesNotContain(fixture.Events, e => e.StartsWith("image:") || e.StartsWith("type:") || e == "terminate-original");
    }

    [Fact]
    public void SharedHostRefusesBeforeJournalOrMutation()
    {
        var fixture = new Fixture(); fixture.Platform.Shared = true;
        var result = fixture.Engine.Activate(fixture.Request, () => false);
        Assert.Equal("unsupported", result.Status);
        Assert.Null(fixture.Store.Value);
        Assert.DoesNotContain("terminate-original", fixture.Events);
    }

    [Fact]
    public void HostBecomesSharedBeforeTerminationRollsBackWithoutKillingIt()
    {
        var fixture = new Fixture();
        fixture.AfterEvent = e => { if (e == "save:configuration_changed") fixture.Platform.Shared = true; };
        Assert.Equal("unsupported", fixture.Engine.Activate(fixture.Request, () => false).Status);
        Assert.DoesNotContain("terminate-original", fixture.Events);
        Assert.Equal(Original, fixture.Platform.Registry);
    }

    [Theory]
    [InlineData("save:prepared")]
    [InlineData("save:configuration_changed")]
    [InlineData("save:original_exited")]
    [InlineData("save:registry_restored")]
    public void OwnerDeathAtEachActivationBoundaryRestores(string after)
    {
        var fixture = new Fixture();
        fixture.AfterEvent = e => { if (e == after) fixture.Platform.OwnerAlive = false; };
        Assert.NotEqual("active", fixture.Engine.Activate(fixture.Request, () => false).Status);
        Assert.Equal(Original, fixture.Platform.Registry);
        Assert.Equal("original", fixture.Platform.Service);
    }

    [Fact]
    public void StopWhilePreparingCannotPublishLateActive()
    {
        var fixture = new Fixture(); bool stop = false;
        fixture.AfterEvent = e => { if (e == "save:original_exited") stop = true; };
        Assert.NotEqual("active", fixture.Engine.Activate(fixture.Request, () => stop).Status);
        Assert.DoesNotContain("save:active", fixture.Events);
        Assert.Equal("original", fixture.Platform.Service);
    }

    [Fact]
    public void UnknownRegistryEditIsPreservedAndNeedsRecovery()
    {
        var fixture = new Fixture();
        fixture.Engine.Activate(fixture.Request, () => false);
        var external = new RegistryState("third-party-command", 0x20);
        fixture.Platform.Registry = external;
        fixture.Events.Clear();
        Assert.Equal("recoveryRequired", fixture.Engine.Restore().Status);
        Assert.Equal(external, fixture.Platform.Registry);
        Assert.DoesNotContain(fixture.Events, e => e.StartsWith("image:") || e.StartsWith("type:") || e == "restore-service");
    }

    [Fact]
    public void RegistryRaceAfterRecheckDoesNotTerminateOriginal()
    {
        var fixture = new Fixture();
        fixture.AfterEvent = e => { if (e == "recheck") fixture.Platform.Registry = new("external", 0x20); };
        Assert.Equal("recoveryRequired", fixture.Engine.Activate(fixture.Request, () => false).Status);
        Assert.DoesNotContain("terminate-original", fixture.Events);
        Assert.Equal("external", fixture.Platform.Registry.ImagePath);
    }

    [Theory]
    [InlineData(false, 0x20u)]
    [InlineData(false, 0x10u)]
    [InlineData(true, 0x20u)]
    [InlineData(true, 0x10u)]
    public void AllOwnedPartialRegistryStatesRestore(bool stubImage, uint type)
    {
        var fixture = new Fixture();
        fixture.Store.Value = new(1, fixture.Request, Original, "stub-command", "configuration_changed");
        fixture.Platform.Registry = new(stubImage ? "stub-command" : Original.ImagePath, type);
        Assert.Equal("off", fixture.Engine.Restore().Status);
        Assert.Equal(Original, fixture.Platform.Registry);
    }

    [Fact]
    public void ForeignRunningStubIsNeverTerminated()
    {
        var fixture = new Fixture();
        fixture.Engine.Activate(fixture.Request, () => false);
        fixture.Platform.Service = "foreign";
        Assert.Equal("recoveryRequired", fixture.Engine.Restore().Status);
        Assert.Equal("foreign", fixture.Platform.Service);
        Assert.Equal(0, fixture.Platform.ForeignTerminations);
    }

    [Fact]
    public void OriginalRestartFailureKeepsDurableRecoveryRequiredWithoutBroadKill()
    {
        var fixture = new Fixture();
        fixture.Engine.Activate(fixture.Request, () => false);
        fixture.FailOnce = "restore-service";
        Assert.Equal("recoveryRequired", fixture.Engine.Restore().Status);
        Assert.Equal("recovery_required", fixture.Store.Value!.Phase);
        Assert.Equal(Original, fixture.Platform.Registry);
        Assert.Equal("off", fixture.Engine.Restore().Status);
    }

    [Fact]
    public void SecondLeaseCannotReplaceActiveLease()
    {
        var fixture = new Fixture();
        fixture.Engine.Activate(fixture.Request, () => false);
        var result = fixture.Engine.Activate(Request(), () => false);
        Assert.Equal("busy", result.Status);
        Assert.Equal(fixture.Request.Lease, result.Lease);
        Assert.Single(fixture.Events, e => e == "terminate-original");
    }

    [Fact]
    public void InspectDoesNotMutateOrClaimDeadOwnerIsActive()
    {
        var fixture = new Fixture();
        fixture.Engine.Activate(fixture.Request, () => false);
        fixture.Platform.BackendAlive = false; fixture.Events.Clear();
        Assert.Equal("recoveryRequired", fixture.Engine.Inspect().Status);
        Assert.DoesNotContain(fixture.Events, e => e.StartsWith("save:") || e.StartsWith("image:") || e.StartsWith("type:"));
    }

    [Theory]
    [InlineData("image:stub")]
    [InlineData("terminate-original")]
    [InlineData("start-stub")]
    public void PersistentJournalWriteFailureStillRestoresSystemDns(string after)
    {
        var fixture = new Fixture();
        fixture.AfterEvent = e => { if (e == after) fixture.Store.WritesFail = true; };
        Assert.Equal("recoveryRequired", fixture.Engine.Activate(fixture.Request, () => false).Status);
        Assert.Equal(Original, fixture.Platform.Registry);
        Assert.Equal("original", fixture.Platform.Service);
        Assert.NotNull(fixture.Store.Value);
        Assert.NotEqual("complete", fixture.Store.Value.Phase);
    }

    [Fact]
    public void OwnProcessOriginalTypeIsPreservedAcrossActivationAndRecovery()
    {
        var fixture = new Fixture();
        fixture.Platform.ExpectedOriginal = Original with { Type = 0x10 };
        fixture.Platform.Registry = fixture.Platform.ExpectedOriginal;
        Assert.Equal("active", fixture.Engine.Activate(fixture.Request, () => false).Status);
        Assert.Equal(0x10u, fixture.Store.Value!.Original.Type);
        Assert.Equal("off", fixture.Engine.Restore().Status);
        Assert.Equal(fixture.Platform.ExpectedOriginal, fixture.Platform.Registry);
    }

    private sealed record Snapshot(GuardJournal? Journal, RegistryState Registry, string Service);
    private sealed class Fixture
    {
        internal readonly LeaseRequest Request;
        internal readonly List<string> Events = new();
        internal readonly List<Snapshot> Snapshots = new();
        internal string? FailOnce;
        internal Action<string>? AfterEvent;
        internal readonly Store Store;
        internal readonly Platform Platform;
        internal readonly GuardEngine Engine;
        internal Fixture(LeaseRequest? request = null)
        { Request = request ?? GuardEngineTests.Request(); Store = new(this); Platform = new(this); Engine = new(Platform, Store); }
        internal void Event(string name)
        {
            Events.Add(name);
            if (FailOnce == name) { FailOnce = null; throw new IOException("Injected storage/platform fault with private detail"); }
            AfterEvent?.Invoke(name);
        }
        internal void Snapshot() => Snapshots.Add(new(Store.Value, Platform.Registry, Platform.Service));
    }
    private sealed class Store(Fixture f) : IGuardJournalStore
    {
        internal GuardJournal? Value;
        internal bool WritesFail;
        public GuardJournal? Read() => Value;
        public void Write(GuardJournal value)
        {
            if (WritesFail) throw new IOException("Persistent storage failure");
            f.Event("save:" + value.Phase); Value = value; f.Snapshot();
        }
    }
    private sealed class Process(Func<bool> alive) : IGuardProcess { public bool Alive => alive(); public void Dispose() { } }
    private sealed class Platform(Fixture f) : IGuardPlatform
    {
        internal RegistryState Registry = Original;
        internal RegistryState ExpectedOriginal = Original;
        internal string Service = "original";
        internal bool OwnerAlive = true, BackendAlive = true, Shared;
        internal int ForeignTerminations = 0;
        public RegistryState ReadRegistry() => Registry;
        public string StubImage(Guid lease) => "stub-command";
        public void SetImage(RegistryState expected, string image)
        {
            f.Event("image:" + (image == Original.ImagePath ? "original" : "stub"));
            if (Registry != expected) throw new GuardException("registry_conflict");
            Registry = Registry with { ImagePath = image }; f.Snapshot();
        }
        public void SetType(RegistryState expected, uint type)
        {
            f.Event("type:" + type);
            if (Registry != expected) throw new GuardException("registry_conflict");
            Registry = Registry with { Type = type }; f.Snapshot();
        }
        public IGuardProcess OpenOwner(ProcessIdentity identity, bool backend)
        { f.Event(backend ? "backend" : "owner"); return new Process(() => backend ? BackendAlive : OwnerAlive); }
        public IGuardProcess InspectOriginal(RegistryState original)
        { f.Event("inspect"); if (Shared) throw new GuardException("shared_or_unknown_host", true); return new Process(() => Service == "original"); }
        public void RecheckOriginal(IGuardProcess process, RegistryState original)
        { f.Event("recheck"); if (Shared) throw new GuardException("shared_or_unknown_host", true); }
        public void TerminateOriginal(IGuardProcess process)
        { f.Event("terminate-original"); Assert.True(process.Alive); Service = "down"; f.Snapshot(); }
        public void StartAndConfirmStub(GuardJournal journal)
        { f.Event("start-stub"); Assert.Equal(new RegistryState("stub-command", 0x10), Registry); Service = "stub"; f.Snapshot(); }
        public bool IsConfirmedStub(GuardJournal journal) { f.Event("confirm-stub"); return Service == "stub"; }
        public void RestoreOriginalService(GuardJournal journal)
        {
            f.Event("restore-service");
            if (Service == "foreign") throw new GuardException("foreign_dnscache_process");
            Assert.Equal(ExpectedOriginal, Registry); Service = "original"; f.Snapshot();
        }
    }
}
