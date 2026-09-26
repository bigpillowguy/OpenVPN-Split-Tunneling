using System.Diagnostics;
using VpnClient.Ui;
using Vpnclient.Status;
using Xunit;

namespace VpnClient.Tests;

public sealed class ExperimentalDnsTests
{
    private static readonly DnsProcessIdentity Owner = new(17, 133700000000000001);
    private static DnsEligibility Target() => new(Guid.NewGuid(), Guid.NewGuid(), new(19, 133700000000000002));
    private static DnsGuardReply Off(Guid? lease = null) => new(1, "off", lease, "restored");

    [Fact]
    public void PreferenceDefaultsOffAndPersistsBothDirections()
    {
        var directory = Path.Combine(Path.GetTempPath(), "VpnClient-dns-config-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "config.json");
        try
        {
            var config = Config.Load(path);
            Assert.False(config.ExperimentalSplitDns);
            config.ExperimentalSplitDns = true; config.Save();
            Assert.True(Config.Load(path).ExperimentalSplitDns);
            config.ExperimentalSplitDns = false; config.Save();
            Assert.False(Config.Load(path).ExperimentalSplitDns);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task DoesNotAcquireWithoutExplicitPreferenceAndFreshEligibility()
    {
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner);
        await model.InitializeAsync(false);
        await model.ObserveAsync(Target());
        Assert.Empty(guard.Acquired);
        await model.SetEnabledAsync(true);
        Assert.Single(guard.Acquired);
        Assert.Equal(ExperimentalDnsState.Active, model.State);
        await model.SetEnabledAsync(false);
        Assert.Equal(guard.Acquired[0], Assert.Single(guard.Released));
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task LateAcquireAfterDisconnectIsReleasedBeforePauseCompletes()
    {
        var guard = new FakeGuard { BlockAcquire = true };
        var model = new ExperimentalDnsController(guard, Owner);
        model.StateChanged += (_, _) => guard.ObservedStates.Add(model.State);
        await model.InitializeAsync(true);
        var observed = model.ObserveAsync(Target());
        await guard.AcquireStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var stopped = model.PauseAsync();
        Assert.False(stopped.IsCompleted);
        guard.AcquireReply.SetResult(new(1, "active", guard.Acquired[0], "active"));
        await Task.WhenAll(observed, stopped);
        Assert.Equal(guard.Acquired[0], Assert.Single(guard.Released));
        Assert.Equal(ExperimentalDnsState.Off, model.State);
        Assert.DoesNotContain(ExperimentalDnsState.Active, guard.ObservedStates);
    }

    [Fact]
    public async Task NewSessionWaitsForOldLeaseRestorationEvenWithSameBackendPid()
    {
        var guard = new FakeGuard { BlockAcquire = true };
        var model = new ExperimentalDnsController(guard, Owner);
        model.StateChanged += (_, _) => guard.ObservedStates.Add(model.State);
        await model.InitializeAsync(true);
        var old = model.ObserveAsync(Target());
        await guard.AcquireStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var newer = model.ObserveAsync(Target());
        guard.BlockAcquire = false;
        guard.AcquireReply.SetResult(new(1, "active", guard.Acquired[0], "active"));
        await Task.WhenAll(old, newer);
        Assert.Equal(new[] { "recover", "acquire", "release", "acquire" }, guard.Calls);
        Assert.Equal(2, guard.Acquired.Count);
        Assert.NotEqual(guard.Acquired[0], guard.Acquired[1]);
        Assert.Equal(ExperimentalDnsState.Active, model.State);
    }

    [Fact]
    public async Task ExpiredBackendReadinessRevokesActiveLease()
    {
        var now = DateTimeOffset.UtcNow;
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner, () => now);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        now += TimeSpan.FromSeconds(3);
        await model.CheckFreshnessAsync();
        Assert.Single(guard.Released);
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task ForeignLiveStartupLeaseIsNotReleasedOrAcquired()
    {
        var guard = new FakeGuard { Recovery = new(1, "busy", Guid.NewGuid(), "live_owner") };
        var model = new ExperimentalDnsController(guard, Owner);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
        Assert.Empty(guard.Acquired); Assert.Empty(guard.Released);
    }

    [Fact]
    public async Task UnconfirmedReleasePreventsStoppingUntilRetrySucceeds()
    {
        var guard = new FakeGuard { FailRelease = true };
        var model = new ExperimentalDnsController(guard, Owner);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        await Assert.ThrowsAsync<InvalidOperationException>(model.PauseAsync);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
        guard.FailRelease = false;
        await model.PauseAsync();
        Assert.Equal(2, guard.Released.Count);
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task UncertainAcquireIsRestoredAndDoesNotRetryEverySnapshot()
    {
        var guard = new FakeGuard { ThrowAcquire = true };
        var model = new ExperimentalDnsController(guard, Owner);
        await model.InitializeAsync(true);
        var target = Target(); await model.ObserveAsync(target); await model.ObserveAsync(target);
        Assert.Single(guard.Acquired); Assert.Single(guard.Released);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public async Task ActiveGuardLeaseMustRemainConfirmed()
    {
        var now = DateTimeOffset.UtcNow;
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner, () => now);
        await model.InitializeAsync(true); var target = Target(); await model.ObserveAsync(target);
        now += TimeSpan.FromSeconds(4); await model.ObserveAsync(target);
        guard.Inspected = Off();
        await model.CheckFreshnessAsync();
        Assert.Contains("inspect", guard.Calls);
        Assert.Single(guard.Released);
        Assert.Single(guard.Acquired);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public void GuardArgumentsCarryExactOwnershipWithoutShellQuoting()
    {
        var lease = Guid.NewGuid(); var backend = Target().Backend;
        var arguments = DnsGuardClient.AcquireArguments(lease, Owner, backend);
        Assert.Equal(new[] { "acquire", "--lease", lease.ToString("D"), "--owner-pid", "17", "--owner-created", "133700000000000001",
            "--backend-pid", "19", "--backend-created", "133700000000000002" }, arguments);
        var start = new ProcessStartInfo(); Redirector.AddSplitDnsArgument(start, false); Assert.Empty(start.ArgumentList);
        Redirector.AddSplitDnsArgument(start, true); Assert.Equal("--split-dns", Assert.Single(start.ArgumentList));
    }

    [Theory]
    [InlineData("{\"version\":1,\"status\":\"active\",\"reason\":\"active\"}", 0)]
    [InlineData("{\"version\":1,\"status\":\"off\",\"reason\":\"off\"}", 4)]
    [InlineData("{\"version\":2,\"status\":\"off\",\"reason\":\"off\"}", 0)]
    public void GuardProtocolRejectsUnownedOrInconsistentSuccess(string json, int exit)
        => Assert.Throws<InvalidDataException>(() => DnsGuardClient.ParseReply(json, exit));

    [Fact]
    public void ReadinessRequiresCurrentProviderGenerationAndOwnedBinding()
    {
        var target = Target();
        var binding = new VpnSessionBinding(1, target.SessionId, 30, 100, @"C:\OpenVPN\openvpn.exe", Guid.NewGuid(), 4, "10.8.0.2", "10.8.0.1",
            new("ready", target.Generation, new[] { new VpnDnsServer("10.8.0.1") }));
        var snapshot = new Snapshot { Vpn = new() { Up = true, AdapterIp = binding.Ipv4 }, SplitDns = new()
            { Enabled = true, Ready = true, SessionId = target.SessionId.ToString("N"), Generation = target.Generation.ToString("N") } };
        Assert.Equal(target, ExperimentalDnsReadiness.Evaluate(true, true, snapshot, binding, target.Backend));
        Assert.Null(ExperimentalDnsReadiness.Evaluate(true, false, snapshot, binding, target.Backend));
        snapshot.SplitDns.Generation = Guid.NewGuid().ToString("N");
        Assert.Null(ExperimentalDnsReadiness.Evaluate(true, true, snapshot, binding, target.Backend));
        snapshot.SplitDns = null;
        Assert.Null(ExperimentalDnsReadiness.Evaluate(true, true, snapshot, binding, target.Backend));
    }

    [Fact]
    public void ReadinessRejectsInconsistentOrOversizedBackendFlags()
    {
        var id = Guid.NewGuid().ToString("N");
        var snapshot = new Snapshot { Vpn = new(), SplitDns = new() { Enabled = false, Ready = true, SessionId = id, Generation = id } };
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.SplitDns.Enabled = true; snapshot.SplitDns.Fault = new string('x', 65);
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.SplitDns.Fault = ""; snapshot.SplitDns.Generation = "invalid";
        Assert.False(SnapshotValidator.IsValid(snapshot));
    }

    [Fact]
    public void DiagnosticsRequireFreshActiveStateAndNeverDisplayRawFaults()
    {
        var state = new SplitDnsState { Enabled = true, Dropped = 5, Fault = "unsupported_transport" };
        Assert.Equal(" Blocked packets: 5 (unsupported DNS transport).", ExperimentalDnsDiagnostics.Format(state, true, true));
        Assert.Empty(ExperimentalDnsDiagnostics.Format(state, false, true));
        Assert.Empty(ExperimentalDnsDiagnostics.Format(state, true, false));
        state.Fault = "arbitrary backend content";
        Assert.Equal(" Blocked packets: 5 (DNS routing error).", ExperimentalDnsDiagnostics.Format(state, true, true));
        state.Fault = ""; state.Dropped = 0;
        Assert.Empty(ExperimentalDnsDiagnostics.Format(state, true, true));
    }

    private sealed class FakeGuard : IDnsGuardClient
    {
        public readonly List<string> Calls = new();
        public readonly List<Guid> Acquired = new(), Released = new();
        public readonly List<ExperimentalDnsState> ObservedStates = new();
        public readonly TaskCompletionSource AcquireStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<DnsGuardReply> AcquireReply = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool BlockAcquire, ThrowAcquire, FailRelease;
        public DnsGuardReply Recovery = Off();
        public DnsGuardReply? Inspected;
        public Task<DnsGuardReply> RecoverAsync() { Calls.Add("recover"); return Task.FromResult(Recovery); }
        public Task<DnsGuardReply> InspectAsync() { Calls.Add("inspect"); return Task.FromResult(Inspected ?? new(1, "active", Acquired.Last(), "active")); }
        public Task<DnsGuardReply> AcquireAsync(Guid lease, DnsProcessIdentity owner, DnsProcessIdentity backend)
        {
            Assert.Equal(Owner, owner); Calls.Add("acquire"); Acquired.Add(lease); AcquireStarted.TrySetResult();
            if (ThrowAcquire) throw new IOException("owned fake transport failure");
            return BlockAcquire ? AcquireReply.Task : Task.FromResult(new DnsGuardReply(1, "active", lease, "active"));
        }
        public Task<DnsGuardReply> ReleaseAsync(Guid lease)
        { Calls.Add("release"); Released.Add(lease); return Task.FromResult(FailRelease ? new DnsGuardReply(1, "recoveryRequired", lease, "restore_failed") : Off(lease)); }
    }
}
