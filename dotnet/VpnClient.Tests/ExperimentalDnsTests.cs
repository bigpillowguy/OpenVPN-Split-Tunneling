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
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
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
        var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
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
        var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
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
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner, new FakeControl(), () => now);
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
        var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
        Assert.Empty(guard.Acquired); Assert.Empty(guard.Released);
    }

    [Fact]
    public async Task UnconfirmedReleasePreventsStoppingUntilRetrySucceeds()
    {
        var guard = new FakeGuard { FailRelease = true };
        var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
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
        var model = new ExperimentalDnsController(guard, Owner, new FakeControl());
        await model.InitializeAsync(true);
        var target = Target(); await model.ObserveAsync(target); await model.ObserveAsync(target);
        Assert.Single(guard.Acquired); Assert.Single(guard.Released);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public async Task ActiveGuardLeaseMustRemainConfirmed()
    {
        var now = DateTimeOffset.UtcNow;
        var guard = new FakeGuard(); var model = new ExperimentalDnsController(guard, Owner, new FakeControl(), () => now);
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

    [Fact]
    public async Task ArmAcknowledgementPrecedesGuardAcquireAndDisarmAckPrecedesOff()
    {
        var guard = new FakeGuard(); var control = new FakeControl(guard.Calls) { BlockArm = true, BlockDisarm = true };
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true);
        var observe = model.ObserveAsync(Target());
        await control.ArmStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Empty(guard.Acquired);
        control.ArmAck.SetResult(); await observe;
        Assert.Equal(ExperimentalDnsState.Active, model.State);
        var pause = model.PauseAsync();
        await control.DisarmStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Single(guard.Released);
        Assert.False(pause.IsCompleted);
        Assert.Equal(ExperimentalDnsState.Restoring, model.State);
        control.DisarmAck.SetResult(); await pause;
        Assert.Equal(new[] { "recover", "arm", "acquire", "release", "disarm" }, guard.Calls);
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task TimedOutArmIsDisarmedWithoutEverChangingTheWindowsService()
    {
        var guard = new FakeGuard(); var control = new FakeControl { ThrowArm = true };
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        Assert.Empty(guard.Acquired); Assert.Empty(guard.Released);
        Assert.Equal(control.LastArm, control.LastDisarm);
        Assert.NotNull(control.LastDisarm);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public async Task SupersededArmAcknowledgementCannotStartTheGuard()
    {
        var guard = new FakeGuard(); var control = new FakeControl { BlockArm = true };
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true);
        var observe = model.ObserveAsync(Target());
        await control.ArmStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var pause = model.PauseAsync();
        control.ArmAck.SetResult(); await Task.WhenAll(observe, pause);
        Assert.Empty(guard.Acquired); Assert.Empty(guard.Released);
        Assert.Equal(control.LastArm, control.LastDisarm);
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task FailedGuardRestoreNeverDisarmsAdmission()
    {
        var guard = new FakeGuard { FailRelease = true }; var control = new FakeControl();
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        await Assert.ThrowsAsync<InvalidOperationException>(model.PauseAsync);
        Assert.Null(control.LastDisarm);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public async Task FailedDisarmKeepsLeaseAndPauseBlockedEvenThoughGuardIsAlreadyOff()
    {
        var guard = new FakeGuard(); var control = new FakeControl { FailDisarm = true };
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        await Assert.ThrowsAsync<InvalidOperationException>(model.PauseAsync);
        Assert.Single(guard.Released);
        control.FailDisarm = false; await model.PauseAsync();
        Assert.Single(guard.Released); // The confirmed guard release is retained across a control retry.
        Assert.Equal(ExperimentalDnsState.Off, model.State);
    }

    [Fact]
    public async Task LostBackendArmAcknowledgementRestoresGuardBeforeDisarming()
    {
        var guard = new FakeGuard(); var control = new FakeControl(guard.Calls);
        var model = new ExperimentalDnsController(guard, Owner, control);
        await model.InitializeAsync(true); await model.ObserveAsync(Target());
        control.Confirmed = false;
        await model.CheckFreshnessAsync();
        Assert.Equal(new[] { "recover", "arm", "acquire", "release", "disarm" }, guard.Calls);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
    }

    [Fact]
    public async Task UnsupportedDnsApiConfigurationWaitsForDisarmAndDoesNotRetrySameSession()
    {
        var guard = new FakeGuard { UnsupportedReason = "dns_api_fallback_unverified" };
        var control = new FakeControl(guard.Calls) { BlockDisarm = true };
        var model = new ExperimentalDnsController(guard, Owner, control);
        model.StateChanged += (_, _) => guard.ObservedStates.Add(model.State);
        await model.InitializeAsync(true);
        var target = Target();
        var observed = model.ObserveAsync(target);
        await control.DisarmStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Single(guard.Released);
        Assert.False(observed.IsCompleted);
        Assert.Equal(ExperimentalDnsState.RecoveryRequired, model.State);
        control.DisarmAck.SetResult();
        await observed;
        Assert.Equal(ExperimentalDnsState.Unsupported, model.State);
        Assert.Contains("per-app DNS isolation is off", model.Detail);
        Assert.False(control.Confirmed);
        Assert.Equal(new[] { "recover", "arm", "acquire", "release", "disarm" }, guard.Calls);
        await model.ObserveAsync(target);
        await model.CheckFreshnessAsync();
        Assert.Single(guard.Acquired);
        Assert.DoesNotContain(ExperimentalDnsState.Active, guard.ObservedStates);
        await model.PauseAsync();
    }

    private sealed class FakeControl(List<string>? calls = null) : IDnsControlClient
    {
        private Guid? _lease;
        public Guid? LastArm, LastDisarm;
        public bool BlockArm, BlockDisarm, ThrowArm, FailDisarm, Confirmed;
        public readonly TaskCompletionSource ArmStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource ArmAck = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource DisarmStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource DisarmAck = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task ArmAsync(Guid lease, DnsEligibility target)
        {
            calls?.Add("arm"); LastArm = _lease = lease; Confirmed = false; ArmStarted.TrySetResult();
            if (ThrowArm) throw new IOException("Uncertain arm ACK");
            if (BlockArm) await ArmAck.Task;
            Confirmed = true;
        }
        public async Task DisarmAsync(Guid lease, DnsEligibility target)
        {
            calls?.Add("disarm"); LastDisarm = lease; DisarmStarted.TrySetResult();
            if (FailDisarm) throw new IOException("Uncertain off ACK");
            if (BlockDisarm) await DisarmAck.Task;
            _lease = null; Confirmed = false;
        }
        public bool IsArmed(Guid lease, DnsEligibility target) => Confirmed && _lease == lease;
    }

    private sealed class FakeGuard : IDnsGuardClient
    {
        public readonly List<string> Calls = new();
        public readonly List<Guid> Acquired = new(), Released = new();
        public readonly List<ExperimentalDnsState> ObservedStates = new();
        public readonly TaskCompletionSource AcquireStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<DnsGuardReply> AcquireReply = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool BlockAcquire, ThrowAcquire, FailRelease;
        public string? UnsupportedReason;
        public DnsGuardReply Recovery = Off();
        public DnsGuardReply? Inspected;
        public Task<DnsGuardReply> RecoverAsync() { Calls.Add("recover"); return Task.FromResult(Recovery); }
        public Task<DnsGuardReply> InspectAsync() { Calls.Add("inspect"); return Task.FromResult(Inspected ?? new(1, "active", Acquired.Last(), "active")); }
        public Task<DnsGuardReply> AcquireAsync(Guid lease, DnsProcessIdentity owner, DnsProcessIdentity backend)
        {
            Assert.Equal(Owner, owner); Calls.Add("acquire"); Acquired.Add(lease); AcquireStarted.TrySetResult();
            if (ThrowAcquire) throw new IOException("owned fake transport failure");
            if (UnsupportedReason is { } reason) return Task.FromResult(new DnsGuardReply(1, "unsupported", lease, reason));
            return BlockAcquire ? AcquireReply.Task : Task.FromResult(new DnsGuardReply(1, "active", lease, "active"));
        }
        public Task<DnsGuardReply> ReleaseAsync(Guid lease)
        { Calls.Add("release"); Released.Add(lease); return Task.FromResult(FailRelease ? new DnsGuardReply(1, "recoveryRequired", lease, "restore_failed") : Off(lease)); }
    }
}
