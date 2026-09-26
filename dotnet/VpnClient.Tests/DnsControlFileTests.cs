using System.Diagnostics;
using System.Text.Json;
using VpnClient.Ui;
using Vpnclient.Status;
using Xunit;

namespace VpnClient.Tests;

public sealed class DnsControlFileTests
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    [Fact]
    public void SharedRustFixtureRoundTripsThroughProductionWriterWithoutNumericOrGuidLoss()
    {
        string fixture = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "dns-control-arm-v1.json"));
        var request = JsonSerializer.Deserialize<DnsControlRequest>(fixture, Json)!;
        Assert.Equal(9007199254740993UL, request.Revision);
        Assert.Equal(133000000000000001UL, request.OwnerCreationTime);
        Assert.Equal(133000000000000002UL, request.BackendCreationTime);
        using var stream = new MemoryStream();
        DnsControlFile.WriteRequest(stream, request);
        using var expected = JsonDocument.Parse(fixture);
        using var actual = JsonDocument.Parse(stream.ToArray());
        Assert.Equal(expected.RootElement.EnumerateObject().Count(), actual.RootElement.EnumerateObject().Count());
        foreach (var property in expected.RootElement.EnumerateObject())
            Assert.Equal(property.Value.GetRawText(), actual.RootElement.GetProperty(property.Name).GetRawText());
    }

    [Fact]
    public async Task OnlyFreshExactRevisionLeaseAndStateAcknowledgesAndCounterSurvivesOff()
    {
        using var fixture = new Fixture(); Guid lease = Guid.NewGuid();
        var arm = fixture.Control.ApplyAsync(lease, fixture.Target, true);
        var request = await fixture.Request(1);
        fixture.Acknowledge(request with { Lease = Guid.NewGuid() });
        Assert.False(arm.IsCompleted);
        fixture.Acknowledge(request, Stopwatch.GetTimestamp() - Stopwatch.Frequency * 3);
        Assert.False(arm.IsCompleted);
        fixture.Acknowledge(request, error: "control_revision_conflict");
        Assert.False(arm.IsCompleted);
        fixture.Acknowledge(request);
        await arm.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(fixture.Control.IsArmed(lease, fixture.Target));
        var off = fixture.Control.ApplyAsync(lease, fixture.Target, false);
        var disarm = await fixture.Request(2);
        Assert.False(disarm.Armed); Assert.Equal(lease, disarm.Lease);
        fixture.Acknowledge(request); // Delayed arm ACK cannot acknowledge disarm.
        Assert.False(off.IsCompleted);
        fixture.Acknowledge(disarm);
        await off.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(fixture.Control.IsArmed(lease, fixture.Target));
        var next = fixture.Control.ApplyAsync(Guid.NewGuid(), fixture.Target, true);
        var newer = await fixture.Request(3);
        Assert.Equal(3UL, newer.Revision);
        fixture.Acknowledge(newer); await next.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task UnacknowledgedArmCanBeDeactivatedWithHigherRevision()
    {
        using var fixture = new Fixture(TimeSpan.FromMilliseconds(80)); Guid lease = Guid.NewGuid();
        await Assert.ThrowsAsync<IOException>(() => fixture.Control.ApplyAsync(lease, fixture.Target, true));
        var original = await fixture.Request(1);
        var off = fixture.Control.ApplyAsync(lease, fixture.Target, false);
        var disarm = await fixture.Request(2);
        fixture.Acknowledge(original);
        Assert.False(off.IsCompleted);
        fixture.Acknowledge(disarm); await off;
    }

    [Fact]
    public async Task RetainedBackendDeathProvesNoCaptureAfterGuardRestoration()
    {
        using var fixture = new Fixture(); Guid lease = Guid.NewGuid();
        var arm = fixture.Control.ApplyAsync(lease, fixture.Target, true);
        await fixture.Request(1);
        fixture.Alive = false;
        await Assert.ThrowsAsync<IOException>(() => arm);
        await fixture.Control.ApplyAsync(lease, fixture.Target, false);
        Assert.False(fixture.Control.IsArmed(lease, fixture.Target));
    }

    [Fact]
    public async Task ReusedBackendPidOrForeignArmedLeaseCannotBorrowAcknowledgement()
    {
        using var fixture = new Fixture(); Guid lease = Guid.NewGuid();
        var changed = fixture.Target with { Backend = fixture.Target.Backend with { Created = fixture.Target.Backend.Created + 1 } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Control.ApplyAsync(lease, changed, true));
        Assert.False(File.Exists(fixture.Control.FilePath));
        var arm = fixture.Control.ApplyAsync(lease, fixture.Target, true);
        fixture.Acknowledge(await fixture.Request(1)); await arm;
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Control.ApplyAsync(Guid.NewGuid(), fixture.Target, false));
    }

    [Fact]
    public async Task DisarmKeepsOriginalSessionIdentityAfterProviderGenerationChanges()
    {
        using var fixture = new Fixture(); Guid lease = Guid.NewGuid();
        var arm = fixture.Control.ApplyAsync(lease, fixture.Target, true);
        fixture.Acknowledge(await fixture.Request(1)); await arm;
        var off = fixture.Control.ApplyAsync(lease, fixture.Target, false);
        var request = await fixture.Request(2);
        Assert.Equal(fixture.Target.SessionId, request.SessionId);
        Assert.Equal(fixture.Target.Generation, request.Generation);
        fixture.Acknowledge(request); await off;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "VpnClient-dns-control-" + Guid.NewGuid().ToString("N"));
        internal readonly DnsEligibility Target = new(Guid.NewGuid(), Guid.NewGuid(), new(23, 133000000000000002));
        internal readonly DnsControlFile Control;
        internal bool Alive = true;
        internal Fixture(TimeSpan? timeout = null)
        {
            Directory.CreateDirectory(_directory);
            Control = new(Path.Combine(_directory, "dns-control.json"), new(17, 133000000000000001), Target.Backend, () => Alive, timeout);
        }
        internal async Task<DnsControlRequest> Request(ulong revision)
        {
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(2))
            {
                if (File.Exists(Control.FilePath))
                {
                    var request = JsonSerializer.Deserialize<DnsControlRequest>(File.ReadAllText(Control.FilePath), Json)!;
                    if (request.Revision == revision) return request;
                }
                await Task.Delay(10);
            }
            throw new TimeoutException("Test command was not written");
        }
        internal void Acknowledge(DnsControlRequest request, long? received = null, string error = "") =>
            Control.Observe(new Snapshot { Vpn = new(), SplitDns = new()
            {
                Enabled = true, Armed = request.Armed, ControlRevision = request.Revision,
                ControlLease = request.Lease.ToString("N"), ControlError = error,
            } }, received ?? Stopwatch.GetTimestamp());
        public void Dispose() { Control.Dispose(); Directory.Delete(_directory, true); }
    }
}
