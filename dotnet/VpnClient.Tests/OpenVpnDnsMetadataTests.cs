using System.Text;
using System.Text.Json;
using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public class OpenVpnDnsMetadataTests
{
    [Fact]
    public void CompleteAuthenticatedPushBecomesReadyOnlyAfterConnectedAndSurvivesUp()
    {
        var metadata = new OpenVpnDnsMetadata();
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53,dhcp-option DNS 10.8.0.54,auth-token-user secret-value"));
        Assert.Equal("unknown", metadata.Current.Status);
        Assert.Empty(metadata.Current.Servers);
        metadata.Consume(">UPDOWN:UP"); // UP belongs to the separate tunnel parser.
        var ready = metadata.OnConnected();
        Assert.Equal("ready", ready.Status);
        Assert.Equal(new[] { "10.8.0.53", "10.8.0.54" }, ready.Servers.Select(server => server.Address));
        Assert.All(ready.Servers, server => Assert.Equal(53, server.Port));
        Assert.DoesNotContain("secret-value", JsonSerializer.Serialize(ready));
        Assert.Equal(ready.Generation, metadata.OnConnected().Generation);
    }

    [Theory]
    [InlineData("dhcp-option\tDNS\t\"10.8.0.53\"")]
    [InlineData("\"dhcp-option\" 'DNS' '10.8.0.53'")]
    [InlineData("--dhcp-option DNS 10.8.0.53")]
    public void UsesOpenVpnOptionQuotesWhitespaceAndDoubleDash(string option)
    {
        var metadata = Ready("PUSH_REPLY," + option);
        Assert.Equal("ready", metadata.Current.Status);
        Assert.Equal("10.8.0.53", Assert.Single(metadata.Current.Servers).Address);
    }

    [Fact]
    public void ContinuationPublishesOnlyCompleteCombinedSetAndDeduplicates()
    {
        var metadata = new OpenVpnDnsMetadata();
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53,push-continuation 2"));
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.54,push-continuation 2"));
        Assert.Equal("unknown", metadata.Current.Status);
        Assert.Empty(metadata.Current.Servers);
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53,push-continuation 1"));
        Assert.Equal("unknown", metadata.Current.Status);
        Assert.Equal(2, metadata.OnConnected().Servers.Count);
    }

    [Theory]
    [InlineData("PUSH_REPLY,push-continuation 1")]
    [InlineData("PUSH_REPLY,push-continuation 3")]
    [InlineData("PUSH_REPLY,push-continuation 2,push-continuation 1")]
    [InlineData("PUSH_REPLY,dhcp-option DNS \"10.8.0.53")]
    [InlineData("PUSH_REPLY,,dhcp-option DNS 10.8.0.53")]
    public void MalformedPushCannotAuthorizeDns(string push)
    {
        var metadata = Ready(push);
        Assert.Equal("invalid", metadata.Current.Status);
        Assert.Empty(metadata.Current.Servers);
    }

    [Fact]
    public void IncompleteAndMissingTerminalContinuationsAreInvalidAtConnected()
    {
        var metadata = new OpenVpnDnsMetadata();
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53,push-continuation 2"));
        Assert.Equal("invalid", metadata.OnConnected().Status);
        metadata.Reset();
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53,push-continuation 2"));
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.54"));
        Assert.Equal("invalid", metadata.OnConnected().Status);
    }

    [Theory]
    [InlineData("hostname", "invalid")]
    [InlineData("10.8.53", "invalid")]
    [InlineData("0.0.0.0", "invalid")]
    [InlineData("127.0.0.53", "invalid")]
    [InlineData("169.254.1.2", "invalid")]
    [InlineData("224.0.0.1", "invalid")]
    [InlineData("10.8.0.53:53", "unsupported")]
    [InlineData("2001:db8::53", "unsupported")]
    public void ResolverAddressesAreStrictAndNoPublicFallbackIsInvented(string address, string status)
    {
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS " + address);
        Assert.Equal(status, metadata.Current.Status);
        Assert.Empty(metadata.Current.Servers);
    }

    [Theory]
    [InlineData("dns server 0 address 10.8.0.53")]
    [InlineData("dns server 0 transport DoH")]
    [InlineData("dhcp-option DNS6 2001:db8::53")]
    [InlineData("dhcp-option DOMAIN-ROUTE example.test")]
    [InlineData("dhcp-option DOMAIN example.test")]
    public void UnsupportedSemanticsDoNotBecomePlainDns(string option)
    {
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS 10.8.0.53," + option);
        Assert.Equal("unsupported", metadata.Current.Status);
        Assert.Empty(metadata.Current.Servers);
    }

    [Fact]
    public void UnknownAbsentAndLocalDnsAreDifferentStates()
    {
        Assert.Equal("unknown", new OpenVpnDnsMetadata().OnConnected().Status);
        Assert.Equal("not-provided", Ready("PUSH_REPLY").Current.Status);
        Assert.Equal("not-provided", Ready("PUSH_REPLY,route-gateway 10.8.0.1").Current.Status);
        var local = new OpenVpnDnsMetadata(hasLocalDns: true);
        local.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53"));
        Assert.Equal("unsupported", local.OnConnected().Status);
        Assert.Equal("local_dns_unsupported", local.Current.Reason);
        Assert.True(OpenVpnDnsMetadata.HasLocalDns(OvpnDocument.Parse("dhcp-option DNS 10.0.0.53")));
        Assert.True(OpenVpnDnsMetadata.HasLocalDns(OvpnDocument.Parse("dns server 0 address 10.0.0.53")));
        Assert.False(OpenVpnDnsMetadata.HasLocalDns(OvpnDocument.Parse("remote example.test\nroute-gateway 10.0.0.1")));
    }

    [Fact]
    public void UpdateRevokesImmediatelyAndCannotBeReauthorizedUntilReconnect()
    {
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS 10.8.0.53");
        var ready = metadata.Current;
        Assert.True(metadata.Consume(Log("PUSH_UPDATE,dhcp-option DNS 10.8.0.54")));
        Assert.Equal("unsupported", metadata.Current.Status);
        Assert.Equal("push_update_unsupported", metadata.Current.Reason);
        Assert.NotEqual(ready.Generation, metadata.Current.Generation);
        Assert.Empty(metadata.Current.Servers);
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.54"));
        Assert.Equal("unsupported", metadata.OnConnected().Status);
        metadata.Reset();
        Assert.Equal("unknown", metadata.Current.Status);
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.53"));
        Assert.Equal("ready", metadata.OnConnected().Status);
        Assert.NotEqual(ready.Generation, metadata.Current.Generation);
    }

    [Fact]
    public void TokenRefreshDoesNotEraseDnsOrRetainSecretsOrConsumeSequenceBudget()
    {
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS 10.8.0.53");
        var generation = metadata.Current.Generation;
        for (var i = 0; i < 100; i++)
            Assert.False(metadata.Consume(Log("PUSH_REPLY,auth-token [redacted],auth-token-user private-value")));
        Assert.Equal(generation, metadata.Current.Generation);
        Assert.Equal("ready", metadata.Current.Status);
        Assert.DoesNotContain("private-value", JsonSerializer.Serialize(metadata.Current));
        metadata.Consume(Log("PUSH_REPLY,dhcp-option DNS 10.8.0.54"));
        Assert.Equal("unsupported", metadata.Current.Status);
    }

    [Fact]
    public void CollectionAndFrameBudgetsFailClosed()
    {
        var push = "PUSH_REPLY," + string.Join(',', Enumerable.Range(1, 5).Select(i => "dhcp-option DNS 10.8.0." + i));
        Assert.Equal("unsupported", Ready(push).Current.Status);
        var metadata = new OpenVpnDnsMetadata();
        for (var i = 0; i < 33; i++) metadata.Consume(Log("PUSH_REPLY,push-continuation 2"));
        Assert.Equal("invalid", metadata.Current.Status);
        metadata.Reset();
        metadata.Consume(Log("PUSH_REPLY," + new string('x', ManagementProtocol.MaximumFrameBytes)));
        Assert.Equal("invalid", metadata.Current.Status);
    }

    [Fact]
    public void UnknownPushFormatRevokesAndNeverAppearsInPublishedReason()
    {
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS 10.8.0.53");
        metadata.Consume(">LOG:123,I,PUSH: new-format-with-sensitive-value");
        Assert.Equal("unknown", metadata.Current.Status);
        Assert.DoesNotContain("sensitive-value", JsonSerializer.Serialize(metadata.Current));
        Assert.Empty(metadata.Current.Servers);
    }

    [Fact]
    public void BindingPublishesDnsAtomicallyAndRejectsLateUpdatesAfterRevokeOrReplacement()
    {
        using var store = new VpnSessionBindingStore();
        using var lease = store.Begin();
        var metadata = Ready("PUSH_REPLY,dhcp-option DNS 10.8.0.53");
        var binding = Binding(metadata.Current);
        var notifications = 0;
        store.SnapshotChanged += (_, _) => { _ = store.Current; notifications++; };
        lease.Publish(binding);
        using (var json = JsonDocument.Parse(File.ReadAllText(store.FilePath)))
        {
            Assert.Equal(1, json.RootElement.GetProperty("version").GetInt32());
            Assert.Equal("ready", json.RootElement.GetProperty("dns").GetProperty("status").GetString());
            Assert.Equal(metadata.Current.Generation, json.RootElement.GetProperty("dns").GetProperty("generation").GetGuid());
        }
        metadata.Consume(Log("PUSH_UPDATE,dhcp-option DNS 10.8.0.54"));
        Assert.True(lease.UpdateDns(binding.SessionId, metadata.Current));
        Assert.Equal(binding.SessionId, store.Current!.SessionId);
        Assert.Equal("unsupported", store.Current.Dns!.Status);
        lease.Revoke();
        Assert.Null(store.Current);
        Assert.False(lease.UpdateDns(binding.SessionId, binding.Dns!));
        var newer = binding with { SessionId = Guid.NewGuid() };
        lease.Publish(newer);
        Assert.False(lease.UpdateDns(binding.SessionId, metadata.Current));
        using var next = store.Begin();
        Assert.False(lease.UpdateDns(newer.SessionId, metadata.Current));
        next.Publish(newer);
        lease.Dispose();
        Assert.Equal(newer.SessionId, store.Current!.SessionId);
        Assert.True(notifications >= 5);
    }

    [Fact]
    public void BindingAccessorCannotBeMutatedThroughOriginalServerCollection()
    {
        using var store = new VpnSessionBindingStore();
        using var lease = store.Begin();
        var servers = new[] { new VpnDnsServer("10.8.0.53") };
        lease.Publish(Binding(new("ready", Guid.NewGuid(), servers)));
        servers[0] = new("192.168.1.1");
        Assert.Equal("10.8.0.53", store.Current!.Dns!.Servers[0].Address);
        Assert.Throws<NotSupportedException>(() => ((IList<VpnDnsServer>)store.Current.Dns.Servers)[0] = servers[0]);
    }

    private static OpenVpnDnsMetadata Ready(string push)
    {
        var metadata = new OpenVpnDnsMetadata();
        metadata.Consume(Log(push));
        metadata.OnConnected();
        return metadata;
    }

    private static string Log(string push) => ">LOG:1770000000,I,PUSH: Received control message: '" + push + "'";
    private static VpnSessionBinding Binding(VpnDnsSnapshot dns) =>
        new(1, Guid.NewGuid(), 1234, 12345678, @"C:\OpenVPN\openvpn.exe", Guid.NewGuid(), 17, "10.8.0.2", "10.8.0.1", dns);
}
