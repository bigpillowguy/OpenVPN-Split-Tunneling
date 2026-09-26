using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public class SessionBindingTests
{
    [Fact]
    public void NativeUpEnvironmentSuppliesIdentityAndFreshGeneration()
    {
        var metadata = ReadTunnel();
        var first = Assert.IsType<OpenVpnTunnel>(metadata.Current);
        Assert.Equal((uint)17, first.InterfaceIndex);
        Assert.Equal("10.8.0.2", first.Ipv4.ToString());
        Assert.Equal("10.8.0.1", first.Gateway.ToString());
        metadata.Reset(); // RECONNECTING must revoke the old generation even if address/index repeat.
        Assert.Null(metadata.Current);
        FeedTunnel(metadata);
        Assert.NotEqual(first.SessionId, metadata.Current!.SessionId);
    }

    [Fact]
    public void DownEnvironmentCannotAuthorizeAnotherTunnel()
    {
        var metadata = ReadTunnel();
        metadata.Consume(">UPDOWN:DOWN");
        metadata.Consume(">UPDOWN:ENV,dev_idx=17");
        metadata.Consume(">UPDOWN:ENV,ifconfig_local=10.8.0.2");
        metadata.Consume(">UPDOWN:ENV,END");
        Assert.Null(metadata.Current);
    }

    [Theory]
    [InlineData("dev_idx", "0")]
    [InlineData("dev_idx", "4294967296")]
    [InlineData("ifconfig_local", "10.8.2")]
    [InlineData("ifconfig_local", "::1")]
    [InlineData("ifconfig_local", "169.254.10.2")]
    [InlineData("route_vpn_gateway", "255.255.255.0")]
    [InlineData("route_vpn_gateway", "10.8.0.2")]
    public void MalformedIdentityCannotBecomeReady(string key, string value)
    {
        var metadata = new OpenVpnTunnelMetadata();
        Assert.Throws<InvalidDataException>(() => FeedTunnel(metadata, key, value));
        Assert.Null(metadata.Current);
    }

    [Fact]
    public void EnvironmentRejectsDuplicateIdentityAndUnboundedInput()
    {
        var metadata = new OpenVpnTunnelMetadata();
        metadata.Consume(">UPDOWN:UP");
        metadata.Consume(">UPDOWN:ENV,dev_idx=17");
        Assert.Throws<InvalidDataException>(() => metadata.Consume(">UPDOWN:ENV,dev_idx=18"));
        metadata.Reset();
        metadata.Consume(">UPDOWN:UP");
        Assert.Throws<InvalidDataException>(() => metadata.Consume(">UPDOWN:ENV,ignored=" + new string('x', 65536)));
    }

    [Fact]
    public void SubnetMaskIsNeverUsedAsGateway()
    {
        var metadata = new OpenVpnTunnelMetadata();
        metadata.Consume(">UPDOWN:UP");
        foreach (var entry in new[] { "dev_idx=17", "dev=OpenVPN Test", "ifconfig_local=10.8.0.2", "ifconfig_netmask=255.255.255.0" })
            metadata.Consume(">UPDOWN:ENV," + entry);
        Assert.Throws<InvalidDataException>(() => metadata.Consume(">UPDOWN:ENV,END"));
    }

    [Fact]
    public void PointToPointRemoteIsAnAuthoritativeGatewayFallback()
    {
        var metadata = new OpenVpnTunnelMetadata();
        metadata.Consume(">UPDOWN:UP");
        foreach (var entry in new[] { "dev_idx=17", "dev=OpenVPN Test", "ifconfig_local=10.8.0.6", "ifconfig_remote=10.8.0.5" })
            metadata.Consume(">UPDOWN:ENV," + entry);
        metadata.Consume(">UPDOWN:ENV,END");
        Assert.Equal("10.8.0.5", metadata.Current!.Gateway.ToString());
    }

    [Fact]
    public void ExactAdapterWinsOverUnrelatedVpnWithTheSameAddress()
    {
        var tunnel = ReadTunnel().Current!;
        var expected = Adapter(17, "OpenVPN Test");
        var unrelated = Adapter(4, "Other VPN");
        Assert.Equal(expected, WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4, new[] { unrelated, expected }));
        Assert.Throws<InvalidOperationException>(() => WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4, new[] { unrelated }));
        Assert.Throws<InvalidOperationException>(() => WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4,
            new[] { unrelated, expected with { IsUp = false } }));
        Assert.Throws<InvalidOperationException>(() => WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4,
            new[] { expected with { Name = "Reused adapter index" } }));
        Assert.Throws<InvalidDataException>(() => WindowsVpnAdapter.Resolve(tunnel, IPAddress.Parse("10.8.0.3"), new[] { expected }));
    }

    [Fact]
    public void ExplicitGuidMustMatchTheReportedIndex()
    {
        var expected = Adapter(17, "OpenVPN Test");
        var tunnel = ReadTunnel().Current! with { Device = expected.Guid.ToString("B") };
        Assert.Equal(expected, WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4, new[] { expected }));
        Assert.Throws<InvalidOperationException>(() => WindowsVpnAdapter.Resolve(tunnel, tunnel.Ipv4,
            new[] { expected with { Guid = Guid.NewGuid() } }));
    }

    [Fact]
    public void NewLeaseRevokesOldFileAndRejectsLateOldCallbacks()
    {
        using var store = new VpnSessionBindingStore();
        using var old = store.Begin();
        var binding = Binding();
        old.Publish(binding);
        using var replacement = store.Begin();
        Assert.False(File.Exists(store.FilePath));
        var next = binding with { SessionId = Guid.NewGuid() };
        replacement.Publish(next);
        Assert.Throws<InvalidOperationException>(() => old.Publish(binding));
        old.Dispose();
        using (var file = JsonDocument.Parse(File.ReadAllText(store.FilePath)))
            Assert.Equal(next.SessionId, file.RootElement.GetProperty("sessionId").GetGuid());
        replacement.Revoke();
        Assert.False(File.Exists(store.FilePath));
        replacement.Publish(next with { SessionId = Guid.NewGuid() });
        replacement.Dispose();
        Assert.False(File.Exists(store.FilePath));
        Assert.Throws<InvalidOperationException>(() => replacement.Publish(next));
    }

    [Fact]
    public void BindingCapturesNativeProcessIdentityAndPrivateAclWithoutLaunchingAnything()
    {
        using var process = Process.GetCurrentProcess();
        using var store = new VpnSessionBindingStore();
        using var lease = store.Begin();
        var tunnel = ReadTunnel().Current!;
        lease.Publish(process, tunnel, Adapter(17, "OpenVPN Test"));
        using var file = JsonDocument.Parse(File.ReadAllText(store.FilePath));
        var json = file.RootElement;
        Assert.Equal(1, json.GetProperty("version").GetInt32());
        Assert.Equal(process.Id, json.GetProperty("openVpnPid").GetInt32());
        Assert.True(GetProcessTimes(process.Handle, out var created, out _, out _, out _));
        Assert.Equal(created, json.GetProperty("openVpnCreationTime").GetUInt64());
        Assert.Equal(process.MainModule!.FileName, json.GetProperty("openVpnExePath").GetString());
        var owner = WindowsIdentity.GetCurrent().User!;
        var directorySecurity = new DirectoryInfo(Path.GetDirectoryName(store.FilePath)!).GetAccessControl();
        Assert.True(directorySecurity.AreAccessRulesProtected);
        foreach (FileSystemAccessRule rule in new FileInfo(store.FilePath).GetAccessControl()
                     .GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow) Assert.Equal(owner, rule.IdentityReference);
    }

    [Fact]
    public void NativeAdapterEnumerationOnlyReadsWindowsState()
    {
        var adapters = WindowsVpnAdapter.ReadAdapters();
        Assert.All(adapters, adapter => { Assert.NotEqual(Guid.Empty, adapter.Guid); Assert.True(adapter.Index > 0); });
    }

    private static VpnAdapter Adapter(uint index, string name) =>
        new(Guid.NewGuid(), index, name, true, new[] { IPAddress.Parse("10.8.0.2") });

    private static VpnSessionBinding Binding() =>
        new(1, Guid.NewGuid(), 1234, 12345678, @"C:\Program Files\OpenVPN\bin\openvpn.exe", Guid.NewGuid(), 17, "10.8.0.2", "10.8.0.1");

    private static OpenVpnTunnelMetadata ReadTunnel()
    {
        var metadata = new OpenVpnTunnelMetadata();
        FeedTunnel(metadata);
        return metadata;
    }

    private static void FeedTunnel(OpenVpnTunnelMetadata metadata, string? changedKey = null, string? changedValue = null)
    {
        metadata.Consume(">UPDOWN:UP");
        foreach (var entry in new Dictionary<string, string>
        {
            ["dev_idx"] = "17", ["dev"] = "OpenVPN Test", ["ifconfig_local"] = "10.8.0.2",
            ["ifconfig_netmask"] = "255.255.255.0", ["route_vpn_gateway"] = "10.8.0.1"
        }) metadata.Consume(">UPDOWN:ENV," + entry.Key + "=" + (entry.Key == changedKey ? changedValue : entry.Value));
        metadata.Consume(">UPDOWN:ENV,END");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(IntPtr process, out ulong creation, out ulong exit, out ulong kernel, out ulong user);
}
