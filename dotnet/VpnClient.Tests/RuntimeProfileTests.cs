using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public sealed class RuntimeProfileTests
{
    [Fact]
    public void LocalRoutesAndBothDnsDialectsCannotOverrideManagedPolicy()
    {
        var source = OvpnDocument.Parse("""
            client
            dev tun
            remote vpn.example.test 1194 udp
            redirect-gateway def1
            --redirect-private
            route 0.0.0.0 128.0.0.0
            route 128.0.0.0 128.0.0.0
            route-ipv6 ::/1
            dhcp-option DNS 10.8.0.1
            dns server 0 address 10.8.0.1
            register-dns
            block-outside-dns
            persist-tun
            topology subnet
            ifconfig 10.8.0.2 255.255.255.0
            route-gateway 10.8.0.1
            """);
        var nodes = OvpnRuntimeProfile.Prepare(source).Nodes;
        var directives = nodes.Where(node => node.Kind == OvpnNodeKind.Directive).ToArray();
        Assert.Equal(new[] { "route", "0.0.0.0", "0.0.0.0", "vpn_gateway" }, Assert.Single(directives, node => node.Name == "route").Tokens);
        Assert.Single(directives, node => node.Name == "route-noexec");
        Assert.Single(directives, node => node.Name == "route-nopull");
        Assert.DoesNotContain(directives, node => new[] { "redirect-gateway", "redirect-private", "route-ipv6", "dhcp-option", "dns", "register-dns", "block-outside-dns", "persist-tun" }.Contains(node.Name));
        Assert.Equal(new[] { "route-gateway", "10.8.0.1" }, Assert.Single(directives, node => node.Name == "route-gateway").Tokens);
        Assert.Contains(directives, node => node.Name == "ifconfig");
        Assert.Contains(directives, node => node.Name == "topology");
    }

    [Fact]
    public void ManagedFiltersPrecedeCatchAllAcceptAndInlineMaterialRemainsOpaque()
    {
        var source = OvpnDocument.Parse("""
            pull-filter accept ""
            pull-filter reject compress
            <key>
            # literal data, not directives
            route 1.2.3.4
            </key>
            <connection>
            remote "vpn.example.test" 443 tcp-client
            </connection>
            """);
        var result = OvpnRuntimeProfile.Prepare(source);
        var filters = result.Nodes.Where(node => node.Kind == OvpnNodeKind.Directive && node.Name == "pull-filter").ToArray();
        var accept = Array.FindIndex(filters, node => node.Tokens[1] == "accept");
        Assert.True(accept > 0);
        Assert.All(filters.Take(accept), node => Assert.Equal("ignore", node.Tokens[1]));
        Assert.Contains(filters.Take(accept), node => node.Tokens[2] == "dns");
        Assert.Contains(filters.Take(accept), node => node.Tokens[2] == "route ");
        Assert.DoesNotContain(filters.Take(accept), node => node.Tokens[2] is "route" or "route-gateway");
        Assert.Equal(source.Nodes.Single(node => node.Kind == OvpnNodeKind.InlineBlock).RawText,
            result.Nodes.Single(node => node.Kind == OvpnNodeKind.InlineBlock).RawText);
        Assert.Equal("remote \"vpn.example.test\" 443 tcp-client", result.Nodes.Single(node => node.Name == "remote").RawText);
        Assert.Equal(result.Render(), OvpnDocument.Parse(result.Render()).Render());
    }

    [Fact]
    public void RuntimeCopyContainsExpandedPolicyAndIsRemovedWithItsSecrets()
    {
        var root = Path.Combine(Path.GetTempPath(), "vpn-runtime-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var original = Path.Combine(root, "original.ovpn");
            var included = Path.Combine(root, "routes.conf");
            File.WriteAllText(included, "redirect-gateway def1\ndns server 0 address 10.8.0.1\n");
            var originalText = "client\ndev tun\nremote vpn.example.test\nconfig routes.conf\n<key>\nprivate-data\n</key>\n";
            File.WriteAllText(original, originalText);
            string runtimePath;
            using (var session = new SessionSecrets(root))
            {
                runtimePath = OvpnRuntimeProfile.Create(original, session.DirectoryPath);
                Assert.True(File.Exists(runtimePath));
                var nodes = OvpnDocument.Load(runtimePath).Nodes;
                Assert.DoesNotContain(nodes, node => node.Kind == OvpnNodeKind.Directive && node.Name is "config" or "redirect-gateway" or "dns");
                Assert.Contains(nodes, node => node.Name == "route-noexec");
                Assert.Equal(originalText, File.ReadAllText(original));
            }
            Assert.False(File.Exists(runtimePath));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData("up \"command.exe\"")]
    [InlineData("plugin \"untrusted.dll\"")]
    [InlineData("management 127.0.0.1 1234")]
    [InlineData("setenv dev_idx 12")]
    public void LegacyProfileCannotExecuteHooksOrOverrideSessionControl(string directive)
    {
        var root = Path.Combine(Path.GetTempPath(), "vpn-runtime-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var original = Path.Combine(root, "legacy.ovpn");
            File.WriteAllText(original, "client\ndev tun\nremote vpn.example.test\n" + directive + "\n");
            using var session = new SessionSecrets(root);
            Assert.ThrowsAny<Exception>(() => OvpnRuntimeProfile.Create(original, session.DirectoryPath));
            Assert.False(File.Exists(Path.Combine(session.DirectoryPath, "runtime.ovpn")));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
