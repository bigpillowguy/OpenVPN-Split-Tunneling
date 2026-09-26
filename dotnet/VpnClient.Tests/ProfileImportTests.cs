using System.Security.AccessControl;
using System.Security.Principal;
using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public sealed class ProfileImportTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "VpnClient-import-tests-" + Guid.NewGuid().ToString("N"));
    private string Source => Path.Combine(_root, "source");
    private string Destination => Path.Combine(_root, "imported");
    public ProfileImportTests() => Directory.CreateDirectory(Source);

    private string Write(string relative, string contents)
    {
        var path = Path.Combine(Source, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, contents);
        return path;
    }

    [Fact]
    public void QuotesEscapesCommentsAndLiteralInlinePayloadRoundTrip()
    {
        var original = "# retained\n\tremote \"host # one\" 1194 ; trailing comment\nca 'C:\\cert path\\ca.crt'\n" +
            "<cert>\nremote this-is-opaque\n\\not-an-option-escape\n</cert>\n<connection>\nremote second 443 tcp\n</connection>\n";
        var document = OvpnDocument.Parse(original);
        Assert.Equal(original, document.Render());
        Assert.Equal(new[] { "remote", "host # one", "1194" }, document.Nodes[1].Tokens);
        Assert.Equal(@"C:\cert path\ca.crt", document.Nodes[2].Tokens[1]);
        Assert.Single(document.Nodes, node => node.Kind == OvpnNodeKind.InlineBlock);
        Assert.Equal(new[] { "remote", "a b", "c\\d", "a\"b", "" },
            OvpnDocument.Tokenize(OvpnDocument.FormatTokens(new[] { "remote", "a b", "c\\d", "a\"b", "" })));
        Assert.Equal(new[] { "remote", "quoted", "suffix", "host#literal" }, OvpnDocument.Tokenize("remote \"quoted\"suffix host#literal ; comment"));
        Assert.Equal(new[] { "ca", "a b.crt" }, OvpnDocument.Tokenize(@"ca a\ b.crt"));
    }

    [Theory]
    [InlineData("ca \"unterminated")]
    [InlineData(@"ca C:\bad\escape.crt")]
    [InlineData("remote x\0hidden")]
    [InlineData("<ca>\nnot closed")]
    [InlineData("<ca>\nvalue\n</ca> hidden")]
    [InlineData("<connection>\n<connection>\n</connection>\n</connection>")]
    [InlineData("</connection>")]
    [InlineData("<connection>\nremote host\n--</connection>")]
    [InlineData("<connection>\nremote host\n\"</connection>\"")]
    [InlineData("<connection>\n<ca>\n</connection>\n</ca>\n</connection>")]
    public void AmbiguousSyntaxIsRejected(string text) => Assert.Throws<InvalidDataException>(() => OvpnDocument.Parse(text));

    [Fact]
    public void ParserEnforcesOpenVpnByteAndTokenBoundsAndExactDoubleDash()
    {
        Assert.Throws<InvalidDataException>(() => OvpnDocument.Parse("#" + new string('x', 254) + "\nup exploit\n"));
        Assert.Throws<InvalidDataException>(() => OvpnDocument.Parse("remote " + new string('я', 124)));
        Assert.Throws<InvalidDataException>(() => OvpnDocument.Tokenize(string.Join(" ", Enumerable.Repeat("x", 17))));
        Assert.Equal("remote", OvpnDocument.Parse("--remote host").Nodes[0].Name);
        Assert.Equal("-remote", OvpnDocument.Parse("---remote host").Nodes[0].Name);
        Assert.Equal(new[] { "remote\u00a0host" }, OvpnDocument.Tokenize("remote\u00a0host"));
    }

    [Fact]
    public void ImportCopiesAllDependenciesFlattensIncludesAndSurvivesSourceRemoval()
    {
        var source = Write("profile.ovpn", "client\nconfig nested/options.conf\n<connection>\nremote backup.example 443 tcp\n</connection>\nauth-user-pass\ninactive 600\n");
        Write("nested/options.conf", "remote \"primary.example\" 1194\nconfig final.conf\nca \"ca with spaces.crt\"\n");
        Write("final.conf", "cert cert.crt\nkey key.pem\ntls-auth auth.key 1\ntls-crypt crypt.key\ntls-crypt-v2 crypt2.key\n" +
            "pkcs12 bundle.p12\ncrl-verify revocations.pem\nextra-certs chain.pem\ndh dh.pem\n");
        foreach (var dependency in new[] { "ca with spaces.crt", "cert.crt", "key.pem", "auth.key", "crypt.key", "crypt2.key", "bundle.p12", "revocations.pem", "chain.pem", "dh.pem" })
            Write(dependency, "material for " + dependency);
        using var imported = OvpnProfileImporter.Import(source, Destination);
        Assert.Equal("primary.example", imported.ServerHostname);
        Assert.True(imported.CredentialsRequired);
        Assert.Equal("profile", imported.DisplayName);
        Assert.Equal(10, Directory.GetFiles(Path.Combine(Path.GetDirectoryName(imported.ProfilePath)!, "files")).Length);
        Assert.DoesNotContain("config ", File.ReadAllText(imported.ProfilePath));
        imported.Commit();
        Directory.Delete(Source, recursive: true);
        var portable = OvpnProfileImporter.LoadExpanded(imported.ProfilePath);
        Assert.Equal("primary.example", OvpnParser.ParseRemote(imported.ProfilePath));
        Assert.True(OvpnParser.RequiresUserPassword(imported.ProfilePath));
        Assert.Contains(portable.Nodes, node => node.Name == "tls-auth" && node.Tokens[2] == "1");
        Assert.Equal(10, portable.Nodes.Count(node => node.Tokens.Count >= 2 && node.Tokens[1].StartsWith("files/")));
        Assert.True(OvpnProfileImporter.DeleteOwnedProfile(imported.ProfilePath, Destination));
        Assert.Empty(Directory.GetDirectories(Destination));
    }

    [Fact]
    public void ImportKeepsInlineDataAndDeduplicatesExternalMaterial()
    {
        var source = Write("profile.ovpn", "client\nca shared.pem\nextra-certs shared.pem\ndh none\n<key>\nopaque-key\n</key>\n");
        Write("shared.pem", "certificate");
        using var imported = OvpnProfileImporter.Import(source, Destination);
        Assert.False(imported.CredentialsRequired);
        Assert.Single(Directory.GetFiles(Path.Combine(Path.GetDirectoryName(imported.ProfilePath)!, "files")));
        Assert.Contains("<key>\nopaque-key\n</key>", File.ReadAllText(imported.ProfilePath));
        var acl = new DirectoryInfo(Path.GetDirectoryName(imported.ProfilePath)!).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        Assert.All(rules, rule => Assert.Equal(WindowsIdentity.GetCurrent().User, rule.IdentityReference));
    }

    [Theory]
    [InlineData("auth-user-pass credentials.txt")]
    [InlineData("<auth-user-pass>\nuser\npassword\n</auth-user-pass>")]
    public void CredentialMaterialIsRejectedWithoutCreatingImportOrReadingFile(string contents)
    {
        var source = Write("profile.ovpn", contents);
        var error = Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination));
        Assert.Contains("bare auth-user-pass", error.Message);
        Assert.False(Directory.Exists(Destination));
    }

    [Theory]
    [InlineData("up script.cmd")]
    [InlineData("plugin evil.dll")]
    [InlineData("setenv dev_idx 17")]
    [InlineData("setenv-safe dev_idx 17")]
    [InlineData("setenv opt up script.cmd")]
    [InlineData("management 127.0.0.1 1234")]
    [InlineData("management-client")]
    [InlineData("log output.txt")]
    [InlineData("writepid process.pid")]
    [InlineData("cd other")]
    [InlineData("chroot other")]
    [InlineData("askpass password.txt")]
    [InlineData("http-proxy proxy 8080 creds.txt")]
    [InlineData("socks-proxy proxy 1080 creds.txt")]
    [InlineData("unknown-future-option filename")]
    [InlineData("<up>\ncommand\n</up>")]
    public void UnsupportedExecutableEnvironmentAndPathOptionsAreRejected(string contents)
    {
        var source = Write("profile.ovpn", contents);
        Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.LoadExpanded(source));
        Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination));
        Assert.False(Directory.Exists(Destination));
    }

    [Fact]
    public void MissingDependencyAndIncludeCycleDoNotModifyDestination()
    {
        var source = Write("profile.ovpn", "config sub/options.conf\n");
        Write("sub/options.conf", "ca missing.pem\n");
        var missing = Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination));
        Assert.Contains("options.conf:1", missing.Message);
        Assert.False(Directory.Exists(Destination));
        Write("sub/options.conf", "config profile.ovpn\n");
        Assert.Contains("Cyclic", Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination)).Message);
        Assert.False(Directory.Exists(Destination));
    }

    [Fact]
    public void IncludePathsUseTopLevelWorkingDirectoryAndGuardNestedConnections()
    {
        var source = Write("profile.ovpn", "config sub/options.conf\n");
        Write("sub/options.conf", "ca material.pem\n");
        Write("material.pem", "top-level material");
        Write("sub/material.pem", "wrong relative base");
        using (var imported = OvpnProfileImporter.Import(source, Destination))
            Assert.Equal("top-level material", File.ReadAllText(Path.Combine(Path.GetDirectoryName(imported.ProfilePath)!, "files", "001.bin")));
        Write("profile.ovpn", "<connection>\nconfig sub/options.conf\n</connection>\n");
        Write("sub/options.conf", "<connection>\nremote host\n</connection>\n");
        Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.LoadExpanded(source));
    }

    [Fact]
    public void FailedConfigSaveRollsBackNewImportAndRetainsPreviousCommittedProfile()
    {
        var source = Write("profile.ovpn", "client\n");
        string original;
        using (var existing = OvpnProfileImporter.Import(source, Destination)) { original = existing.ProfilePath; existing.Commit(); }
        var configPath = Path.Combine(_root, "broken-config.json");
        File.WriteAllText(configPath, "broken");
        var config = Config.Load(configPath);
        string rolledBack;
        using (var imported = OvpnProfileImporter.Import(source, Destination))
        {
            rolledBack = imported.ProfilePath;
            config.OvpnFiles.Add(new OvpnEntry { FilePath = imported.ProfilePath });
            Assert.Throws<InvalidOperationException>(() => config.Save());
        }
        Assert.True(File.Exists(original));
        Assert.False(File.Exists(rolledBack));
        Assert.Single(Directory.GetDirectories(Destination));
    }

    [Fact]
    public void DeletionPreservesLegacyExternalAndUnexpectedUserFiles()
    {
        var source = Write("profile.ovpn", "client\n");
        Assert.False(OvpnProfileImporter.DeleteOwnedProfile(source, Destination));
        using var imported = OvpnProfileImporter.Import(source, Destination);
        imported.Commit();
        var personal = Path.Combine(Path.GetDirectoryName(imported.ProfilePath)!, "user-notes.txt");
        File.WriteAllText(personal, "keep me");
        Assert.Throws<IOException>(() => OvpnProfileImporter.DeleteOwnedProfile(imported.ProfilePath, Destination));
        Assert.True(File.Exists(imported.ProfilePath));
        Assert.Equal("keep me", File.ReadAllText(personal));
        Assert.True(File.Exists(source));
    }

    [Fact]
    public void PendingRollbackPreservesUnexpectedUserFiles()
    {
        var source = Write("profile.ovpn", "client\n");
        var imported = OvpnProfileImporter.Import(source, Destination);
        var personal = Path.Combine(Path.GetDirectoryName(imported.ProfilePath)!, "user-notes.txt");
        File.WriteAllText(personal, "keep me");
        Assert.Throws<IOException>(() => imported.Dispose());
        Assert.True(File.Exists(imported.ProfilePath));
        Assert.Equal("keep me", File.ReadAllText(personal));
    }

    [Theory]
    [InlineData("ca NUL")]
    [InlineData("ca //./pipe/probe")]
    [InlineData("config //./pipe/probe")]
    [InlineData("ca //?/C:/material.pem")]
    [InlineData("ca COM¹")]
    [InlineData("ca LPT².txt")]
    [InlineData("ca data.pem:secret")]
    [InlineData("ca C:relative.pem")]
    [InlineData("crl-verify revocations dir")]
    [InlineData("tls-auth auth.key 2")]
    public void SpecialPathsAndUnsupportedDependencyModesFailClearly(string option)
    {
        var source = Write("profile.ovpn", option);
        Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination));
        Assert.False(Directory.Exists(Destination));
    }

    [Theory]
    [InlineData("//./pipe/probe")]
    [InlineData("NUL")]
    public void TopLevelDevicePathsAreRejectedBeforeOpening(string source)
        => Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.LoadExpanded(source));

    [Fact]
    public void OversizedDependenciesAreRejectedBeforeCopying()
    {
        var source = Write("profile.ovpn", "ca huge.pem\n");
        using (var file = File.Create(Path.Combine(Source, "huge.pem"))) file.SetLength(8 * 1024 * 1024 + 1);
        Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination));
        Assert.False(Directory.Exists(Destination));
    }

    [Fact]
    public void IncludeDepthAndDistinctDependencyCountAreBounded()
    {
        for (var i = 0; i < 11; i++) Write($"{i}.conf", i == 10 ? "client\n" : $"config {i + 1}.conf\n");
        Assert.Contains("maximum depth 10", Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.LoadExpanded(Path.Combine(Source, "0.conf"))).Message);
        var lines = new List<string>();
        for (var i = 0; i < 65; i++) { Write($"{i}.pem", "data"); lines.Add($"ca {i}.pem"); }
        var source = Write("profile.ovpn", string.Join("\n", lines));
        Assert.Contains("64 files", Assert.Throws<InvalidDataException>(() => OvpnProfileImporter.Import(source, Destination)).Message);
        Assert.False(Directory.Exists(Destination));
    }

    public void Dispose()
    {
        var resolved = Path.GetFullPath(_root);
        if (!resolved.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(resolved).StartsWith("VpnClient-import-tests-", StringComparison.Ordinal)) throw new InvalidOperationException("Unexpected test path.");
        Directory.Delete(resolved, recursive: true);
    }
}
