using System.Text.Json;
using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public sealed class ConfigTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "VpnClient-tests-" + Guid.NewGuid().ToString("N"));
    private string ConfigPath => Path.Combine(_directory, "config.json");
    public ConfigTests() => Directory.CreateDirectory(_directory);

    [Fact]
    public void DuplicatePathsAreRecoveredAndIPv6IsPreserved()
    {
        var path = Path.Combine(_directory, "Game.exe");
        var model = new Config
        {
            TunneledApps = new() { new() { ExePath = path }, new() { ExePath = path.ToUpperInvariant() } },
            OvpnFiles = new() { new() { ServerHostname = "2001:db8::1" }, new() { ServerHostname = "vpn.example:1194" } },
        };
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(model, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        var loaded = Config.Load(ConfigPath);
        Assert.Single(loaded.TunneledApps);
        Assert.Equal("2001:db8::1", loaded.OvpnFiles[0].ServerHostname);
        Assert.Equal("vpn.example", loaded.OvpnFiles[1].ServerHostname);
    }

    [Fact]
    public void CorruptionRestoresBackupAndPreservesDamagedFile()
    {
        var config = Config.Load(ConfigPath);
        config.ActiveOvpnId = "first";
        config.Save();
        config.ActiveOvpnId = "second";
        config.Save();
        File.WriteAllText(ConfigPath, "broken");
        var recovered = Config.Load(ConfigPath);
        Assert.Equal("first", recovered.ActiveOvpnId);
        Assert.NotNull(recovered.LoadWarning);
        recovered.Save();
        Assert.Equal("first", Config.Load(ConfigPath).ActiveOvpnId);
        Assert.Single(Directory.GetFiles(_directory, "*.corrupt-*"));
        Assert.Equal("broken", File.ReadAllText(Directory.GetFiles(_directory, "*.corrupt-*")[0]));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{invalid")]
    [InlineData("{\"ovpnFiles\":[null]}")]
    [InlineData("{\"tunneledApps\":null}")]
    [InlineData("{\"ovpnFiles\":null}")]
    public void UnrecoverableConfigCannotBeOverwritten(string damaged)
    {
        File.WriteAllText(ConfigPath, damaged);
        var config = Config.Load(ConfigPath);
        Assert.NotNull(config.LoadWarning);
        Assert.Throws<InvalidOperationException>(() => config.Save());
        Assert.Equal(damaged, File.ReadAllText(ConfigPath));
    }

    [Fact]
    public void FailedAtomicReplaceLeavesExistingConfiguration()
    {
        var config = Config.Load(ConfigPath);
        config.ActiveOvpnId = "original";
        config.Save();
        using (var readLock = new FileStream(ConfigPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            config.ActiveOvpnId = "replacement";
            var error = Record.Exception(() => config.Save());
            Assert.True(error is IOException or UnauthorizedAccessException);
        }
        Assert.Equal("original", Config.Load(ConfigPath).ActiveOvpnId);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Fact]
    public async Task ConcurrentReadersRetainLastValidVersionAcrossReplacement()
    {
        var config = Config.Load(ConfigPath);
        config.Save();
        var reader = Task.Run(() =>
        {
            for (var i = 0; i < 100; i++)
            {
                try
                {
                    using var file = new FileStream(ConfigPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var document = JsonDocument.Parse(file);
                    Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
                }
                catch (IOException ex) when ((ex.HResult & 0xFFFF) is 2 or 32 or 33)
                { /* The backend retains its last valid snapshot across replacement/share races. */ }
            }
        });
        for (var i = 0; i < 30; i++) { config.ActiveOvpnId = i.ToString(); config.Save(); }
        await reader;
        Assert.Equal("29", Config.Load(ConfigPath).ActiveOvpnId);
    }

    [Theory]
    [InlineData("remote\tvpn.example 1194\nclient\n", false)]
    [InlineData("client\nauth-user-pass\n", true)]
    [InlineData("# auth-user-pass\n<cert>\nexample\n</cert>\n", false)]
    [InlineData("<auth-user-pass>\nuser\npass\n</auth-user-pass>", true)]
    public void AuthenticationRequirementIsTakenFromProfile(string contents, bool expected)
    {
        var file = Path.Combine(_directory, "profile.ovpn");
        File.WriteAllText(file, contents);
        Assert.Equal(expected, OvpnParser.RequiresUserPassword(file));
        if (contents.StartsWith("remote")) Assert.Equal("vpn.example", OvpnParser.ParseRemote(file));
    }

    [Fact]
    public void RuntimeSecretsAreUniqueReadableAndDeleted()
    {
        string file;
        using (var first = new SessionSecrets(_directory))
        using (var second = new SessionSecrets(_directory))
        {
            file = first.PasswordFile;
            Assert.NotEqual(first.Password, second.Password);
            Assert.Equal(first.Password + "\n", File.ReadAllText(file));
            first.ReleasePasswordFile();
            Assert.False(File.Exists(file));
        }
        Assert.Empty(Directory.EnumerateFiles(_directory, "management.secret", SearchOption.AllDirectories));
    }

    [Fact]
    public void DevDiscoveryFollowsCheckoutInsteadOfHardcodedDirectory()
    {
        var checkout = Path.Combine(_directory, "a path with spaces");
        Directory.CreateDirectory(Path.Combine(checkout, "redirector"));
        File.WriteAllText(Path.Combine(checkout, "Cargo.toml"), "[workspace]");
        File.WriteAllText(Path.Combine(checkout, "redirector", "Cargo.toml"), "[package]");
        var binaries = Path.Combine(checkout, "target", "release");
        Directory.CreateDirectory(binaries);
        var executable = Path.Combine(binaries, "redirector.exe");
        File.WriteAllText(executable, "fake; never executed");
        var ui = Path.Combine(checkout, "dotnet", "bin", "Release");
        Directory.CreateDirectory(ui);
        Assert.Equal(executable, Redirector.FindBinary(ui));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
