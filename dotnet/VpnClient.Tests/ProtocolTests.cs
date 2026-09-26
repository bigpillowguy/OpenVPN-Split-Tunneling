using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using VpnClient.Ui;
using Vpnclient.Status;
using Xunit;

namespace VpnClient.Tests;

public class ProtocolTests
{
    [Fact]
    public async Task ManagementAuthenticatesSplitPromptWithoutNewline()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, deadline.Token);
        using var server = await listener.AcceptTcpClientAsync(deadline.Token);
        Assert.True(LoopbackPeer.IsOwnedBy(client, Environment.ProcessId));
        Assert.False(LoopbackPeer.IsOwnedBy(client, int.MaxValue));
        using var input = new StreamReader(client.GetStream(), Encoding.UTF8, false, 4096, true);
        using var output = new StreamWriter(client.GetStream(), new UTF8Encoding(false), 4096, true) { AutoFlush = true, NewLine = "\n" };
        using var serverInput = new StreamReader(server.GetStream(), Encoding.UTF8, false, 4096, true);
        using var serverOutput = new StreamWriter(server.GetStream(), new UTF8Encoding(false), 4096, true) { AutoFlush = true, NewLine = "\n" };
        var authentication = ManagementProtocol.AuthenticateAsync(input, output, "session-secret", deadline.Token);
        await serverOutput.WriteAsync("ENTER ");
        await serverOutput.WriteAsync("PASSWORD:");
        Assert.Equal("session-secret", await serverInput.ReadLineAsync(deadline.Token));
        await serverOutput.WriteLineAsync("\nSUCCESS: password is correct");
        await authentication;
    }

    [Fact]
    public async Task ManagementRejectsWrongPasswordAndCanCancelSilentPeer()
    {
        using var rejectedInput = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes("ENTER PASSWORD:ERROR: bad password\n")));
        using var sink = new StreamWriter(new MemoryStream()) { AutoFlush = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() => ManagementProtocol.AuthenticateAsync(rejectedInput, sink, "secret", CancellationToken.None));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
        using var server = await listener.AcceptTcpClientAsync();
        using var input = new StreamReader(client.GetStream());
        using var output = new StreamWriter(client.GetStream()) { AutoFlush = true };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ManagementProtocol.AuthenticateAsync(input, output, "secret", deadline.Token));
    }

    [Theory]
    [InlineData("user\npassword Auth attacker")]
    [InlineData("user\rcommand")]
    [InlineData("user\0")]
    public void ManagementCredentialsCannotInjectCommands(string value) => Assert.Throws<ArgumentException>(() => ManagementProtocol.Quote(value));

    [Fact]
    public void ManagementQuotesPasswordsWithQuotesAndBackslashes()
        => Assert.Equal("\"a\\\"b\\\\c\"", ManagementProtocol.Quote("a\"b\\c"));

    [Theory]
    [InlineData("")]
    [InlineData(@"C:\Program Files\OpenVPN\")]
    [InlineData("a b\"c\\")]
    [InlineData("кириллица и пробел")]
    public void WindowsArgumentsRoundTripThroughNativeParser(string argument)
    {
        var buffer = CommandLineToArgvW("program " + WindowsCommandLine.Quote(argument), out var count);
        Assert.NotEqual(IntPtr.Zero, buffer);
        try
        {
            Assert.Equal(2, count);
            Assert.Equal(argument, Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, IntPtr.Size)));
        }
        finally { LocalFree(buffer); }
    }

    [Fact]
    public void TelemetryRejectsOverflowDuplicatesAndInvalidPids()
    {
        var snapshot = ValidSnapshot();
        Assert.True(SnapshotValidator.IsValid(snapshot));
        snapshot.Vpn.UptimeMs = ulong.MaxValue;
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.Vpn.UptimeMs = 100;
        snapshot.Apps[0].Pids.Add(new PidStats { Pid = 42 });
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.Apps[0].Pids.RemoveAt(1);
        snapshot.Apps[0].Pids[0].Pid = uint.MaxValue;
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.Apps[0].Pids[0].Pid = 42;
        snapshot.Apps.Add(new AppStats { ExePath = @"c:\apps\game.exe" });
        Assert.False(SnapshotValidator.IsValid(snapshot));
    }

    [Fact]
    public void TelemetryRejectsInvalidAddressAndCollectionBudget()
    {
        var snapshot = ValidSnapshot();
        snapshot.Vpn.AdapterIp = "not an address";
        Assert.False(SnapshotValidator.IsValid(snapshot));
        snapshot.Vpn.AdapterIp = "10.8.0.2";
        for (var i = 0; i < 1024; i++) snapshot.Apps.Add(new AppStats { ExePath = "path-" + i });
        Assert.False(SnapshotValidator.IsValid(snapshot));
    }

    private static Snapshot ValidSnapshot()
    {
        var snapshot = new Snapshot { Vpn = new VpnState { Up = true, AdapterIp = "10.8.0.2", UptimeMs = 100 } };
        var app = new AppStats { ExePath = @"C:\Apps\game.exe" };
        app.Pids.Add(new PidStats { Pid = 42 });
        snapshot.Apps.Add(app);
        return snapshot;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
