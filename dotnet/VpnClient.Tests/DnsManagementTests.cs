using System.Net;
using System.Net.Sockets;
using System.Text;
using VpnClient.Ui;
using Xunit;

namespace VpnClient.Tests;

public class DnsManagementTests
{
    [Fact]
    public async Task LogSubscriptionMustBeAcknowledgedBeforeHoldCanBeReleased()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, deadline.Token);
        using var server = await listener.AcceptTcpClientAsync(deadline.Token);
        using var input = new StreamReader(client.GetStream(), new UTF8Encoding(false, true), false, 4096, true);
        using var output = new StreamWriter(client.GetStream(), new UTF8Encoding(false), 4096, true) { AutoFlush = true, NewLine = "\n" };
        using var serverInput = new StreamReader(server.GetStream(), Encoding.UTF8, false, 4096, true);
        using var serverOutput = new StreamWriter(server.GetStream(), new UTF8Encoding(false), 4096, true) { AutoFlush = true, NewLine = "\n" };
        var metadata = new OpenVpnDnsMetadata();
        async Task Startup()
        {
            await ManagementProtocol.EnableRealtimeLogAsync(input, output, line => metadata.Consume(line), deadline.Token);
            await output.WriteLineAsync("hold release");
        }
        var startup = Startup();
        Assert.Equal("log on", await serverInput.ReadLineAsync(deadline.Token));
        await serverOutput.WriteLineAsync(">HOLD:Waiting for hold release:0");
        await serverOutput.WriteLineAsync(">LOG:123,I,ordinary startup message");
        Assert.False(startup.IsCompleted);
        Assert.False(server.GetStream().DataAvailable);
        await serverOutput.WriteLineAsync("SUCCESS: real-time log notification set to ON");
        Assert.Equal("hold release", await serverInput.ReadLineAsync(deadline.Token));
        await startup;
    }

    [Theory]
    [InlineData("ERROR: sensitive raw diagnostic\n")]
    [InlineData("SUCCESS: other-command-with-sensitive-value\n")]
    [InlineData(">FATAL:sensitive raw diagnostic\n")]
    public async Task WrongOrRejectedLogAcknowledgementUsesControlledError(string reply)
    {
        using var input = Reader(reply);
        using var output = new StreamWriter(new MemoryStream()) { AutoFlush = true };
        var error = await Assert.ThrowsAnyAsync<Exception>(() => ManagementProtocol.EnableRealtimeLogAsync(input, output, _ => { }, CancellationToken.None));
        Assert.DoesNotContain("sensitive", error.Message);
    }

    [Theory]
    [InlineData("a", 16384)]
    [InlineData("я", 8192)]
    [InlineData("😀", 4096)]
    public async Task ManagementFrameLimitCountsUtf8Bytes(string character, int repetitions)
    {
        var valid = string.Concat(Enumerable.Repeat(character, repetitions));
        using var input = Reader(valid + "\n");
        Assert.Equal(valid, await ManagementProtocol.ReadLineAsync(input, CancellationToken.None));
        using var oversized = Reader(valid + character + "\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => ManagementProtocol.ReadLineAsync(oversized, CancellationToken.None));
    }

    [Fact]
    public async Task AuthenticationAndLogAckAreBoundedAndTruncationIsNotAccepted()
    {
        using var auth = Reader("ENTER PASSWORD:SUCCESS: password is correct" + new string('x', 16384) + "\n");
        using var output = new StreamWriter(new MemoryStream()) { AutoFlush = true };
        await Assert.ThrowsAsync<InvalidDataException>(() => ManagementProtocol.AuthenticateAsync(auth, output, "test", CancellationToken.None));
        using var ack = Reader(">LOG:" + new string('x', 16384) + "\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => ManagementProtocol.EnableRealtimeLogAsync(ack, output, _ => { }, CancellationToken.None));
        using var partial = Reader(">LOG:partial-secret");
        var error = await Assert.ThrowsAsync<EndOfStreamException>(() => ManagementProtocol.ReadLineAsync(partial, CancellationToken.None));
        Assert.DoesNotContain("partial-secret", error.Message);
    }

    [Fact]
    public async Task InvalidUtf8AndNulFramesAreRejectedWithoutRawBytesInError()
    {
        using var invalid = new StreamReader(new MemoryStream(new byte[] { 0xff, 0xfe, 10 }), new UTF8Encoding(false, true), false);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => ManagementProtocol.ReadLineAsync(invalid, CancellationToken.None));
        Assert.Equal("OpenVPN management encoding is invalid.", error.Message);
        using var nul = Reader("raw-secret\0\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => ManagementProtocol.ReadLineAsync(nul, CancellationToken.None));
    }

    private static StreamReader Reader(string text) => new(new MemoryStream(Encoding.UTF8.GetBytes(text)), new UTF8Encoding(false, true), false);
}
