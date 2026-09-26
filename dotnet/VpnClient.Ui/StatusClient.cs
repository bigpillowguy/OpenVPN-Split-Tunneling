using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using Vpnclient.Status;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VpnClient.Ui;

public class StatusClient
{
    public const string PipeName = "vpnclient-status";

    public event EventHandler<Snapshot>? SnapshotReceived;
    public event EventHandler<bool>? ConnectionChanged;

    private readonly CancellationTokenSource _cts = new();

    public void Start()
    {
        _ = Task.Run(() => RunLoop(_cts.Token));
    }

    public void Stop()
    {
        _cts.Cancel();
    }

    private async Task RunLoop(CancellationToken ct)
    {
        var backoffMs = 500;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(2000, ct);
                if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverPid) || !Redirector.IsOwnedServer(serverPid))
                    throw new IOException("Status pipe does not belong to the redirector started by this client.");
                ConnectionChanged?.Invoke(this, true);
                backoffMs = 500;
                await ReadFrames(pipe, ct);
            }
            catch (TimeoutException) { }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (OperationCanceledException) { } // A frame deadline expires: disconnect and retry.
            catch (Exception)
            {
                // swallow and retry
            }
            ConnectionChanged?.Invoke(this, false);
            try { await Task.Delay(backoffMs, ct); } catch { return; }
            backoffMs = Math.Min(backoffMs * 2, 4000);
        }
    }

    private async Task ReadFrames(NamedPipeClientStream pipe, CancellationToken ct)
    {
        var lenBuf = new byte[4];
        while (!ct.IsCancellationRequested)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            if (!await ReadExactly(pipe, lenBuf, deadline.Token)) return;
            var len = BinaryPrimitives.ReadUInt32LittleEndian(lenBuf);
            if (len == 0 || len > (1u << 20)) return;
            var body = new byte[len];
            if (!await ReadExactly(pipe, body, deadline.Token)) return;
            var msg = StatusMessage.Parser.ParseFrom(body);
            if (msg.BodyCase == StatusMessage.BodyOneofCase.Snapshot)
            {
                if (!SnapshotValidator.IsValid(msg.Snapshot)) throw new InvalidDataException("Invalid status snapshot.");
                SnapshotReceived?.Invoke(this, msg.Snapshot);
            }
        }
    }

    private static async Task<bool> ReadExactly(Stream s, byte[] buf, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buf.Length)
        {
            var n = await s.ReadAsync(buf.AsMemory(offset), ct);
            if (n <= 0) return false;
            offset += n;
        }
        return true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
}
