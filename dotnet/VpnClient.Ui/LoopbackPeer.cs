using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace VpnClient.Ui;

internal static class LoopbackPeer
{
    // Check the accepted server-side 4-tuple before disclosing authentication material.
    public static bool IsOwnedBy(TcpClient connection, int processId)
    {
        var local = (IPEndPoint)connection.Client.LocalEndPoint!;
        var remote = (IPEndPoint)connection.Client.RemoteEndPoint!;
        uint size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0); // AF_INET, TCP_TABLE_OWNER_PID_ALL
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(checked((int)size));
            try
            {
                var result = GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0);
                if (result == 122) continue; // table grew
                if (result != 0) throw new Win32Exception((int)result, "GetExtendedTcpTable");
                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<TcpRow>();
                for (var index = 0; index < count; index++)
                {
                    var row = Marshal.PtrToStructure<TcpRow>(IntPtr.Add(buffer, 4 + index * rowSize));
                    if (row.State == 5 && row.ProcessId == processId && row.LocalAddress == 0x0100007F && row.RemoteAddress == 0x0100007F &&
                        BinaryPrimitives.ReverseEndianness((ushort)row.LocalPort) == remote.Port &&
                        BinaryPrimitives.ReverseEndianness((ushort)row.RemotePort) == local.Port) return true;
                }
                return false;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("Could not identify the OpenVPN management server.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRow { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, ProcessId; }
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint family, uint tableClass, uint reserved);
}
