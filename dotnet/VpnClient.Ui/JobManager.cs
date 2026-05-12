using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace VpnClient.Ui;

/// <summary>
/// Single Win32 Job Object owned by the UI process. Any child (redirector,
/// openvpn) we assign to it dies when this process dies — clean exit or
/// crash. That's what gives us the "close the UI → tunnel really stops"
/// guarantee without writing PID-tracking files to disk.
/// </summary>
public static class JobManager
{
    private static readonly Lazy<IntPtr> _job = new(CreateJob);

    public static void Assign(Process process)
    {
        if (process.HasExited) return;
        if (!AssignProcessToJobObject(_job.Value, process.Handle))
        {
            // Already in a job that can't be broken out of? Surface so the
            // caller knows the "kill-on-close" guarantee isn't in effect.
            // We don't throw — the process still runs, just unguarded.
            var err = Marshal.GetLastWin32Error();
            Debug.WriteLine($"AssignProcessToJobObject failed: {err}");
        }
    }

    private static IntPtr CreateJob()
    {
        var handle = CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject");

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        int len = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            Marshal.StructureToPtr(info, buf, false);
            if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, buf, (uint)len))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject");
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return handle;
    }

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
}
