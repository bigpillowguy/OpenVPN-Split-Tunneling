using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace VpnClient.Ui;

/// <summary>
/// Single Win32 Job Object owned by the UI process. Any child (redirector,
/// openvpn) we assign to it dies when this process dies — clean exit or
/// crash. That's what gives us the "close the UI → tunnel really stops"
/// guarantee without writing PID-tracking files to disk.
/// </summary>
public static class JobManager
{
    private static readonly Lazy<SafeFileHandle> _job = new(CreateJob);

    public static void Initialize() => _ = _job.Value;

    /// <summary>Assign atomically during creation, then resume only after obtaining an owned handle.</summary>
    public static Process Start(ProcessStartInfo startInfo)
    {
        Initialize();
        if (startInfo.UseShellExecute || startInfo.Arguments.Length != 0)
            throw new ArgumentException("Owned children require an explicit executable and ArgumentList.");
        var command = new StringBuilder(WindowsCommandLine.Quote(startInfo.FileName));
        foreach (var argument in startInfo.ArgumentList)
            command.Append(' ').Append(WindowsCommandLine.Quote(argument));
        nuint bytes = 0;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
        var attributes = Marshal.AllocHGlobal(checked((int)bytes));
        var jobValue = Marshal.AllocHGlobal(IntPtr.Size);
        var initialized = false;
        try
        {
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList");
            initialized = true;
            Marshal.WriteIntPtr(jobValue, _job.Value.DangerousGetHandle());
            // PROC_THREAD_ATTRIBUTE_JOB_LIST: the kernel assigns before the child can execute.
            if (!UpdateProcThreadAttribute(attributes, 0, (nuint)0x0002000D, jobValue, (nuint)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute(JOB_LIST)");
            var startup = new STARTUPINFOEX { StartupInfo = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFOEX>() }, AttributeList = attributes };
            const uint flags = 0x00080000 | 0x08000000 | 0x00000004; // EXTENDED_STARTUPINFO | NO_WINDOW | SUSPENDED
            if (!CreateProcess(startInfo.FileName, command, IntPtr.Zero, IntPtr.Zero, false, flags,
                    IntPtr.Zero, startInfo.WorkingDirectory, ref startup, out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess (owned Job)");
            using var processHandle = new SafeFileHandle(info.Process, ownsHandle: true);
            using var threadHandle = new SafeFileHandle(info.Thread, ownsHandle: true);
            Process? process = null;
            try
            {
                process = Process.GetProcessById((int)info.ProcessId);
                _ = process.Handle; // Keep identity pinned while the primary thread is suspended.
                if (ResumeThread(threadHandle) == uint.MaxValue)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread");
                return process;
            }
            catch
            {
                TerminateProcess(processHandle, 1);
                WaitForSingleObject(processHandle, 5000);
                process?.Dispose();
                throw;
            }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);
            Marshal.FreeHGlobal(jobValue);
        }
    }

    public static void Close() { if (_job.IsValueCreated) _job.Value.Dispose(); }

    private static SafeFileHandle CreateJob()
    {
        var handle = new SafeFileHandle(CreateJobObject(IntPtr.Zero, null), ownsHandle: true);
        if (handle.IsInvalid)
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
        catch { handle.Dispose(); throw; }
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
        SafeFileHandle hJob, int JobObjectInfoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, Reserved2;
        public IntPtr Reserved2Ptr, StdInput, StdOutput, StdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr AttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, IntPtr environment, string? directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(SafeFileHandle process, uint milliseconds);
}
