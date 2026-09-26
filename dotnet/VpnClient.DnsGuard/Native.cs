using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VpnClient.DnsGuard;

internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private ServiceHandle() : base(true) { }
    protected override bool ReleaseHandle() => Native.CloseServiceHandle(handle);
}
internal static class Native
{
    internal const string GuardName = "VpnClientDnsGuard";
    internal const string DnsName = "Dnscache";
    [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus { public uint Type, State, Accepted, Error, Specific, Checkpoint, WaitHint; }
    [StructLayout(LayoutKind.Sequential)] internal struct StatusProcess { public uint Type, State, Accepted, Error, Specific, Checkpoint, WaitHint, Pid, Flags; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct ServiceConfig
    { public uint Type, Start, Error; public IntPtr Image, Group; public uint Tag; public IntPtr Dependencies, Account, Display; }
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] internal struct Action { public uint Type, Delay; }
    [StructLayout(LayoutKind.Sequential)] internal struct FailureActions { public uint Reset; public IntPtr Reboot, Command; public uint Count; public IntPtr Actions; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct ServiceEntry
    { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; public ServiceMain? Main; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void ServiceMain(uint argc, IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate uint ServiceControl(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern ServiceHandle OpenService(ServiceHandle scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out StatusProcess status, int length, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool QueryServiceConfig(ServiceHandle service, IntPtr config, int length, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool StartService(ServiceHandle service, int count, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[]? args);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern ServiceHandle CreateService(ServiceHandle scm, string name, string display, uint access, uint type, uint start, uint error, string image, string? group, IntPtr tag, string? dependencies, string? account, string? password);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, IntPtr info);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool QueryServiceConfig2(ServiceHandle service, uint level, IntPtr info, int length, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool DeleteService(ServiceHandle service);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool StartServiceCtrlDispatcher([In] ServiceEntry[] table);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern IntPtr RegisterServiceCtrlHandlerEx(string name, ServiceControl handler, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus status);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeHandle handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool TerminateProcess(SafeProcessHandle process, uint code);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(SafeAccessTokenHandle token, int type, IntPtr data, int length, out int needed);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, System.Text.StringBuilder name, ref int size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool MoveFileEx(string oldName, string newName, uint flags);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, IntPtr length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeWaitHandle CreateMutex(ref SecurityAttributes attributes, bool initialOwner, string name);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool ReleaseMutex(SafeWaitHandle mutex);

    internal static ServiceHandle Scm(uint rights = 1)
    {
        var handle = OpenSCManager(null, null, rights);
        if (handle.IsInvalid) { handle.Dispose(); throw new GuardException("scm_access_denied", true); }
        return handle;
    }
    internal static ServiceHandle Service(string name, uint rights = 4)
    {
        using var scm = Scm();
        var handle = OpenService(scm, name, rights);
        if (handle.IsInvalid) { int code = Marshal.GetLastWin32Error(); handle.Dispose(); throw new GuardException(code == 1060 ? "service_missing" : "service_access_denied", true); }
        return handle;
    }
    internal static StatusProcess Status(ServiceHandle service)
    {
        if (!QueryServiceStatusEx(service, 0, out var result, Marshal.SizeOf<StatusProcess>(), out _)) throw new GuardException("service_status_unavailable", true);
        return result;
    }
    internal sealed record Configuration(uint Type, uint Start, string Image, string Account);
    internal static Configuration Config(ServiceHandle service)
    {
        var memory = Marshal.AllocHGlobal(8192);
        try
        {
            if (!QueryServiceConfig(service, memory, 8192, out _)) throw new GuardException("service_config_unavailable", true);
            var value = Marshal.PtrToStructure<ServiceConfig>(memory);
            return new(value.Type, value.Start, Marshal.PtrToStringUni(value.Image) ?? "", Marshal.PtrToStringUni(value.Account) ?? "");
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    internal static void Start(ServiceHandle service, string[]? args = null)
    {
        if (!StartService(service, args?.Length ?? 0, args))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != 1056) throw new GuardException(error == 1290 ? "incompatible_service_sid" : "service_start_failed");
        }
    }
    internal static void WaitState(ServiceHandle service, uint state, int timeoutMs = 10000, string timeoutReason = "service_timeout")
    {
        var timer = System.Diagnostics.Stopwatch.StartNew();
        while (Status(service).State != state)
        {
            if (timer.ElapsedMilliseconds >= timeoutMs) throw new GuardException(timeoutReason);
            Thread.Sleep(100);
        }
    }
    internal static string[] Arguments(string command)
    {
        IntPtr ptr = CommandLineToArgvW(command, out int count);
        if (ptr == IntPtr.Zero || count is < 1 or > 16) { if (ptr != IntPtr.Zero) LocalFree(ptr); throw new GuardException("command_unrecognized", true); }
        try { return Enumerable.Range(0, count).Select(i => Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptr, i * IntPtr.Size)) ?? "").ToArray(); }
        finally { LocalFree(ptr); }
    }
}
