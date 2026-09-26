using System.Runtime.InteropServices;
using System.Security.Principal;

namespace VpnClient.DnsGuard;

internal static class GuardianService
{
    internal static string ServiceImage => $"\"{ProtectedStorage.Executable}\" service";
    internal static void EnsureInstalled()
    {
        using var scm = Native.Scm(1 | 2);
        using var existing = Native.OpenService(scm, Native.GuardName, 1 | 4);
        if (!existing.IsInvalid)
        {
            Verify(existing);
            using var writable = Native.OpenService(scm, Native.GuardName, 1 | 2 | 4 | 16);
            if (writable.IsInvalid) throw new GuardException("guardian_access_denied");
            RecoveryPolicy.Ensure(new ServiceRecoverySettings(writable));
            return;
        }
        if (Marshal.GetLastWin32Error() != 1060) throw new GuardException("guardian_access_denied");
        using var created = Native.CreateService(scm, Native.GuardName, "VPN Client experimental DNS recovery", 0xF01FF,
            0x10, 2, 1, ServiceImage, null, IntPtr.Zero, null, null, null);
        if (created.IsInvalid) throw new GuardException("guardian_install_failed");
        try { RecoveryPolicy.Ensure(new ServiceRecoverySettings(created)); }
        catch { Native.DeleteService(created); throw; }
    }
    private sealed class ServiceRecoverySettings(ServiceHandle service) : IRecoverySettings
    {
        public void VerifyOwnership() => Verify(service);
        public RecoverySettings Read()
        {
            const int capacity = 8192;
            IntPtr data = Marshal.AllocHGlobal(capacity);
            try
            {
                if (!Native.QueryServiceConfig2(service, 2, data, capacity, out _)) throw new GuardException("guardian_recovery_query_failed");
                var settings = Marshal.PtrToStructure<Native.FailureActions>(data);
                if (settings.Count > 64) throw new GuardException("guardian_recovery_configuration_failed");
                int bytes = checked((int)settings.Count * Marshal.SizeOf<Native.Action>());
                if (settings.Count > 0 && (settings.Actions.ToInt64() < data.ToInt64() || settings.Actions.ToInt64() + bytes > data.ToInt64() + capacity))
                    throw new GuardException("guardian_recovery_configuration_failed");
                var actions = Enumerable.Range(0, (int)settings.Count).Select(i =>
                {
                    var action = Marshal.PtrToStructure<Native.Action>(settings.Actions + i * Marshal.SizeOf<Native.Action>());
                    return new RestartAction(action.Type, action.Delay);
                }).ToArray();
                bool command = settings.Command != IntPtr.Zero && !string.IsNullOrEmpty(Marshal.PtrToStringUni(settings.Command));
                bool reboot = settings.Reboot != IntPtr.Zero && !string.IsNullOrEmpty(Marshal.PtrToStringUni(settings.Reboot));
                if (!Native.QueryServiceConfig2(service, 4, data, capacity, out _)) throw new GuardException("guardian_recovery_query_failed");
                return new(settings.Reset, actions, Marshal.ReadInt32(data) != 0, command, reboot);
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        public void ConfigureRequired()
        {
        // Failure actions run the configured service without the one-shot acquisition GUID.
        // Such a start performs recovery only and never activates the DNS experiment.
        var actions = Marshal.AllocHGlobal(Marshal.SizeOf<Native.Action>() * 3);
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<Native.FailureActions>());
        var flag = Marshal.AllocHGlobal(4);
        try
        {
            for (int i = 0; i < 3; i++) Marshal.StructureToPtr(new Native.Action { Type = 1, Delay = (uint)(i == 0 ? 1000 : 60000) }, actions + i * Marshal.SizeOf<Native.Action>(), false);
            // Empty strings clear stale administrator-configured executable/reboot actions.
            IntPtr empty = Marshal.StringToHGlobalUni("");
            try
            {
            Marshal.StructureToPtr(new Native.FailureActions { Reset = 86400, Count = 3, Actions = actions, Command = empty, Reboot = empty }, info, false);
            Marshal.WriteInt32(flag, 1);
            if (!Native.ChangeServiceConfig2(service, 2, info) || !Native.ChangeServiceConfig2(service, 4, flag))
                throw new GuardException("guardian_recovery_configuration_failed");
            }
            finally { Marshal.FreeHGlobal(empty); }
        }
        finally { Marshal.FreeHGlobal(actions); Marshal.FreeHGlobal(info); Marshal.FreeHGlobal(flag); }
        }
    }
    internal static void Verify(ServiceHandle service)
    {
        var config = Native.Config(service);
        if (config.Type != 0x10 || config.Start != 2 || config.Image != ServiceImage ||
            !string.Equals(config.Account, "LocalSystem", StringComparison.OrdinalIgnoreCase))
            throw new GuardException("guardian_configuration_conflict");
    }
    internal static ServiceHandle? Open(uint access)
    {
        using var scm = Native.Scm();
        var service = Native.OpenService(scm, Native.GuardName, access | 1 | 4);
        if (service.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error(); service.Dispose();
            if (error == 1060) return null;
            throw new GuardException("guardian_access_denied");
        }
        try { Verify(service); return service; } catch { service.Dispose(); throw; }
    }
    internal static int Run(bool stub)
    {
        if (WindowsIdentity.GetCurrent().User?.Value != (stub ? "S-1-5-20" : "S-1-5-18"))
            throw new GuardException("service_account_required", true);
        string name = stub ? Native.DnsName : Native.GuardName;
        using var stop = new ManualResetEvent(false);
        Native.ServiceControl control = (value, _, _, _) =>
        { if (value is 1 or 5) { stop.Set(); return 0; } return value == 4 ? 0u : 120u; };
        Native.ServiceMain main = (argc, argv) =>
        {
            IntPtr handle = Native.RegisterServiceCtrlHandlerEx(name, control, IntPtr.Zero);
            if (handle == IntPtr.Zero) return;
            var status = new Native.ServiceStatus { Type = 0x10, State = 4, Accepted = 1 | 4 };
            if (!Native.SetServiceStatus(handle, ref status)) return;
            uint error = 0;
            try
            {
                if (stub) stop.WaitOne();
                else
                {
                    string? requested = argc == 2 ? Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, IntPtr.Size)) : null;
                    error = Work(requested, stop) ? 0u : 1u;
                }
            }
            catch { error = 1; }
            finally
            {
                status.State = 1; status.Accepted = 0; status.Error = error;
                Native.SetServiceStatus(handle, ref status);
            }
        };
        var table = new[] { new Native.ServiceEntry { Name = name, Main = main }, new Native.ServiceEntry() };
        if (!Native.StartServiceCtrlDispatcher(table)) throw new GuardException("service_dispatch_failed");
        GC.KeepAlive(main); GC.KeepAlive(control);
        return 0;
    }
    private static bool Work(string? requested, ManualResetEvent stop)
    {
        ProtectedStorage.ValidateInstallation();
        ProtectedStorage.EnsureCreated();
        var store = new ProtectedStorage();
        var platform = new WindowsPlatform();
        var engine = new GuardEngine(platform, store);
        if (!Guid.TryParseExact(requested, "D", out var lease))
        {
            var restored = engine.Restore(); store.WriteResult(restored);
            return restored.Status == "off";
        }
        var request = store.ReadRequest();
        if (request is null || request.Lease != lease) throw new GuardException("request_mismatch");
        platform.ValidateOwners(request, false);
        // Keep exact kernel process identities alive throughout the lease, even
        // while Inspect performs additional independent state validation.
        using var owner = platform.OpenOwner(request.Owner, false);
        using var backend = platform.OpenOwner(request.Backend, true);
        var result = engine.Activate(request, () => stop.WaitOne(0));
        store.WriteResult(result);
        if (result.Status != "active") return result.Status is "off" or "unsupported";
        while (!stop.WaitOne(500))
        {
            if (!owner.Alive || !backend.Alive || engine.Inspect().Status != "active") break;
        }
        result = engine.Restore(); store.WriteResult(result);
        return result.Status == "off";
    }
}
