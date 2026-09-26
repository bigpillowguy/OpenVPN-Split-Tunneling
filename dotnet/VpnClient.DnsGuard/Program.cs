using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace VpnClient.DnsGuard;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "service") return GuardianService.Run(false);
            if (args.Length == 3 && args[0] == "stub-service" && args[1] == "--lease" && Guid.TryParseExact(args[2], "D", out _)) return GuardianService.Run(true);
            var result = Execute(args);
            Console.WriteLine(JsonSerializer.Serialize(result, ProtectedStorage.Json));
            return result.ExitCode;
        }
        catch (Exception ex)
        {
            string reason = GuardEngine.Reason(ex);
            var result = GuardResult.Of(reason is "maintenance_active" or "operation_busy" ? "busy" :
                ex is GuardException { Unsupported: true } ? "unsupported" : "recoveryRequired", reason: reason);
            Console.WriteLine(JsonSerializer.Serialize(result, ProtectedStorage.Json));
            return result.ExitCode;
        }
    }
    private static GuardResult Execute(string[] args)
    {
        if (args.Length == 0) throw new GuardException("invalid_arguments", true);
        // Inspect is read-only, including unsafe development launches: do not create
        // ProgramData, named synchronization objects, services or registry values.
        var store = new ProtectedStorage();
        try { ProtectedStorage.ValidateInstallation(); }
        catch (GuardException ex) when (ex.Reason == "unsafe_install_location" && args[0] is "uninstall" or "maintenance-complete")
        {
            Options(args, "maintenance-owner");
            using var scm = Native.Scm();
            using var registration = Native.OpenService(scm, Native.GuardName, 1 | 4);
            bool exists = !registration.IsInvalid;
            if (!exists && Marshal.GetLastWin32Error() != 1060) throw new GuardException("guardian_access_denied");
            // Custom installs never qualify for acquisition. They still need a
            // read-only no-op uninstall when no system state belongs to any guard.
            if (GuardProtocol.UninstalledNoOp(exists, store.Read(), store.ReadMaintenance())) return GuardResult.Of("off");
            throw;
        }
        var platform = new WindowsPlatform();
        var engine = new GuardEngine(platform, store);
        if (args.SequenceEqual(new[] { "inspect" }))
        {
            var existing = store.Read();
            if (existing is not null && existing.Phase != "complete") return engine.Inspect();
            using var host = platform.InspectOriginal(platform.ReadRegistry());
            return GuardResult.Of("off");
        }
        ProtectedStorage.RequireAdmin();
        using var mutex = MachineMutex.Enter();
        ProtectedStorage.EnsureCreated();
        switch (args[0])
        {
            case "acquire":
            {
                var options = Options(args, "lease", "owner-pid", "owner-created", "backend-pid", "backend-created");
                var request = new LeaseRequest(GuidValue(options, "lease"), Identity(options, "owner"), Identity(options, "backend"));
                if (request.Owner.Pid == request.Backend.Pid) throw new GuardException("owner_identity_mismatch", true);
                CheckMaintenance(store);
                var journal = store.Read();
                if (journal is not null && journal.Phase != "complete") return GuardResult.Of("busy", journal.Request.Lease, "existing_lease");
                // Read-only preflight before creating even the separate recovery service.
                platform.ValidateOwners(request, true);
                using (platform.InspectOriginal(platform.ReadRegistry())) { }
                GuardianService.EnsureInstalled();
                using var service = GuardianService.Open(16 | 32) ?? throw new GuardException("guardian_missing");
                if (Native.Status(service).State != 1) return GuardResult.Of("busy", reason: "guardian_running");
                store.WriteRequest(request);
                store.WriteResult(GuardResult.Of("preparing", request.Lease));
                Native.Start(service, new[] { request.Lease.ToString("D") });
                return WaitResult(store, service, request.Lease);
            }
            case "release":
            {
                var options = Options(args, "lease");
                Guid lease = GuidValue(options, "lease");
                var journal = store.Read();
                if (journal is not null && journal.Phase != "complete" && journal.Request.Lease != lease)
                    return GuardResult.Of("busy", journal.Request.Lease, "foreign_lease");
                using (var service = GuardianService.Open(4))
                {
                    if (service is not null && Native.Status(service).State != 1 && store.ReadRequest() is { } pending && pending.Lease != lease)
                        return GuardResult.Of("busy", pending.Lease, "foreign_lease");
                }
                return GuardProtocol.ReleaseResult(lease, Recover(store, engine, false));
            }
            case "recover":
                Options(args);
                return Recover(store, engine, true);
            case "uninstall":
            {
                var options = Options(args, "maintenance-owner");
                using var owner = RetainedProcess.Open(UInt(options, "maintenance-owner"));
                if (!owner.Alive) throw new GuardException("maintenance_owner_ended");
                var identity = new ProcessIdentity(owner.Pid, owner.Created);
                CheckMaintenance(store, identity);
                store.WriteMaintenance(identity);
                var result = Recover(store, engine, true);
                if (result.Status != "off") return result;
                using var service = GuardianService.Open(32 | 0x10000);
                if (service is not null)
                {
                    StopAndWait(service);
                    if (!Native.DeleteService(service)) throw new GuardException("guardian_delete_failed");
                }
                return GuardResult.Of("off");
            }
            case "maintenance-complete":
            {
                var options = Options(args, "maintenance-owner");
                using var owner = RetainedProcess.Open(UInt(options, "maintenance-owner"));
                var marker = store.ReadMaintenance();
                if (marker is not null && marker != new ProcessIdentity(owner.Pid, owner.Created))
                    return GuardResult.Of("busy", reason: "foreign_maintenance");
                store.DeleteMaintenance();
                return GuardResult.Of("off");
            }
            default: throw new GuardException("invalid_arguments", true);
        }
    }
    private static GuardResult Recover(ProtectedStorage store, GuardEngine engine, bool requireStale)
    {
        var journal = store.Read();
        using var service = GuardianService.Open(32 | 16);
        LeaseRequest? active = journal is not null && journal.Phase != "complete" ? journal.Request :
            service is not null && Native.Status(service).State != 1 ? store.ReadRequest() : null;
        if (requireStale && active is not null && Alive(active.Owner) && Alive(active.Backend))
            return GuardResult.Of("busy", active.Lease, "live_owner");
        if (service is not null)
        {
            if (Native.Status(service).State != 1) StopAndWait(service);
            // Prefer LocalSystem recovery, preserving the same registry/service access as acquire.
            journal = store.Read();
            if (journal is not null && journal.Phase != "complete")
            {
                Native.Start(service); Native.WaitState(service, 1, 30000, "guardian_recovery_timeout");
            }
        }
        journal = store.Read();
        if (journal is null || journal.Phase == "complete") return GuardResult.Of("off", journal?.Request.Lease);
        return GuardResult.Of("recoveryRequired", journal.Request.Lease, journal.Reason == "none" ? "guardian_missing" : journal.Reason);
    }
    private static void StopAndWait(ServiceHandle service)
    {
        if (Native.Status(service).State == 1) return;
        if (!Native.ControlService(service, 1, out _) && Marshal.GetLastWin32Error() != 1062) throw new GuardException("guardian_stop_failed");
        Native.WaitState(service, 1, 30000, "guardian_stop_timeout");
    }
    private static GuardResult WaitResult(ProtectedStorage store, ServiceHandle service, Guid lease)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            var result = store.ReadResult();
            if (result?.Lease == lease && result.Status != "preparing") return result;
            if (Native.Status(service).State == 1) return GuardResult.Of("recoveryRequired", lease, "guardian_stopped");
            Thread.Sleep(100);
        }
        return GuardResult.Of("preparing", lease, "operation_pending");
    }
    private static void CheckMaintenance(ProtectedStorage store, ProcessIdentity? requested = null)
    {
        if (store.ReadMaintenance() is not { } owner) return;
        if (!GuardProtocol.MaintenanceAllowed(owner, requested, Alive)) throw new GuardException("maintenance_active");
        if (owner != requested) store.DeleteMaintenance();
    }
    private static bool Alive(ProcessIdentity identity)
    {
        try { using var process = RetainedProcess.Open(identity.Pid); return process.Created == identity.Created && process.Alive; }
        catch (GuardException ex) when (ex.Reason == "process_unavailable")
        {
            // Access denied is NOT proof of death. Validate the numeric PID through
            // Process.GetProcessById before deciding the owner disappeared.
            try { using var process = Process.GetProcessById(checked((int)identity.Pid)); return !process.HasExited; }
            catch (ArgumentException) { return false; }
        }
    }
    private static Dictionary<string, string> Options(string[] args, params string[] names)
    {
        if (args.Length != 1 + 2 * names.Length) throw new GuardException("invalid_arguments", true);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; i += 2)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || !names.Contains(args[i][2..]) || !result.TryAdd(args[i][2..], args[i + 1]))
                throw new GuardException("invalid_arguments", true);
        }
        return result;
    }
    private static Guid GuidValue(Dictionary<string, string> values, string key) => Guid.TryParseExact(values[key], "D", out var value) && value != Guid.Empty ? value : throw new GuardException("invalid_arguments", true);
    private static uint UInt(Dictionary<string, string> values, string key) => uint.TryParse(values[key], out var value) && value is > 0 and <= int.MaxValue ? value : throw new GuardException("invalid_arguments", true);
    private static ProcessIdentity Identity(Dictionary<string, string> values, string prefix) => new(UInt(values, prefix + "-pid"), ulong.TryParse(values[prefix + "-created"], out var value) && value > 0 ? value : throw new GuardException("invalid_arguments", true));
}

internal sealed class MachineMutex : IDisposable
{
    private readonly SafeWaitHandle _handle;
    private MachineMutex(SafeWaitHandle handle) { _handle = handle; }
    internal static MachineMutex Enter()
    {
        if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)", 1, out var descriptor, IntPtr.Zero)) throw new GuardException("mutex_security_failed");
        try
        {
            var attributes = new Native.SecurityAttributes { Length = Marshal.SizeOf<Native.SecurityAttributes>(), Descriptor = descriptor };
            var handle = Native.CreateMutex(ref attributes, false, @"Global\VpnClient.DnsGuard.Control.v1");
            if (handle.IsInvalid) { handle.Dispose(); throw new GuardException("mutex_unavailable"); }
            uint result = Native.WaitForSingleObject(handle, 35000);
            if (result is not (0 or 0x80)) { handle.Dispose(); throw new GuardException("operation_busy"); }
            return new(handle);
        }
        finally { Native.LocalFree(descriptor); }
    }
    public void Dispose() { Native.ReleaseMutex(_handle); _handle.Dispose(); }
}
