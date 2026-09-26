using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace VpnClient.DnsGuard;

internal sealed class RetainedProcess(SafeProcessHandle handle, uint pid, ulong created) : IGuardProcess
{
    internal SafeProcessHandle Handle { get; } = handle;
    internal uint Pid { get; } = pid;
    internal ulong Created { get; } = created;
    public bool Alive => Native.WaitForSingleObject(Handle, 0) == 258;
    public void Dispose() => Handle.Dispose();
    internal string Image
    {
        get
        {
            var text = new StringBuilder(32768); int size = text.Capacity;
            if (!Native.QueryFullProcessImageName(Handle, 0, text, ref size)) throw new GuardException("process_image_unavailable", true);
            return text.ToString();
        }
    }
    internal static RetainedProcess Open(uint pid, bool terminate = false)
    {
        var handle = Native.OpenProcess(0x1000 | 0x100000u | (terminate ? 1u : 0u), false, pid);
        if (handle.IsInvalid) { handle.Dispose(); throw new GuardException("process_unavailable", true); }
        if (!Native.GetProcessTimes(handle, out var created, out _, out _, out _)) { handle.Dispose(); throw new GuardException("process_identity_unavailable", true); }
        return new(handle, pid, checked((ulong)created));
    }
}

internal sealed class WindowsPlatform : IGuardPlatform
{
    private const string Key = @"SYSTEM\CurrentControlSet\Services\Dnscache";
    internal static string InstallRoot => Path.GetDirectoryName(Path.GetDirectoryName(ProtectedStorage.Executable))!;
    internal static string BuildStubImage(Guid lease) => $"\"{ProtectedStorage.Executable}\" stub-service --lease {lease:D}";
    public string StubImage(Guid lease) => BuildStubImage(lease);
    internal void ValidateOwners(LeaseRequest request, bool callerMustMatch)
    {
        using var owner = (RetainedProcess)OpenOwner(request.Owner, false);
        using var backend = (RetainedProcess)OpenOwner(request.Backend, true);
        var ownerToken = Security(owner);
        if (ownerToken != Security(backend) || (callerMustMatch && ownerToken.Sid != System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value))
            throw new GuardException("owner_security_mismatch", true);
    }
    private static (string Sid, int Session) Security(RetainedProcess process)
    {
        if (!Native.OpenProcessToken(process.Handle, 8, out var token)) throw new GuardException("owner_security_unavailable", true);
        using (token)
        {
            IntPtr data = Marshal.AllocHGlobal(4096);
            try
            {
                if (!Native.GetTokenInformation(token, 1, data, 4096, out _)) throw new GuardException("owner_security_unavailable", true);
                string sid = new System.Security.Principal.SecurityIdentifier(Marshal.ReadIntPtr(data)).Value;
                if (!Native.GetTokenInformation(token, 12, data, 4096, out _)) throw new GuardException("owner_security_unavailable", true);
                return (sid, Marshal.ReadInt32(data));
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
    private static string SystemSvchost => Path.Combine(Environment.SystemDirectory, "svchost.exe");
    internal static bool IsExpectedOriginal(RegistryState value)
    {
        if (value.Type is not (0x10 or 0x20)) return false;
        string raw = value.ImagePath;
        return new[] { @"%SystemRoot%\system32\svchost.exe -k NetworkService -p", @"%SystemRoot%\system32\svchost.exe -k NetworkService" }
            .Contains(raw, StringComparer.OrdinalIgnoreCase);
    }
    public RegistryState ReadRegistry()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Key, false) ?? throw new GuardException("dnscache_missing", true);
        if (key.GetValueKind("ImagePath") != RegistryValueKind.ExpandString || key.GetValueKind("Type") != RegistryValueKind.DWord)
            throw new GuardException("registry_type_unrecognized", true);
        return new((string)key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames)!, unchecked((uint)(int)key.GetValue("Type")!));
    }
    public void SetImage(RegistryState expected, string image) => Change(expected, "ImagePath", image, RegistryValueKind.ExpandString);
    public void SetType(RegistryState expected, uint type) => Change(expected, "Type", unchecked((int)type), RegistryValueKind.DWord);
    private void Change(RegistryState expected, string name, object value, RegistryValueKind kind)
    {
        // Windows provides no multi-value CAS. This is an optimistic check under our
        // machine-wide ownership; unrelated administrator edits are conflicts, never defaults to overwrite.
        if (ReadRegistry() != expected) throw new GuardException("registry_conflict");
        using var key = Registry.LocalMachine.OpenSubKey(Key, true) ?? throw new GuardException("registry_access_denied");
        key.SetValue(name, value, kind); key.Flush();
    }
    public IGuardProcess OpenOwner(ProcessIdentity identity, bool backend)
    {
        var process = RetainedProcess.Open(identity.Pid);
        try
        {
            string expected = Path.Combine(InstallRoot, backend ? "redirector.exe" : "VpnClient.Ui.exe");
            if (identity.Created != process.Created || !process.Alive || !PathEquals(process.Image, expected))
                throw new GuardException("owner_identity_mismatch", true);
            ProtectedStorage.ValidatePath(expected, false);
            return process;
        }
        catch { process.Dispose(); throw; }
    }
    public IGuardProcess InspectOriginal(RegistryState original)
    {
        if (!IsExpectedOriginal(original)) throw new GuardException("dnscache_configuration_unsupported", true);
        using var service = Native.Service(Native.DnsName, 4 | 1 | 16);
        var status = Native.Status(service);
        if (status.State != 4 || status.Pid == 0) throw new GuardException("dnscache_not_running", true);
        var config = Native.Config(service);
        if (config.Type != original.Type || config.Start == 4 || !ExpectedServiceImage(config.Image, original) ||
            !string.Equals(config.Account, @"NT AUTHORITY\NetworkService", StringComparison.OrdinalIgnoreCase))
            throw new GuardException("dnscache_configuration_unsupported", true);
        var process = RetainedProcess.Open(status.Pid, true);
        try { CheckDedicated(process, original.Type); return process; }
        catch { process.Dispose(); throw; }
    }
    public void RecheckOriginal(IGuardProcess process, RegistryState original)
    {
        // Registry now refers to our stub, but the old retained process must still
        // be exactly the original, isolated Dnscache process reported by SCM.
        var retained = (RetainedProcess)process;
        using var service = Native.Service(Native.DnsName);
        var status = Native.Status(service);
        if (status.State != 4 || status.Pid != retained.Pid || !retained.Alive) throw new GuardException("original_process_changed", true);
        CheckDedicated(retained, original.Type);
    }
    private static bool ExpectedServiceImage(string image, RegistryState original) =>
        string.Equals(image, original.ImagePath, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(image, original.ImagePath.Replace(@"%SystemRoot%\system32", Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase);
    private static void CheckDedicated(RetainedProcess process, uint originalType)
    {
        if (!PathEquals(process.Image, SystemSvchost)) throw new GuardException("dnscache_image_unrecognized", true);
        ProtectedStorage.ValidatePath(SystemSvchost, false);
        if (!Signature.IsMicrosoftWindows(SystemSvchost)) throw new GuardException("svchost_signature_unverified", true);
        string[] args = Native.Arguments(CommandLine(process.Pid));
        // Require SCM's explicit single-service launch, not merely a NetworkService group.
        bool argsValid = args.Length is 5 or 6 && PathEquals(args[0], SystemSvchost) && args[1] == "-k" &&
            args[2].Equals("NetworkService", StringComparison.OrdinalIgnoreCase) &&
            args[^2] == "-s" && args[^1].Equals("Dnscache", StringComparison.OrdinalIgnoreCase) &&
            (args.Length == 5 || args[3] == "-p");
        // OWN_PROCESS is an SCM isolation contract. Preserve full peer visibility
        // checks, but SCM need not append -s for this service type.
        argsValid |= originalType == 0x10 && args.Length is 3 or 4 && PathEquals(args[0], SystemSvchost) && args[1] == "-k" &&
            args[2].Equals("NetworkService", StringComparison.OrdinalIgnoreCase) && (args.Length == 3 || args[3] == "-p");
        if (!argsValid) throw new GuardException("shared_or_unknown_host", true);
        CheckServiceVisibility(process.Pid);
        if (!process.Alive) throw new GuardException("original_process_changed", true);
    }
    private static void CheckServiceVisibility(uint pid)
    {
        // SCM enumeration alone silently omits services with denied QUERY_STATUS.
        // Enumerate every service registry key and demand status access for every
        // registered service, including stopped services. Never treat access denial as absence.
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services") ?? throw new GuardException("service_visibility_incomplete", true);
        string[] names = root.GetSubKeyNames();
        using var scm = Native.Scm();
        var peers = new List<string>();
        foreach (string name in names)
        {
            using var service = Native.OpenService(scm, name, 4);
            if (service.IsInvalid)
            {
                if (Marshal.GetLastWin32Error() == 1060) continue; // Registry-only driver/device key, absent from SCM.
                throw new GuardException("service_visibility_incomplete", true);
            }
            var status = Native.Status(service);
            if ((status.Type & 0x30) == 0) continue;
            if (status.State is 2 or 3) throw new GuardException("service_transition_in_progress", true);
            if (status.Pid == pid && status.State != 1) peers.Add(name);
        }
        if (!names.Order(StringComparer.OrdinalIgnoreCase).SequenceEqual(root.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase))
            throw new GuardException("service_visibility_changed", true);
        if (peers.Count != 1 || !peers[0].Equals(Native.DnsName, StringComparison.OrdinalIgnoreCase))
            throw new GuardException("shared_or_unknown_host", true);
    }
    internal static string CommandLine(uint pid)
    {
        using var process = new ManagementObject(new ManagementPath($"Win32_Process.Handle='{pid}'"),
            new ObjectGetOptions { Timeout = TimeSpan.FromSeconds(2) });
        try { process.Get(); return process["CommandLine"] as string ?? throw new GuardException("command_unavailable", true); }
        catch (ManagementException) { throw new GuardException("command_unavailable", true); }
    }
    public void TerminateOriginal(IGuardProcess process) => Terminate((RetainedProcess)process);
    private static void Terminate(RetainedProcess process)
    {
        if (!Native.TerminateProcess(process.Handle, 1) && Native.WaitForSingleObject(process.Handle, 0) != 0)
            throw new GuardException("process_termination_failed");
        if (Native.WaitForSingleObject(process.Handle, 10000) != 0) throw new GuardException("process_exit_timeout");
    }
    public void StartAndConfirmStub(GuardJournal journal)
    {
        if (ReadRegistry() != new RegistryState(journal.StubImage, 0x10)) throw new GuardException("registry_conflict");
        using var service = Native.Service(Native.DnsName, 4 | 16);
        EnsureRunning(service, journal, true);
        if (!IsConfirmedStub(journal)) throw new GuardException("stub_identity_mismatch");
    }

    private void EnsureRunning(ServiceHandle service, GuardJournal journal, bool stub)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        ServiceTransition.EnsureRunning(() => ObserveTransition(service, journal, stub),
            () => Native.Start(service), () => Thread.Sleep(100), () => watch.Elapsed,
            stub ? "stub_start" : "original_restore", TimeSpan.FromSeconds(10), stub ? null : () =>
            {
                using var owned = GetStub(journal, true);
                return owned is not null && StopOwnedStub(owned);
            });
    }

    private ServiceTransitionState ObserveTransition(ServiceHandle service, GuardJournal journal, bool stub)
    {
        var expected = stub ? new RegistryState(journal.StubImage, 0x10) : journal.Original;
        if (ReadRegistry() != expected) throw new GuardException("registry_conflict");
        var status = Native.Status(service);
        if (status.State == 1) return ServiceTransitionState.Stopped;
        if (status.State is 2 or 3) return ServiceTransitionState.Pending;
        if (status.State != 4 || status.Pid == 0) return ServiceTransitionState.UnexpectedRunning;
        RetainedProcess process;
        try { process = RetainedProcess.Open(status.Pid); }
        catch (GuardException ex) when (ex.Reason == "process_unavailable")
        {
            // SCM can briefly report the departed PID after its process exited.
            // Access denial remains bounded uncertainty, never identity approval.
            return ServiceTransitionState.Pending;
        }
        using (process)
        {
            try
            {
            if (!process.Alive) return ServiceTransitionState.Pending;
            bool isStub = PathEquals(process.Image, ProtectedStorage.Executable) && CommandLine(process.Pid) == journal.StubImage;
            bool isOriginal = !stub && PathEquals(process.Image, SystemSvchost) && Signature.IsMicrosoftWindows(SystemSvchost);
            var again = Native.Status(service);
            if (!process.Alive || again.State != 4 || again.Pid != process.Pid) return ServiceTransitionState.Pending;
            if (stub ? isStub : isOriginal) return ServiceTransitionState.ExpectedRunning;
            // Graceful STOP can leave our exact stub running while its dispatcher
            // winds down. It is not a foreign service and must not be killed again.
            if (!stub && isStub) return ServiceTransitionState.OwnedReplacementRunning;
            return ServiceTransitionState.UnexpectedRunning;
            }
            catch (Exception) when (!process.Alive)
            {
                // Image/WMI observation can race with the retained process exit.
                // A still-live unidentified process keeps its original failure.
                return ServiceTransitionState.Pending;
            }
        }
    }
    private RetainedProcess? GetStub(GuardJournal journal, bool terminate)
    {
        using var service = Native.Service(Native.DnsName);
        var status = Native.Status(service);
        if (status.State != 4 || status.Pid == 0) return null;
        RetainedProcess process;
        try { process = RetainedProcess.Open(status.Pid, terminate); }
        catch (GuardException ex) when (ex.Reason == "process_unavailable") { return null; }
        try
        {
            if (!PathEquals(process.Image, ProtectedStorage.Executable) || !process.Alive || CommandLine(process.Pid) != journal.StubImage)
            { process.Dispose(); return null; }
            var again = Native.Status(service);
            if (!process.Alive || again.State != 4 || again.Pid != process.Pid) { process.Dispose(); return null; }
            return process;
        }
        catch (Exception) when (!process.Alive) { process.Dispose(); return null; }
        catch { process.Dispose(); throw; }
    }
    public bool IsConfirmedStub(GuardJournal journal) { using var process = GetStub(journal, false); return process is not null; }
    public void RestoreOriginalService(GuardJournal journal)
    {
        if (ReadRegistry() != journal.Original) throw new GuardException("registry_conflict");
        using var service = Native.Service(Native.DnsName, 4 | 16);
        if (ReadRegistry() != journal.Original) throw new GuardException("registry_conflict");
        EnsureRunning(service, journal, false);
    }
    private static bool StopOwnedStub(RetainedProcess stub)
    {
        using var scm = Native.Scm();
        using var service = Native.OpenService(scm, Native.DnsName, 4 | 32);
        if (!service.IsInvalid)
        {
            var status = Native.Status(service);
            if (!stub.Alive) return true;
            if (status.State != 4 || status.Pid != stub.Pid) return false;
            // Prefer a normal zero-exit shutdown; it does not schedule another
            // crash restart. Dnscache's existing ACL may deny STOP even to SYSTEM.
            if (Native.ControlService(service, 1, out _)) return true;
            int error = Marshal.GetLastWin32Error();
            if (error == 1062) return false;
            if (error is not (5 or 1061)) throw new GuardException("stub_stop_failed");
        }
        else if (Marshal.GetLastWin32Error() != 5) throw new GuardException("stub_stop_access_failed");
        // Only the previously verified, retained instance can be force-stopped.
        // Never terminate another PID or any NetworkService peer.
        if (stub.Alive) Terminate(stub);
        return true;
    }
    private static bool PathEquals(string a, string b) => string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
}

internal static class Signature
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct FileInfo
    { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle, Subject; }
    [StructLayout(LayoutKind.Sequential)] private struct TrustData
    { public uint Size; public IntPtr Policy, Sip; public uint Ui, Revocation, Choice; public IntPtr File; public uint State; public IntPtr StateData, Url; public uint Flags, Context; public IntPtr Signature; }
    [DllImport("wintrust.dll", ExactSpelling = true)] private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    internal static bool IsMicrosoftWindows(string path)
    {
        IntPtr file = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        var info = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = path };
        Marshal.StructureToPtr(info, file, false);
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), Ui = 2, Choice = 1, File = file, State = 1, Flags = 0x1000 };
        try
        {
            if (WinVerifyTrust(new IntPtr(-1), ref action, ref data) != 0) return false;
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            string subject = cert.GetNameInfo(X509NameType.SimpleName, false);
            return subject is "Microsoft Windows" or "Microsoft Windows Publisher";
        }
        catch { return false; }
        finally { data.State = 2; WinVerifyTrust(new IntPtr(-1), ref action, ref data); Marshal.DestroyStructure<FileInfo>(file); Marshal.FreeHGlobal(file); }
    }
}
