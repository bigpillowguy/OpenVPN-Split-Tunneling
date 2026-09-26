using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

namespace VpnClient.DnsGuard;

internal sealed class ProtectedStorage : IGuardJournalStore
{
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    internal static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VpnClient.DnsGuard");
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private const string InstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    public GuardJournal? Read()
    {
        var value = ReadFile<GuardJournal>("journal.json");
        if (value is null) return null;
        if (value.Version != 1 || value.Request.Lease == Guid.Empty || value.Original.Type is not (0x10 or 0x20) ||
            value.StubImage != WindowsPlatform.BuildStubImage(value.Request.Lease) ||
            !WindowsPlatform.IsExpectedOriginal(value.Original) || !Phases.Contains(value.Phase))
            throw new GuardException("journal_invalid");
        return value;
    }
    private static readonly HashSet<string> Phases = new(StringComparer.Ordinal)
    { "prepared", "image_changed", "configuration_changed", "original_exited", "stub_running", "registry_restored", "active", "restoring", "complete", "recovery_required" };
    public void Write(GuardJournal value) => WriteFile("journal.json", value);
    internal LeaseRequest? ReadRequest() => ReadFile<LeaseRequest>("request.json");
    internal GuardResult? ReadResult() => ReadFile<GuardResult>("result.json");
    internal void WriteRequest(LeaseRequest request) => WriteFile("request.json", request);
    internal void WriteResult(GuardResult result) => WriteFile("result.json", result);
    internal ProcessIdentity? ReadMaintenance() => ReadFile<ProcessIdentity>("maintenance.json");
    internal void WriteMaintenance(ProcessIdentity owner) => WriteFile("maintenance.json", owner);
    internal void DeleteMaintenance() { ValidatePath(Root, true); File.Delete(Path.Combine(Root, "maintenance.json")); }

    internal static void EnsureCreated()
    {
        RequireAdmin();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(AdminSid);
        foreach (var sid in new[] { SystemSid, AdminSid })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(Root).Create(security);
        ValidatePath(Root, true);
    }
    internal static void RequireAdmin()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new GuardException("administrator_required", true);
    }
    internal static string Executable => Environment.ProcessPath ?? throw new GuardException("executable_unknown", true);
    internal static void ValidateInstallation()
    {
        string exe = Path.GetFullPath(Executable);
        string programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        if (!exe.StartsWith(programFiles + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(exe), "VpnClient.DnsGuard.exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(Path.GetDirectoryName(exe)), "DnsGuard", StringComparison.OrdinalIgnoreCase))
            throw new GuardException("unsafe_install_location", true);
        ValidatePath(exe, false);
        for (string? path = Path.GetDirectoryName(exe); path is not null && path.Length >= programFiles.Length; path = Path.GetDirectoryName(path))
            ValidatePath(path, true);
        // Framework-dependent modules and runtime configuration are executable trust
        // inputs too. An individually writable DLL must not escape the directory check.
        var pending = new Stack<string>(); pending.Push(Path.GetDirectoryName(exe)!);
        int count = 0;
        while (pending.TryPop(out var directory))
            foreach (string path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++count > 2048) throw new GuardException("installation_too_large", true);
                bool isDirectory = (File.GetAttributes(path) & FileAttributes.Directory) != 0;
                ValidatePath(path, isDirectory);
                if (isDirectory) pending.Push(path);
            }
    }
    internal static void ValidatePath(string path, bool directory)
    {
        var full = Path.GetFullPath(path);
        for (var current = full; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new GuardException("unsafe_reparse_path", true);
        FileSystemSecurity security = directory ? new DirectoryInfo(full).GetAccessControl() : new FileInfo(full).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !Trusted(owner)) throw new GuardException("untrusted_path_owner", true);
        const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0 &&
                (rule.FileSystemRights & writes) != 0 && !Trusted((SecurityIdentifier)rule.IdentityReference))
                throw new GuardException("unprivileged_path_write", true);
    }
    private static bool Trusted(SecurityIdentifier sid) => sid == SystemSid || sid == AdminSid || sid.Value == InstallerSid;

    private static T? ReadFile<T>(string name) where T : class
    {
        if (!Exists(Root)) return null;
        ValidatePath(Root, true);
        string path = Path.Combine(Root, name);
        if (!Exists(path)) return null;
        ValidatePath(path, false);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (file.Length > 16384) throw new GuardException("journal_invalid");
        return JsonSerializer.Deserialize<T>(file, Json) ?? throw new GuardException("journal_invalid");
    }
    private static bool Exists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        // File.Exists/Directory.Exists also return false for access denial. An
        // unreadable protected journal must never be mistaken for absent state.
    }
    private static void WriteFile<T>(string name, T value)
    {
        ValidatePath(Root, true);
        string temporary = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { JsonSerializer.Serialize(file, value, Json); file.Flush(true); }
            if (!Native.MoveFileEx(temporary, Path.Combine(Root, name), 0x1 | 0x8)) throw new GuardException("journal_flush_failed");
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
