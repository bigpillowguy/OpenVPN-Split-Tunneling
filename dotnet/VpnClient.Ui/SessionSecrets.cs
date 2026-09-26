using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace VpnClient.Ui;

public sealed class SessionSecrets : IDisposable
{
    public static string RuntimeDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VpnClient", "runtime");
    private readonly FileStream _file;
    public string DirectoryPath { get; }
    public string PasswordFile { get; }
    public string Password { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public SessionSecrets(string? runtimeDirectory = null)
    {
        var root = runtimeDirectory ?? RuntimeDirectory;
        Directory.CreateDirectory(root);
        DirectoryPath = Path.Combine(root, Guid.NewGuid().ToString("N"));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).Create(security);
        PasswordFile = Path.Combine(DirectoryPath, "management.secret");
        try
        {
            // CRT fopen used by OpenVPN does not share DELETE; delete only after it has read the file.
            _file = new FileStream(PasswordFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                4096, FileOptions.None);
            _file.Write(Encoding.ASCII.GetBytes(Password + "\n"));
            _file.Flush(flushToDisk: true);
            _file.Dispose();
        }
        catch { if (_file is not null) _file.Dispose(); TryRemoveDirectory(); throw; }
    }

    public static void CleanupLegacyCredentials()
    {
        // Only after the singleton lock: this file belonged to older releases.
        var path = Path.Combine(RuntimeDirectory, "auth.txt");
        if (File.Exists(path)) File.Delete(path);
        if (!Directory.Exists(RuntimeDirectory)) return;
        foreach (var directory in new DirectoryInfo(RuntimeDirectory).EnumerateDirectories())
        {
            if (!Guid.TryParseExact(directory.Name, "N", out _) || (directory.Attributes & FileAttributes.ReparsePoint) != 0) continue;
            var secret = Path.Combine(directory.FullName, "management.secret");
            if (File.Exists(secret)) File.Delete(secret);
            // Runtime profiles can contain inline private keys. Retain only diagnostic logs.
            var profile = Path.Combine(directory.FullName, "runtime.ovpn");
            if (File.Exists(profile)) File.Delete(profile);
        }
    }

    public void ReleasePasswordFile()
    {
        _file.Dispose();
        if (File.Exists(PasswordFile)) File.Delete(PasswordFile);
    }

    public void Dispose()
    {
        ReleasePasswordFile();
        var profile = Path.Combine(DirectoryPath, "runtime.ovpn");
        if (File.Exists(profile)) File.Delete(profile);
        TryRemoveDirectory();
    }

    private void TryRemoveDirectory()
    {
        try { Directory.Delete(DirectoryPath, recursive: false); }
        catch (IOException) { } // Logs may intentionally remain.
        catch (UnauthorizedAccessException) { }
    }
}
