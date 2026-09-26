using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace VpnClient.Ui;

/// <summary>Import a bounded, self-contained client profile without executing profile commands.</summary>
public static class OvpnProfileImporter
{
    private const string MarkerName = ".vpnclient-profile.json";
    private const int MaximumDependencyBytes = 8 * 1024 * 1024;
    private const int MaximumTotalDependencyBytes = 32 * 1024 * 1024;
    private const string CredentialsMessage = "Credential files and inline credentials are not imported. Replace them with a bare auth-user-pass option and enter the username/password in the profile editor.";
    private static readonly HashSet<string> FileOptions = new(StringComparer.Ordinal)
        { "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "crl-verify", "extra-certs", "dh" };
    // A positive list also rejects future options which might load code, write files,
    // change the working directory, or override the authenticated management channel.
    private static readonly HashSet<string> ClientOptions = new((
        "client tls-client pull remote remote-random remote-random-hostname proto proto-force port rport lport local nobind bind " +
        "resolv-retry connect-retry connect-retry-max connect-timeout server-poll-timeout remote-cert-tls remote-cert-ku remote-cert-eku " +
        "verify-x509-name peer-fingerprint auth-user-pass auth-nocache auth-retry static-challenge " +
        "dev dev-type dev-node windows-driver disable-dco topology ifconfig ifconfig-ipv6 ifconfig-noexec ifconfig-nowarn " +
        "route route-ipv6 route-gateway route-metric route-delay route-table route-noexec route-nopull redirect-gateway redirect-private " +
        "dhcp-option dns block-outside-dns register-dns block-ipv6 pull-filter allow-pull-fqdn " +
        "persist-key persist-tun persist-local-ip persist-remote-ip ping ping-exit ping-restart ping-timer-rem keepalive " +
        "cipher data-ciphers data-ciphers-fallback auth tls-version-min tls-version-max tls-cipher tls-ciphersuites tls-groups " +
        "tls-timeout reneg-sec reneg-bytes reneg-pkts hand-window tran-window key-direction keying-material-exporter " +
        "tun-mtu tun-mtu-extra link-mtu mtu-disc mtu-test mssfix fragment max-packet-size sndbuf rcvbuf txqueuelen " +
        "compress comp-lzo comp-noadapt allow-compression allow-recursive-routing passtos fast-io tcp-nodelay socket-flags " +
        "explicit-exit-notify inactive session-timeout float single-session tls-exit socks-proxy http-proxy http-proxy-option " +
        "http-proxy-retry http-proxy-timeout http-proxy-timeout-retry socks-proxy-retry verb mute mute-replay-warnings suppress-timestamps machine-readable-output " +
        "ncp-disable client-to-client route-ipv6-gateway auth-nocache push-peer-info ssl-fingerprints opt-verify remote-cert-ku " +
        "ip-win32 route-method tap-sleep dhcp-renew dhcp-pre-release dhcp-release disable-occ up-delay up-restart down-pre " +
        "tls-cert-profile tls-crypt-v2-max-age tls-crypt-v2-force-cookie vlan-tagging vlan-accept vlan-pvid")
        .Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);

    public static OvpnDocument LoadExpanded(string sourcePath, bool validateSupported = true)
    {
        var fullPath = ResolvePath(sourcePath, Environment.CurrentDirectory,
            new OvpnNode(OvpnNodeKind.Directive, "", new[] { "config", sourcePath }, "<profile>", 1));
        var baseDirectory = Path.GetDirectoryName(fullPath)!;
        var nodes = new List<OvpnNode>();
        var active = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = 0;
        long bytes = 0;
        void Expand(string path, int depth)
        {
            if (depth > 10 || ++files > 64) throw new InvalidDataException("Too many nested OpenVPN configuration files (maximum depth 10, files 64).");
            if (!active.Add(path)) throw new InvalidDataException($"Cyclic OpenVPN config include: {path}");
            try
            {
                var document = OvpnDocument.Load(path);
                bytes += Encoding.UTF8.GetByteCount(document.Render());
                if (bytes > OvpnDocument.MaximumBytes) throw new InvalidDataException("Expanded OpenVPN configuration is too large.");
                foreach (var node in document.Nodes)
                {
                    if (node.Kind == OvpnNodeKind.Directive && node.Name == "config")
                    {
                        if (node.Tokens.Count != 2) throw node.Error("config requires exactly one file path.");
                        Expand(ResolvePath(node.Tokens[1], baseDirectory, node), depth + 1);
                    }
                    else nodes.Add(node);
                }
            }
            finally { active.Remove(path); }
        }
        Expand(fullPath, 1);
        var result = new OvpnDocument(nodes, baseDirectory);
        if (validateSupported) ValidateSupported(result);
        return result;
    }

    public static void ValidateSupported(OvpnDocument document)
    {
        var connection = false;
        var references = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long dependencyBytes = 0;
        foreach (var node in document.Nodes)
        {
            if (node.Kind == OvpnNodeKind.Trivia) continue;
            if (node.Kind == OvpnNodeKind.ConnectionStart)
            {
                if (connection) throw node.Error("Nested <connection> blocks are not supported, including through config includes.");
                connection = true;
                continue;
            }
            if (node.Kind == OvpnNodeKind.ConnectionEnd)
            {
                if (!connection) throw node.Error("Unexpected </connection>.");
                connection = false;
                continue;
            }
            if (node.Name == "auth-user-pass")
            {
                if (node.Kind == OvpnNodeKind.InlineBlock || node.Tokens.Count != 1) throw node.Error(CredentialsMessage);
                continue;
            }
            if (node.Kind == OvpnNodeKind.InlineBlock)
            {
                if (!FileOptions.Contains(node.Name)) throw node.Error($"Inline <{node.Name}> data is not supported.");
                continue;
            }
            if (FileOptions.Contains(node.Name))
            {
                var allowedCount = node.Name == "tls-auth" && node.Tokens.Count == 3 && node.Tokens[2] is "0" or "1";
                if (node.Tokens.Count != 2 && !allowedCount)
                    throw node.Error($"{node.Name} requires a file path{(node.Name == "tls-auth" ? " and optional direction 0 or 1" : "")}; directory mode is not supported.");
                if (node.Name == "dh" && node.Tokens[1] == "none") continue;
                var path = ResolvePath(node.Tokens[1], document.BaseDirectory, node);
                using var file = OpenDependency(path, node);
                if (references.Add(path))
                {
                    dependencyBytes += file.Length;
                    if (references.Count > 64 || dependencyBytes > MaximumTotalDependencyBytes)
                        throw node.Error("Profile dependencies exceed the limit of 64 files or 32 MiB.");
                }
                continue;
            }
            if (!ClientOptions.Contains(node.Name))
                throw node.Error($"The '{node.Name}' option is not supported by this client. External commands, plugins, environment changes, credential files, file output and management overrides are not allowed.");
            if ((node.Name == "socks-proxy" && node.Tokens.Count > 3) ||
                (node.Name == "http-proxy" && node.Tokens.Count > 3))
                throw node.Error("Proxy credential files and proxy authentication are not supported; use a proxy without authentication.");
        }
        if (connection) throw new InvalidDataException("Missing </connection>.");
    }

    public static PendingOvpnImport Import(string sourcePath, string profilesRoot)
    {
        var document = LoadExpanded(sourcePath);
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        var copiedPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var rewritten = new List<OvpnNode>();
        var total = 0;
        foreach (var node in document.Nodes)
        {
            if (node.Kind != OvpnNodeKind.Directive || !FileOptions.Contains(node.Name) ||
                (node.Name == "dh" && node.Tokens[1] == "none")) { rewritten.Add(node); continue; }
            var source = ResolvePath(node.Tokens[1], document.BaseDirectory, node);
            if (!copiedPaths.TryGetValue(source, out var relative))
            {
                if (files.Count >= 64) throw node.Error("Too many profile dependencies (maximum 64).");
                using var input = OpenDependency(source, node);
                total = checked(total + (int)input.Length);
                if (total > MaximumTotalDependencyBytes) throw node.Error("Profile dependencies exceed 32 MiB.");
                var content = new byte[(int)input.Length];
                input.ReadExactly(content);
                relative = $"files/{files.Count + 1:D3}.bin";
                copiedPaths.Add(source, relative);
                files.Add(relative, content);
            }
            var tokens = node.Tokens.ToArray();
            tokens[1] = relative;
            rewritten.Add(node.WithTokens(tokens));
        }
        // All configuration parsing and dependency reads have succeeded before any writes.
        var rendered = new OvpnDocument(rewritten).Render();
        var root = Path.GetFullPath(profilesRoot);
        Directory.CreateDirectory(root);
        RejectReparseAncestors(root);
        var id = Guid.NewGuid().ToString("N");
        var directory = Path.Combine(root, id);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).Create(security);
        var owned = new List<string> { "profile.ovpn", MarkerName };
        owned.AddRange(files.Keys);
        var ownedFiles = owned.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var pending = new PendingOvpnImport(root, directory, id, Path.GetFileNameWithoutExtension(sourcePath),
            document.Nodes.FirstOrDefault(node => node.Kind == OvpnNodeKind.Directive && node.Name == "remote" && node.Tokens.Count >= 2)?.Tokens[1] ?? "",
            document.Nodes.Any(node => node.Name == "auth-user-pass"), ownedFiles);
        try
        {
            WriteNew(Path.Combine(directory, MarkerName), Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new ProfileManifest(1, id, owned))));
            if (files.Count > 0) Directory.CreateDirectory(Path.Combine(directory, "files"));
            foreach (var pair in files) WriteNew(Path.Combine(directory, pair.Key), pair.Value);
            WriteNew(pending.ProfilePath, Encoding.UTF8.GetBytes(rendered));
            return pending;
        }
        catch
        {
            // This path was just allocated by us; deletion still checks scope and links.
            DeleteDirectory(root, directory, ownedFiles);
            throw;
        }
    }

    /// <summary>Return false for legacy/unowned files; never delete a caller-provided arbitrary path.</summary>
    public static bool DeleteOwnedProfile(string profilePath, string profilesRoot)
    {
        var root = Path.GetFullPath(profilesRoot);
        var path = Path.GetFullPath(profilePath);
        var directory = Path.GetDirectoryName(path)!;
        if (!Path.GetFileName(path).Equals("profile.ovpn", StringComparison.OrdinalIgnoreCase) || !IsOwnedDirectory(root, directory)) return false;
        if (!Directory.Exists(directory)) return false;
        RejectReparseAncestors(directory);
        var markerPath = Path.Combine(directory, MarkerName);
        if (!File.Exists(markerPath)) return false;
        if ((File.GetAttributes(markerPath) & FileAttributes.ReparsePoint) != 0) throw new IOException("Profile ownership marker is a link; files were preserved.");
        using var marker = new FileStream(markerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (marker.Length > 16384) throw new InvalidDataException("Profile ownership marker is invalid; files were preserved.");
        var manifest = JsonSerializer.Deserialize<ProfileManifest>(marker);
        if (manifest is null || manifest.Version != 1 || manifest.Id != Path.GetFileName(directory) || manifest.Files is null ||
            manifest.Files.Count > 66 || !manifest.Files.Contains("profile.ovpn") || !manifest.Files.Contains(MarkerName))
            throw new InvalidDataException("Profile ownership marker is invalid; files were preserved.");
        marker.Dispose();
        DeleteDirectory(root, directory, manifest.Files.ToHashSet(StringComparer.OrdinalIgnoreCase));
        return true;
    }

    private static FileStream OpenDependency(string path, OvpnNode node)
    {
        try
        {
            var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                if (file.Length > MaximumDependencyBytes) throw node.Error("A profile dependency exceeds 8 MiB.");
                return file;
            }
            catch { file.Dispose(); throw; }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
        { throw node.Error($"Cannot read dependency '{path}': {error.Message}"); }
    }

    private static string ResolvePath(string value, string? baseDirectory, OvpnNode node)
    {
        value = value.Replace('/', '\\');
        if (value.Length == 0 || value is "stdin" or "[inline]" || IsDeviceNamespace(value))
            throw node.Error("A dependency must be a regular file path; use <name> blocks for inline data.");
        if (baseDirectory is null) throw node.Error("Cannot resolve dependencies without a source directory.");
        if (Path.IsPathRooted(value) && !Path.IsPathFullyQualified(value)) throw node.Error("Drive-relative and root-relative dependency paths are not supported.");
        var path = Path.GetFullPath(value, baseDirectory);
        // GetFullPath can itself expand a DOS alias such as NUL to \\.\NUL.
        if (IsDeviceNamespace(path)) throw node.Error("Device paths are not supported.");
        var tail = path[Path.GetPathRoot(path)!.Length..];
        if (tail.Contains(':') || tail.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(IsDeviceName))
            throw node.Error("Device paths and alternate data streams are not supported.");
        return path;
    }

    private static bool IsDeviceNamespace(string path) => path.StartsWith("\\\\?", StringComparison.Ordinal) || path.StartsWith("\\\\.", StringComparison.Ordinal);

    private static bool IsDeviceName(string segment)
    {
        var name = segment.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL" ||
            (name.Length == 4 && (name.StartsWith("COM", StringComparison.Ordinal) || name.StartsWith("LPT", StringComparison.Ordinal)) && (name[3] is >= '1' and <= '9' or '¹' or '²' or '³'));
    }

    private static void WriteNew(string path, byte[] data)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        file.Write(data);
        file.Flush(flushToDisk: true);
    }

    private static bool IsOwnedDirectory(string root, string directory) =>
        string.Equals(Path.GetDirectoryName(directory), Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase) &&
        Guid.TryParseExact(Path.GetFileName(directory), "N", out _);

    private static void RejectReparseAncestors(string directory)
    {
        for (var current = new DirectoryInfo(directory); current is not null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Linked profile directories are not supported: {current.FullName}");
    }

    private static void DeleteDirectory(string root, string directory, HashSet<string> expectedFiles)
    {
        if (!IsOwnedDirectory(root, directory)) throw new IOException("Refusing to delete a directory outside the owned profiles folder.");
        if (!Directory.Exists(directory)) return;
        RejectReparseAncestors(directory);
        var filePaths = new List<string>();
        var directories = new List<string>();
        void Inspect(string current)
        {
            foreach (var item in new DirectoryInfo(current).EnumerateFileSystemInfos())
            {
                if ((item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Profile contains a link; files were preserved.");
                var relative = Path.GetRelativePath(directory, item.FullName).Replace('\\', '/');
                if ((item.Attributes & FileAttributes.Directory) != 0)
                {
                    if (relative != "files") throw new IOException("Profile contains an unrecognized directory; files were preserved.");
                    Inspect(item.FullName);
                    directories.Add(item.FullName);
                }
                else
                {
                    if (!expectedFiles.Contains(relative)) throw new IOException("Profile contains an unrecognized file; files were preserved.");
                    filePaths.Add(item.FullName);
                }
            }
        }
        Inspect(directory);
        // Full inspection precedes deletion, so an unexpected user file preserves the folder.
        foreach (var path in filePaths) File.Delete(path);
        foreach (var path in directories) Directory.Delete(path, recursive: false);
        Directory.Delete(directory, recursive: false);
    }

    private sealed record ProfileManifest(int Version, string Id, List<string> Files);

    public sealed class PendingOvpnImport : IDisposable
    {
        private readonly string _root;
        private readonly string _directory;
        private readonly HashSet<string> _ownedFiles;
        private bool _committed;
        internal PendingOvpnImport(string root, string directory, string id, string displayName, string server, bool credentialsRequired, HashSet<string> ownedFiles)
        { _root = root; _directory = directory; _ownedFiles = ownedFiles; Id = id; DisplayName = displayName; ServerHostname = server; CredentialsRequired = credentialsRequired; }
        public string Id { get; }
        public string ProfilePath => Path.Combine(_directory, "profile.ovpn");
        public string DisplayName { get; }
        public string ServerHostname { get; }
        public bool CredentialsRequired { get; }
        public void Commit() => _committed = true;
        public void Dispose()
        {
            if (!_committed) DeleteDirectory(_root, _directory, _ownedFiles);
        }
    }
}
