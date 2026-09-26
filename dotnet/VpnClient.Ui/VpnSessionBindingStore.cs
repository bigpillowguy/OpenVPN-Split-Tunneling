using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace VpnClient.Ui;

internal sealed record VpnSessionBinding(int Version, Guid SessionId, uint OpenVpnPid, ulong OpenVpnCreationTime,
    string OpenVpnExePath, Guid AdapterGuid, uint InterfaceIndex, string Ipv4, string Gateway, VpnDnsSnapshot? Dns = null);

/// <summary>One private launch file; a lease prevents late callbacks from replacing a newer session.</summary>
internal sealed class VpnSessionBindingStore : IDisposable
{
    private readonly object _gate = new();
    private readonly string _directory;
    private Guid _lease;
    private bool _disposed;
    private VpnSessionBinding? _current;
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public string FilePath { get; }
    // Event consumers reread Current and marshal to their UI thread; an event may
    // already be superseded by another publication/revocation when delivered.
    public VpnSessionBinding? Current { get { lock (_gate) return _current; } }
    public event EventHandler? SnapshotChanged;

    public VpnSessionBindingStore(string? root = null)
    {
        root ??= SessionSecrets.RuntimeDirectory;
        Directory.CreateDirectory(root);
        _directory = Path.Combine(root, Guid.NewGuid().ToString("N"));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(_directory).Create(security);
        FilePath = Path.Combine(_directory, "session.json");
    }

    public Lease Begin()
    {
        Lease lease;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _lease = Guid.Empty;
            _current = null;
            File.Delete(FilePath);
            _lease = Guid.NewGuid();
            lease = new Lease(this, _lease);
        }
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return lease;
    }

    private void Publish(Guid lease, VpnSessionBinding binding)
    {
        lock (_gate)
        {
            if (_disposed || lease != _lease) throw new InvalidOperationException("The VPN session binding lease expired.");
            WriteLocked(binding);
        }
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
    }

    private void WriteLocked(VpnSessionBinding binding)
    {
        if (binding.Dns is { } dns)
            binding = binding with { Dns = dns with { Servers = Array.AsReadOnly(dns.Servers.ToArray()) } };
        var temporary = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(file, binding, Json);
                file.Flush(flushToDisk: true);
            }
            File.Move(temporary, FilePath, overwrite: true);
            _current = binding;
        }
        finally { File.Delete(temporary); }
    }

    private bool UpdateDns(Guid lease, Guid sessionId, VpnDnsSnapshot dns)
    {
        lock (_gate)
        {
            if (_disposed || lease != _lease || _current is null || _current.SessionId != sessionId) return false;
            WriteLocked(_current with { Dns = dns });
        }
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
        return true;
    }

    private void Revoke(Guid lease, bool release)
    {
        lock (_gate)
        {
            if (_disposed || lease != _lease) return;
            if (release) _lease = Guid.Empty;
            _current = null;
            File.Delete(FilePath);
        }
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _lease = Guid.Empty;
            _current = null;
            File.Delete(FilePath);
            // Preserve backend diagnostics from this launch; only session.json is ephemeral.
            try { Directory.Delete(_directory, recursive: false); }
            catch (IOException) when (File.Exists(Path.Combine(_directory, "dns-control.json")) || File.Exists(Path.Combine(_directory, "redirector.log")) ||
                                      File.Exists(Path.Combine(_directory, "redirector.log.1"))) { }
        }
        SnapshotChanged?.Invoke(this, EventArgs.Empty);
    }

    internal sealed class Lease : IDisposable
    {
        private readonly VpnSessionBindingStore _store;
        private readonly Guid _id;
        internal Lease(VpnSessionBindingStore store, Guid id) { _store = store; _id = id; }
        public void Publish(Process process, OpenVpnTunnel tunnel, VpnAdapter adapter, VpnDnsSnapshot? dns = null)
        {
            if (process.HasExited) throw new InvalidOperationException("OpenVPN exited before its tunnel was ready.");
            var executable = process.MainModule?.FileName ?? throw new InvalidOperationException("Cannot verify the OpenVPN executable.");
            Publish(new(1, tunnel.SessionId, checked((uint)process.Id), checked((ulong)process.StartTime.ToFileTimeUtc()),
                Path.GetFullPath(executable), adapter.Guid, adapter.Index, tunnel.Ipv4.ToString(), tunnel.Gateway.ToString(), dns));
        }
        internal void Publish(VpnSessionBinding binding) => _store.Publish(_id, binding);
        public bool UpdateDns(Guid sessionId, VpnDnsSnapshot dns) => _store.UpdateDns(_id, sessionId, dns);
        public void Revoke() => _store.Revoke(_id, release: false);
        public void Dispose() => _store.Revoke(_id, release: true);
    }
}
