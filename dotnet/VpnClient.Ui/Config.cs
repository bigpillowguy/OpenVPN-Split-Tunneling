using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Text;

namespace VpnClient.Ui;

public class Config
{
    public int SchemaVersion { get; set; } = 1;
    public List<OvpnEntry> OvpnFiles { get; set; } = new();
    public string? ActiveOvpnId { get; set; }
    public List<AppEntry> TunneledApps { get; set; } = new();
    public bool ExperimentalSplitDns { get; set; }

    [JsonIgnore]
    public static string AppDataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VpnClient");

    [JsonIgnore]
    public static string ConfigPath => Path.Combine(AppDataDir, "config.json");

    [JsonIgnore]
    public static string OvpnDir => Path.Combine(AppDataDir, "ovpn");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private string? _storagePath;
    private bool _readFailed;
    private bool _fromBackup;
    [JsonIgnore] public string? LoadWarning { get; private set; }

    public static Config Load(string? path = null)
    {
        path ??= ConfigPath;
        if (!File.Exists(path)) return new Config { _storagePath = path };
        try
        {
            return Read(path, path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or ArgumentException)
        {
            try
            {
                var restored = Read(path + ".bak", path);
                restored._fromBackup = true;
                restored.LoadWarning = "The configuration could not be read. The last backup was recovered; save a change to restore it.";
                return restored;
            }
            catch (Exception backupError) when (backupError is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or ArgumentException)
            {
                return new Config
                {
                    _storagePath = path, _readFailed = true,
                    LoadWarning = $"Cannot read configuration or its backup. Your files were preserved. Restore {path} before saving changes. {ex.Message}",
                };
            }
        }
    }

    private static Config Read(string source, string destination)
    {
        var config = JsonSerializer.Deserialize<Config>(File.ReadAllText(source), JsonOpts)
            ?? throw new InvalidDataException("The configuration is null.");
        config.Normalize();
        config._storagePath = destination;
        return config;
    }

    public static string NormalizeAppPath(string path) => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private void Normalize()
    {
        if (SchemaVersion > 1) throw new InvalidDataException("This configuration was written by a newer client.");
        if (OvpnFiles is null || TunneledApps is null) throw new InvalidDataException("Configuration lists cannot be null.");
        if (OvpnFiles.Any(entry => entry is null) || TunneledApps.Any(entry => entry is null))
            throw new InvalidDataException("The configuration contains a null entry.");
        foreach (var entry in OvpnFiles)
        {
            entry.ServerHostname ??= "";
            entry.ServerOverride ??= "";
            entry.Username ??= "";
            entry.PasswordEncrypted ??= "";
            entry.DisplayName ??= "";
            entry.FilePath ??= "";
            var idx = entry.ServerHostname.IndexOf(':');
            // Only migrate unambiguous host:port; IPv6 addresses contain more than one colon.
            if (idx > 0 && idx == entry.ServerHostname.LastIndexOf(':') &&
                ushort.TryParse(entry.ServerHostname[(idx + 1)..], out _))
            {
                entry.ServerHostname = entry.ServerHostname[..idx];
            }
        }
        foreach (var entry in TunneledApps)
        {
            if (string.IsNullOrWhiteSpace(entry.ExePath)) throw new InvalidDataException("An application path is empty.");
            entry.ExePath = NormalizeAppPath(entry.ExePath);
        }
        TunneledApps = TunneledApps.DistinctBy(entry => entry.ExePath, StringComparer.OrdinalIgnoreCase).ToList();
        SchemaVersion = 1;
    }

    public void Save()
    {
        if (_readFailed) throw new InvalidOperationException(LoadWarning);
        Normalize();
        var path = _storagePath ?? ConfigPath;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this, JsonOpts));
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            if (File.Exists(path))
            {
                if (_fromBackup) File.Copy(path, path + ".corrupt-" + Guid.NewGuid().ToString("N"));
                // Readers must retain their last valid snapshot across transient filesystem errors.
                // A successfully opened version always contains the complete flushed JSON.
                File.Replace(temporary, path, _fromBackup ? null : path + ".bak", ignoreMetadataErrors: true);
            }
            else File.Move(temporary, path);
            _fromBackup = false;
            LoadWarning = null;
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}

public class OvpnEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string DisplayName { get; set; } = "";
    public string FilePath { get; set; } = "";

    /// <summary>The `remote &lt;host&gt; &lt;port&gt;` line parsed from the .ovpn file. Read-only display.</summary>
    public string ServerHostname { get; set; } = "";

    /// <summary>If set, used at connect time instead of <see cref="ServerHostname"/>. Format `host[:port]`.</summary>
    public string ServerOverride { get; set; } = "";

    /// <summary>Plaintext username (per `auth-user-pass`). Stored in user-scope config.</summary>
    public string Username { get; set; } = "";

    /// <summary>DPAPI-encrypted, base64-encoded password. Never set this directly — use SetPassword / GetPassword.</summary>
    public string PasswordEncrypted { get; set; } = "";

    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;

    [JsonIgnore]
    public string EffectiveServer => string.IsNullOrWhiteSpace(ServerOverride) ? ServerHostname : ServerOverride;

    public void SetPassword(string plain)
    {
        PasswordEncrypted = Crypto.Encrypt(plain);
    }

    public string GetPassword()
    {
        return Crypto.Decrypt(PasswordEncrypted);
    }
}

public class AppEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string DisplayName { get; set; } = "";
    public string ExePath { get; set; } = "";
    public DateTime AddedAt { get; set; } = DateTime.UtcNow;
}
