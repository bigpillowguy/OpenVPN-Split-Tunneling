using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VpnClient.Ui;

public class Config
{
    public List<OvpnEntry> OvpnFiles { get; set; } = new();
    public string? ActiveOvpnId { get; set; }
    public List<AppEntry> TunneledApps { get; set; } = new();

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

    public static Config Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                var cfg = JsonSerializer.Deserialize<Config>(json, JsonOpts);
                if (cfg is not null)
                {
                    cfg.MigrateInPlace();
                    return cfg;
                }
            }
        }
        catch (Exception ex)
        {
            // Bad config — start fresh, log to stderr for diagnostics
            Console.Error.WriteLine($"config load failed: {ex.Message}");
        }
        return new Config();
    }

    /// <summary>
    /// Drop any legacy "host:port" stored under ServerHostname down to just the host.
    /// We now display hostname-only to match OpenVPN Connect's convention.
    /// </summary>
    private void MigrateInPlace()
    {
        var dirty = false;
        foreach (var entry in OvpnFiles)
        {
            var idx = entry.ServerHostname.IndexOf(':');
            if (idx > 0)
            {
                entry.ServerHostname = entry.ServerHostname[..idx];
                dirty = true;
            }
        }
        if (dirty)
        {
            try { Save(); } catch { }
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(AppDataDir);
        Directory.CreateDirectory(OvpnDir);
        var json = JsonSerializer.Serialize(this, JsonOpts);
        File.WriteAllText(ConfigPath, json);
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
