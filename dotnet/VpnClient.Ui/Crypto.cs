using System;
using System.Security.Cryptography;
using System.Text;

namespace VpnClient.Ui;

/// <summary>
/// DPAPI wrapper: encrypts secrets so only the current Windows user
/// account can decrypt them, on this machine. Suitable for storing
/// VPN auth credentials at rest in user-scope config files.
/// </summary>
public static class Crypto
{
    public static string Encrypt(string plaintext)
    {
        if (string.IsNullOrEmpty(plaintext)) return "";
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(encrypted);
    }

    public static string Decrypt(string encrypted)
    {
        if (string.IsNullOrEmpty(encrypted)) return "";
        try
        {
            var bytes = Convert.FromBase64String(encrypted);
            var decrypted = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(decrypted);
        }
        catch
        {
            return "";
        }
    }
}
