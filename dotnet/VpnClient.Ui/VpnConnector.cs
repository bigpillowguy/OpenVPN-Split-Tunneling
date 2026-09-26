using System;
using System.IO;

namespace VpnClient.Ui;

public sealed class VpnConnector : VpnSessionController
{
    public VpnConnector() : base(profile => new OpenVpnSession(profile)) { }

    public static string? FindOpenVpn()
    {
        foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            var path = Path.Combine(Environment.GetFolderPath(root), "OpenVPN", "bin", "openvpn.exe");
            if (File.Exists(path)) return path;
        }
        return null;
    }
}
