using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Vpnclient.Status;

namespace VpnClient.Ui;

public static class SnapshotValidator
{
    public static bool IsValid(Snapshot snapshot)
    {
        if (snapshot.Vpn is null || snapshot.Vpn.UptimeMs > (ulong)(TimeSpan.MaxValue.Ticks / TimeSpan.TicksPerMillisecond)) return false;
        if (snapshot.Vpn.Up && (!IPAddress.TryParse(snapshot.Vpn.AdapterIp, out var address) || address.AddressFamily != AddressFamily.InterNetwork)) return false;
        if (snapshot.Apps.Count > 1024) return false;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pids = new HashSet<uint>();
        foreach (var app in snapshot.Apps)
        {
            if (string.IsNullOrWhiteSpace(app.ExePath) || app.ExePath.Length > 32767 || !paths.Add(app.ExePath) || app.Pids.Count > 4096) return false;
            foreach (var pid in app.Pids)
                if (pid.Pid == 0 || pid.Pid > int.MaxValue || !pids.Add(pid.Pid) || pids.Count > 16384) return false;
        }
        return true;
    }
}
