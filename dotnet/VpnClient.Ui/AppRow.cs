using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;

namespace VpnClient.Ui;

public class AppRow : INotifyPropertyChanged
{
    public string Id { get; }
    public string DisplayName { get; }
    public string ExePath { get; }
    public ObservableCollection<PidRow> Pids { get; } = new();

    private ulong _bytesOut;
    private ulong _bytesIn;
    private ulong _bytesOutPerSec;
    private ulong _bytesInPerSec;
    private uint _activePids;

    public AppRow(AppEntry entry)
    {
        Id = entry.Id;
        DisplayName = entry.DisplayName;
        ExePath = entry.ExePath;
    }

    public string TotalOutText => $"↑ {FormatBytes(_bytesOut)}";
    public string TotalInText => $"↓ {FormatBytes(_bytesIn)}";
    public string RateOutText => _bytesOutPerSec > 0 ? FormatRate(_bytesOutPerSec) : "idle";
    public string RateInText => _bytesInPerSec > 0 ? FormatRate(_bytesInPerSec) : "idle";
    public string ProcessCountText => _activePids == 0
        ? "no processes"
        : _activePids == 1 ? "1 process" : $"{_activePids} processes";

    public void UpdateStats(
        ulong bytesOut,
        ulong bytesIn,
        ulong rateOut,
        ulong rateIn,
        uint activePids,
        IReadOnlyList<(uint pid, ulong bytesOut, ulong bytesIn, ulong rateOut, ulong rateIn)> pids)
    {
        _bytesOut = bytesOut;
        _bytesIn = bytesIn;
        _bytesOutPerSec = rateOut;
        _bytesInPerSec = rateIn;
        _activePids = activePids;
        OnChanged(nameof(TotalOutText));
        OnChanged(nameof(TotalInText));
        OnChanged(nameof(RateOutText));
        OnChanged(nameof(RateInText));
        OnChanged(nameof(ProcessCountText));

        UpdatePidRows(pids);
    }

    public void ResetStats()
    {
        UpdateStats(0, 0, 0, 0, 0, Array.Empty<(uint, ulong, ulong, ulong, ulong)>());
    }

    private void UpdatePidRows(
        IReadOnlyList<(uint pid, ulong bytesOut, ulong bytesIn, ulong rateOut, ulong rateIn)> incoming)
    {
        // Reconcile in place: keep existing PidRow instances so their bindings
        // don't flicker; add new ones; drop ones not present anymore.
        var existing = Pids.ToDictionary(p => p.Pid);
        var seen = new HashSet<uint>();
        foreach (var s in incoming)
        {
            seen.Add(s.pid);
            if (existing.TryGetValue(s.pid, out var row))
            {
                row.Update(s.bytesOut, s.bytesIn, s.rateOut, s.rateIn);
            }
            else
            {
                Pids.Add(new PidRow(s.pid, s.bytesOut, s.bytesIn, s.rateOut, s.rateIn));
            }
        }
        for (int i = Pids.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(Pids[i].Pid))
                Pids.RemoveAt(i);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    internal static string FormatBytes(ulong bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        double v = bytes;
        string[] units = { "KB", "MB", "GB", "TB" };
        int i = -1;
        do
        {
            v /= 1024.0;
            i++;
        } while (v >= 1024.0 && i < units.Length - 1);
        return $"{v:0.##} {units[i]}";
    }

    internal static string FormatRate(ulong bps) => $"{FormatBytes(bps)}/s";
}

public class PidRow : INotifyPropertyChanged
{
    public uint Pid { get; }

    private ulong _bytesOut;
    private ulong _bytesIn;
    private ulong _bytesOutPerSec;
    private ulong _bytesInPerSec;

    public PidRow(uint pid, ulong bytesOut, ulong bytesIn, ulong rateOut, ulong rateIn)
    {
        Pid = pid;
        _bytesOut = bytesOut;
        _bytesIn = bytesIn;
        _bytesOutPerSec = rateOut;
        _bytesInPerSec = rateIn;
    }

    public string PidText => $"PID {Pid}";
    public string TotalOutText => $"↑ {AppRow.FormatBytes(_bytesOut)}";
    public string TotalInText => $"↓ {AppRow.FormatBytes(_bytesIn)}";
    public string RateOutText => _bytesOutPerSec > 0 ? AppRow.FormatRate(_bytesOutPerSec) : "idle";
    public string RateInText => _bytesInPerSec > 0 ? AppRow.FormatRate(_bytesInPerSec) : "idle";

    public void Update(ulong bytesOut, ulong bytesIn, ulong rateOut, ulong rateIn)
    {
        _bytesOut = bytesOut;
        _bytesIn = bytesIn;
        _bytesOutPerSec = rateOut;
        _bytesInPerSec = rateIn;
        OnChanged(nameof(TotalOutText));
        OnChanged(nameof(TotalInText));
        OnChanged(nameof(RateOutText));
        OnChanged(nameof(RateInText));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
