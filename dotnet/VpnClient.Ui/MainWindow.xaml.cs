using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.ComponentModel;
using System.Windows.Threading;
using MessageBoxButton = System.Windows.MessageBoxButton;
using Vpnclient.Status;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

public partial class MainWindow : FluentWindow
{
    private readonly StatusClient _statusClient = new();
    private Config _config = Config.Load();
    private readonly ObservableCollection<AppRow> _appRows = new();
    private readonly DispatcherTimer _dnsTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private long _snapshotReceivedAt;
    private bool _dnsInitialized, _dnsToggleBusy, _dnsPollBusy;

    public MainWindow()
    {
        InitializeComponent();
        _statusClient.SnapshotReceived += OnSnapshot;
        _statusClient.ConnectionChanged += OnConnectionChanged;
        App.Connector.StateChanged += OnVpnStateChanged;
        Redirector.StateChanged += OnVpnStateChanged;
        App.ExperimentalDns.StateChanged += OnDnsStateChanged;
        _dnsTimer.Tick += async (_, _) =>
        {
            if (_dnsPollBusy || _closing) return;
            _dnsPollBusy = true;
            try { ObserveDnsReadiness(); await App.ExperimentalDns.CheckFreshnessAsync(); }
            finally { _dnsPollBusy = false; }
        };
        Loaded += async (_, _) => {
            _statusClient.Start();
            RefreshAppList();
            RefreshConnectionState();
            if (_config.LoadWarning is { } warning)
                System.Windows.MessageBox.Show(warning, "Configuration recovery", MessageBoxButton.OK, MessageBoxImage.Warning);
            await App.ExperimentalDns.InitializeAsync(_config.ExperimentalSplitDns);
            _dnsInitialized = true;
            _dnsTimer.Start();
            RefreshConnectionState();
        };
        Closing += OnClosing;
        Closed += (_, _) => { _dnsTimer.Stop(); _statusClient.Stop(); App.Connector.StateChanged -= OnVpnStateChanged; Redirector.StateChanged -= OnVpnStateChanged; App.ExperimentalDns.StateChanged -= OnDnsStateChanged; };
    }

    private bool _redirectorConnected;
    private Snapshot? _snapshot;
    private bool _closing;
    private bool _allowClose;

    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_allowClose) return;
        e.Cancel = true;
        if (_closing || _dnsToggleBusy || !_dnsInitialized) return;
        _closing = true;
        RefreshConnectionState();
        try { await App.ExperimentalDns.PauseAsync(); }
        catch (Exception ex)
        {
            _closing = false;
            System.Windows.MessageBox.Show(ex.Message, "DNS restoration needs attention", MessageBoxButton.OK, MessageBoxImage.Error);
            RefreshConnectionState();
            return;
        }
        try { await App.Connector.DisconnectAsync(); }
        catch { /* OnExit closes the owned Job even if graceful shutdown failed. */ }
        try { await Redirector.StopAsync(); }
        catch { /* Job fallback remains bounded if the backend does not respond. */ }
        _allowClose = true;
        Close();
    }

    private void OnVpnStateChanged(object? sender, EventArgs e) => Dispatcher.BeginInvoke(RefreshConnectionState);
    private void OnDnsStateChanged(object? sender, EventArgs e) => Dispatcher.BeginInvoke(RefreshConnectionState);

    private void OnConnectionChanged(object? sender, bool connected)
    {
        Dispatcher.BeginInvoke(() =>
        {
            _redirectorConnected = connected;
            if (!connected) _snapshot = null;
            RefreshConnectionState();
        });
    }

    private void OnSnapshot(object? sender, Snapshot snapshot)
    {
        var receivedAt = Stopwatch.GetTimestamp();
        Dispatcher.BeginInvoke(() =>
        {
            _snapshot = snapshot;
            _snapshotReceivedAt = receivedAt;
            Redirector.ObserveDnsControl(snapshot, receivedAt);
            RefreshConnectionState();

            var totals = snapshot.Totals;
            if (totals is not null)
            {
                BytesOutText.Text = FormatBytes(totals.BytesAppToRemote);
                BytesInText.Text = FormatBytes(totals.BytesRemoteToApp);
            }

            ApplyAppStats(snapshot.Apps);
        });
    }

    private void ApplyAppStats(IEnumerable<AppStats> apps)
    {
        var byPath = new Dictionary<string, AppStats>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in apps) byPath[s.ExePath] = s;

        foreach (var row in _appRows)
        {
            if (byPath.TryGetValue(row.ExePath, out var s))
            {
                var pidTuples = s.Pids
                    .Select(p => (p.Pid, p.BytesOut, p.BytesIn, p.BytesOutPerSec, p.BytesInPerSec))
                    .ToList();
                row.UpdateStats(s.BytesOut, s.BytesIn, s.BytesOutPerSec, s.BytesInPerSec, s.ActivePids, pidTuples);
            }
            else
            {
                row.ResetStats();
            }
        }
    }

    private void SettingsBtn_Click(object sender, RoutedEventArgs e)
    {
        var settings = new SettingsWindow(_config) { Owner = this };
        settings.ConfigChanged += (_, _) => RefreshAppList();
        settings.ShowDialog();
    }

    private void VpnSettingsBtn_Click(object sender, RoutedEventArgs e)
    {
        var vpn = new VpnConfigWindow(_config) { Owner = this };
        vpn.ConfigChanged += (_, _) =>
        {
            _config = Config.Load();
            RefreshConnectionState();
        };
        vpn.ShowDialog();
        // also refresh after close in case ActiveOvpnId changed
        _config = Config.Load();
        RefreshConnectionState();
    }

    private void RefreshConnectionState()
    {
        var connector = App.Connector;
        var busy = connector.State is VpnConnectionState.Connecting or VpnConnectionState.Disconnecting;
        var canStop = connector.HasSession || connector.State == VpnConnectionState.Connecting;
        var ready = Redirector.IsRunning && _redirectorConnected && _snapshot?.Vpn?.Up == true;
        StateSpinner.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        StateDot.Visibility = busy ? Visibility.Collapsed : Visibility.Visible;
        StateText.Text = connector.State switch
        {
            VpnConnectionState.Connecting => "Connecting…",
            VpnConnectionState.Connected => ready ? "VPN connected" : "VPN connected — routing unavailable",
            VpnConnectionState.Disconnecting => "Disconnecting…",
            VpnConnectionState.Failed => "VPN failed",
            _ => "VPN disconnected",
        };
        StateDot.Fill = new SolidColorBrush(connector.State == VpnConnectionState.Connected && ready
            ? Color.FromRgb(0x10, 0xA1, 0x6B) : Color.FromRgb(0xC5, 0x72, 0x42));
        AdapterText.Text = connector.LastError ?? Redirector.Failure ?? (!_redirectorConnected ? "Redirector unavailable; you can still stop OpenVPN."
            : ready ? $"egress source {_snapshot!.Vpn.AdapterIp}" : "Waiting for a usable VPN route");
        AdapterText.TextWrapping = TextWrapping.Wrap;
        UptimeText.Text = connector.State == VpnConnectionState.Connected && ready ? FormatUptime(_snapshot!.Vpn.UptimeMs) : "—";
        ConnectBtn.Content = canStop ? (connector.State == VpnConnectionState.Connecting ? "Cancel" : "Disconnect") : "Connect";
        ConnectBtn.Icon = new SymbolIcon(canStop ? SymbolRegular.Stop20 : SymbolRegular.Play20);
        ConnectBtn.Appearance = canStop ? ControlAppearance.Secondary : ControlAppearance.Primary;
        ConnectBtn.IsEnabled = !_closing && connector.State != VpnConnectionState.Disconnecting && (canStop || _config.OvpnFiles.Count > 0);
        ConnectBtn.ToolTip = canStop ? "Stop this VPN session" : "Connect using the selected profile";
        ConnectBtn.IsEnabled &= !_dnsToggleBusy;
        VpnSettingsBtn.IsEnabled = ManageAppsBtn.IsEnabled = !_closing && !_dnsToggleBusy;
        ExperimentalDnsToggle.IsChecked = _config.ExperimentalSplitDns;
        ExperimentalDnsToggle.IsEnabled = _dnsInitialized && !_closing && !_dnsToggleBusy && !connector.HasSession && !busy;
        ExperimentalDnsToggle.ToolTip = connector.HasSession || busy ? "Disconnect the VPN first. Changing this setting restarts the backend." : "Changing this setting restarts the backend; applications are started normally.";
        ExperimentalDnsText.Text = _dnsToggleBusy ? "Restoring DNS and restarting the backend…" : App.ExperimentalDns.Detail +
            ExperimentalDnsDiagnostics.Format(_snapshot?.SplitDns, App.ExperimentalDns.State == ExperimentalDnsState.Active,
                _redirectorConnected && Stopwatch.GetElapsedTime(_snapshotReceivedAt) <= TimeSpan.FromSeconds(2));
        ObserveDnsReadiness();
    }

    private void ObserveDnsReadiness()
    {
        if (!_dnsInitialized) return;
        var current = !_closing && !_dnsToggleBusy && _redirectorConnected &&
            Stopwatch.GetElapsedTime(_snapshotReceivedAt) <= TimeSpan.FromSeconds(2) && App.Connector.State == VpnConnectionState.Connected;
        var target = ExperimentalDnsReadiness.Evaluate(current, Redirector.SplitDnsMode, _snapshot, Redirector.SessionBinding, Redirector.Identity);
        _ = App.ExperimentalDns.ObserveAsync(target);
    }

    private async void ExperimentalDnsToggle_Click(object sender, RoutedEventArgs e)
    {
        var enabled = ExperimentalDnsToggle.IsChecked == true;
        if (_dnsToggleBusy || !_dnsInitialized || App.Connector.HasSession || App.Connector.State is VpnConnectionState.Connecting or VpnConnectionState.Disconnecting)
        { RefreshConnectionState(); return; }
        _dnsToggleBusy = true;
        var previous = _config.ExperimentalSplitDns;
        RefreshConnectionState();
        try
        {
            await App.ExperimentalDns.PauseAsync();
            await App.ExperimentalDns.SetEnabledAsync(false);
            await Redirector.StopAsync();
            Redirector.Dispose();
            _snapshot = null; _redirectorConnected = false;
            _config.ExperimentalSplitDns = enabled;
            _config.Save();
            Redirector.Start(enabled);
            await App.ExperimentalDns.SetEnabledAsync(enabled);
            await App.ExperimentalDns.ResumeAsync();
        }
        catch (Exception ex)
        {
            _config.ExperimentalSplitDns = previous;
            try { _config.Save(); } catch { }
            System.Windows.MessageBox.Show(ex.Message + "\nRestart the client if its backend is unavailable.", "Experimental DNS setting", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { _dnsToggleBusy = false; RefreshConnectionState(); }
    }

    private OvpnEntry? ResolveActiveProfile()
    {
        if (!string.IsNullOrEmpty(_config.ActiveOvpnId))
        {
            var active = _config.OvpnFiles.FirstOrDefault(p => p.Id == _config.ActiveOvpnId);
            if (active is not null) return active;
        }
        return _config.OvpnFiles.FirstOrDefault();
    }

    private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (App.Connector.HasSession || App.Connector.State == VpnConnectionState.Connecting)
                await App.Connector.DisconnectAsync();
            else if (ResolveActiveProfile() is { } profile)
            {
                await App.Connector.ConnectAsync(profile);
                await App.ExperimentalDns.ResumeAsync();
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                ex.Message,
                "VPN error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }
        finally { RefreshConnectionState(); }
    }

    private void RefreshAppList()
    {
        _config = Config.Load();
        // Rebuild AppRow set, preserving any rows whose path is still in the config.
        var existing = _appRows.GroupBy(r => r.ExePath, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        _appRows.Clear();
        foreach (var entry in _config.TunneledApps)
        {
            var row = existing.GetValueOrDefault(entry.ExePath) ?? new AppRow(entry);
            _appRows.Add(row);
        }
        AppsList.ItemsSource = _appRows;
        EmptyAppsText.Visibility = _config.TunneledApps.Count == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
        RefreshConnectionState();
    }

    private static string FormatBytes(ulong bytes)
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

    private static string FormatUptime(ulong ms)
    {
        if (ms == 0) return "—";
        var span = TimeSpan.FromTicks(checked((long)ms * TimeSpan.TicksPerMillisecond));
        if (span.TotalDays >= 1) return $"{(int)span.TotalDays}d {span.Hours:D2}h {span.Minutes:D2}m";
        if (span.TotalHours >= 1) return $"{(int)span.TotalHours}h {span.Minutes:D2}m {span.Seconds:D2}s";
        if (span.TotalMinutes >= 1) return $"{(int)span.TotalMinutes}m {span.Seconds:D2}s";
        return $"{(int)span.TotalSeconds}s";
    }
}
