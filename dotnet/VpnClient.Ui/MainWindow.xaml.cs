using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using Vpnclient.Status;
using Wpf.Ui.Controls;

namespace VpnClient.Ui;

public partial class MainWindow : FluentWindow
{
    private readonly StatusClient _statusClient = new();
    private Config _config = Config.Load();
    private readonly ObservableCollection<AppRow> _appRows = new();

    public MainWindow()
    {
        InitializeComponent();
        _statusClient.SnapshotReceived += OnSnapshot;
        _statusClient.ConnectionChanged += OnConnectionChanged;
        Loaded += (_, _) => {
            _statusClient.Start();
            RefreshAppList();
            UpdateConnectButtonState(false);
        };
        Closed += (_, _) => _statusClient.Stop();
    }

    private void OnConnectionChanged(object? sender, bool connected)
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!connected)
            {
                StateText.Text = "Disconnected from redirector";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x6B, 0x6B, 0x6B));
                AdapterText.Text = "redirector service not running, or pipe ACL denies access";
            }
        });
    }

    private void OnSnapshot(object? sender, Snapshot snapshot)
    {
        Dispatcher.BeginInvoke(() =>
        {
            var vpn = snapshot.Vpn;
            if (vpn is null)
            {
                StateText.Text = "Unknown VPN state";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x6B, 0x6B, 0x6B));
                AdapterText.Text = string.Empty;
            }
            else if (vpn.Up)
            {
                _connecting = false;
                StateSpinner.Visibility = Visibility.Collapsed;
                StateDot.Visibility = Visibility.Visible;
                StateText.Text = "VPN connected";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0x10, 0xA1, 0x6B));
                AdapterText.Text = $"egress source {vpn.AdapterIp}";
                UptimeText.Text = FormatUptime(vpn.UptimeMs);
                UpdateConnectButtonState(true);
            }
            else if (_connecting)
            {
                StateSpinner.Visibility = Visibility.Visible;
                StateDot.Visibility = Visibility.Collapsed;
                StateText.Text = "Connecting…";
                AdapterText.Text = "openvpn handshake in progress";
                UptimeText.Text = "—";
            }
            else
            {
                StateSpinner.Visibility = Visibility.Collapsed;
                StateDot.Visibility = Visibility.Visible;
                StateText.Text = "VPN disconnected";
                StateDot.Fill = new SolidColorBrush(Color.FromRgb(0xC5, 0x42, 0x42));
                AdapterText.Text = string.Empty;
                UptimeText.Text = "—";
                UpdateConnectButtonState(false);
            }

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
            UpdateConnectButtonState(_lastVpnUp);
        };
        vpn.ShowDialog();
        // also refresh after close in case ActiveOvpnId changed
        _config = Config.Load();
        UpdateConnectButtonState(_lastVpnUp);
    }

    private bool _lastVpnUp;
    private bool _connecting;

    private void UpdateConnectButtonState(bool vpnUp)
    {
        _lastVpnUp = vpnUp;
        var hasProfiles = _config.OvpnFiles.Count > 0;
        if (vpnUp)
        {
            ConnectBtn.Content = "Disconnect";
            ConnectBtn.Icon = new SymbolIcon(SymbolRegular.Stop20);
            ConnectBtn.Appearance = ControlAppearance.Secondary;
            ConnectBtn.IsEnabled = true;
            ConnectBtn.ToolTip = "Stop the VPN tunnel";
        }
        else
        {
            ConnectBtn.Content = "Connect";
            ConnectBtn.Icon = new SymbolIcon(SymbolRegular.Play20);
            ConnectBtn.Appearance = ControlAppearance.Primary;
            ConnectBtn.IsEnabled = hasProfiles && !_connecting;
            if (!hasProfiles)
            {
                ConnectBtn.ToolTip = "Import a .ovpn profile via the gear icon first";
            }
            else
            {
                var profile = ResolveActiveProfile();
                ConnectBtn.ToolTip = profile is null
                    ? "Connect"
                    : $"Connect using \"{profile.DisplayName}\"";
            }
        }
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
        // Toggle: if VPN is up, this click means "Disconnect"
        if (_lastVpnUp)
        {
            ConnectBtn.IsEnabled = false;
            try
            {
                await App.Connector.DisconnectAsync();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"Disconnect failed:\n{ex.Message}",
                    "Disconnect error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
            return;
        }

        var profile = ResolveActiveProfile();
        if (profile is null) return;

        if (string.IsNullOrWhiteSpace(profile.Username)
            || string.IsNullOrWhiteSpace(profile.GetPassword()))
        {
            System.Windows.MessageBox.Show(
                $"Profile \"{profile.DisplayName}\" has no saved credentials.\n" +
                "Open the gear icon to add a username + password and try again.",
                "Missing credentials",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        _connecting = true;
        StateSpinner.Visibility = Visibility.Visible;
        StateDot.Visibility = Visibility.Collapsed;
        StateText.Text = "Connecting…";
        AdapterText.Text = $"using profile \"{profile.DisplayName}\"";
        ConnectBtn.IsEnabled = false;
        try
        {
            await App.Connector.ConnectAsync(profile);
            // Status snapshot will flip _connecting off once the VPN adapter is detected.
            // If we don't see UP within ~30s, give up the spinner so the user isn't stuck.
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(30));
                await Dispatcher.BeginInvoke(() =>
                {
                    if (_connecting && !_lastVpnUp)
                    {
                        _connecting = false;
                        StateSpinner.Visibility = Visibility.Collapsed;
                        StateDot.Visibility = Visibility.Visible;
                        UpdateConnectButtonState(false);
                        // OnSnapshot will paint the actual disconnected state on the next tick
                    }
                });
            });
        }
        catch (Exception ex)
        {
            _connecting = false;
            StateSpinner.Visibility = Visibility.Collapsed;
            StateDot.Visibility = Visibility.Visible;
            System.Windows.MessageBox.Show(
                $"Connect failed:\n{ex.Message}",
                "Connect error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }
    }

    private void RefreshAppList()
    {
        _config = Config.Load();
        // Rebuild AppRow set, preserving any rows whose path is still in the config.
        var existing = _appRows.ToDictionary(r => r.ExePath, StringComparer.OrdinalIgnoreCase);
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
        var span = TimeSpan.FromMilliseconds(ms);
        if (span.TotalDays >= 1) return $"{(int)span.TotalDays}d {span.Hours:D2}h {span.Minutes:D2}m";
        if (span.TotalHours >= 1) return $"{(int)span.TotalHours}h {span.Minutes:D2}m {span.Seconds:D2}s";
        if (span.TotalMinutes >= 1) return $"{(int)span.TotalMinutes}m {span.Seconds:D2}s";
        return $"{(int)span.TotalSeconds}s";
    }
}
