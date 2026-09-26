using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Controls;
using MessageBoxButton = System.Windows.MessageBoxButton;

namespace VpnClient.Ui;

public partial class VpnConfigWindow : FluentWindow
{
    private readonly Config _cfg;
    public ObservableCollection<OvpnEntry> Profiles { get; }
    public event EventHandler? ConfigChanged;

    private OvpnEntry? _editing;

    public VpnConfigWindow(Config cfg)
    {
        InitializeComponent();
        _cfg = cfg;
        Profiles = new ObservableCollection<OvpnEntry>(cfg.OvpnFiles);
        ProfileList.ItemsSource = Profiles;
        if (Profiles.Count > 0)
            ProfileList.SelectedIndex = 0;
        App.Connector.StateChanged += OnConnectorStateChanged;
        Closed += (_, _) => App.Connector.StateChanged -= OnConnectorStateChanged;
        RefreshConnectButton();
    }

    private void OnConnectorStateChanged(object? sender, EventArgs e) => Dispatcher.BeginInvoke(RefreshConnectButton);
    private void RefreshConnectButton() => ConnectProfileBtn.IsEnabled = App.Connector.State is not (VpnConnectionState.Connecting or VpnConnectionState.Disconnecting);

    private void ImportBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "OpenVPN configs (*.ovpn)|*.ovpn|All files (*.*)|*.*",
            Title = "Import OpenVPN configuration",
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            using var imported = OvpnProfileImporter.Import(dlg.FileName, Config.OvpnDir);
            var entry = new OvpnEntry
            {
                Id = imported.Id,
                DisplayName = imported.DisplayName,
                FilePath = imported.ProfilePath,
                ServerHostname = imported.ServerHostname,
            };
            var previous = _cfg.OvpnFiles;
            _cfg.OvpnFiles = Profiles.Append(entry).ToList();
            try { _cfg.Save(); }
            catch { _cfg.OvpnFiles = previous; throw; }
            imported.Commit();
            Profiles.Add(entry);
            ProfileList.SelectedItem = entry;
            ConfigChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Import failed:\n{ex.Message}", "Import error",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void ProfileList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ProfileList.SelectedItem is OvpnEntry entry)
        {
            _editing = entry;
            DetailGrid.Visibility = Visibility.Visible;
            EmptyText.Visibility = Visibility.Collapsed;
            DisplayNameBox.Text = entry.DisplayName;
            ServerHostnameBox.Text = entry.ServerHostname;
            ServerOverrideBox.Text = entry.ServerOverride;
            UsernameBox.Text = entry.Username;
            PasswordBox.Password = entry.GetPassword();
        }
        else
        {
            _editing = null;
            DetailGrid.Visibility = Visibility.Collapsed;
            EmptyText.Visibility = Visibility.Visible;
        }
    }

    private void SaveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        var current = _editing;
        current.DisplayName = DisplayNameBox.Text.Trim();
        if (string.IsNullOrEmpty(current.DisplayName))
            current.DisplayName = Path.GetFileNameWithoutExtension(current.FilePath);
        current.ServerOverride = ServerOverrideBox.Text.Trim();
        current.Username = UsernameBox.Text.Trim();
        try { current.SetPassword(PasswordBox.Password); Persist(); }
        catch (Exception ex) { ShowSaveError(ex); }

        // OvpnEntry isn't observable; force the ListView to re-render in place.
        ProfileList.Items.Refresh();
    }

    private void DeleteBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        var entry = _editing;
        if (ProfileIsInUse(entry))
        {
            System.Windows.MessageBox.Show("Disconnect this profile before deleting it; its certificates and keys may still be in use.",
                "Profile is in use", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var result = System.Windows.MessageBox.Show(
            $"Delete profile \"{entry.DisplayName}\"?\nIts owned import folder will be removed. Legacy or external files are preserved.",
            "Confirm delete",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);
        if (result != System.Windows.MessageBoxResult.Yes) return;
        // A connection attempt can start while the confirmation dialog pumps events.
        if (ProfileIsInUse(entry))
        {
            System.Windows.MessageBox.Show("Disconnect this profile before deleting it.",
                "Profile is in use", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var previous = _cfg.OvpnFiles;
        var previousActive = _cfg.ActiveOvpnId;
        _cfg.OvpnFiles = Profiles.Where(profile => profile.Id != entry.Id).ToList();
        if (_cfg.ActiveOvpnId == entry.Id) _cfg.ActiveOvpnId = _cfg.OvpnFiles.FirstOrDefault()?.Id;
        try { _cfg.Save(); }
        catch (Exception error)
        {
            _cfg.OvpnFiles = previous;
            _cfg.ActiveOvpnId = previousActive;
            ShowSaveError(error);
            return;
        }
        Profiles.Remove(entry);
        if (Profiles.Count > 0) ProfileList.SelectedIndex = 0;
        ConfigChanged?.Invoke(this, EventArgs.Empty);
        try { OvpnProfileImporter.DeleteOwnedProfile(entry.FilePath, Config.OvpnDir); }
        catch (Exception error)
        {
            System.Windows.MessageBox.Show($"The profile was removed from the list, but its files were preserved:\n{error.Message}",
                "Profile files retained", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static bool ProfileIsInUse(OvpnEntry entry) => App.Connector.ActiveProfileId == entry.Id &&
        (App.Connector.HasSession || App.Connector.State is VpnConnectionState.Connecting or VpnConnectionState.Connected or VpnConnectionState.Disconnecting);

    private async void ConnectProfileBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        try
        {
            _cfg.ActiveOvpnId = _editing.Id;
            _cfg.Save();
            await App.Connector.ConnectAsync(_editing);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Connect failed:\n{ex.Message}",
                "Connect error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

    private void Persist()
    {
        try
        {
            _cfg.OvpnFiles = Profiles.ToList();
            _cfg.Save();
            ConfigChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) { ShowSaveError(ex); }
    }

    private static void ShowSaveError(Exception ex) => System.Windows.MessageBox.Show($"Profile changes were not saved:\n{ex.Message}", "Save error", MessageBoxButton.OK, MessageBoxImage.Error);
}
