using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Controls;

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
    }

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
            Directory.CreateDirectory(Config.OvpnDir);
            var fname = Path.GetFileName(dlg.FileName);
            var dest = Path.Combine(Config.OvpnDir, fname);
            var counter = 1;
            while (File.Exists(dest))
            {
                var nameOnly = Path.GetFileNameWithoutExtension(fname);
                var ext = Path.GetExtension(fname);
                dest = Path.Combine(Config.OvpnDir, $"{nameOnly}-{counter}{ext}");
                counter++;
            }
            File.Copy(dlg.FileName, dest);

            var remote = OvpnParser.ParseRemote(dest) ?? "";
            var entry = new OvpnEntry
            {
                DisplayName = Path.GetFileNameWithoutExtension(dest),
                FilePath = dest,
                ServerHostname = remote,
            };
            Profiles.Add(entry);
            ProfileList.SelectedItem = entry;
            Persist();
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
        current.SetPassword(PasswordBox.Password);
        Persist();

        // OvpnEntry isn't observable; force the ListView to re-render in place.
        ProfileList.Items.Refresh();
    }

    private void DeleteBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        var result = System.Windows.MessageBox.Show(
            $"Delete profile \"{_editing.DisplayName}\"?\nThis also removes the imported .ovpn file.",
            "Confirm delete",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);
        if (result != System.Windows.MessageBoxResult.Yes) return;

        try { File.Delete(_editing.FilePath); } catch { }
        Profiles.Remove(_editing);
        _editing = null;
        DetailGrid.Visibility = Visibility.Collapsed;
        EmptyText.Visibility = Visibility.Visible;
        Persist();
    }

    private async void ConnectProfileBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_editing is null) return;
        if (string.IsNullOrWhiteSpace(_editing.Username)
            || string.IsNullOrWhiteSpace(_editing.GetPassword()))
        {
            var result = System.Windows.MessageBox.Show(
                "This profile has no username or password saved yet.\n" +
                "OpenVPN will prompt interactively, which won't work from a hidden window.\n\n" +
                "Save credentials in this profile first and try again.",
                "Missing credentials",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Warning);
            return;
        }

        _cfg.ActiveOvpnId = _editing.Id;
        _cfg.Save();

        try
        {
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
        _cfg.OvpnFiles = Profiles.ToList();
        _cfg.Save();
        ConfigChanged?.Invoke(this, EventArgs.Empty);
    }
}
