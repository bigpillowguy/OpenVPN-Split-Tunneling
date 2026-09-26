using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using Wpf.Ui.Controls;
using MessageBoxButton = System.Windows.MessageBoxButton;

namespace VpnClient.Ui;

public partial class SettingsWindow : FluentWindow
{
    private readonly Config _cfg;
    public ObservableCollection<AppEntry> Apps { get; }
    public event EventHandler? ConfigChanged;

    public SettingsWindow(Config cfg)
    {
        InitializeComponent();
        _cfg = cfg;
        Apps = new ObservableCollection<AppEntry>(cfg.TunneledApps);
        AppList.ItemsSource = Apps;
    }

    private void AddAppBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            // Default to All files so .ark, .com, repackaged executables etc.
            // can be registered too. Games sometimes ship binaries under custom
            // extensions (Lost Ark's LOSTARKWeb64.ark for the in-game browser
            // is a common case).
            Filter = "All files (*.*)|*.*|Executables (*.exe)|*.exe",
            Title = "Pick the file to tunnel",
        };
        if (dlg.ShowDialog(this) != true) return;

        var entry = new AppEntry
        {
            DisplayName = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName),
            ExePath = Config.NormalizeAppPath(dlg.FileName),
        };
        if (Apps.Any(app => string.Equals(Config.NormalizeAppPath(app.ExePath), entry.ExePath, StringComparison.OrdinalIgnoreCase)))
        {
            AppList.SelectedItem = Apps.First(app => string.Equals(app.ExePath, entry.ExePath, StringComparison.OrdinalIgnoreCase));
            return;
        }
        Apps.Add(entry);
        Persist();
    }

    private void RemoveApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string id) return;
        var entry = Apps.FirstOrDefault(a => a.Id == id);
        if (entry is null) return;
        Apps.Remove(entry);
        Persist();
    }

    private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();

    private void Persist()
    {
        try
        {
            _cfg.TunneledApps = Apps.ToList();
            _cfg.Save();
            ConfigChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Settings were not saved:\n{ex.Message}", "Save error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
