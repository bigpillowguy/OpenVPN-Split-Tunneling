using System.Windows;
using System;
using System.Security.Principal;
using System.Threading;
using System.Diagnostics;

namespace VpnClient.Ui;

public partial class App : Application
{
    public static VpnConnector Connector { get; } = new VpnConnector();
    internal static ExperimentalDnsController ExperimentalDns { get; } = CreateDnsController();
    private static ExperimentalDnsController CreateDnsController()
    {
        using var owner = Process.GetCurrentProcess();
        return new(new DnsGuardClient(AppContext.BaseDirectory), new(checked((uint)owner.Id), checked((ulong)owner.StartTime.ToFileTimeUtc())), new RedirectorDnsControlClient());
    }
    private Mutex? _instance;
    private bool _ownsInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        _instance = new Mutex(false, @"Global\VpnClient.Ui." + WindowsIdentity.GetCurrent().User!.Value);
        try { _ownsInstance = _instance.WaitOne(0); }
        catch (AbandonedMutexException) { _ownsInstance = true; }
        if (!_ownsInstance)
        {
            MessageBox.Show("This user already has a VPN client running.", "VPN client", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }
        try
        {
            JobManager.Initialize();
            SessionSecrets.CleanupLegacyCredentials();
            var config = Config.Load();
            if (config.LoadWarning is { } warning)
            {
                MessageBox.Show(warning, "Configuration recovery", MessageBoxButton.OK, MessageBoxImage.Warning);
                // Backend reads the primary JSON. Persist a recovered backup before starting it;
                // unrecoverable input refuses Save and leaves the original file untouched.
                config.Save();
            }
            Redirector.Start(config.ExperimentalSplitDns);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"The VPN backend could not start:\n{ex.Message}", "Startup error", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsInstance)
        {
            JobManager.Close();
            Redirector.Dispose();
            _instance!.ReleaseMutex();
        }
        _instance?.Dispose();
        base.OnExit(e);
    }
}
