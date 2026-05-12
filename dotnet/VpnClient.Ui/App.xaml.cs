using System.Windows;

namespace VpnClient.Ui;

public partial class App : Application
{
    public static VpnConnector Connector { get; } = new VpnConnector();

    protected override void OnStartup(StartupEventArgs e)
    {
        // 1. Kill any redirector/openvpn left behind by a previous UI
        //    session that didn't have the job-object teardown.
        // 2. Start a fresh redirector and lift it into the UI's job so
        //    it dies with us — clean exit or crash.
        // Failure is silent; the UI will surface "Disconnected from
        //    redirector" in the header if step 2 fails.
        Redirector.KillOrphans();
        Redirector.TryStart();
        base.OnStartup(e);
    }
}
