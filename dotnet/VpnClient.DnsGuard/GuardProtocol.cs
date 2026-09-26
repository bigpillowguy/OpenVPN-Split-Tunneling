namespace VpnClient.DnsGuard;

internal static class GuardProtocol
{
    // A completed historical lease does not own today's release acknowledgement.
    // The caller must first reject every foreign non-complete or pending lease.
    internal static GuardResult ReleaseResult(Guid requested, GuardResult recovered) =>
        recovered.Status == "off" ? recovered with { Lease = requested } : recovered;

    internal static bool MaintenanceAllowed(ProcessIdentity? existing, ProcessIdentity? requested,
        Func<ProcessIdentity, bool> alive) => existing is null || existing == requested || !alive(existing);

    internal static bool UninstalledNoOp(bool serviceRegistered, GuardJournal? journal, ProcessIdentity? maintenance) =>
        !serviceRegistered && (journal is null || journal.Phase == "complete") && maintenance is null;
}
