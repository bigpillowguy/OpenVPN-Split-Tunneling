namespace VpnClient.DnsGuard;

internal sealed record RestartAction(uint Type, uint Delay);
internal sealed record RecoverySettings(uint ResetSeconds, RestartAction[] Actions, bool NonCrash,
    bool HasCommand = false, bool HasRebootMessage = false)
{
    internal bool Required => ResetSeconds == 86400 && NonCrash && !HasCommand && !HasRebootMessage &&
        Actions.SequenceEqual(new[] { new RestartAction(1, 1000), new RestartAction(1, 60000), new RestartAction(1, 60000) });
}
internal interface IRecoverySettings
{
    void VerifyOwnership();
    RecoverySettings Read();
    void ConfigureRequired();
}
internal static class RecoveryPolicy
{
    internal static void Ensure(IRecoverySettings service)
    {
        service.VerifyOwnership();
        if (!service.Read().Required) service.ConfigureRequired();
        // Existing services may have survived a crash between CreateService and
        // ChangeServiceConfig2. Never infer recovery policy from base configuration.
        service.VerifyOwnership();
        if (!service.Read().Required) throw new GuardException("guardian_recovery_configuration_failed");
    }
}
