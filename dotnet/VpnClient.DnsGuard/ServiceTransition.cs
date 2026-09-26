namespace VpnClient.DnsGuard;

internal enum ServiceTransitionState { Stopped, Pending, ExpectedRunning, UnexpectedRunning, OwnedReplacementRunning }

internal static class ServiceTransition
{
    // SCM failure actions can skip the observable STOPPED interval entirely.
    // The required postcondition is the verified running identity, not a sampled
    // sequence of status values. Never terminate an unexpected running instance.
    internal static void EnsureRunning(Func<ServiceTransitionState> observe, Action start,
        Action pause, Func<TimeSpan> elapsed, string stage, TimeSpan timeout, Func<bool>? stopOwned = null)
    {
        bool started = false;
        bool stoppedOwned = false;
        while (true)
        {
            switch (observe())
            {
                case ServiceTransitionState.ExpectedRunning: return;
                case ServiceTransitionState.UnexpectedRunning:
                    throw new GuardException(stage + "_identity_mismatch");
                case ServiceTransitionState.OwnedReplacementRunning:
                    if (stopOwned is null) throw new GuardException(stage + "_identity_mismatch");
                    if (!stoppedOwned) stoppedOwned = stopOwned();
                    break;
                case ServiceTransitionState.Stopped:
                    if (started) throw new GuardException(stage + "_stopped");
                    start(); started = true;
                    break;
            }
            if (elapsed() >= timeout) throw new GuardException(stage + "_timeout");
            pause();
        }
    }
}
