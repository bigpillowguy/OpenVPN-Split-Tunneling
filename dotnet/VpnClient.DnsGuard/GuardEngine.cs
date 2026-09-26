using System.Text.Json.Serialization;

namespace VpnClient.DnsGuard;

public sealed record ProcessIdentity(uint Pid, ulong Created);
public sealed record LeaseRequest(Guid Lease, ProcessIdentity Owner, ProcessIdentity Backend);
public sealed record RegistryState(string ImagePath, uint Type);
public sealed record GuardJournal(int Version, LeaseRequest Request, RegistryState Original, string StubImage,
    string Phase, string Reason = "none");
public sealed record GuardResult(int Version, string Status, Guid? Lease, string Reason, string? Message = null)
{
    public static GuardResult Of(string status, Guid? lease = null, string reason = "none") => new(1, status, lease, reason);
    [JsonIgnore] public int ExitCode => Status switch { "unsupported" => 2, "busy" => 3, "recoveryRequired" => 4, _ => 0 };
}
public sealed class GuardException(string reason, bool unsupported = false) : Exception(reason)
{
    public string Reason { get; } = reason;
    public bool Unsupported { get; } = unsupported;
}

public interface IGuardJournalStore
{
    GuardJournal? Read();
    void Write(GuardJournal value);
}
public interface IGuardProcess : IDisposable { bool Alive { get; } }
public interface IGuardPlatform
{
    RegistryState ReadRegistry();
    void SetImage(RegistryState expected, string image);
    void SetType(RegistryState expected, uint type);
    string StubImage(Guid lease);
    // Returns a retained handle only after all platform isolation/trust checks pass.
    IGuardProcess InspectOriginal(RegistryState original);
    IGuardProcess OpenOwner(ProcessIdentity identity, bool backend);
    void RecheckOriginal(IGuardProcess process, RegistryState original);
    void TerminateOriginal(IGuardProcess process);
    void StartAndConfirmStub(GuardJournal journal);
    bool IsConfirmedStub(GuardJournal journal);
    // May stop only an exactly verified, retained instance of our own stub.
    void RestoreOriginalService(GuardJournal journal);
}

/// <summary>Original implementation. No PIA code is incorporated. All machine operations are injectable.</summary>
public sealed class GuardEngine(IGuardPlatform platform, IGuardJournalStore store)
{
    public GuardResult Activate(LeaseRequest request, Func<bool> stopRequested)
    {
        IGuardProcess? originalProcess = null;
        IGuardProcess? owner = null;
        IGuardProcess? backend = null;
        bool wroteJournal = false;
        try
        {
            var previous = store.Read();
            if (previous is not null && previous.Phase != "complete")
                return GuardResult.Of("busy", previous.Request.Lease, "existing_lease");
            owner = platform.OpenOwner(request.Owner, false);
            backend = platform.OpenOwner(request.Backend, true);
            var original = platform.ReadRegistry();
            originalProcess = platform.InspectOriginal(original);
            var journal = new GuardJournal(1, request, original, platform.StubImage(request.Lease), "prepared");
            // Durable write precedes either registry mutation. A failed write performs no machine mutation.
            store.Write(journal);
            wroteJournal = true;
            CheckLive();
            platform.SetImage(original, journal.StubImage);
            journal = Save(journal, "image_changed");
            platform.SetType(new(journal.StubImage, original.Type), 0x10);
            journal = Save(journal, "configuration_changed");
            CheckLive();
            platform.RecheckOriginal(originalProcess, original);
            if (platform.ReadRegistry() != new RegistryState(journal.StubImage, 0x10)) throw new GuardException("registry_conflict");
            platform.TerminateOriginal(originalProcess);
            journal = Save(journal, "original_exited");
            CheckLive();
            platform.StartAndConfirmStub(journal);
            journal = Save(journal, "stub_running");
            RestoreRegistry(journal);
            journal = Save(journal, "registry_restored");
            CheckLive();
            if (!platform.IsConfirmedStub(journal)) throw new GuardException("stub_not_running");
            Save(journal, "active");
            return GuardResult.Of("active", request.Lease);

            void CheckLive()
            {
                if (stopRequested() || !owner.Alive || !backend.Alive) throw new GuardException("owner_ended");
            }
        }
        catch (Exception ex)
        {
            string reason = Reason(ex);
            if (wroteJournal)
            {
                var restored = Restore();
                if (restored.Status != "off") return restored;
            }
            return GuardResult.Of(ex is GuardException { Unsupported: true } ? "unsupported" : "recoveryRequired",
                request.Lease, reason);
        }
        finally { originalProcess?.Dispose(); owner?.Dispose(); backend?.Dispose(); }
    }

    public GuardResult Restore()
    {
        GuardJournal? journal = null;
        try
        {
            journal = store.Read();
            if (journal is null || journal.Phase == "complete") return GuardResult.Of("off", journal?.Request.Lease);
            // The original durable write already contains everything recovery
            // needs. A full disk must not prevent restoring system DNS settings.
            try { journal = Save(journal, "restoring"); } catch { }
            RestoreRegistry(journal);
            platform.RestoreOriginalService(journal);
            Save(journal, "complete");
            return GuardResult.Of("off", journal.Request.Lease);
        }
        catch (Exception ex)
        {
            if (journal is not null)
            {
                try { store.Write(journal with { Phase = "recovery_required", Reason = Reason(ex) }); } catch { }
            }
            return GuardResult.Of("recoveryRequired", journal?.Request.Lease, Reason(ex));
        }
    }

    public GuardResult Inspect()
    {
        try
        {
            var journal = store.Read();
            if (journal is null || journal.Phase == "complete") return GuardResult.Of("off", journal?.Request.Lease);
            if (journal.Phase == "active")
            {
                using var owner = platform.OpenOwner(journal.Request.Owner, false);
                using var backend = platform.OpenOwner(journal.Request.Backend, true);
                if (!owner.Alive || !backend.Alive) return GuardResult.Of("recoveryRequired", journal.Request.Lease, "owner_ended");
                if (platform.ReadRegistry() != journal.Original || !platform.IsConfirmedStub(journal))
                    return GuardResult.Of("recoveryRequired", journal.Request.Lease, "active_state_changed");
                return GuardResult.Of("active", journal.Request.Lease);
            }
            return GuardResult.Of(journal.Phase == "recovery_required" ? "recoveryRequired" :
                journal.Phase == "restoring" ? "restoring" : "preparing", journal.Request.Lease, journal.Reason);
        }
        catch (Exception ex) { return GuardResult.Of("recoveryRequired", reason: Reason(ex)); }
    }

    private GuardJournal Save(GuardJournal journal, string phase)
    {
        var updated = journal with { Phase = phase, Reason = "none" };
        store.Write(updated);
        return updated;
    }
    private void RestoreRegistry(GuardJournal journal)
    {
        var current = platform.ReadRegistry();
        if ((current.ImagePath != journal.Original.ImagePath && current.ImagePath != journal.StubImage) ||
            (current.Type != journal.Original.Type && current.Type != 0x10))
            throw new GuardException("registry_conflict");
        if (current.ImagePath != journal.Original.ImagePath)
        {
            platform.SetImage(current, journal.Original.ImagePath);
            current = new(journal.Original.ImagePath, current.Type);
        }
        if (current.Type != journal.Original.Type) platform.SetType(current, journal.Original.Type);
        if (platform.ReadRegistry() != journal.Original) throw new GuardException("registry_conflict");
    }
    internal static string Reason(Exception ex) => ex is GuardException known ? known.Reason :
        ex is UnauthorizedAccessException ? "access_denied" : ex is IOException ? "storage_failed" : "operation_failed";
}
