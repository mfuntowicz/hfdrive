using HfDrive.Desktop.ViewModels;
using HfDrive.Protocol;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>
/// Regression tests for the tray's "everything is up to date" readiness logic,
/// compiled from the same <c>TraySyncReadiness.cs</c> source the tray ships.
/// These cover the consumer-visible contract: a truly caught-up read-only or
/// multi-device account may celebrate, while active/failed work in a
/// non-selected drive, uninspected activity pages, activity failure or
/// staleness, missing baselines/features/accounts and paused/error/dirty
/// states can never celebrate.
/// </summary>
public sealed class TraySyncReadinessTests
{
    private static readonly Guid DriveA = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly Guid DriveB = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid Baseline = Guid.Parse("aaaaaaa0-0000-4000-8000-000000000001");
    private static readonly Guid BaselineB = Guid.Parse("aaaaaaa0-0000-4000-8000-000000000002");

    private const long SessionGeneration = 7;

    /// <summary>Builds one connection status; nullable commit fields are the real DTO fields.</summary>
    private static ConnectionStatus Drive(
        Guid connectionId,
        Guid? observed,
        Guid? applied,
        Guid? published,
        ConnectionMode mode = ConnectionMode.Writable,
        CapabilityState capability = CapabilityState.Writable,
        ConnectionState state = ConnectionState.UpToDate,
        int pending = 0,
        int dirty = 0,
        int conflicts = 0,
        ProtocolError? lastError = null) => new()
    {
        ConnectionId = connectionId,
        WorkspaceId = Guid.NewGuid(),
        Owner = new Owner
        {
            OwnerKind = OwnerKind.Personal,
            OwnerId = "owner",
            Namespace = "owner-ns",
            DisplayName = "Owner",
            Restrictions = Array.Empty<string>(),
            CanCreate = false,
        },
        Bucket = new Bucket
        {
            BucketId = "bucket-id",
            Name = "bucket",
            Namespace = "owner-ns",
            Visibility = Visibility.Private,
        },
        Prefix = "hfdrive/workspace",
        RootPath = $@"C:\sync\{connectionId:N}",
        Mode = mode,
        Capability = capability,
        State = state,
        Pin = PinState.Unpinned,
        Hydration = HydrationState.Full,
        ObservedCommit = observed,
        AppliedCommit = applied,
        PublishedCommit = published,
        PendingFiles = pending,
        DirtyFiles = dirty,
        ConflictFiles = conflicts,
        OnlineOnlyFiles = 0,
        PinnedFiles = 0,
        PendingUploadBytes = 0,
        LocalBytes = 0,
        StagingUsedBytes = 0,
        RangeCacheUsedBytes = 0,
        TransferMemoryUsedBytes = 0,
        LastError = lastError,
        UpdatedAt = "2026-01-01T00:00:00Z",
    };

    /// <summary>A fully up-to-date writable drive that published its own baseline.</summary>
    private static ConnectionStatus CaughtUpDrive(Guid connectionId) =>
        Drive(connectionId, Baseline, Baseline, Baseline);

    /// <summary>Evidence bag whose probes are recorded as accepted <c>list_activity</c> outcomes.</summary>
    private static TraySyncEvidence Evidence(
        TrayActivityProbe[] probes,
        bool featureAvailable = true,
        bool sessionMatches = true,
        bool acceptedStatus = true,
        AuthenticationState account = AuthenticationState.SignedIn)
    {
        var evidence = new TraySyncEvidence
        {
            HasAcceptedStatus = acceptedStatus,
            AccountState = account,
            SessionGeneration = SessionGeneration,
            SessionMatches = sessionMatches,
            ActivityFeatureAvailable = featureAvailable,
        };
        foreach (TrayActivityProbe probe in probes)
        {
            evidence.SetActivityProbe(probe);
        }
        return evidence;
    }

    private static TrayActivityProbe Idle(Guid connectionId, long generation = SessionGeneration) =>
        new(connectionId, generation, hasItems: false, hasMore: false);

    private static TrayActivityProbe Work(Guid connectionId, long generation = SessionGeneration) =>
        new(connectionId, generation, hasItems: true, hasMore: false);

    private static TrayActivityProbe MorePages(Guid connectionId, long generation = SessionGeneration) =>
        new(connectionId, generation, hasItems: false, hasMore: true);

    // ── The celebration is allowed for genuinely caught-up accounts ──────

    [Fact]
    public void ReadOnlyDriveMayCelebrate()
    {
        // A read-only drive never publishes; PublishedCommit stays null.
        var connection = Drive(DriveA, Baseline, Baseline, published: null,
            mode: ConnectionMode.ReadOnly, capability: CapabilityState.ReadOnly);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Idle(DriveA) }));

        Assert.True(result.Ready);
        Assert.Equal(TrayReadinessFailure.None, result.Failure);
        Assert.True(TraySyncReadiness.IsAllSynced(new[] { connection }, Evidence(new[] { Idle(DriveA) })));
    }

    [Fact]
    public void RemoteDeviceCommitMayCelebrateWithoutLocalPublication()
    {
        // Fully caught up with another device's commit: this device never
        // published it, so PublishedCommit is null while observed == applied.
        var connection = Drive(DriveA, Baseline, Baseline, published: null);

        Assert.True(TraySyncReadiness.Evaluate(new[] { connection }, Evidence(new[] { Idle(DriveA) })).Ready);
    }

    [Fact]
    public void OlderPublishedCommitDoesNotBlock()
    {
        var connection = Drive(DriveA, Baseline, Baseline, BaselineB);

        Assert.True(TraySyncReadiness.Evaluate(new[] { connection }, Evidence(new[] { Idle(DriveA) })).Ready);
    }

    [Fact]
    public void MultipleDrivesWithIdleProbesCelebrate()
    {
        var driveA = CaughtUpDrive(DriveA);
        var driveB = Drive(DriveB, BaselineB, BaselineB, published: null,
            mode: ConnectionMode.ReadOnly, capability: CapabilityState.ReadOnly);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { driveA, driveB }, Evidence(new[] { Idle(DriveA), Idle(DriveB) }));

        Assert.True(result.Ready);
    }

    // ── Active or failed work in a non-selected drive blocks ─────────────

    [Fact]
    public void ActiveWorkInAnyDriveBlocksEvenWhenThatDriveIsNotSelected()
    {
        var driveA = CaughtUpDrive(DriveA);
        var driveB = Drive(DriveB, BaselineB, BaselineB, BaselineB);

        // Readiness is evaluated per configured connection and knows nothing
        // about the displayed selection: drive B's active work blocks the
        // celebration regardless of which connection the activity list pages.
        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { driveA, driveB }, Evidence(new[] { Idle(DriveA), Work(DriveB) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.WorkRecorded, result.Failure);
        Assert.Equal(DriveB, result.ConnectionId);
    }

    [Fact]
    public void FailedWorkRecordBlocks()
    {
        // A single non-empty record (the failed row the provider retains) is
        // unfinished/failed work: an empty probe page is the only idle proof.
        var connection = CaughtUpDrive(DriveA);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Work(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.WorkRecorded, result.Failure);
    }

    // ── Uninspected pages are never idle ─────────────────────────────────

    [Fact]
    public void ContinuationCursorBlocksEvenOnEmptyFirstPage()
    {
        var connection = CaughtUpDrive(DriveA);

        // A bounded probe that returned no record but a continuation cursor has
        // uninspected pages; that is unproven, not idle.
        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { MorePages(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.WorkRecorded, result.Failure);
    }

    [Fact]
    public void OnlyAFullEmptyProbeProvesIdle()
    {
        Assert.True(TraySyncReadiness.IsIdleProbe(Idle(DriveA)));
        Assert.False(TraySyncReadiness.IsIdleProbe(Work(DriveA)));
        Assert.False(TraySyncReadiness.IsIdleProbe(MorePages(DriveA)));
    }

    // ── Activity failure, staleness and missing evidence block ───────────

    [Fact]
    public void MissingActivityEvidenceBlocks()
    {
        var driveA = CaughtUpDrive(DriveA);
        var driveB = Drive(DriveB, BaselineB, BaselineB, BaselineB);

        // Drive B has no probe at all (its query failed, or it was never
        // asked): unknown is never idle.
        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { driveA, driveB }, Evidence(new[] { Idle(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.ActivityUnknown, result.Failure);
        Assert.Equal(DriveB, result.ConnectionId);
    }

    [Fact]
    public void ActivityFailureDropsEvidenceAndBlocks()
    {
        var connection = CaughtUpDrive(DriveA);

        // A cancelled/never-issued probe leaves no evidence: unknown is never idle.
        TrayReadinessResult unknown = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(Array.Empty<TrayActivityProbe>()));
        Assert.False(unknown.Ready);
        Assert.Equal(TrayReadinessFailure.ActivityUnknown, unknown.Failure);

        // A failed probe is an explicit failure, never stale success.
        TrayReadinessResult failed = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { TrayActivityProbe.FailedProbe(DriveA, SessionGeneration) }));
        Assert.False(failed.Ready);
        Assert.Equal(TrayReadinessFailure.ActivityFailed, failed.Failure);
    }

    [Fact]
    public void StaleSessionEvidenceBlocks()
    {
        var connection = CaughtUpDrive(DriveA);

        // A probe from a previous provider session is stale success and must
        // never be reused.
        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA) }, sessionMatches: false));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.SessionChanged, result.Failure);
    }

    [Fact]
    public void ProbeFromAnotherSessionGenerationBlocks()
    {
        var connection = CaughtUpDrive(DriveA);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA, generation: SessionGeneration + 1) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.ActivityStale, result.Failure);
    }

    [Fact]
    public void MissingFeatureBlocks()
    {
        var connection = CaughtUpDrive(DriveA);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA) }, featureAvailable: false));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.FeatureUnavailable, result.Failure);
    }

    [Fact]
    public void MissingAccountOrStatusBlocks()
    {
        var connection = CaughtUpDrive(DriveA);

        TrayReadinessResult signedOut = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA) }, account: AuthenticationState.SignedOut));
        Assert.False(signedOut.Ready);
        Assert.Equal(TrayReadinessFailure.AccountNotSignedIn, signedOut.Failure);

        TrayReadinessResult needsSignIn = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA) }, account: AuthenticationState.NeedsSignIn));
        Assert.False(needsSignIn.Ready);
        Assert.Equal(TrayReadinessFailure.AccountNotSignedIn, needsSignIn.Failure);

        TrayReadinessResult noStatus = TraySyncReadiness.Evaluate(
            new[] { connection },
            Evidence(new[] { Idle(DriveA) }, acceptedStatus: false));
        Assert.False(noStatus.Ready);
        Assert.Equal(TrayReadinessFailure.StatusUnavailable, noStatus.Failure);

        TrayReadinessResult noConnections = TraySyncReadiness.Evaluate(
            Array.Empty<ConnectionStatus>(), Evidence(new[] { Idle(DriveA) }));
        Assert.False(noConnections.Ready);
        Assert.Equal(TrayReadinessFailure.NoConnections, noConnections.Failure);
    }

    // ── Missing baseline and unhealthy connection states block ───────────

    [Fact]
    public void MissingBaselineBlocks()
    {
        var noObserved = Drive(DriveA, observed: null, applied: Baseline, published: null);
        Assert.Equal(TrayReadinessFailure.MissingBaseline,
            TraySyncReadiness.Evaluate(new[] { noObserved }, Evidence(new[] { Idle(DriveA) })).Failure);

        var noApplied = Drive(DriveA, observed: Baseline, applied: null, published: null);
        Assert.Equal(TrayReadinessFailure.MissingBaseline,
            TraySyncReadiness.Evaluate(new[] { noApplied }, Evidence(new[] { Idle(DriveA) })).Failure);
    }

    [Fact]
    public void UnappliedObservedCommitBlocks()
    {
        var connection = Drive(DriveA, Baseline, BaselineB, Baseline);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Idle(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.NotUpToDate, result.Failure);
    }

    [Theory]
    [InlineData(ConnectionState.PendingUpload)]
    [InlineData(ConnectionState.Uploading)]
    [InlineData(ConnectionState.PublishingChanges)]
    [InlineData(ConnectionState.Downloading)]
    [InlineData(ConnectionState.Offline)]
    [InlineData(ConnectionState.NeedsSignIn)]
    [InlineData(ConnectionState.StorageSetupRequired)]
    [InlineData(ConnectionState.PermissionDenied)]
    [InlineData(ConnectionState.Conflict)]
    [InlineData(ConnectionState.DiskFull)]
    [InlineData(ConnectionState.WriteSyncPaused)]
    public void PausedOrErroredStateBlocks(ConnectionState state)
    {
        var connection = Drive(DriveA, Baseline, Baseline, Baseline, state: state);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Idle(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.NotUpToDate, result.Failure);
    }

    [Fact]
    public void UnhealthyCapabilityBlocks()
    {
        var paused = Drive(DriveA, Baseline, Baseline, Baseline,
            capability: CapabilityState.WriteSyncPaused, state: ConnectionState.WriteSyncPaused);
        Assert.Equal(TrayReadinessFailure.NotUpToDate,
            TraySyncReadiness.Evaluate(new[] { paused }, Evidence(new[] { Idle(DriveA) })).Failure);

        var setupRequired = Drive(DriveA, Baseline, Baseline, Baseline,
            capability: CapabilityState.StorageSetupRequired, state: ConnectionState.StorageSetupRequired);
        Assert.Equal(TrayReadinessFailure.NotUpToDate,
            TraySyncReadiness.Evaluate(new[] { setupRequired }, Evidence(new[] { Idle(DriveA) })).Failure);
    }

    [Fact]
    public void ConnectionErrorBlocks()
    {
        var connection = Drive(DriveA, Baseline, Baseline, Baseline,
            lastError: new ProtocolError { Code = ProtocolErrorCode.PermissionDenied, Message = "denied" });

        Assert.Equal(TrayReadinessFailure.NotUpToDate,
            TraySyncReadiness.Evaluate(new[] { connection }, Evidence(new[] { Idle(DriveA) })).Failure);
    }

    [Theory]
    [InlineData(3, 0, 0)]
    [InlineData(0, 2, 0)]
    [InlineData(0, 0, 1)]
    public void PendingDirtyOrConflictCountsBlock(int pending, int dirty, int conflicts)
    {
        var connection = Drive(DriveA, Baseline, Baseline, Baseline,
            pending: pending, dirty: dirty, conflicts: conflicts);

        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Idle(DriveA) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.UnfinishedWork, result.Failure);
    }

    [Fact]
    public void EvidenceForAnUnknownConnectionNeverSatisfiesAnotherDrive()
    {
        var connection = CaughtUpDrive(DriveA);

        // Evidence recorded for a connection that is no longer configured does
        // not satisfy the configured connection's probe requirement.
        TrayReadinessResult result = TraySyncReadiness.Evaluate(
            new[] { connection }, Evidence(new[] { Idle(DriveB) }));

        Assert.False(result.Ready);
        Assert.Equal(TrayReadinessFailure.ActivityUnknown, result.Failure);
        Assert.Equal(DriveA, result.ConnectionId);
    }
}
