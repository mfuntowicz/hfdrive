using HfDrive.Desktop.ViewModels;
using HfDrive.Protocol;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>
/// Regression tests for the tray's issues/status projection, compiled from the
/// same <c>TrayIssueProjection.cs</c> source the tray ships. These cover the
/// consumer-visible contract: a failed history authorization followed by a
/// successful empty conflicts page must never read "No sync issues"; a recorded
/// connection error stays visible (even for a generic message) until a fresh
/// status drops it; a fresh success clears only its own request's error; a
/// superseded request's late success or failure is dead on arrival, so an
/// older in-flight page never erases a newer failure (or the reverse) in the
/// same session/connection; one
/// observed error is never shown on duplicate cards; permission guidance comes
/// from the typed error code, never from parsing message text; issue rows carry
/// only real conflict ids and navigate to the Connections/Operations surfaces;
/// and an empty activity queue while sync is blocked never looks healthy.
/// </summary>
public sealed class TrayIssueProjectionTests
{
    private static readonly Guid DriveA = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly Guid DriveB = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid DriveC = Guid.Parse("33333333-3333-4333-8333-333333333333");
    private static readonly Guid ConflictId = Guid.Parse("ccccccc0-0000-4000-8000-000000000001");

    private const long SessionGeneration = 7;

    /// <summary>Builds one connection status; nullable fields are the real DTO fields.</summary>
    private static ConnectionStatus Drive(
        Guid connectionId,
        ConnectionState state = ConnectionState.UpToDate,
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
        Mode = ConnectionMode.Writable,
        Capability = CapabilityState.Writable,
        State = state,
        Pin = PinState.Unpinned,
        Hydration = HydrationState.Full,
        PendingFiles = 0,
        DirtyFiles = 0,
        ConflictFiles = 0,
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

    private static ConflictRecord Conflict(string name, ConflictResolution resolution = ConflictResolution.Unresolved) => new()
    {
        ConflictId = ConflictId,
        ItemId = Guid.NewGuid(),
        Kind = ConflictKind.Content,
        OriginalNames = new[] { name },
        DetectedAt = "2026-01-01T00:00:00Z",
        ResolutionState = resolution,
    };

    private static ActivityRecord FailedTransfer(Guid connectionId, string name, ProtocolError? error = null) => new()
    {
        ActivityId = Guid.NewGuid(),
        ConnectionId = connectionId,
        ItemName = name,
        Direction = ActivityDirection.Upload,
        Phase = ActivityPhase.Failed,
        BytesCompleted = 0,
        StartedAt = "2026-01-01T00:00:00Z",
        LastError = error,
    };

    private static TrayObservedError Error(ProtocolErrorCode? code, string message) =>
        new() { Code = code, Message = message };

    /// <summary>Issues one request for the drive and records its failure.</summary>
    private static TrayRequestStamp FailedRequest(
        TrayRequestErrorLog log, TrayRequestKind kind, TrayObservedError error, long generation = SessionGeneration)
    {
        TrayRequestStamp stamp = log.BeginRequest(DriveA, kind, generation);
        log.RecordFailure(stamp, error);
        return stamp;
    }

    /// <summary>Issues one request for the drive and accepts its fresh success.</summary>
    private static TrayRequestStamp SuccessfulRequest(
        TrayRequestErrorLog log, TrayRequestKind kind, long generation = SessionGeneration)
    {
        TrayRequestStamp stamp = log.BeginRequest(DriveA, kind, generation);
        log.ClearFreshSuccess(stamp);
        return stamp;
    }

    /// <summary>The exact projection the tray performs for one selection.</summary>
    private static IReadOnlyList<TrayIssueRow> Issues(
        TrayRequestErrorLog log,
        ConnectionStatus[] connections,
        ConflictRecord[]? conflicts = null,
        ActivityRecord[]? activities = null) =>
        TrayIssueProjection.Build(
            connections,
            log,
            SessionGeneration,
            conflicts ?? Array.Empty<ConflictRecord>(),
            activities ?? Array.Empty<ActivityRecord>(),
            connections.FirstOrDefault()?.ConnectionId);

    // ── The reported bug: failed history + empty conflicts stays an issue ──

    [Fact]
    public void FailedHistoryAuthorizationWithEmptyConflictsIsStillAnIssue()
    {
        var connection = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History,
            TrayObservedError.FromException(new ProtocolException(ProtocolErrorCode.PermissionDenied, "storage access denied")));

        // The conflicts request then succeeds with an empty page: it must not
        // erase the history authorization failure or claim "No sync issues".
        SuccessfulRequest(log, TrayRequestKind.Conflicts);

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        TrayIssueRow issue = Assert.Single(rows);

        Assert.Equal(TrayIssueKind.Connection, issue.Kind);
        Assert.Contains("recent changes", issue.Detail);
        Assert.Contains("bucket permissions and storage access keys", issue.Detail);
        Assert.Contains("storage access denied", issue.Detail);
        Assert.Equal("connections", issue.SectionTag);
        Assert.Equal(DriveA, issue.ConnectionId);
        Assert.Null(issue.ConflictId);
    }

    [Fact]
    public void RecordedConnectionErrorIsVisibleEvenWhenStateIsUpToDate()
    {
        // A generic recorded connection failure (no typed code) must remain
        // visible verbatim even though the state reads up to date and every
        // listing request recovered.
        var connection = Drive(DriveA, lastError: new ProtocolError
        {
            Code = ProtocolErrorCode.Internal,
            Message = "storage backend rejected the request",
        });
        var log = new TrayRequestErrorLog();
        SuccessfulRequest(log, TrayRequestKind.Activity);
        SuccessfulRequest(log, TrayRequestKind.History);
        SuccessfulRequest(log, TrayRequestKind.Conflicts);

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        TrayIssueRow issue = Assert.Single(rows);

        Assert.Equal(TrayIssueKind.Connection, issue.Kind);
        Assert.Contains("storage backend rejected the request", issue.Detail);
        Assert.Contains("The provider recorded an error", issue.Detail);
        Assert.Equal("connections", issue.SectionTag);
    }

    // ── Recovery clears only its own error ─────────────────────────────────

    [Fact]
    public void FreshSuccessClearsOnlyItsOwnErrorAndNotUnrelatedFailures()
    {
        var connection = Drive(DriveA, lastError: new ProtocolError
        {
            Code = ProtocolErrorCode.Internal,
            Message = "backend error",
        });
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History, Error(ProtocolErrorCode.PermissionDenied, "history denied"));
        FailedRequest(log, TrayRequestKind.Conflicts, Error(ProtocolErrorCode.Timeout, "conflicts timed out"));

        // Conflicts recover: only the conflicts error disappears.
        SuccessfulRequest(log, TrayRequestKind.Conflicts);
        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        Assert.Equal(2, rows.Count);
        Assert.DoesNotContain(rows, row => row.Detail.Contains("conflicts timed out"));
        Assert.Contains(rows, row => row.Detail.Contains("history denied"));
        Assert.Contains(rows, row => row.Detail.Contains("backend error"));

        // History recovers: only the history error disappears; the recorded
        // connection error is unrelated and stays until a fresh status drops it.
        SuccessfulRequest(log, TrayRequestKind.History);
        rows = Issues(log, new[] { connection });
        TrayIssueRow remaining = Assert.Single(rows);
        Assert.Contains("backend error", remaining.Detail);

        // A fresh status without the recorded error finally reports no issues.
        rows = Issues(log, new[] { Drive(DriveA) });
        Assert.Empty(rows);
    }

    [Fact]
    public void HistorySectionRecoversOnlyOnFreshSuccess()
    {
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History, Error(ProtocolErrorCode.PermissionDenied, "denied"));

        Assert.Contains("Couldn't load", TrayIssueProjection.HistoryStateText(0, responseAccepted: false, requestFailed: true));
        Assert.Equal("Loading committed history…",
            TrayIssueProjection.HistoryStateText(0, responseAccepted: false, requestFailed: false));

        SuccessfulRequest(log, TrayRequestKind.History);
        Assert.Equal("No committed changes yet.",
            TrayIssueProjection.HistoryStateText(0, responseAccepted: true, requestFailed: false));
    }

    // ── One observed error is never shown twice ────────────────────────────

    [Fact]
    public void IdenticalObservedErrorFromConnectionAndListingsIsOneCard()
    {
        var connection = Drive(DriveA, lastError: new ProtocolError
        {
            Code = ProtocolErrorCode.PermissionDenied,
            Message = "denied",
        });
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History, Error(ProtocolErrorCode.PermissionDenied, "denied"));
        FailedRequest(log, TrayRequestKind.Conflicts, Error(ProtocolErrorCode.PermissionDenied, "denied"));

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        TrayIssueRow issue = Assert.Single(rows);

        Assert.Contains("The provider recorded an error", issue.Detail);
        Assert.Contains("recent changes and issues", issue.Detail);
        Assert.Contains("bucket permissions and storage access keys", issue.Detail);
    }

    [Fact]
    public void DistinctObservedErrorsRemainSeparateCards()
    {
        var connection = Drive(DriveA, lastError: new ProtocolError { Code = ProtocolErrorCode.Internal, Message = "backend error" });
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History, Error(ProtocolErrorCode.Timeout, "timed out"));

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, row => row.Detail.Contains("backend error"));
        Assert.Contains(rows, row => row.Detail.Contains("timed out"));
    }

    // ── Session-generation freshness ───────────────────────────────────────

    [Fact]
    public void StaleSessionFailuresNeverSurfaceAndStaleSuccessNeverClears()
    {
        var connection = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        TrayRequestStamp stale = FailedRequest(log, TrayRequestKind.History, Error(null, "old session failure"), SessionGeneration - 1);

        // A failure from a previous session generation is never reported.
        Assert.Empty(Issues(log, new[] { connection }));

        // A stale success can never erase a current failure.
        FailedRequest(log, TrayRequestKind.History, Error(null, "current failure"));
        log.ClearFreshSuccess(stale);
        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        TrayIssueRow issue = Assert.Single(rows);
        Assert.Contains("current failure", issue.Detail);
    }

    // ── Superseded requests are dead (same generation and kind) ────────────

    [Fact]
    public void OlderSuccessAfterNewerFailureDoesNotEraseTheFailure()
    {
        var connection = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        TrayRequestStamp older = log.BeginRequest(DriveA, TrayRequestKind.History, SessionGeneration);
        TrayRequestStamp newer = log.BeginRequest(DriveA, TrayRequestKind.History, SessionGeneration);
        log.RecordFailure(newer, Error(ProtocolErrorCode.PermissionDenied, "denied"));
        Assert.False(log.IsCurrent(older));
        Assert.True(log.IsCurrent(newer));

        // The superseded in-flight page finally succeeds: it must not erase
        // the newer request's PermissionDenied in the same session/connection.
        log.ClearFreshSuccess(older);

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection });
        TrayIssueRow issue = Assert.Single(rows);
        Assert.Contains("denied", issue.Detail);
    }

    [Fact]
    public void OlderFailureAfterNewerSuccessIsIgnored()
    {
        var connection = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        TrayRequestStamp older = log.BeginRequest(DriveA, TrayRequestKind.History, SessionGeneration);
        TrayRequestStamp newer = log.BeginRequest(DriveA, TrayRequestKind.History, SessionGeneration);
        log.ClearFreshSuccess(newer);

        // The superseded request's late failure is dead on arrival: the newer
        // request's accepted success stands and nothing surfaces.
        log.RecordFailure(older, Error(null, "late failure"));

        Assert.Empty(Issues(log, new[] { connection }));
    }

    [Fact]
    public void RecordedFailureStaysVisibleWhileANewRequestIsPending()
    {
        var connection = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.Conflicts, Error(null, "conflicts unavailable"));

        // A retry is pending: the previous failure stays visible until the new
        // request's fresh accepted success clears it.
        TrayRequestStamp retry = log.BeginRequest(DriveA, TrayRequestKind.Conflicts, SessionGeneration);
        Assert.Contains(Issues(log, new[] { connection }), row => row.Detail.Contains("conflicts unavailable"));

        log.ClearFreshSuccess(retry);
        Assert.Empty(Issues(log, new[] { connection }));
    }

    // ── Permission wording comes from the typed code, never the message ────

    [Fact]
    public void PermissionGuidanceComesFromTheTypedCodeNotTheMessage()
    {
        var generic = Drive(DriveA, lastError: new ProtocolError
        {
            Code = ProtocolErrorCode.Internal,
            Message = "PermissionDenied: looks like a permission problem",
        });
        IReadOnlyList<TrayIssueRow> rows = Issues(new TrayRequestErrorLog(), new[] { generic });
        TrayIssueRow issue = Assert.Single(rows);
        // The generic recorded message stays visible, but no permission
        // category is inferred from its wording.
        Assert.Contains("PermissionDenied: looks like a permission problem", issue.Detail);
        Assert.DoesNotContain("storage access keys", issue.Detail);

        var typed = Drive(DriveA, lastError: new ProtocolError
        {
            Code = ProtocolErrorCode.PermissionDenied,
            Message = "denied",
        });
        rows = Issues(new TrayRequestErrorLog(), new[] { typed });
        issue = Assert.Single(rows);
        Assert.Contains("bucket permissions and storage access keys", issue.Detail);
    }

    // ── Empty activity while blocked is never presented as healthy ─────────

    [Fact]
    public void EmptyActivityQueueWhileSyncIsBlockedNeverLooksHealthy()
    {
        string blocked = TrayIssueProjection.ActivityStateText(
            featureAvailable: true, responseAccepted: true, requestFailed: false,
            activityCount: 0, activeCount: 0, syncBlocked: true);
        Assert.NotEqual("Nothing is syncing right now.", blocked);
        Assert.Contains("blocked", blocked);

        Assert.Equal("Nothing is syncing right now.", TrayIssueProjection.ActivityStateText(
            featureAvailable: true, responseAccepted: true, requestFailed: false,
            activityCount: 0, activeCount: 0, syncBlocked: false));

        // Observed counts are always retained.
        Assert.Equal("2 files and folders are transferring.", TrayIssueProjection.ActivityStateText(
            featureAvailable: true, responseAccepted: true, requestFailed: false,
            activityCount: 3, activeCount: 2, syncBlocked: true));
        Assert.Equal("1 file or folder is transferring.", TrayIssueProjection.ActivityStateText(
            featureAvailable: true, responseAccepted: true, requestFailed: false,
            activityCount: 1, activeCount: 1, syncBlocked: true));

        // A failed request is unknown work, never "nothing is syncing".
        Assert.Contains("Couldn't load", TrayIssueProjection.ActivityStateText(
            featureAvailable: true, responseAccepted: true, requestFailed: true,
            activityCount: 0, activeCount: 0, syncBlocked: false));
    }

    [Fact]
    public void SyncBlockedReflectsObservedProblemsOnly()
    {
        var healthy = Drive(DriveA);
        var log = new TrayRequestErrorLog();
        Assert.False(TrayIssueProjection.IsSyncBlocked(
            healthy, log, SessionGeneration, Array.Empty<ConflictRecord>(), Array.Empty<ActivityRecord>()));

        FailedRequest(log, TrayRequestKind.Conflicts, Error(null, "x"));
        Assert.True(TrayIssueProjection.IsSyncBlocked(
            healthy, log, SessionGeneration, Array.Empty<ConflictRecord>(), Array.Empty<ActivityRecord>()));

        SuccessfulRequest(log, TrayRequestKind.Conflicts);
        Assert.False(TrayIssueProjection.IsSyncBlocked(
            healthy, log, SessionGeneration, Array.Empty<ConflictRecord>(), Array.Empty<ActivityRecord>()));

        Assert.True(TrayIssueProjection.IsSyncBlocked(
            healthy, log, SessionGeneration, new[] { Conflict("notes.txt") }, Array.Empty<ActivityRecord>()));
        Assert.True(TrayIssueProjection.IsSyncBlocked(
            healthy, log, SessionGeneration, Array.Empty<ConflictRecord>(), new[] { FailedTransfer(DriveA, "big.bin") }));
        Assert.True(TrayIssueProjection.IsSyncBlocked(
            Drive(DriveA, state: ConnectionState.WriteSyncPaused), log, SessionGeneration,
            Array.Empty<ConflictRecord>(), Array.Empty<ActivityRecord>()));
    }

    // ── Navigation carries only real conflict ids ──────────────────────────

    [Fact]
    public void IssueRowsCarryOnlyRealConflictIds()
    {
        var connection = Drive(DriveA, lastError: new ProtocolError { Code = ProtocolErrorCode.Internal, Message = "boom" });
        var log = new TrayRequestErrorLog();
        FailedRequest(log, TrayRequestKind.History, Error(null, "listing failed"));

        IReadOnlyList<TrayIssueRow> rows = Issues(log, new[] { connection },
            conflicts: new[] { Conflict("notes.txt") },
            activities: new[] { FailedTransfer(DriveA, "big.bin") });

        TrayIssueRow conflictRow = Assert.Single(rows, row => row.ConflictId.HasValue);
        Assert.Equal(TrayIssueKind.File, conflictRow.Kind);
        Assert.Equal(ConflictId, conflictRow.ConflictId);
        Assert.Equal("operations", conflictRow.SectionTag);

        foreach (TrayIssueRow row in rows.Where(row => row != conflictRow))
        {
            Assert.Null(row.ConflictId);
            Assert.Contains(row.SectionTag, new[] { "account", "connections", "operations" });
        }

        // Connection problems land on Connections; listing/transfer problems
        // land on the Operations surface.
        Assert.Contains(rows, row => row.SectionTag == "connections");
        TrayIssueRow transferRow = Assert.Single(rows, row => row.Title.StartsWith("Couldn't sync \"big.bin\"", StringComparison.Ordinal));
        Assert.Equal(TrayIssueKind.File, transferRow.Kind);
        Assert.Contains(rows, row => row.SectionTag == "operations" && row.Detail.Contains("listing failed"));

        // A storage-access problem of a configured drive must never route into
        // the setup (Add Drive) wizard: it is managed on the Connections
        // surface of that existing connection. Sign-in still opens the account
        // surface.
        rows = Issues(new TrayRequestErrorLog(), new[]
        {
            Drive(DriveB, state: ConnectionState.StorageSetupRequired),
            Drive(DriveC, state: ConnectionState.NeedsSignIn),
        });

        TrayIssueRow storageRow = Assert.Single(rows, row => row.ConnectionId == DriveB);
        Assert.Equal("Manage storage", storageRow.ActionText);
        Assert.Equal("connections", storageRow.SectionTag);
        Assert.Null(storageRow.ConflictId);

        TrayIssueRow signInRow = Assert.Single(rows, row => row.ConnectionId == DriveC);
        Assert.Equal("Sign in", signInRow.ActionText);
        Assert.Equal("account", signInRow.SectionTag);
        Assert.Null(signInRow.ConflictId);

        // A typed storage-setup error card routes the same way, whichever
        // request observed it.
        var storageErrors = new TrayRequestErrorLog();
        FailedRequest(storageErrors, TrayRequestKind.History, Error(ProtocolErrorCode.StorageSetupRequired, "storage access keys missing"));
        rows = Issues(storageErrors, new[] { Drive(DriveA) });
        TrayIssueRow storageError = Assert.Single(rows);
        Assert.Equal("Manage storage", storageError.ActionText);
        Assert.Equal("connections", storageError.SectionTag);
        Assert.Null(storageError.ConflictId);
    }

    [Fact]
    public void IssueKindsSeparateConnectionWideAndFileFailures()
    {
        IReadOnlyList<TrayIssueRow> rows = Issues(new TrayRequestErrorLog(), new[]
        {
            Drive(DriveA, state: ConnectionState.Conflict),
            Drive(DriveB, state: ConnectionState.Offline),
        });

        TrayIssueRow conflictSummary = Assert.Single(rows, row => row.ConnectionId == DriveA);
        Assert.Equal(TrayIssueKind.File, conflictSummary.Kind);
        TrayIssueRow offline = Assert.Single(rows, row => row.ConnectionId == DriveB);
        Assert.Equal(TrayIssueKind.Connection, offline.Kind);
    }

    // ── Healthy baseline is unchanged ──────────────────────────────────────

    [Fact]
    public void HealthyConnectionWithEmptyListingsReportsNoSyncIssues()
    {
        IReadOnlyList<TrayIssueRow> rows = Issues(new TrayRequestErrorLog(), new[] { Drive(DriveA) },
            conflicts: new[] { Conflict("notes.txt", ConflictResolution.KeepLocal) });

        Assert.Empty(rows);
    }
}
