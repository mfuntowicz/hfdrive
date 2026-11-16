using HfDrive.Protocol;

namespace HfDrive.Desktop.ViewModels;

/// <summary>Why an account cannot be reported as having no unfinished work.</summary>
public enum TrayReadinessFailure
{
    /// <summary>Nothing is wrong as far as this check has observed.</summary>
    None,
    /// <summary>The provider session is not connected or has no accepted status.</summary>
    StatusUnavailable,
    /// <summary>The session has been reconnected since the evidence was gathered.</summary>
    SessionChanged,
    /// <summary>No account is signed in.</summary>
    AccountNotSignedIn,
    /// <summary>No connection is configured.</summary>
    NoConnections,
    /// <summary>A connection has no known remote baseline commit.</summary>
    MissingBaseline,
    /// <summary>A connection is not in its up-to-date, healthy capability state.</summary>
    NotUpToDate,
    /// <summary>A connection still reports pending, dirty or conflicted files.</summary>
    UnfinishedWork,
    /// <summary>The provider does not advertise the <c>list_activity</c> feature.</summary>
    FeatureUnavailable,
    /// <summary>No <c>list_activity</c> response has been accepted for a connection.</summary>
    ActivityUnknown,
    /// <summary>A <c>list_activity</c> response for a connection is stale.</summary>
    ActivityStale,
    /// <summary>A <c>list_activity</c> request failed for a connection.</summary>
    ActivityFailed,
    /// <summary>An activity record shows unfinished or failed work.</summary>
    WorkRecorded,
}

/// <summary>
/// A bounded <c>list_activity</c> probe: exactly one <c>Limit = 1</c> request.
/// Idle is proven only when the single record slot came back empty and the
/// response carries no continuation cursor, so uninspected pages can never be
/// mistaken for an idle drive. A failed request is recorded as failed, never as
/// idle; a cancelled request leaves no probe at all (unknown, not idle).
/// </summary>
public readonly record struct TrayActivityProbe
{
    /// <summary>An accepted, complete first page, or a recorded request failure.</summary>
    public TrayActivityProbe(Guid connectionId, long sessionGeneration, bool hasItems, bool hasMore, bool failed = false)
    {
        ConnectionId = connectionId;
        SessionGeneration = sessionGeneration;
        HasItems = hasItems;
        HasMore = hasMore;
        Failed = failed;
    }

    /// <summary>A probe whose <c>list_activity</c> request failed.</summary>
    public static TrayActivityProbe FailedProbe(Guid connectionId, long sessionGeneration) =>
        new(connectionId, sessionGeneration, hasItems: false, hasMore: false, failed: true);

    /// <summary>Connection this probe belongs to.</summary>
    public Guid ConnectionId { get; }

    /// <summary>Provider session generation that produced the response.</summary>
    public long SessionGeneration { get; }

    /// <summary>True when the one-record page returned a record.</summary>
    public bool HasItems { get; }

    /// <summary>True when the response carries a continuation cursor.</summary>
    public bool HasMore { get; }

    /// <summary>True when the probe request failed instead of returning a page.</summary>
    public bool Failed { get; }
}

/// <summary>
/// Pure, reusable all-synced readiness evaluation for the tray celebration.
/// Free of WinUI types so the protocol tests can exercise the exact source the
/// tray uses. Readiness requires, for every configured connection, a known
/// observed baseline that is fully applied locally plus a healthy up-to-date
/// status with zero pending/dirty/conflict counts and current no-unfinished-work
/// activity evidence. The connection's own <c>PublishedCommit</c> is this
/// device's last publication and is deliberately NOT required to match: a
/// read-only drive or a device fully caught up with another device's commit is
/// up to date without ever publishing itself.
/// </summary>
public static class TraySyncReadiness
{
    /// <summary>Size of the bounded idle probe (one record slot plus a cursor).</summary>
    public const int IdleProbeLimit = 1;

    /// <summary>
    /// True only when a single accepted <c>list_activity</c> page proves there
    /// is no work at all: the request succeeded, no records were returned and
    /// no continuation cursor points at uninspected pages. The DTO shape alone
    /// is not proof, so this probe carries the observed empty/paging result;
    /// failed and cancelled probes are never idle.
    /// </summary>
    public static bool IsIdleProbe(TrayActivityProbe probe) => !probe.Failed && !probe.HasItems && !probe.HasMore;

    /// <summary>Evaluates overall readiness; the first blocking reason found is reported.</summary>
    public static bool IsAllSynced(IReadOnlyList<ConnectionStatus> connections, TraySyncEvidence evidence) =>
        Evaluate(connections, evidence).Ready;

    /// <summary>
    /// Evaluates readiness and reports the first blocking reason, so the tray
    /// can explain instead of silently not celebrating. Evidence that belongs
    /// to a different session generation or a connection that is no longer
    /// configured is invalid and never reused.
    /// </summary>
    public static TrayReadinessResult Evaluate(IReadOnlyList<ConnectionStatus> connections, TraySyncEvidence evidence)
    {
        if (evidence is null)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.StatusUnavailable, Guid.Empty);
        }

        if (!evidence.HasAcceptedStatus)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.StatusUnavailable, Guid.Empty);
        }

        if (!evidence.SessionMatches)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.SessionChanged, Guid.Empty);
        }

        if (evidence.AccountState != AuthenticationState.SignedIn)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.AccountNotSignedIn, Guid.Empty);
        }

        if (connections is null || connections.Count == 0)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.NoConnections, Guid.Empty);
        }

        foreach (ConnectionStatus connection in connections)
        {
            TrayReadinessResult blocked = EvaluateConnection(connection);
            if (!blocked.Ready)
            {
                return blocked;
            }
        }

        if (!evidence.ActivityFeatureAvailable)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.FeatureUnavailable, Guid.Empty);
        }

        foreach (ConnectionStatus connection in connections)
        {
            TrayReadinessResult blocked = EvaluateActivity(connection.ConnectionId, evidence);
            if (!blocked.Ready)
            {
                return blocked;
            }
        }

        return new TrayReadinessResult(true, TrayReadinessFailure.None, Guid.Empty);
    }

    /// <summary>
    /// Status-level readiness for one connection: known observed baseline fully
    /// applied locally, authoritative up-to-date capability/health state and
    /// zero pending/dirty/conflict counts. <c>PublishedCommit</c> is not part of
    /// this check by design.
    /// </summary>
    public static TrayReadinessResult EvaluateConnection(ConnectionStatus connection)
    {
        if (connection.ObservedCommit is not { } observed || connection.AppliedCommit is not { } applied)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.MissingBaseline, connection.ConnectionId);
        }

        if (observed != applied)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.NotUpToDate, connection.ConnectionId);
        }

        if (connection.State != ConnectionState.UpToDate)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.NotUpToDate, connection.ConnectionId);
        }

        if (connection.Capability is not (CapabilityState.Writable or CapabilityState.ReadOnly))
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.NotUpToDate, connection.ConnectionId);
        }

        if (connection.LastError is not null)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.NotUpToDate, connection.ConnectionId);
        }

        if (connection.PendingFiles != 0 || connection.DirtyFiles != 0 || connection.ConflictFiles != 0)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.UnfinishedWork, connection.ConnectionId);
        }

        return new TrayReadinessResult(true, TrayReadinessFailure.None, connection.ConnectionId);
    }

    /// <summary>
    /// Current no-unfinished-work evidence for one configured connection.
    /// Only a fresh, current-generation, accepted idle probe counts; failure,
    /// staleness, a missing probe, active/failed work or uninspected pages all
    /// block readiness. Callers evaluate every configured connection.
    /// </summary>
    public static TrayReadinessResult EvaluateActivity(Guid connectionId, TraySyncEvidence evidence)
    {
        if (!evidence.ActivityFeatureAvailable)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.FeatureUnavailable, connectionId);
        }

        if (!evidence.TryGetActivityEvidence(connectionId, out TrayActivityProbe probe))
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.ActivityUnknown, connectionId);
        }

        if (!evidence.SessionMatches || probe.SessionGeneration != evidence.SessionGeneration)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.ActivityStale, connectionId);
        }

        if (probe.Failed)
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.ActivityFailed, connectionId);
        }

        if (!IsIdleProbe(probe))
        {
            return new TrayReadinessResult(false, TrayReadinessFailure.WorkRecorded, connectionId);
        }

        return new TrayReadinessResult(true, TrayReadinessFailure.None, connectionId);
    }
}

/// <summary>Readiness verdict: ready plus the first blocking reason and its connection.</summary>
public readonly record struct TrayReadinessResult(bool Ready, TrayReadinessFailure Failure, Guid ConnectionId);

/// <summary>
/// Small, boring evidence bag for the readiness evaluation: the account and
/// session state plus one <c>list_activity</c> outcome per connection. Status
/// records themselves are carried by the caller's connection list. Evidence
/// with a different session generation or an unknown connection id is never
/// consulted, so a stale or foreign success cannot celebrate.
/// </summary>
public sealed class TraySyncEvidence
{
    private readonly Dictionary<Guid, TrayActivityProbe> _probes = new();

    /// <summary>True once the live session has accepted a status snapshot.</summary>
    public required bool HasAcceptedStatus { get; init; }

    /// <summary>Account state from the accepted status.</summary>
    public required AuthenticationState AccountState { get; init; }

    /// <summary>Live provider session generation the status belongs to.</summary>
    public required long SessionGeneration { get; init; }

    /// <summary>False when this session generation differs from the live one.</summary>
    public required bool SessionMatches { get; init; }

    /// <summary>True when the provider advertises the <c>list_activity</c> feature.</summary>
    public required bool ActivityFeatureAvailable { get; init; }

    /// <summary>Records one accepted bounded probe (replacing any earlier evidence).</summary>
    public void SetActivityProbe(TrayActivityProbe probe) => _probes[probe.ConnectionId] = probe;

    /// <summary>Gets the recorded probe; false means unknown, never idle.</summary>
    public bool TryGetActivityEvidence(Guid connectionId, out TrayActivityProbe probe) =>
        _probes.TryGetValue(connectionId, out probe);
}
