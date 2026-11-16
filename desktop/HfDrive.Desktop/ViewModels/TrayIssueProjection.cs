using HfDrive.Protocol;

namespace HfDrive.Desktop.ViewModels;

/// <summary>Which tray listing request a recorded failure belongs to.</summary>
public enum TrayRequestKind
{
    /// <summary>The <c>list_activity</c> request behind the sync-activity list.</summary>
    Activity,
    /// <summary>The <c>list_history</c> request behind the committed history.</summary>
    History,
    /// <summary>The <c>list_conflicts</c> request behind the recorded conflicts.</summary>
    Conflicts,
}

/// <summary>
/// A non-secret observed error: the provider's typed error code when one was
/// reported, otherwise a generic message with no code. The typed code is the
/// only basis for category wording — a generic message is never parsed to
/// guess one — and a generic recorded error is still shown verbatim.
/// </summary>
public sealed record TrayObservedError
{
    /// <summary>Typed provider error code, or null for a generic non-protocol failure.</summary>
    public required ProtocolErrorCode? Code { get; init; }

    /// <summary>Non-secret message exactly as observed.</summary>
    public required string Message { get; init; }

    /// <summary>Projects a caught exception; a protocol failure keeps its typed code.</summary>
    public static TrayObservedError FromException(Exception error) =>
        error is ProtocolException protocol
            ? new TrayObservedError { Code = protocol.Error.Code, Message = protocol.Error.Message }
            : new TrayObservedError { Code = null, Message = error.Message };

    /// <summary>Provider-style non-secret text; the bare message when no code was reported.</summary>
    public string ErrorText => Code is { } code ? $"{code}: {Message}" : Message;
}

/// <summary>One failed tray listing request, stamped with the session generation that observed it.</summary>
public sealed record TrayRequestFailure
{
    /// <summary>Connection the request was issued for.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Request kind that failed.</summary>
    public required TrayRequestKind Kind { get; init; }

    /// <summary>Provider session generation that produced the failure.</summary>
    public required long SessionGeneration { get; init; }

    /// <summary>The observed error.</summary>
    public required TrayObservedError Error { get; init; }
}

/// <summary>
/// Identity of one issued listing request within its (connection, kind) slot.
/// <see cref="TrayRequestErrorLog.BeginRequest"/> returns the stamp that
/// supersedes every earlier request of the same slot: only the current stamp
/// may record or clear the slot's error or apply page data, cursors and
/// loading flags, so a superseded request's late response — success or
/// failure — is dead on arrival.
/// </summary>
public readonly record struct TrayRequestStamp
{
    internal TrayRequestStamp(Guid connectionId, TrayRequestKind kind, long sessionGeneration, long sequence)
    {
        ConnectionId = connectionId;
        Kind = kind;
        SessionGeneration = sessionGeneration;
        Sequence = sequence;
    }

    /// <summary>Connection the request was issued for.</summary>
    public Guid ConnectionId { get; }

    /// <summary>Request kind (the slot) the request belongs to.</summary>
    public TrayRequestKind Kind { get; }

    /// <summary>Provider session generation the request was issued under.</summary>
    public long SessionGeneration { get; }

    /// <summary>Slot-unique monotonic identity of this request.</summary>
    internal long Sequence { get; }
}

/// <summary>
/// Pure per-(connection, request kind) slot store for the tray listings: each
/// slot holds the latest issued request's stamp and that request's recorded
/// failure. Only the current (newest) stamp of a slot may record or clear its
/// failure, so an older in-flight page's late success can never erase a newer
/// request's error and an older request's late failure after a newer success is
/// ignored. Beginning a request retains the previous failure while the new one
/// is pending: it disappears only on the corresponding fresh accepted success.
/// Failures from other session generations are never reported.
/// </summary>
public sealed class TrayRequestErrorLog
{
    /// <summary>Per-slot bookkeeping; mutated only through the stamp-guarded methods.</summary>
    private sealed class TrayRequestSlot
    {
        public TrayRequestStamp Latest;
        public TrayRequestFailure? Failure;
    }

    private readonly Dictionary<(Guid ConnectionId, TrayRequestKind Kind), TrayRequestSlot> _slots = new();
    private long _sequence;

    /// <summary>
    /// Begins one request in its slot and returns the stamp that supersedes
    /// every earlier request of that (connection, kind). Any previously
    /// recorded failure stays visible while the new request is pending.
    /// </summary>
    public TrayRequestStamp BeginRequest(Guid connectionId, TrayRequestKind kind, long sessionGeneration)
    {
        var stamp = new TrayRequestStamp(connectionId, kind, sessionGeneration, ++_sequence);
        var key = (connectionId, kind);
        if (_slots.TryGetValue(key, out TrayRequestSlot? slot))
            slot.Latest = stamp;
        else
            _slots[key] = new TrayRequestSlot { Latest = stamp };
        return stamp;
    }

    /// <summary>
    /// True only for the newest request of its slot. A superseded stamp is
    /// dead: it may neither record/clear the slot's error nor apply page data.
    /// </summary>
    public bool IsCurrent(TrayRequestStamp stamp) =>
        _slots.TryGetValue((stamp.ConnectionId, stamp.Kind), out TrayRequestSlot? slot)
        && slot.Latest.Sequence == stamp.Sequence;

    /// <summary>
    /// Records the failure observed for one request. A superseded stamp's late
    /// failure is ignored entirely: the newer request's outcome stands.
    /// </summary>
    public void RecordFailure(TrayRequestStamp stamp, TrayObservedError error)
    {
        if (!IsCurrent(stamp)) return;
        _slots[(stamp.ConnectionId, stamp.Kind)].Failure = new TrayRequestFailure
        {
            ConnectionId = stamp.ConnectionId,
            Kind = stamp.Kind,
            SessionGeneration = stamp.SessionGeneration,
            Error = error,
        };
    }

    /// <summary>
    /// Clears the slot's recorded failure when the newest request of the slot
    /// succeeded. A superseded success can never erase a newer failure, and
    /// other slots (other kinds/connections) are untouched.
    /// </summary>
    public void ClearFreshSuccess(TrayRequestStamp stamp)
    {
        if (!IsCurrent(stamp)) return;
        if (_slots.TryGetValue((stamp.ConnectionId, stamp.Kind), out TrayRequestSlot? slot))
            slot.Failure = null;
    }

    /// <summary>Failures recorded for one connection in the given session generation.</summary>
    public IReadOnlyList<TrayRequestFailure> FailuresFor(Guid connectionId, long sessionGeneration)
    {
        List<TrayRequestFailure>? matches = null;
        foreach (var entry in _slots)
        {
            TrayRequestFailure? failure = entry.Value.Failure;
            if (failure is null || failure.ConnectionId != connectionId || failure.SessionGeneration != sessionGeneration)
                continue;
            (matches ??= new()).Add(failure);
        }
        if (matches is null) return Array.Empty<TrayRequestFailure>();
        matches.Sort(static (left, right) => ((int)left.Kind).CompareTo((int)right.Kind));
        return matches;
    }
}

/// <summary>One friendly, actionable issue row (conflict, connection problem or failed transfer).</summary>
public sealed class TrayIssueRow
{
    public required string Title { get; init; }

    public required string Detail { get; init; }

    /// <summary>Label of the management action.</summary>
    public required string ActionText { get; init; }

    /// <summary>Section tag for <c>MainWindow.OpenSection</c>.</summary>
    public required string SectionTag { get; init; }

    /// <summary>Conflict identifier when this row is a recorded conflict; null for every other issue.</summary>
    public Guid? ConflictId { get; init; }

    public Guid? ConnectionId { get; init; }
}

/// <summary>
/// Pure issues/status projection for the tray panel, free of WinUI types so the
/// protocol tests exercise the exact source the tray ships. It turns the
/// observed connection statuses, recorded request failures, conflicts and
/// failed transfers into actionable issue rows plus the truthful section
/// texts. A problem stays visible until the corresponding fresh data succeeds:
/// a successful empty listing only clears its own request's failure, while a
/// recorded connection error remains until a fresh status drops it. Identical
/// observed errors are merged into one card, typed permission failures explain
/// checking bucket permissions/storage access keys (never guessed from message
/// text), and issue navigation carries only real conflict identifiers.
/// </summary>
public static class TrayIssueProjection
{
    /// <summary>Guidance shown for a typed <see cref="ProtocolErrorCode.PermissionDenied"/> error.</summary>
    private const string PermissionGuidance =
        "Check the bucket permissions and storage access keys for this connection.";

    /// <summary>Owner/bucket display title shared by the connection and issue rows.</summary>
    public static string ConnectionTitle(ConnectionStatus status)
    {
        string owner = string.IsNullOrEmpty(status.Owner.DisplayName)
            ? status.Owner.Namespace ?? status.Owner.OwnerId
            : status.Owner.DisplayName;
        return $"{owner} / {status.Bucket.Name}";
    }

    /// <summary>
    /// Builds the issue rows: one state row per connection in a blocked state,
    /// one row per distinct observed error (merging the connection's recorded
    /// error with listing failures of the exact same error), unresolved
    /// conflicts and failed transfers. Rows never carry invented conflict ids.
    /// </summary>
    public static IReadOnlyList<TrayIssueRow> Build(
        IReadOnlyList<ConnectionStatus> connections,
        TrayRequestErrorLog requestErrors,
        long sessionGeneration,
        IReadOnlyList<ConflictRecord> recordedConflicts,
        IReadOnlyList<ActivityRecord> activityRecords,
        Guid? selectedConnectionId)
    {
        List<TrayIssueRow>? rows = null;

        for (int index = 0; index < connections.Count; index++)
        {
            ConnectionStatus status = connections[index];
            Guid connectionId = status.ConnectionId;
            IReadOnlyList<TrayRequestFailure> failures = requestErrors.FailuresFor(connectionId, sessionGeneration);
            if (status.LastError is null && failures.Count == 0 && !IsBlockedState(status.State)) continue;
            string title = ConnectionTitle(status);

            // One entry per distinct observed error identity for this
            // connection, merging the connection's own recorded error with
            // listing failures carrying exactly the same error so one problem
            // is never shown on two cards.
            var groups = new List<(TrayObservedError Error, bool FromConnection, List<TrayRequestKind> Kinds)>();
            void Add(TrayObservedError error, bool fromConnection, TrayRequestKind? kind)
            {
                for (int i = 0; i < groups.Count; i++)
                {
                    if (groups[i].Error.Code != error.Code || groups[i].Error.Message != error.Message) continue;
                    if (fromConnection && !groups[i].FromConnection)
                        groups[i] = (groups[i].Error, true, groups[i].Kinds);
                    if (kind is { } observed && !groups[i].Kinds.Contains(observed))
                        groups[i].Kinds.Add(observed);
                    return;
                }
                groups.Add((error, fromConnection,
                    kind is { } first ? new List<TrayRequestKind> { first } : new List<TrayRequestKind>()));
            }

            if (status.LastError is { } recorded)
                Add(new TrayObservedError { Code = recorded.Code, Message = recorded.Message }, fromConnection: true, kind: null);
            foreach (TrayRequestFailure failure in failures)
                Add(failure.Error, fromConnection: false, kind: failure.Kind);

            // The state row describes the connection's blocked state; when an
            // error card of the same typed category already covers it, exactly
            // one merged card is shown instead.
            bool covered = status.State == ConnectionState.Offline && status.LastError is not null;
            foreach (var group in groups)
            {
                if (!ErrorCoversState(group.Error.Code, status.State)) continue;
                covered = true;
                break;
            }
            if (IsBlockedState(status.State) && !covered)
            {
                (rows ??= new()).Add(new TrayIssueRow
                {
                    Title = $"{title}: {StatusDisplayText.Get(status.State)}",
                    Detail = IssueTextFor(status),
                    // A configured drive never routes into the setup (Add
                    // Drive) wizard: its storage-access problem is managed on
                    // the Connections surface for that existing connection.
                    ActionText = status.State switch
                    {
                        ConnectionState.NeedsSignIn => "Sign in",
                        ConnectionState.StorageSetupRequired => "Manage storage",
                        _ => "Manage",
                    },
                    SectionTag = status.State switch
                    {
                        ConnectionState.NeedsSignIn => "account",
                        ConnectionState.Conflict => "operations",
                        _ => "connections",
                    },
                    ConnectionId = connectionId,
                });
            }

            foreach ((TrayObservedError error, bool fromConnection, List<TrayRequestKind> kinds) in groups)
            {
                (rows ??= new()).Add(new TrayIssueRow
                {
                    Title = $"{title}: {ErrorTitle(error.Code)}",
                    Detail = ErrorDetail(error, fromConnection, kinds),
                    ActionText = error.Code switch
                    {
                        ProtocolErrorCode.NeedsSignIn => "Sign in",
                        ProtocolErrorCode.StorageSetupRequired => "Manage storage",
                        _ => "Manage",
                    },
                    // A connection/authorization problem is managed on the
                    // Connections surface — including storage-access errors,
                    // which never route a configured drive into the setup (Add
                    // Drive) wizard; a failed listing belongs to the
                    // Operations surface that shows the listings. Only real
                    // conflicts below carry a conflict id.
                    SectionTag = error.Code switch
                    {
                        ProtocolErrorCode.NeedsSignIn => "account",
                        ProtocolErrorCode.StorageSetupRequired or ProtocolErrorCode.PermissionDenied => "connections",
                        _ => fromConnection ? "connections" : "operations",
                    },
                    ConnectionId = connectionId,
                });
            }
        }

        foreach (ConflictRecord conflict in recordedConflicts)
        {
            if (conflict.ResolutionState != ConflictResolution.Unresolved) continue;
            string name = conflict.OriginalNames.FirstOrDefault() ?? conflict.ItemId.ToString();
            (rows ??= new()).Add(new TrayIssueRow
            {
                Title = $"Conflict: \"{name}\"",
                Detail = ConflictText(conflict, name),
                ActionText = "Resolve",
                SectionTag = "operations",
                ConflictId = conflict.ConflictId,
                ConnectionId = selectedConnectionId,
            });
        }

        HashSet<(Guid, string, string)>? seenTransfers = null;
        foreach (ActivityRecord activity in activityRecords)
        {
            if (activity.Phase != ActivityPhase.Failed) continue;
            TrayObservedError? observed = activity.LastError is { } failure
                ? new TrayObservedError { Code = failure.Code, Message = failure.Message }
                : null;
            string detail = observed is { } error
                ? GuidanceFor(error.Code) is { } guidance ? $"{guidance} ({error.ErrorText})" : error.ErrorText
                : "The provider reported this transfer as failed; retry from HF Drive.";
            if (!(seenTransfers ??= new()).Add((activity.ConnectionId, activity.ItemName, detail))) continue;
            (rows ??= new()).Add(new TrayIssueRow
            {
                Title = $"Couldn't sync \"{activity.ItemName}\"",
                Detail = detail,
                ActionText = "Manage",
                SectionTag = "operations",
                ConnectionId = activity.ConnectionId,
            });
        }

        if (rows is null) return Array.Empty<TrayIssueRow>();
        return rows;
    }

    /// <summary>Issue-count summary shown above the rows.</summary>
    public static string IssuesStateText(int issueCount) => issueCount switch
    {
        0 => "No sync issues.",
        1 => "1 issue needs attention.",
        _ => $"{issueCount} issues need attention.",
    };

    /// <summary>
    /// True when the selected connection cannot sync right now: its state is
    /// blocked, the provider recorded a connection error, a listing request
    /// failed, a transfer failed or an unresolved conflict is recorded. An
    /// empty activity queue under this condition must never look healthy.
    /// </summary>
    public static bool IsSyncBlocked(
        ConnectionStatus? selected,
        TrayRequestErrorLog requestErrors,
        long sessionGeneration,
        IReadOnlyList<ConflictRecord> recordedConflicts,
        IReadOnlyList<ActivityRecord> activityRecords)
    {
        if (selected is null) return false;
        if (IsBlockedState(selected.State) || selected.LastError is not null) return true;
        if (requestErrors.FailuresFor(selected.ConnectionId, sessionGeneration).Count > 0) return true;
        for (int index = 0; index < recordedConflicts.Count; index++)
            if (recordedConflicts[index].ResolutionState == ConflictResolution.Unresolved) return true;
        for (int index = 0; index < activityRecords.Count; index++)
        {
            ActivityRecord activity = activityRecords[index];
            if (activity.ConnectionId == selected.ConnectionId && activity.Phase == ActivityPhase.Failed) return true;
        }
        return false;
    }

    /// <summary>
    /// Truthful sync-activity section text. Counts are always the observed
    /// ones; an empty queue while sync is blocked says so instead of implying
    /// health, and a failed or not-yet-accepted request is never "nothing is
    /// syncing".
    /// </summary>
    public static string ActivityStateText(
        bool featureAvailable,
        bool responseAccepted,
        bool requestFailed,
        int activityCount,
        int activeCount,
        bool syncBlocked)
    {
        if (!featureAvailable) return "Live activity is unavailable from this provider.";
        if (requestFailed) return "Couldn't load current sync activity — see Issues below.";
        if (!responseAccepted) return "Loading current work…";
        if (activityCount == 0)
        {
            return syncBlocked
                ? "Nothing is transferring right now because syncing is blocked. See Issues below."
                : "Nothing is syncing right now.";
        }
        if (activeCount == 0)
        {
            return syncBlocked
                ? "No files or folders are transferring because syncing is blocked. See Issues below."
                : "No files or folders are transferring.";
        }
        return activeCount == 1 ? "1 file or folder is transferring." : $"{activeCount} files and folders are transferring.";
    }

    /// <summary>Truthful committed-history section text for the current selection.</summary>
    public static string HistoryStateText(int historyCount, bool responseAccepted, bool requestFailed)
    {
        if (requestFailed) return "Couldn't load recent activity — see Issues below.";
        if (!responseAccepted) return "Loading committed history…";
        return historyCount == 0
            ? "No committed changes yet."
            : $"{historyCount} committed change{(historyCount == 1 ? "" : "s")}.";
    }

    /// <summary>States in which sync is actively progressing and are not issues by themselves.</summary>
    private static bool IsBlockedState(ConnectionState state) => state is not (
        ConnectionState.UpToDate or ConnectionState.PendingUpload or ConnectionState.Uploading
        or ConnectionState.PublishingChanges or ConnectionState.Downloading);

    /// <summary>
    /// Whether a typed error already describes the same problem as the
    /// connection's blocked state, so exactly one card is shown. Typed enum
    /// values only; a generic message is never parsed to infer a category.
    /// </summary>
    private static bool ErrorCoversState(ProtocolErrorCode? code, ConnectionState state) => (code, state) switch
    {
        (ProtocolErrorCode.NeedsSignIn, ConnectionState.NeedsSignIn) => true,
        (ProtocolErrorCode.StorageSetupRequired, ConnectionState.StorageSetupRequired) => true,
        (ProtocolErrorCode.PermissionDenied, ConnectionState.PermissionDenied) => true,
        _ => false,
    };

    private static string ErrorTitle(ProtocolErrorCode? code) => code switch
    {
        ProtocolErrorCode.PermissionDenied => "access denied",
        ProtocolErrorCode.NeedsSignIn => "sign-in required",
        ProtocolErrorCode.StorageSetupRequired => "storage setup required",
        _ => "provider error",
    };

    /// <summary>Actionable guidance for typed errors; never derived from message text.</summary>
    private static string? GuidanceFor(ProtocolErrorCode? code) => code switch
    {
        ProtocolErrorCode.PermissionDenied => PermissionGuidance,
        ProtocolErrorCode.NeedsSignIn => "Sign in again to resume syncing. Local work is retained.",
        ProtocolErrorCode.StorageSetupRequired => "Supplemental storage access is missing, so changes cannot upload yet.",
        _ => null,
    };

    private static string ErrorDetail(TrayObservedError error, bool fromConnection, IReadOnlyList<TrayRequestKind> kinds)
    {
        var sentences = new List<string>();
        if (fromConnection) sentences.Add("The provider recorded an error for this connection.");
        if (kinds.Count > 0) sentences.Add($"HF Drive couldn't load {ListPhrases(kinds)} for this connection.");
        if (GuidanceFor(error.Code) is { } guidance) sentences.Add(guidance);
        sentences.Add($"({error.ErrorText})");
        return string.Join(" ", sentences);
    }

    private static string ListPhrases(IReadOnlyList<TrayRequestKind> kinds)
    {
        string[] ordered = kinds.OrderBy(kind => kind).Select(kind => kind switch
        {
            TrayRequestKind.Activity => "sync activity",
            TrayRequestKind.History => "recent changes",
            TrayRequestKind.Conflicts => "issues",
            _ => kind.ToString(),
        }).ToArray();
        return ordered.Length switch
        {
            1 => ordered[0],
            2 => $"{ordered[0]} and {ordered[1]}",
            _ => $"{string.Join(", ", ordered.Take(ordered.Length - 1))} and {ordered[^1]}",
        };
    }

    private static string IssueTextFor(ConnectionStatus status) => status.State switch
    {
        ConnectionState.Offline => "HF Drive can't reach the remote services. Local changes are queued until the connection returns.",
        ConnectionState.NeedsSignIn => "Sign in again to resume syncing. Local work is retained.",
        ConnectionState.StorageSetupRequired => "Supplemental storage access is missing, so changes cannot upload yet.",
        ConnectionState.PermissionDenied => $"Access was denied for this drive. {PermissionGuidance}",
        ConnectionState.Conflict => $"{status.ConflictFiles} unresolved conflict(s) are blocking this drive.",
        ConnectionState.DiskFull => "The local disk is full. Free some space to resume syncing.",
        ConnectionState.WriteSyncPaused => "Write sync is paused for this drive.",
        _ => "This drive is not fully synchronized.",
    };

    private static string ConflictText(ConflictRecord conflict, string name) => conflict.Kind switch
    {
        ConflictKind.Content => $"Both devices changed \"{name}\". Both complete versions were kept.",
        ConflictKind.Rename => $"\"{name}\" was renamed or moved on two devices at once.",
        ConflictKind.DeleteEdit => $"\"{name}\" was deleted on one device while it changed on another. The changed version was preserved.",
        ConflictKind.CaseCollision => $"\"{name}\" differs only by letter case between devices.",
        ConflictKind.MoveCycle => $"Moving \"{name}\" would have created a folder loop, so it was preserved under a recovery folder.",
        _ => $"\"{name}\" needs a resolution.",
    };
}
