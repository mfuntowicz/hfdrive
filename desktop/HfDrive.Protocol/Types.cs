namespace HfDrive.Protocol;

/// <summary>Progress update for a long-running request.</summary>
public sealed record ProgressUpdate
{
    /// <summary>Units completed so far (decimal string on the wire).</summary>
    public required ulong Completed { get; init; }

    /// <summary>Total units, when known (decimal string on the wire).</summary>
    public ulong? Total { get; init; }

    /// <summary>Display-only phase label.</summary>
    public required string Phase { get; init; }
}

/// <summary>Verified owner candidate populated from userinfo and capability probes.</summary>
public sealed record Owner
{
    /// <summary>Whether the owner is the person or an organization.</summary>
    public required OwnerKind OwnerKind { get; init; }

    /// <summary>Stable server-side owner identifier (retained across display renames).</summary>
    public required string OwnerId { get; init; }

    /// <summary>Validated canonical namespace, null when the provider did not supply one.</summary>
    public string? Namespace { get; init; }

    /// <summary>Display-only name.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Role hint for display; never an authorization decision.</summary>
    public string? Role { get; init; }

    /// <summary>Provider-reported display hints, never authorization.</summary>
    public required IReadOnlyList<string> Restrictions { get; init; }

    /// <summary>True when storage creation was observed to be permitted.</summary>
    public required bool CanCreate { get; init; }
}

/// <summary>A bucket candidate.</summary>
public sealed record Bucket
{
    /// <summary>Stable server-side bucket identifier.</summary>
    public required string BucketId { get; init; }

    /// <summary>Bucket name.</summary>
    public required string Name { get; init; }

    /// <summary>Owner namespace of the bucket.</summary>
    public required string Namespace { get; init; }

    /// <summary>Bucket visibility.</summary>
    public required Visibility Visibility { get; init; }
}

/// <summary>The validated remote binding selected for a connection.</summary>
public sealed record RemoteBinding
{
    /// <summary>Canonical owner namespace.</summary>
    public required string OwnerNamespace { get; init; }

    /// <summary>Stable owner identifier.</summary>
    public required string OwnerId { get; init; }

    /// <summary>Owner kind.</summary>
    public required OwnerKind OwnerKind { get; init; }

    /// <summary>Bucket name.</summary>
    public required string Bucket { get; init; }

    /// <summary>Stable bucket identifier.</summary>
    public required string BucketId { get; init; }

    /// <summary>Managed prefix inside the bucket.</summary>
    public required string Prefix { get; init; }

    /// <summary>Workspace identifier of the managed namespace at that prefix.</summary>
    public required Guid WorkspaceId { get; init; }
}

/// <summary>A single probe expectation/observation.</summary>
public sealed record ProbeCheck
{
    /// <summary>Which check this record describes.</summary>
    public required ProbeCheckKind Kind { get; init; }

    /// <summary>Expected behavior (display text).</summary>
    public required string Expected { get; init; }

    /// <summary>Observed behavior (display text).</summary>
    public required string Observed { get; init; }

    /// <summary>Outcome.</summary>
    public required ProbeOutcome Outcome { get; init; }

    /// <summary>Optional non-secret detail.</summary>
    public string? Detail { get; init; }
}

/// <summary>A connect-preview collision record.</summary>
public sealed record Collision
{
    /// <summary>Collision class.</summary>
    public required CollisionKind Kind { get; init; }

    /// <summary>Relative path under the connection root (display form).</summary>
    public required string RelativePath { get; init; }

    /// <summary>Item identifier when one side is already tracked.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Proposed action requiring user review.</summary>
    public required ProposedAction ProposedAction { get; init; }
}

/// <summary>A proposed namespace/file action shown during connect preview.</summary>
public sealed record ProposedActionRecord
{
    /// <summary>Item the action concerns, when known.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Action class.</summary>
    public required ProposedAction Action { get; init; }

    /// <summary>Display-only description.</summary>
    public required string Description { get; init; }
}

/// <summary>One change inside a history record.</summary>
public sealed record HistoryChange
{
    /// <summary>Item identifier.</summary>
    public required Guid ItemId { get; init; }

    /// <summary>Change class.</summary>
    public required HistoryChangeKind Kind { get; init; }

    /// <summary>Display name after the change.</summary>
    public required string Name { get; init; }

    /// <summary>Parent after the change (null only for the root item).</summary>
    public Guid? ParentId { get; init; }
}

/// <summary>A committed history entry.</summary>
public sealed record HistoryRecord
{
    /// <summary>Commit identifier.</summary>
    public required Guid CommitId { get; init; }

    /// <summary>Parent commit, null only for the initial commit.</summary>
    public Guid? ParentCommitId { get; init; }

    /// <summary>Generation recorded in HEAD for this commit, when retained evidence proves it.</summary>
    public Guid? Generation { get; init; }

    /// <summary>Device that produced the commit (display only).</summary>
    public required Guid DeviceId { get; init; }

    /// <summary>Display-only RFC 3339 creation time; never used for ordering.</summary>
    public required string CreatedAt { get; init; }

    /// <summary>Summary of changes.</summary>
    public IReadOnlyList<HistoryChange> Changes { get; init; } = Array.Empty<HistoryChange>();
}

/// <summary>A recorded conflict.</summary>
public sealed record ConflictRecord
{
    /// <summary>Deterministic conflict identifier (UUIDv5).</summary>
    public required Guid ConflictId { get; init; }

    /// <summary>Item identifier.</summary>
    public required Guid ItemId { get; init; }

    /// <summary>Conflict class.</summary>
    public required ConflictKind Kind { get; init; }

    /// <summary>Competing operation UUIDs, sorted.</summary>
    public IReadOnlyList<Guid> CompetingOperationIds { get; init; } = Array.Empty<Guid>();

    /// <summary>Both revisions involved.</summary>
    public IReadOnlyList<Guid> Revisions { get; init; } = Array.Empty<Guid>();

    /// <summary>Original names/locations preserved for both sides.</summary>
    public IReadOnlyList<string> OriginalNames { get; init; } = Array.Empty<string>();

    /// <summary>Display-only RFC 3339 timestamp.</summary>
    public required string DetectedAt { get; init; }

    /// <summary>Current resolution state.</summary>
    public required ConflictResolution ResolutionState { get; init; }
}

/// <summary>An activity record for the Activity page.</summary>
public sealed record ActivityRecord
{
    /// <summary>Activity identifier.</summary>
    public required Guid ActivityId { get; init; }

    /// <summary>Connection the activity belongs to.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Item the activity concerns, when known.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Display-only item name; internal object keys are never exposed.</summary>
    public required string ItemName { get; init; }

    /// <summary>Direction.</summary>
    public required ActivityDirection Direction { get; init; }

    /// <summary>Lifecycle phase.</summary>
    public required ActivityPhase Phase { get; init; }

    /// <summary>Logical bytes completed (decimal string on the wire).</summary>
    public required ulong BytesCompleted { get; init; }

    /// <summary>Logical bytes total, when known (decimal string on the wire).</summary>
    public ulong? BytesTotal { get; init; }

    /// <summary>Display-only RFC 3339 timestamp.</summary>
    public required string StartedAt { get; init; }

    /// <summary>Last error, if the activity failed.</summary>
    public ProtocolError? LastError { get; init; }
}

/// <summary>Per-connection status snapshot record.</summary>
public sealed record ConnectionStatus
{
    /// <summary>Connection identifier.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Managed workspace identifier.</summary>
    public required Guid WorkspaceId { get; init; }

    /// <summary>Verified owner.</summary>
    public required Owner Owner { get; init; }

    /// <summary>Selected bucket.</summary>
    public required Bucket Bucket { get; init; }

    /// <summary>Managed prefix.</summary>
    public required string Prefix { get; init; }

    /// <summary>Absolute local root path.</summary>
    public required string RootPath { get; init; }

    /// <summary>Access mode.</summary>
    public required ConnectionMode Mode { get; init; }

    /// <summary>Capability gate state.</summary>
    public required CapabilityState Capability { get; init; }

    /// <summary>Display/health state.</summary>
    public required ConnectionState State { get; init; }

    /// <summary>Pin state (requested).</summary>
    public required PinState Pin { get; init; }

    /// <summary>Placeholder hydration state.</summary>
    public required HydrationState Hydration { get; init; }

    /// <summary>Last remote commit observed.</summary>
    public Guid? ObservedCommit { get; init; }

    /// <summary>Last commit published by this device.</summary>
    public Guid? PublishedCommit { get; init; }

    /// <summary>Last commit applied locally.</summary>
    public Guid? AppliedCommit { get; init; }

    /// <summary>Persisted observed generation counter, when known (decimal string).</summary>
    public ulong? ObservedGeneration { get; init; }

    /// <summary>Files waiting to be uploaded.</summary>
    public required int PendingFiles { get; init; }

    /// <summary>Files with local unsynchronized changes.</summary>
    public required int DirtyFiles { get; init; }

    /// <summary>Files with unresolved conflicts.</summary>
    public required int ConflictFiles { get; init; }

    /// <summary>Files available online only.</summary>
    public required int OnlineOnlyFiles { get; init; }

    /// <summary>Files with a satisfied offline pin.</summary>
    public required int PinnedFiles { get; init; }

    /// <summary>Bytes pending upload (decimal string on the wire).</summary>
    public required ulong PendingUploadBytes { get; init; }

    /// <summary>Local bytes occupied under the root (decimal string on the wire).</summary>
    public required ulong LocalBytes { get; init; }

    /// <summary>Staging bytes currently admitted (decimal string on the wire).</summary>
    public required ulong StagingUsedBytes { get; init; }

    /// <summary>Range-cache bytes currently retained (decimal string on the wire).</summary>
    public required ulong RangeCacheUsedBytes { get; init; }

    /// <summary>Transfer-memory bytes currently used (decimal string on the wire).</summary>
    public required ulong TransferMemoryUsedBytes { get; init; }

    /// <summary>Last non-secret error for this connection.</summary>
    public ProtocolError? LastError { get; init; }

    /// <summary>Display-only RFC 3339 update time.</summary>
    public required string UpdatedAt { get; init; }
}

/// <summary>A full status snapshot.</summary>
public sealed record StatusSnapshot
{
    /// <summary>Event sequence this snapshot reflects (decimal string on the wire).</summary>
    public required ulong Sequence { get; init; }

    /// <summary>Full account and interactive-login state.</summary>
    public required AccountStatus Account { get; init; }

    /// <summary>Status of every configured connection.</summary>
    public IReadOnlyList<ConnectionStatus> Connections { get; init; } = Array.Empty<ConnectionStatus>();
}

/// <summary>One settings patch entry.</summary>
public sealed record SettingsPatch
{
    /// <summary>Settings key.</summary>
    public required string Key { get; init; }

    /// <summary>New value as JSON text; null removes the key.</summary>
    public string? ValueJson { get; init; }
}

/// <summary>A resolved settings entry.</summary>
public sealed record SettingsEntry
{
    /// <summary>Settings key.</summary>
    public required string Key { get; init; }

    /// <summary>JSON-encoded value.</summary>
    public required string ValueJson { get; init; }
}

/// <summary>One browsable item returned by inspect_drive.</summary>
public sealed record InspectItem
{
    /// <summary>Item identifier.</summary>
    public required Guid ItemId { get; init; }

    /// <summary>Parent identifier (null only for the root).</summary>
    public Guid? ParentId { get; init; }

    /// <summary>Exact item name ("" only for the root).</summary>
    public required string Name { get; init; }

    /// <summary>Item kind.</summary>
    public required ItemKind Kind { get; init; }

    /// <summary>Current item revision (operation UUID).</summary>
    public required Guid ItemRevision { get; init; }

    /// <summary>Content version identifier for files.</summary>
    public Guid? ContentVersionId { get; init; }
}
