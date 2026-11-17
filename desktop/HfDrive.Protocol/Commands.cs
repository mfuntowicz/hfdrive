namespace HfDrive.Protocol;

/// <summary>hello request; MUST be the first command on a connection.</summary>
public sealed record HelloRequest
{
    /// <summary>Highest protocol major the client implements (1).</summary>
    public required int ProtocolMajor { get; init; }

    /// <summary>Highest protocol minor the client implements (0).</summary>
    public required int ProtocolMinor { get; init; }

    /// <summary>Client role.</summary>
    public required ClientRole Role { get; init; }

    /// <summary>Client build version (display/provenance only).</summary>
    public required string BuildVersion { get; init; }
}

/// <summary>hello result.</summary>
public sealed record HelloResult
{
    /// <summary>Protocol major implemented by the provider (1).</summary>
    public int ProtocolMajor { get; init; }

    /// <summary>Protocol minor implemented by the provider (0).</summary>
    public int ProtocolMinor { get; init; }

    /// <summary>Provider build version.</summary>
    public string ProviderVersion { get; init; } = "";

    /// <summary>Feature names understood by the provider.</summary>
    public IReadOnlyList<string> SupportedFeatures { get; init; } = Array.Empty<string>();

    /// <summary>Lowest protocol minor the provider will still accept (0).</summary>
    public int SupportedMinProtocolMinor { get; init; }
}

/// <summary>get_status request.</summary>
public sealed record GetStatusRequest;

/// <summary>get_status result.</summary>
public sealed record GetStatusResult
{
    /// <summary>Current monotonically increasing event sequence (decimal string on the wire).</summary>
    public required ulong EventSequence { get; init; }

    /// <summary>Full account and login snapshot; pipe connectivity is not sign-in.</summary>
    public required AccountStatus Account { get; init; }

    /// <summary>Status of every configured connection.</summary>
    public IReadOnlyList<ConnectionStatus> Connections { get; init; } = Array.Empty<ConnectionStatus>();
}

/// <summary>
/// subscribe_status request. A new subscribe_status replaces any existing
/// subscription for this connection, and client disconnect removes it; there
/// is no separate stop command.
/// </summary>
public sealed record SubscribeStatusRequest
{
    /// <summary>Last event sequence the client observed; resubscribe after a gap delivers a full snapshot.</summary>
    public ulong? LastSequence { get; init; }
}

/// <summary>subscribe_status result.</summary>
public sealed record SubscribeStatusResult
{
    /// <summary>True when the subscription is active.</summary>
    public required bool Subscribed { get; init; }

    /// <summary>Full status snapshot delivered at subscription time.</summary>
    public required StatusSnapshot Snapshot { get; init; }
}

/// <summary>cancel_request request.</summary>
public sealed record CancelRequestRequest
{
    /// <summary>The request_id whose work should stop.</summary>
    public required Guid TargetRequestId { get; init; }
}

/// <summary>cancel_request result.</summary>
public sealed record CancelRequestResult
{
    /// <summary>True when cancellation was delivered to a known in-flight request.</summary>
    public required bool Accepted { get; init; }
}

/// <summary>start_login request.</summary>
public sealed record StartLoginRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Selected flow.</summary>
    public required LoginFlow Flow { get; init; }

    /// <summary>Login purpose selecting the scope set.</summary>
    public required LoginPurpose Purpose { get; init; }

    /// <summary>Organization identifier for re-consent, when requested.</summary>
    public string? OrganizationId { get; init; }
}

/// <summary>start_login result.</summary>
public sealed record StartLoginResult
{
    /// <summary>Provider-issued login session identifier.</summary>
    public required Guid SessionId { get; init; }

    /// <summary>URL the user should open when a browser did not launch automatically.</summary>
    public string? AuthorizationUrl { get; init; }

    /// <summary>Device user code, for the device flow only.</summary>
    public string? UserCode { get; init; }

    /// <summary>Device verification URI, for the device flow only.</summary>
    public string? VerificationUri { get; init; }

    /// <summary>Display-only RFC 3339 expiry of the login session.</summary>
    public required string ExpiresAt { get; init; }

    public override string ToString() =>
        $"StartLoginResult {{ SessionId = {SessionId}, ExpiresAt = {ExpiresAt}, Instructions = [redacted] }}";
}

/// <summary>cancel_login request.</summary>
public sealed record CancelLoginRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Login session to cancel.</summary>
    public required Guid SessionId { get; init; }
}

/// <summary>cancel_login result.</summary>
public sealed record CancelLoginResult
{
    /// <summary>True when a known session was cancelled.</summary>
    public required bool Cancelled { get; init; }
}

/// <summary>sign_out request.</summary>
public sealed record SignOutRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }
}

/// <summary>sign_out result.</summary>
public sealed record SignOutResult
{
    /// <summary>True when credentials were disabled and local work preserved.</summary>
    public required bool SignedOut { get; init; }
}

/// <summary>list_owners request.</summary>
public sealed record ListOwnersRequest
{
    /// <summary>Optional continuation cursor from a previous page.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>list_owners result.</summary>
public sealed record ListOwnersResult
{
    /// <summary>One page of owners.</summary>
    public IReadOnlyList<Owner> Items { get; init; } = Array.Empty<Owner>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>list_buckets request.</summary>
public sealed record ListBucketsRequest
{
    /// <summary>Owner namespace to list.</summary>
    public required string OwnerNamespace { get; init; }

    /// <summary>Optional continuation cursor from a previous page.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>list_buckets result.</summary>
public sealed record ListBucketsResult
{
    /// <summary>One page of buckets.</summary>
    public IReadOnlyList<Bucket> Items { get; init; } = Array.Empty<Bucket>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>create_bucket request.</summary>
public sealed record CreateBucketRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Stable verified owner identity; namespace alone cannot authorize creation.</summary>
    public required string OwnerId { get; init; }
    public required OwnerKind OwnerKind { get; init; }

    /// <summary>Owner namespace that will own the bucket.</summary>
    public required string OwnerNamespace { get; init; }

    /// <summary>Requested bucket name (validated against service rules).</summary>
    public required string BucketName { get; init; }

    /// <summary>Explicit region selection; null uses the service default.</summary>
    public string? Region { get; init; }
}

/// <summary>create_bucket result.</summary>
public sealed record CreateBucketResult
{
    /// <summary>The created bucket.</summary>
    public required Bucket Bucket { get; init; }

    /// <summary>True when the operation completed fully; on partial failure the created resources remain recorded in the setup intent.</summary>
    public required bool Completed { get; init; }
}

/// <summary>inspect_drive request.</summary>
public sealed record InspectDriveRequest
{
    /// <summary>Connection to inspect; null inspects a not-yet-connected binding.</summary>
    public Guid? ConnectionId { get; init; }

    /// <summary>Location to discover without inventing a workspace identifier.</summary>
    public RemoteLocation? Location { get; init; }

    /// <summary>Optional continuation cursor from a previous page.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>inspect_drive result.</summary>
public sealed record InspectDriveResult
{
    /// <summary>Managed identity actually found, absent when no managed HEAD exists.</summary>
    public RemoteBinding? Binding { get; init; }

    /// <summary>Remote HEAD generation, when a managed namespace exists.</summary>
    public Guid? HeadGeneration { get; init; }

    /// <summary>True when the prefix is a compatible managed drive.</summary>
    public required bool IsManagedDrive { get; init; }

    /// <summary>True only after a complete native listing confirms an empty prefix.</summary>
    public required bool PrefixEmpty { get; init; }

    /// <summary>One page of item records.</summary>
    public IReadOnlyList<InspectItem> Items { get; init; } = Array.Empty<InspectItem>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>
/// set_publication_credentials request. <see cref="ProtectedCredentials"/> is
/// the current-user DPAPI envelope of both S3 key fields and their binding.
/// Raw credentials never travel on the pipe; this envelope is never logged.
/// </summary>
public sealed record SetPublicationCredentialsRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection the publication credentials are bound to.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Base64 DPAPI ciphertext containing the complete credential pair and binding.</summary>
    public required string ProtectedCredentials { get; init; }

    /// <summary>Redacted: never exposes the ciphertext.</summary>
    public override string ToString() =>
        "SetPublicationCredentialsRequest { <redacted> }";
}

/// <summary>set_publication_credentials result.</summary>
public sealed record SetPublicationCredentialsResult
{
    /// <summary>True when the protected record was stored.</summary>
    public required bool Stored { get; init; }

    /// <summary>Capability state after storing.</summary>
    public required CapabilityState Capability { get; init; }
}

/// <summary>probe_storage request.</summary>
public sealed record ProbeStorageRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to probe.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Probe run identifier; created probe keys are tracked under it.</summary>
    public required Guid RunId { get; init; }
}

/// <summary>probe_storage result.</summary>
public sealed record ProbeStorageResult
{
    /// <summary>Run identifier echoed back.</summary>
    public required Guid RunId { get; init; }

    /// <summary>Capability state after the probe.</summary>
    public required CapabilityState Capability { get; init; }

    /// <summary>Per-check expectations and observations.</summary>
    public IReadOnlyList<ProbeCheck> Checks { get; init; } = Array.Empty<ProbeCheck>();

    /// <summary>Non-secret artifact path for the capability report.</summary>
    public string? ReportPath { get; init; }
}

/// <summary>
/// repair_storage request.
/// Repairs one existing connected drive's supplemental publication access by
/// rebinding the verified publication credentials recorded for a source setup
/// reservation to the target's existing protection context. No secret travels
/// on the pipe; the source setup reservation is never modified.
/// </summary>
public sealed record RepairStorageRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Existing connected connection whose storage access is repaired.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Source setup reservation whose verified protected credentials are reused.</summary>
    public required Guid CredentialsFromConnectionId { get; init; }
}

/// <summary>repair_storage result.</summary>
public sealed record RepairStorageResult
{
    /// <summary>The repaired target connection identifier.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>
    /// True only when the repaired credentials are committed and the live
    /// binding is active with the fresh proof recorded below. A committed
    /// repair whose runtime refresh failed is reported honestly as false.
    /// </summary>
    public required bool Repaired { get; init; }

    /// <summary>Fresh probe run identity of the required storage check.</summary>
    public required Guid RunId { get; init; }

    /// <summary>Non-secret capability report artifact identity.</summary>
    public string? ReportPath { get; init; }

    /// <summary>Current status of the repaired connection.</summary>
    public required ConnectionStatus Status { get; init; }
}

/// <summary>preview_connect request.</summary>
public sealed record PreviewConnectRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Previously reserved draft; protected credentials cannot be rebound here.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Absolute local root path.</summary>
    public required string RootPath { get; init; }

    /// <summary>Access mode to preview.</summary>
    public required ConnectionMode Mode { get; init; }
}

/// <summary>preview_connect result.</summary>
public sealed record PreviewConnectResult
{
    /// <summary>Persisted preview identifier consumed by connect.</summary>
    public required Guid PreviewId { get; init; }

    /// <summary>Reserved connection this preview will connect.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>The validated binding the preview inspected.</summary>
    public required RemoteBinding Binding { get; init; }

    /// <summary>Freshly observed visibility, included in final consent.</summary>
    public required Visibility Visibility { get; init; }

    /// <summary>Actual HEAD generation, absent for explicit empty-prefix initialization.</summary>
    public Guid? HeadGeneration { get; init; }

    /// <summary>Local scan generation observed during the preview (decimal string on the wire).</summary>
    public required ulong LocalScanGeneration { get; init; }

    /// <summary>Complete counts from the persisted scan.</summary>
    public required IReadOnlyList<CollisionCategorySummary> CollisionSummary { get; init; }

    /// <summary>Up to 200 representative paths; not the complete scan manifest.</summary>
    public IReadOnlyList<Collision> Collisions { get; init; } = Array.Empty<Collision>();

    /// <summary>Total proposed actions in the persisted plan.</summary>
    public required ulong ProposedActionCount { get; init; }

    /// <summary>Up to 200 representative proposed actions.</summary>
    public IReadOnlyList<ProposedActionRecord> ProposedActions { get; init; } = Array.Empty<ProposedActionRecord>();

    /// <summary>True when the preview requires review of every collision category.</summary>
    public required bool RequiresReview { get; init; }
}

/// <summary>connect request.</summary>
public sealed record ConnectRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Preview identifier from preview_connect.</summary>
    public required Guid PreviewId { get; init; }
}

/// <summary>connect result.</summary>
public sealed record ConnectResult
{
    /// <summary>The connected connection identifier.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Final status of the new connection.</summary>
    public required ConnectionStatus Status { get; init; }
}

/// <summary>pause request.</summary>
public sealed record PauseRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to pause; null pauses every connection.</summary>
    public Guid? ConnectionId { get; init; }
}

/// <summary>pause result.</summary>
public sealed record PauseResult
{
    /// <summary>Connections that entered the paused state.</summary>
    public IReadOnlyList<Guid> PausedConnectionIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>resume request.</summary>
public sealed record ResumeRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to resume; null resumes every paused connection.</summary>
    public Guid? ConnectionId { get; init; }
}

/// <summary>resume result.</summary>
public sealed record ResumeResult
{
    /// <summary>Connections that left the paused state.</summary>
    public IReadOnlyList<Guid> ResumedConnectionIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>set_pin request.</summary>
public sealed record SetPinRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to modify.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Optional subtree item; null targets the whole connection.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Pin or unpin.</summary>
    public required PinMode Mode { get; init; }
}

/// <summary>set_pin result.</summary>
public sealed record SetPinResult
{
    /// <summary>Pin state after the request.</summary>
    public required PinState PinState { get; init; }

    /// <summary>Files fully hydrated for the pin right now.</summary>
    public required int PinnedFiles { get; init; }
}

/// <summary>free_space request.</summary>
public sealed record FreeSpaceRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to shrink.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Optional subtree item; null targets the whole connection.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Free-all or free-except-pinned.</summary>
    public required FreeSpaceMode Mode { get; init; }
}

/// <summary>free_space result.</summary>
public sealed record FreeSpaceResult
{
    /// <summary>Logical bytes released from local storage (decimal string on the wire).</summary>
    public required ulong FreedBytes { get; init; }

    /// <summary>Files dehydrated.</summary>
    public required int DehydratedFiles { get; init; }
}

/// <summary>set_selective_sync request.</summary>
public sealed record SetSelectiveSyncRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to modify.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Item identifiers whose subtrees are excluded from sync.</summary>
    public IReadOnlyList<Guid> ExcludeItemIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>set_selective_sync result.</summary>
public sealed record SetSelectiveSyncResult
{
    /// <summary>Effective exclusions after the request.</summary>
    public IReadOnlyList<Guid> ExcludedItemIds { get; init; } = Array.Empty<Guid>();

    /// <summary>Items that retain unsynchronized work locally.</summary>
    public IReadOnlyList<Guid> RetainedDirtyItemIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>update_settings request.</summary>
public sealed record UpdateSettingsRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Scope identifier (global or a connection UUID string).</summary>
    public required string ScopeId { get; init; }

    /// <summary>Settings revision expected by the client (decimal string on the wire).</summary>
    public required ulong ExpectedRevision { get; init; }

    /// <summary>Patched settings values; ValueJson null removes a key.</summary>
    public IReadOnlyList<SettingsPatch> Settings { get; init; } = Array.Empty<SettingsPatch>();
}

/// <summary>update_settings result.</summary>
public sealed record UpdateSettingsResult
{
    /// <summary>New settings revision after applying the patch (decimal string on the wire).</summary>
    public required ulong Revision { get; init; }

    /// <summary>Fully resolved settings after applying the patch.</summary>
    public IReadOnlyList<SettingsEntry> Settings { get; init; } = Array.Empty<SettingsEntry>();
}

/// <summary>list_activity request.</summary>
public sealed record ListActivityRequest
{
    /// <summary>Connection whose activity is listed.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Optional continuation cursor from a previous page; the cursor is bound to the connection that produced it.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>list_activity result.</summary>
public sealed record ListActivityResult
{
    /// <summary>One page of activity records.</summary>
    public IReadOnlyList<ActivityRecord> Items { get; init; } = Array.Empty<ActivityRecord>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>list_history request.</summary>
public sealed record ListHistoryRequest
{
    /// <summary>Connection whose history is listed.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Optional subtree item filter.</summary>
    public Guid? ItemId { get; init; }

    /// <summary>Optional continuation cursor from a previous page.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>list_history result.</summary>
public sealed record ListHistoryResult
{
    /// <summary>One page of history records.</summary>
    public IReadOnlyList<HistoryRecord> Items { get; init; } = Array.Empty<HistoryRecord>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>restore request.</summary>
public sealed record RestoreRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to restore into.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Item to restore.</summary>
    public required Guid ItemId { get; init; }

    /// <summary>Version to restore.</summary>
    public required Guid VersionId { get; init; }
}

/// <summary>restore result.</summary>
public sealed record RestoreResult
{
    /// <summary>Operation identifier echoed back.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Status of the connection after the restore was queued.</summary>
    public required ConnectionStatus Status { get; init; }
}

/// <summary>list_conflicts request.</summary>
public sealed record ListConflictsRequest
{
    /// <summary>Connection whose conflicts are listed.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Optional continuation cursor from a previous page.</summary>
    public string? Cursor { get; init; }

    /// <summary>Maximum records to return (max 200).</summary>
    public required int Limit { get; init; }
}

/// <summary>list_conflicts result.</summary>
public sealed record ListConflictsResult
{
    /// <summary>One page of conflict records.</summary>
    public IReadOnlyList<ConflictRecord> Items { get; init; } = Array.Empty<ConflictRecord>();

    /// <summary>Continuation cursor, null on the last page.</summary>
    public string? NextCursor { get; init; }
}

/// <summary>resolve_conflict request.</summary>
public sealed record ResolveConflictRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection the conflict belongs to.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Conflict identifier.</summary>
    public required Guid ConflictId { get; init; }

    /// <summary>Resolution choice.</summary>
    public required ConflictResolution Resolution { get; init; }
}

/// <summary>resolve_conflict result.</summary>
public sealed record ResolveConflictResult
{
    /// <summary>Conflict identifier echoed back.</summary>
    public required Guid ConflictId { get; init; }

    /// <summary>Resolution state after the request.</summary>
    public required ConflictResolution ResolutionState { get; init; }
}

/// <summary>export_diagnostics request.</summary>
public sealed record ExportDiagnosticsRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Optional connection filter; null exports everything.</summary>
    public Guid? ConnectionId { get; init; }

    /// <summary>Absolute destination path for the redacted diagnostics ZIP.</summary>
    public required string DestinationPath { get; init; }
}

/// <summary>export_diagnostics result.</summary>
public sealed record ExportDiagnosticsResult
{
    /// <summary>Absolute path of the produced archive.</summary>
    public required string ArchivePath { get; init; }

    /// <summary>True when stable per-export aliases were applied to user paths/names.</summary>
    public required bool Redacted { get; init; }
}

/// <summary>One file affected by an unlink preview.</summary>
public sealed record UnlinkFileResult
{
    /// <summary>Exact local path of the affected file.</summary>
    public required string Path { get; init; }

    /// <summary>Logical size of the affected file (decimal string on the wire).</summary>
    public required ulong Size { get; init; }

    /// <summary>True when only part of the file is locally resident.</summary>
    public required bool Partial { get; init; }
}

/// <summary>prepare_unlink request.</summary>
public sealed record PrepareUnlinkRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to unlink.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Planned unlink mode.</summary>
    public required UnlinkMode Mode { get; init; }
}

/// <summary>prepare_unlink result.</summary>
public sealed record PrepareUnlinkResult
{
    /// <summary>True when the unlink can proceed under the selected mode.</summary>
    public required bool SafeToUnlink { get; init; }

    /// <summary>Online-only files needing hydration/export first.</summary>
    public required int OnlineOnlyFiles { get; init; }

    /// <summary>Partially hydrated files blocking a safe remove.</summary>
    public required int PartialFiles { get; init; }

    /// <summary>Files with unsynchronized local changes.</summary>
    public required int DirtyFiles { get; init; }

    /// <summary>Files with unresolved conflicts.</summary>
    public required int ConflictFiles { get; init; }

    /// <summary>Logical bytes required to export/hydrate (decimal string on the wire).</summary>
    public required ulong RequiredExportBytes { get; init; }

    /// <summary>Blocking reasons (non-secret display text), empty when safe.</summary>
    public IReadOnlyList<string> BlockingReasons { get; init; } = Array.Empty<string>();

    /// <summary>Persisted preview identifier consumed by unlink.</summary>
    public required Guid PreviewId { get; init; }

    /// <summary>Opaque fingerprint binding the provider-reviewed identities of this preview.</summary>
    public required string PreviewFingerprint { get; init; }

    /// <summary>True when proceeding destroys bytes that exist only in managed storage;
    /// requires explicit affirmative consent on unlink.</summary>
    public required bool OnlineOnlyDataLoss { get; init; }

    /// <summary>Files affected by the unlink, bounded to 200 entries by the producer.</summary>
    public required IReadOnlyList<UnlinkFileResult> AffectedFiles { get; init; }
}

/// <summary>unlink request.</summary>
public sealed record UnlinkRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Connection to unlink.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>Unlink mode actually selected.</summary>
    public required UnlinkMode Mode { get; init; }

    /// <summary>Preview identifier from prepare_unlink.</summary>
    public required Guid PreviewId { get; init; }

    /// <summary>True when the user explicitly consented to losing bytes that exist only in
    /// managed storage (required when the preview reported data loss).</summary>
    public required bool AcceptOnlineOnlyDataLoss { get; init; }
}

/// <summary>unlink result.</summary>
public sealed record UnlinkResult
{
    /// <summary>Connection echoed back.</summary>
    public required Guid ConnectionId { get; init; }

    /// <summary>True when the root was fully unregistered.</summary>
    public required bool Unregistered { get; init; }

    /// <summary>True when the binding/registration was retained for recovery.</summary>
    public required bool RetainedForRecovery { get; init; }
}

/// <summary>prepare_upgrade request.</summary>
public sealed record PrepareUpgradeRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }
}

/// <summary>prepare_upgrade result.</summary>
public sealed record PrepareUpgradeResult
{
    /// <summary>True when scheduling stopped and state checkpointed.</summary>
    public required bool Checkpointed { get; init; }

    /// <summary>Uncertain remote operations that remain durably recorded.</summary>
    public required int PendingOperations { get; init; }
}

/// <summary>exit_provider request.</summary>
public sealed record ExitProviderRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }
}

/// <summary>exit_provider result.</summary>
public sealed record ExitProviderResult
{
    /// <summary>True when the provider accepted the exit request.</summary>
    public required bool Accepted { get; init; }
}

/// <summary>The target bucket/owner object of a raw bucket import.</summary>
/// <remarks>
/// The import destination is exactly the <c>hfdrive-imports/&lt;import_id&gt;</c>
/// prefix (no trailing slash) reported by the import result; nothing else in the bucket is touched.
/// </remarks>
public sealed record ImportTarget
{
    /// <summary>Whether the target owner is the person or an organization.</summary>
    public required OwnerKind OwnerKind { get; init; }

    /// <summary>Stable server-side owner identifier (retained across display renames).</summary>
    public required string OwnerId { get; init; }

    /// <summary>Canonical owner namespace.</summary>
    public required string OwnerNamespace { get; init; }

    /// <summary>Stable server-side bucket identifier.</summary>
    public required string BucketId { get; init; }

    /// <summary>Bucket name.</summary>
    public required string BucketName { get; init; }

    /// <summary>Bucket visibility as reported by the service.</summary>
    public required Visibility Visibility { get; init; }
}

/// <summary>One imported file in an import result.</summary>
public sealed record ImportFileResult
{
    /// <summary>Exact raw key created under hfdrive-imports/&lt;import_id&gt;.</summary>
    public required string Key { get; init; }

    /// <summary>Imported byte length (decimal string on the wire).</summary>
    public required ulong Size { get; init; }

    /// <summary>Lowercase hex SHA-256 of the imported bytes.</summary>
    public required string Sha256 { get; init; }

    /// <summary>Xet file identifier of the imported payload.</summary>
    public required string XetFileId { get; init; }
}

/// <summary>
/// import request (raw bucket import initiated by Explorer).
/// A durable mutation: operation_id identifies the import operation and a
/// reconnect/retry reusing it must not duplicate the import. import_id
/// determines the exact destination prefix hfdrive-imports/&lt;import_id&gt; (no trailing slash).
/// Per-file result records are paged: the first call carries no FilesCursor and
/// runs the import; a request carrying FilesCursor continues the same
/// operation's persisted result (read replay, never a second mutation).
/// </summary>
public sealed record ImportRequest
{
    /// <summary>Unique durable operation identifier for this mutation.</summary>
    public required Guid OperationId { get; init; }

    /// <summary>Import identifier; fixes the destination prefix.</summary>
    public required Guid ImportId { get; init; }

    /// <summary>Exact target bucket/owner object.</summary>
    public required ImportTarget Target { get; init; }

    /// <summary>Absolute local source paths to import.</summary>
    public required IReadOnlyList<string> Sources { get; init; }

    /// <summary>
    /// Continuation cursor from a previous import result page. Present only for
    /// page continuations of the same operation; absent on the first call.
    /// </summary>
    public string? FilesCursor { get; init; }
}

/// <summary>
/// import result. Files is one page of per-file records (at most 200); the
/// complete import_id, prefix, file_count, total_bytes and empty_directory_count
/// are repeated on every page so each page is self-describing.
/// </summary>
public sealed record ImportResult
{
    /// <summary>Import identifier echoed back.</summary>
    public required Guid ImportId { get; init; }

    /// <summary>Exact destination prefix: hfdrive-imports/&lt;import_id&gt; (no trailing slash).</summary>
    public required string Prefix { get; init; }

    /// <summary>One page of per-file result records.</summary>
    public required IReadOnlyList<ImportFileResult> Files { get; init; }

    /// <summary>Continuation cursor for the next page, null on the last page.</summary>
    public string? NextCursor { get; init; }

    /// <summary>Total number of imported files (all pages).</summary>
    public required int FileCount { get; init; }

    /// <summary>Total imported bytes across all files (decimal string on the wire).</summary>
    public required ulong TotalBytes { get; init; }

    /// <summary>Directories that produced no files; native buckets have no standalone directory objects.</summary>
    public required int EmptyDirectoryCount { get; init; }
}

/// <summary>A compile-safe request/result pair bound to its wire method.</summary>
/// <typeparam name="TRequest">Typed request body.</typeparam>
/// <typeparam name="TResult">Typed result body.</typeparam>
public sealed class CommandSpec<TRequest, TResult>
{
    /// <summary>Wire method name.</summary>
    public string Method { get; }

    /// <summary>Creates a spec bound to a wire method.</summary>
    public CommandSpec(string method)
    {
        Method = method;
    }

    /// <summary>Redacted description; safe for logs.</summary>
    public override string ToString() => Method;
}

/// <summary>
/// The complete command registry. Every wire command appears exactly once;
/// clients call <see cref="NamedPipeProtocolClient.SendAsync{TRequest,TResult}"/>
/// with one of these specs.
/// </summary>
public static class Commands
{
    /// <summary>hello.</summary>
    public static readonly CommandSpec<HelloRequest, HelloResult> Hello = new("hello");

    /// <summary>get_status.</summary>
    public static readonly CommandSpec<GetStatusRequest, GetStatusResult> GetStatus = new("get_status");

    /// <summary>subscribe_status.</summary>
    public static readonly CommandSpec<SubscribeStatusRequest, SubscribeStatusResult> SubscribeStatus = new("subscribe_status");

    /// <summary>cancel_request.</summary>
    public static readonly CommandSpec<CancelRequestRequest, CancelRequestResult> CancelRequest = new("cancel_request");

    /// <summary>start_login.</summary>
    public static readonly CommandSpec<StartLoginRequest, StartLoginResult> StartLogin = new("start_login");

    /// <summary>cancel_login.</summary>
    public static readonly CommandSpec<CancelLoginRequest, CancelLoginResult> CancelLogin = new("cancel_login");

    /// <summary>sign_out.</summary>
    public static readonly CommandSpec<SignOutRequest, SignOutResult> SignOut = new("sign_out");

    /// <summary>list_owners.</summary>
    public static readonly CommandSpec<ListOwnersRequest, ListOwnersResult> ListOwners = new("list_owners");

    /// <summary>list_buckets.</summary>
    public static readonly CommandSpec<ListBucketsRequest, ListBucketsResult> ListBuckets = new("list_buckets");

    /// <summary>create_bucket.</summary>
    public static readonly CommandSpec<CreateBucketRequest, CreateBucketResult> CreateBucket = new("create_bucket");

    /// <summary>inspect_drive.</summary>
    public static readonly CommandSpec<InspectDriveRequest, InspectDriveResult> InspectDrive = new("inspect_drive");

    /// <summary>Reserve setup before credentials, probe, or local-root selection.</summary>
    public static readonly CommandSpec<BeginSetupRequest, BeginSetupResult> BeginSetup = new("begin_setup");

    /// <summary>set_publication_credentials.</summary>
    public static readonly CommandSpec<SetPublicationCredentialsRequest, SetPublicationCredentialsResult> SetPublicationCredentials = new("set_publication_credentials");

    /// <summary>probe_storage.</summary>
    public static readonly CommandSpec<ProbeStorageRequest, ProbeStorageResult> ProbeStorage = new("probe_storage");

    /// <summary>repair_storage.</summary>
    public static readonly CommandSpec<RepairStorageRequest, RepairStorageResult> RepairStorage = new("repair_storage");

    /// <summary>preview_connect.</summary>
    public static readonly CommandSpec<PreviewConnectRequest, PreviewConnectResult> PreviewConnect = new("preview_connect");

    /// <summary>connect.</summary>
    public static readonly CommandSpec<ConnectRequest, ConnectResult> Connect = new("connect");

    /// <summary>pause.</summary>
    public static readonly CommandSpec<PauseRequest, PauseResult> Pause = new("pause");

    /// <summary>resume.</summary>
    public static readonly CommandSpec<ResumeRequest, ResumeResult> Resume = new("resume");

    /// <summary>set_pin.</summary>
    public static readonly CommandSpec<SetPinRequest, SetPinResult> SetPin = new("set_pin");

    /// <summary>free_space.</summary>
    public static readonly CommandSpec<FreeSpaceRequest, FreeSpaceResult> FreeSpace = new("free_space");

    /// <summary>set_selective_sync.</summary>
    public static readonly CommandSpec<SetSelectiveSyncRequest, SetSelectiveSyncResult> SetSelectiveSync = new("set_selective_sync");

    /// <summary>update_settings.</summary>
    public static readonly CommandSpec<UpdateSettingsRequest, UpdateSettingsResult> UpdateSettings = new("update_settings");

    /// <summary>list_activity.</summary>
    public static readonly CommandSpec<ListActivityRequest, ListActivityResult> ListActivity = new("list_activity");

    /// <summary>list_history.</summary>
    public static readonly CommandSpec<ListHistoryRequest, ListHistoryResult> ListHistory = new("list_history");

    /// <summary>restore.</summary>
    public static readonly CommandSpec<RestoreRequest, RestoreResult> Restore = new("restore");

    /// <summary>list_conflicts.</summary>
    public static readonly CommandSpec<ListConflictsRequest, ListConflictsResult> ListConflicts = new("list_conflicts");

    /// <summary>resolve_conflict.</summary>
    public static readonly CommandSpec<ResolveConflictRequest, ResolveConflictResult> ResolveConflict = new("resolve_conflict");

    /// <summary>export_diagnostics.</summary>
    public static readonly CommandSpec<ExportDiagnosticsRequest, ExportDiagnosticsResult> ExportDiagnostics = new("export_diagnostics");

    /// <summary>prepare_unlink.</summary>
    public static readonly CommandSpec<PrepareUnlinkRequest, PrepareUnlinkResult> PrepareUnlink = new("prepare_unlink");

    /// <summary>unlink.</summary>
    public static readonly CommandSpec<UnlinkRequest, UnlinkResult> Unlink = new("unlink");

    /// <summary>prepare_upgrade.</summary>
    public static readonly CommandSpec<PrepareUpgradeRequest, PrepareUpgradeResult> PrepareUpgrade = new("prepare_upgrade");

    /// <summary>exit_provider.</summary>
    public static readonly CommandSpec<ExitProviderRequest, ExitProviderResult> ExitProvider = new("exit_provider");

    /// <summary>import (raw bucket import initiated by Explorer).</summary>
    public static readonly CommandSpec<ImportRequest, ImportResult> Import = new("import");

    /// <summary>All wire methods, in canonical order.</summary>
    public static IReadOnlyList<string> AllMethods { get; } =
    [
        "hello", "get_status", "subscribe_status", "cancel_request",
        "start_login", "cancel_login", "sign_out", "list_owners", "list_buckets", "create_bucket",
        "inspect_drive", "begin_setup", "set_publication_credentials", "probe_storage",
        "repair_storage", "preview_connect", "connect", "pause", "resume", "set_pin", "free_space",
        "set_selective_sync", "update_settings", "list_activity", "list_history", "restore",
        "list_conflicts", "resolve_conflict",
        "export_diagnostics", "prepare_unlink", "unlink", "prepare_upgrade", "exit_provider",
        "import",
    ];

    /// <summary>
    /// True when the method is a durable mutation whose requests carry an
    /// operation_id (unique per operation; reuse must not duplicate it).
    /// Read-only query methods — including the optional list_activity — are
    /// not mutations and never carry an operation_id.
    /// </summary>
    public static bool IsMutation(string method) => method switch
    {
        "get_status" or "subscribe_status" or "cancel_request" or
        "list_owners" or "list_buckets" or "inspect_drive" or "list_activity" or
        "list_history" or "list_conflicts" or
        "hello" => false,
        _ => AllMethods.Contains(method),
    };
}
