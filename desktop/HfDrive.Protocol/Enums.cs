using System.Text.Json.Serialization;

namespace HfDrive.Protocol;

/// <summary>Client role announced in <see cref="HelloRequest"/>.</summary>
public enum ClientRole
{
    /// <summary>The WinUI desktop application.</summary>
    Desktop,
    /// <summary>The <c>hfdrive</c> command line tool.</summary>
    Cli,
}

/// <summary>OAuth login flow selected by the user.</summary>
public enum LoginFlow
{
    /// <summary>Authorization-code flow with PKCE through the system browser.</summary>
    Pkce,
    /// <summary>Explicitly selected device-authorization fallback.</summary>
    Device,
}

/// <summary>Why the login is being started.</summary>
public enum LoginPurpose
{
    /// <summary>Establish the signed-in person.</summary>
    Signin,
    /// <summary>Request read access to storage.</summary>
    ReadStorage,
    /// <summary>Request write access to storage.</summary>
    WriteStorage,
    /// <summary>Request permission to create new storage.</summary>
    CreateStorage,
}

/// <summary>Owner kind for a bucket/namespace owner.</summary>
public enum OwnerKind
{
    /// <summary>The signed-in person's own namespace.</summary>
    Personal,
    /// <summary>An organization namespace.</summary>
    Organization,
}

/// <summary>Bucket visibility as reported by the service.</summary>
public enum Visibility
{
    /// <summary>Private bucket.</summary>
    Private,
    /// <summary>Public bucket.</summary>
    Public,
}

/// <summary>Access mode of a connection.</summary>
public enum ConnectionMode
{
    /// <summary>Committed content is browsable; local edits cannot be uploaded.</summary>
    ReadOnly,
    /// <summary>Full bidirectional synchronization.</summary>
    Writable,
}

/// <summary>Capability state of a connection.</summary>
public enum CapabilityState
{
    /// <summary>Committed content readable, no write authorization.</summary>
    ReadOnly,
    /// <summary>Supplemental publication authorization is missing.</summary>
    StorageSetupRequired,
    /// <summary>Writes are paused pending capability revalidation.</summary>
    WriteSyncPaused,
    /// <summary>Native and publication authorization plus capability evidence present.</summary>
    Writable,
}

/// <summary>Display/health state of a connection (exact UI state list).</summary>
public enum ConnectionState
{
    /// <summary>Committed publication and local generation agree.</summary>
    UpToDate,
    /// <summary>Local changes await upload.</summary>
    PendingUpload,
    /// <summary>Content upload in progress.</summary>
    Uploading,
    /// <summary>Publication (CAS) in progress.</summary>
    PublishingChanges,
    /// <summary>Remote content download in progress.</summary>
    Downloading,
    /// <summary>Provider cannot reach the remote services.</summary>
    Offline,
    /// <summary>Sign-in required.</summary>
    NeedsSignIn,
    /// <summary>Supplemental storage setup required.</summary>
    StorageSetupRequired,
    /// <summary>Authorization denied.</summary>
    PermissionDenied,
    /// <summary>Unresolved conflict present.</summary>
    Conflict,
    /// <summary>Insufficient local disk space.</summary>
    DiskFull,
    /// <summary>Writes paused by the user or policy.</summary>
    WriteSyncPaused,
}

/// <summary>Pin state (requested versus fully resident is tracked separately).</summary>
public enum PinState
{
    /// <summary>No offline pin requested.</summary>
    Unpinned,
    /// <summary>Offline pin requested.</summary>
    Pinned,
    /// <summary>Pin partially satisfied.</summary>
    Partial,
}

/// <summary>Placeholder hydration state.</summary>
public enum HydrationState
{
    /// <summary>All bytes resident.</summary>
    Full,
    /// <summary>Some bytes resident.</summary>
    Partial,
    /// <summary>Metadata only.</summary>
    OnlineOnly,
}

/// <summary>Pin request mode for <c>set_pin</c>.</summary>
public enum PinMode
{
    /// <summary>Keep content fully available offline.</summary>
    Pin,
    /// <summary>Remove the offline pin.</summary>
    Unpin,
}

/// <summary>Free-local-space mode for <c>free_space</c>.</summary>
public enum FreeSpaceMode
{
    /// <summary>Free everything that is safely freeable.</summary>
    All,
    /// <summary>Free everything except pinned subtrees.</summary>
    ExceptPinned,
}

/// <summary>Item kind in the managed namespace.</summary>
public enum ItemKind
{
    /// <summary>A file item.</summary>
    File,
    /// <summary>A directory item.</summary>
    Directory,
}

/// <summary>Direction of an activity record.</summary>
public enum ActivityDirection
{
    /// <summary>Local to remote.</summary>
    Upload,
    /// <summary>Remote to local.</summary>
    Download,
    /// <summary>Metadata only.</summary>
    Metadata,
}

/// <summary>Lifecycle phase of an activity record.</summary>
public enum ActivityPhase
{
    /// <summary>A local save was observed.</summary>
    Observed,
    /// <summary>Snapshot capture in progress.</summary>
    Snapshot,
    /// <summary>Content upload in progress.</summary>
    Uploading,
    /// <summary>Publication in progress.</summary>
    Publishing,
    /// <summary>Download in progress.</summary>
    Downloading,
    /// <summary>The operation completed.</summary>
    Completed,
    /// <summary>The operation failed; see the record's error.</summary>
    Failed,
    /// <summary>The operation is blocked by a conflict.</summary>
    Conflict,
}

/// <summary>Class of a colliding item during connect preview.</summary>
public enum CollisionKind
{
    /// <summary>Both sides have the item with identical bytes.</summary>
    IdenticalContent,
    /// <summary>Both sides differ.</summary>
    DifferentContent,
    /// <summary>Present locally only.</summary>
    LocalOnly,
    /// <summary>Present remotely only.</summary>
    RemoteOnly,
    /// <summary>Case-colliding names on Windows.</summary>
    CaseCollision,
    /// <summary>Name reserved or otherwise invalid.</summary>
    NameInvalid,
}

/// <summary>Proposed preview action for a colliding item.</summary>
public enum ProposedAction
{
    /// <summary>Adopt the identical bytes after digest verification.</summary>
    AdoptIdentical,
    /// <summary>Keep both sides as separate items.</summary>
    KeepBoth,
    /// <summary>Queue the local file as new work.</summary>
    QueueLocal,
    /// <summary>Materialize the remote item locally.</summary>
    DownloadRemote,
    /// <summary>User must choose a resolution.</summary>
    RequiresReview,
}

/// <summary>History change kind.</summary>
public enum HistoryChangeKind
{
    /// <summary>Item created.</summary>
    Create,
    /// <summary>Content changed.</summary>
    Content,
    /// <summary>Item renamed or moved.</summary>
    Location,
    /// <summary>Item deleted.</summary>
    Delete,
}

/// <summary>Conflict kind recorded during reconciliation.</summary>
public enum ConflictKind
{
    /// <summary>Concurrent content edits.</summary>
    Content,
    /// <summary>Concurrent renames/moves.</summary>
    Rename,
    /// <summary>Delete versus edit.</summary>
    DeleteEdit,
    /// <summary>Case-colliding names.</summary>
    CaseCollision,
    /// <summary>Move would produce a cycle.</summary>
    MoveCycle,
}

/// <summary>Conflict resolution choice.</summary>
public enum ConflictResolution
{
    /// <summary>The conflict still needs a resolution.</summary>
    Unresolved,
    /// <summary>Keep the local version as the contested path.</summary>
    KeepLocal,
    /// <summary>Keep the remote version.</summary>
    KeepRemote,
    /// <summary>Keep both versions.</summary>
    KeepBoth,
    /// <summary>Reconciliation preserved the changed side and dropped the deletion.</summary>
    Recovered,
}

/// <summary>Unlink mode.</summary>
public enum UnlinkMode
{
    /// <summary>Hydrate/export committed content, then unregister.</summary>
    SafeRemove,
    /// <summary>Disconnect only, keeping the registration for recovery.</summary>
    DisconnectKeepRegistration,
    /// <summary>Remove the connection even where committed bytes cannot be retained locally;
    /// requires explicit online-only data-loss consent.</summary>
    RemoveUnavailable,
}

/// <summary>Probe check kind.</summary>
public enum ProbeCheckKind
{
    /// <summary>Native upload visible natively.</summary>
    NativeUploadVisibleNatively,
    /// <summary>Native upload visible through S3.</summary>
    NativeUploadVisibleS3,
    /// <summary>GET body and ETag coherence.</summary>
    GetBodyEtagCoherence,
    /// <summary>Guarded initial create.</summary>
    GuardedCreate,
    /// <summary>Two writers with the same ETag: exactly one winner.</summary>
    ConcurrentSameEtag,
    /// <summary>Stale ETag overwrite rejection.</summary>
    StaleOverwriteRejected,
    /// <summary>Discarded successful CAS response recovered through ancestry.</summary>
    AmbiguousCasRecovery,
    /// <summary>Random Xet ranges equal the source slices.</summary>
    XetRangeReads,
}

/// <summary>Probe check outcome.</summary>
public enum ProbeOutcome
{
    /// <summary>Observed behavior matched the expectation.</summary>
    Passed,
    /// <summary>Observed behavior differed.</summary>
    Failed,
    /// <summary>The check could not be executed; see the check detail.</summary>
    NotRun,
}

/// <summary>
/// Exact UI display strings for <see cref="ConnectionState"/>; render through
/// this helper so every surface shows the contract wording.
/// </summary>
public static class StatusDisplayText
{
    /// <summary>Returns the exact display string for a connection state.</summary>
    public static string Get(ConnectionState state) => state switch
    {
        ConnectionState.UpToDate => "Up to date",
        ConnectionState.PendingUpload => "Pending upload",
        ConnectionState.Uploading => "Uploading",
        ConnectionState.PublishingChanges => "Publishing changes",
        ConnectionState.Downloading => "Downloading",
        ConnectionState.Offline => "Offline",
        ConnectionState.NeedsSignIn => "Needs sign-in",
        ConnectionState.StorageSetupRequired => "Storage setup required",
        ConnectionState.PermissionDenied => "Permission denied",
        ConnectionState.Conflict => "Conflict",
        ConnectionState.DiskFull => "Disk full",
        ConnectionState.WriteSyncPaused => "Write sync paused",
        _ => throw new ArgumentOutOfRangeException(nameof(state), state, "unknown connection state"),
    };
}
