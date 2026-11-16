using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HfDrive.Desktop.Services;
using HfDrive.Protocol;
using Microsoft.UI.Dispatching;

namespace HfDrive.Desktop.ViewModels;

/// <summary>Which explicit surface the tray panel currently shows.</summary>
public enum TrayPanelState
{
    /// <summary>No accepted status of the live session yet.</summary>
    Loading,
    /// <summary>The provider session is not connected.</summary>
    Disconnected,
    /// <summary>The live session reports zero configured connections.</summary>
    NeedsSetup,
    /// <summary>A configured account with at least one connection.</summary>
    Ready,
    /// <summary>The session is connected but the data is unavailable.</summary>
    Unavailable,
}

/// <summary>One connection row for the tray panel; 1:1 with observed provider status.</summary>
public sealed class TrayConnectionRow
{
    public TrayConnectionRow(ConnectionStatus status) => Status = status;

    public ConnectionStatus Status { get; }

    public string TitleDisplay => TrayIssueProjection.ConnectionTitle(Status);

    public string DetailText => Status.Mode == ConnectionMode.ReadOnly
        ? "Read-only — local changes cannot be uploaded."
        : $"{Status.PendingFiles} pending · {Status.DirtyFiles} local changes · {Status.ConflictFiles} conflicts";

    public string RootPath => Status.RootPath;

    public string? ErrorText => Status.LastError is { } error
        ? $"Provider error {error.Code}: {error.Message}"
        : null;
}

/// <summary>One activity row (real files/folders currently syncing).</summary>
public sealed class TrayActivityRow
{
    public TrayActivityRow(ActivityRecord record) => Record = record;

    public ActivityRecord Record { get; }

    public string ItemName => Record.ItemName;

    public string PhaseText => (Record.Direction, Record.Phase) switch
    {
        (_, ActivityPhase.Completed) => "Completed",
        (_, ActivityPhase.Failed) => "Failed",
        (_, ActivityPhase.Conflict) => "Needs attention",
        (ActivityDirection.Metadata, _) => "Updating folder",
        (ActivityDirection.Download, _) => "Downloading",
        (ActivityDirection.Upload, ActivityPhase.Observed) => "Change detected",
        (ActivityDirection.Upload, ActivityPhase.Snapshot) => "Preparing a copy",
        (ActivityDirection.Upload, ActivityPhase.Uploading) => "Uploading",
        (ActivityDirection.Upload, ActivityPhase.Publishing) => "Publishing",
        _ => Record.Phase.ToString(),
    };

    public bool HasTotal => Record.BytesTotal.HasValue;

    public bool IsActive => Record.Phase is not (ActivityPhase.Completed or ActivityPhase.Failed);

    public string ProgressText
    {
        get
        {
            string completed = ConnectionViewModel.FormatBytes(Record.BytesCompleted);
            return Record.BytesTotal is { } total
                ? $"{completed} of {ConnectionViewModel.FormatBytes(total)}"
                : $"{completed} · total size unknown";
        }
    }

    public string? ErrorText => Record.LastError is { } error
        ? $"{error.Code}: {error.Message}"
        : null;
}

/// <summary>One committed history entry for the tray panel.</summary>
public sealed class TrayHistoryRow
{
    public TrayHistoryRow(HistoryRecord record) => Record = record;

    public HistoryRecord Record { get; }

    public string SummaryText
    {
        get
        {
            if (Record.Changes.Count == 0)
            {
                return "Committed (no item changes recorded)";
            }

            string first = Describe(Record.Changes[0]);
            return Record.Changes.Count == 1
                ? first
                : $"{first} · and {Record.Changes.Count - 1} more";
        }
    }

    public string TimeText => Record.CreatedAt;

    public string CommitText => $"Commit {Record.CommitId.ToString()[..8]}";

    public string MetaText => $"{TimeText} · {CommitText}";

    private static string Describe(HistoryChange change) => change.Kind switch
    {
        HistoryChangeKind.Create => $"Added \"{change.Name}\"",
        HistoryChangeKind.Content => $"Changed \"{change.Name}\"",
        HistoryChangeKind.Location => $"Moved \"{change.Name}\"",
        HistoryChangeKind.Delete => $"Deleted \"{change.Name}\"",
        _ => $"\"{change.Name}\"",
    };
}

/// <summary>
/// Tray-panel projection of the single provider session: current account and
/// connection status, real in-flight activity (<c>list_activity</c>), paginated
/// committed history and recorded conflicts. Every value comes from an observed
/// provider response; nothing here is fabricated and no mutation runs without a
/// user command. Stale responses are rejected by session generation and the
/// selected connection.
/// </summary>
public sealed partial class TrayViewModel : ObservableObject, IDisposable
{
    /// <summary>Feature name the provider advertises for <c>list_activity</c>.</summary>
    public const string ListActivityFeature = "list_activity";

    /// <summary>Page size for every tray listing request.</summary>
    private const int PageSize = 50;

    private readonly ProviderSession _session;
    private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<Guid, ConnectionStatus> _connectionRecords = new();
    private readonly Dictionary<Guid, TrayConnectionRow> _connectionRows = new();
    private readonly HashSet<Guid> _historySeen = new();
    private readonly HashSet<Guid> _conflictsSeen = new();
    private readonly HashSet<Guid> _activitySeen = new();
    private readonly List<ConflictRecord> _conflictRecords = new();

    /// <summary>
    /// Latest failed listing request per connection and kind; cleared only by
    /// the matching fresh accepted success (see <see cref="TrayRequestErrorLog"/>).
    /// </summary>
    private readonly TrayRequestErrorLog _requestErrors = new();

    /// <summary>
    /// Selection/generation whose first activity page has been accepted, or
    /// null while the current selection's activity state is still unknown.
    /// </summary>
    private (Guid ConnectionId, long Generation)? _activityAcceptedFor;

    private CancellationTokenSource? _loadCts;
    private AccountStatus? _account;
    private long _statusGeneration = -1;
    private ulong _statusSequence;
    private bool _haveStatus;
    private string? _historyCursor;
    private string? _conflictsCursor;
    private string? _activityCursor;

    /// <summary>
    /// True once the user paged the activity list past its first page. Used
    /// only to keep a poll from destroying that paging; readiness never
    /// consults it.
    /// </summary>
    private bool _activityPagedBeyondFirst;

    /// <summary>Latest bounded idle probe per connection (see <see cref="TraySyncReadiness"/>).</summary>
    private readonly Dictionary<Guid, TrayActivityProbe> _readinessProbes = new();

    private bool _historyLoaded;
    private bool _disposed;
    private bool _isPolling;
    private bool _selectionDirty;

    public TrayViewModel(ProviderSession session)
    {
        _session = session;
        _session.StateChanged += OnSessionChanged;
        _session.StatusChanged += OnStatusChanged;
        ApplySessionState();
    }

    // ── Panel surface state ──────────────────────────────────────────────

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLoadingView), nameof(IsDisconnectedView), nameof(IsNeedsSetupView),
        nameof(IsReadyView), nameof(IsUnavailableView))]
    public partial TrayPanelState PanelState { get; set; } = TrayPanelState.Loading;

    public bool IsLoadingView => PanelState == TrayPanelState.Loading;
    public bool IsDisconnectedView => PanelState == TrayPanelState.Disconnected;
    public bool IsNeedsSetupView => PanelState == TrayPanelState.NeedsSetup;
    public bool IsReadyView => PanelState == TrayPanelState.Ready;
    public bool IsUnavailableView => PanelState == TrayPanelState.Unavailable;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasWarningText))]
    public partial string? WarningText { get; set; }

    public bool HasWarningText => !string.IsNullOrWhiteSpace(WarningText);

    // ── Account avatar (display identity only; never a credential) ──────

    /// <summary>
    /// Validated avatar URI of the current signed-in account, or null while
    /// loading, signed out, or when the profile carries no usable URI. The
    /// panel renders CatchingHuggy as the fallback for every null. The URI
    /// comes from the provider's verified userinfo avatar and is fetched
    /// anonymously by the image loader: no bearer credential is ever attached
    /// to it.
    /// </summary>
    [ObservableProperty]
    public partial Uri? AvatarUri { get; set; }

    /// <summary>Account key the current <see cref="AvatarUri"/> belongs to.</summary>
    private string? _avatarAccountKey;

    /// <summary>
    /// Accessible name of the account avatar; follows account changes so a
    /// screen reader never attributes the picture to the wrong person.
    /// </summary>
    public string AvatarAutomationName => _account is { State: AuthenticationState.SignedIn, Profile: { } profile }
        ? $"Signed-in account picture for {profile.Namespace}"
        : "Signed-in account picture";

    [ObservableProperty]
    public partial string DisconnectedText { get; set; } = "The tray panel is not connected to the HF Drive provider.";

    [ObservableProperty]
    public partial bool IsFeatureUnavailable { get; set; }

    [ObservableProperty]
    public partial string FeatureUnavailableText { get; set; } = string.Empty;

    // ── Activity tab selection (view state only; no provider mutation) ────

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSyncingTabSelected), nameof(IsHistoryTabSelected))]
    public partial TrayActivityTab SelectedActivityTab { get; set; } = TrayActivityTab.Syncing;

    public bool IsSyncingTabSelected
    {
        get => SelectedActivityTab == TrayActivityTab.Syncing;
        set => SelectedActivityTab = TrayActivityTabSelection.ApplyChecked(
            SelectedActivityTab, TrayActivityTab.Syncing, value);
    }

    public bool IsHistoryTabSelected
    {
        get => SelectedActivityTab == TrayActivityTab.History;
        set => SelectedActivityTab = TrayActivityTabSelection.ApplyChecked(
            SelectedActivityTab, TrayActivityTab.History, value);
    }

    // ── All-synced state (the only state that may celebrate) ─────────────

    /// <summary>
    /// True only when the live session has accepted status showing at least one
    /// configured connection, the account is signed in, every connection has a
    /// known observed baseline fully applied locally, is
    /// <see cref="ConnectionState.UpToDate"/> with a healthy capability state
    /// and zero pending/dirty/conflict counts, and every configured connection
    /// has current, empty <c>list_activity</c> evidence. The connection's own
    /// <c>PublishedCommit</c> is this device's last publication and is never
    /// required to match: a read-only drive or a device caught up with another
    /// device's commit is up to date without publishing. Unknown, stale,
    /// paused, failed, disconnected and no-drive states are never "all synced".
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AllSyncedText), nameof(IsActivityStatusVisible))]
    public partial bool IsAllSynced { get; set; }

    public string AllSyncedText => IsAllSynced
        ? "Everything is up to date"
        : string.Empty;

    /// <summary>Hide the ordinary empty-queue text while the green all-synced
    /// confirmation is shown; blocked or unknown states keep their real text.</summary>
    public bool IsActivityStatusVisible => !IsAllSynced;

    /// <summary>
    /// First reason the celebration is withheld (diagnostics only); null while
    /// the account is genuinely up to date.
    /// </summary>
    public TrayReadinessFailure? ReadinessFailure { get; private set; }

    // ── Connections ─────────────────────────────────────────────────────

    public ObservableCollection<TrayConnectionRow> Connections { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasConnectionSelector))]
    public partial TrayConnectionRow? SelectedConnection { get; set; }

    public bool HasConnectionSelector => Connections.Count > 1;

    // ── Activity (files/folders currently syncing) ───────────────────────

    public ObservableCollection<TrayActivityRow> ActivityItems { get; } = new();

    [ObservableProperty]
    public partial string ActivityStateText { get; set; } = "Loading…";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreActivityCommand))]
    public partial bool IsActivityLoading { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreActivityCommand))]
    public partial bool HasMoreActivity { get; set; }

    // ── History (real committed commits) ─────────────────────────────────

    public ObservableCollection<TrayHistoryRow> HistoryItems { get; } = new();

    [ObservableProperty]
    public partial string HistoryStateText { get; set; } = "Loading…";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreHistoryCommand))]
    public partial bool IsHistoryLoading { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreHistoryCommand))]
    public partial bool HasMoreHistory { get; set; }

    // ── Issues (top service banner + file issues in Syncing now) ─────────

    public ObservableCollection<TrayIssueRow> FileIssueItems { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasConnectionIssue))]
    public partial TrayIssueRow? ConnectionIssue { get; set; }

    [ObservableProperty]
    public partial string ConnectionIssueTitle { get; set; } = string.Empty;

    public bool HasConnectionIssue => ConnectionIssue is not null;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreIssuesCommand))]
    public partial bool IsIssuesLoading { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreIssuesCommand))]
    public partial bool HasMoreIssues { get; set; }

    // ── Pause / resume (real provider mutations) ─────────────────────────

    [ObservableProperty]
    public partial bool IsCommandBusy { get; set; }

    [ObservableProperty]
    public partial string PauseResumeText { get; set; } = "Pause syncing";

    [ObservableProperty]
    public partial string? LastActionText { get; set; }

    /// <summary>True when the provider advertises the activity feature.</summary>
    public bool HasListActivityFeature =>
        _session.Hello?.SupportedFeatures?.Contains(ListActivityFeature, StringComparer.Ordinal) == true;

    /// <summary>Most recently accepted account status of the live session.</summary>
    public AccountStatus? CurrentAccount => _account;

    // ── Session/status plumbing ─────────────────────────────────────────

    private void OnSessionChanged(object? sender, EventArgs args) =>
        _dispatcher.TryEnqueue(() => { if (!_disposed) ApplySessionState(); });

    private void OnStatusChanged(long generation, StatusChangedEvent status) =>
        _dispatcher.TryEnqueue(() => { if (!_disposed) ApplyStatus(generation, status); });

    /// <summary>
    /// The live session has accepted no status for too long while the panel was
    /// open: report the status as unavailable instead of loading forever. A
    /// later accepted status restores the real state.
    /// </summary>
    public void MarkStatusUnavailable()
    {
        if (_disposed || _haveStatus || _session.State != ProviderConnectionState.Ready) return;
        PanelState = TrayPanelState.Unavailable;
    }

    /// <summary>Mirrors the session's observed state; never treats a disconnect as empty configuration.</summary>
    public void ApplySessionState()
    {
        DisconnectedText = _session.State switch
        {
            ProviderConnectionState.Disconnected => "The tray panel lost the HF Drive provider. Reconnect to see live status.",
            ProviderConnectionState.Connecting => "Connecting to the HF Drive provider…",
            ProviderConnectionState.Failed => _session.LastError ?? "The HF Drive provider connection failed.",
            ProviderConnectionState.Ready => _session.StatusText,
            _ => _session.StatusText,
        };

        if (_session.State != ProviderConnectionState.Ready)
        {
            if (_session.State == ProviderConnectionState.Connecting && !_haveStatus)
            {
                PanelState = TrayPanelState.Loading;
            }
            else
            {
                PanelState = TrayPanelState.Disconnected;
            }
        }
        else if (!_haveStatus || _statusGeneration != _session.Generation)
        {
            PanelState = TrayPanelState.Loading;
        }
        else
        {
            PanelState = Connections.Count == 0 ? TrayPanelState.NeedsSetup : TrayPanelState.Ready;
        }

        if (_session.LastError is { } error)
        {
            WarningText = error;
        }

        OnPropertyChanged(nameof(HasListActivityFeature));
        // A disconnect/failed session invalidates readiness immediately instead
        // of leaving a stale success on screen.
        UpdateAllSynced();
    }

    private void ApplyStatus(long generation, StatusChangedEvent status)
    {
        if (generation != _session.Generation) return;
        if (_statusGeneration != generation)
        {
            _statusGeneration = generation;
            _haveStatus = false;
        }
        if (_haveStatus && status.Sequence < _statusSequence) return;
        _haveStatus = true;
        _statusSequence = status.Sequence;
        _account = status.Account;

        if (status.Snapshot)
        {
            _connectionRecords.Clear();
            foreach (ConnectionStatus connection in status.Changes)
                _connectionRecords[connection.ConnectionId] = connection;
        }
        else
        {
            foreach (Guid removed in status.RemovedConnectionIds)
                _connectionRecords.Remove(removed);
            foreach (ConnectionStatus connection in status.Changes)
                _connectionRecords[connection.ConnectionId] = connection;
        }

        Guid? selectedId = SelectedConnection?.Status.ConnectionId;
        var nextRows = new List<TrayConnectionRow>();
        foreach (ConnectionStatus connection in _connectionRecords.Values.OrderBy(c => c.RootPath, StringComparer.OrdinalIgnoreCase))
        {
            if (_connectionRows.TryGetValue(connection.ConnectionId, out var existing) && existing.Status == connection)
                nextRows.Add(existing);
            else
            {
                var row = new TrayConnectionRow(connection);
                _connectionRows[connection.ConnectionId] = row;
                nextRows.Add(row);
            }
        }
        Connections.Clear();
        foreach (TrayConnectionRow row in nextRows)
            Connections.Add(row);
        foreach (Guid stale in _connectionRows.Keys.Where(id => !_connectionRecords.ContainsKey(id)).ToList())
            _connectionRows.Remove(stale);

        // Keep the selection reference stable across status events so a routine
        // status delta never restarts the per-connection loads.
        TrayConnectionRow? desired = selectedId is { } id
            ? nextRows.FirstOrDefault(r => r.Status.ConnectionId == id) ?? nextRows.FirstOrDefault()
            : nextRows.FirstOrDefault();
        if (!ReferenceEquals(SelectedConnection, desired))
            SelectedConnection = desired;
        else
            OnPropertyChanged(nameof(HasConnectionSelector));

        UpdateAvatar(status.Account);
        UpdateAllSynced();
        UpdatePauseResume();
        ApplySessionState();
        RebuildIssues();

        // Status events refresh rows/summary/issues only. Per-connection list
        // loads restart on an actual selection change (partial property hook)
        // and while visible the panel's bounded poll keeps them fresh; a
        // routine status delta must not restart paged history.
    }

    /// <summary>
    /// Publishes the current account's validated avatar URI. A missing/invalid
    /// URI is published as null (the panel falls back to CatchingHuggy). An
    /// account change clears the previous URI first, so the previous user's
    /// picture is never shown for a new account.
    /// </summary>
    private void UpdateAvatar(AccountStatus account)
    {
        string? accountKey = account.Profile?.AccountKey;
        if (!string.Equals(accountKey, _avatarAccountKey, StringComparison.Ordinal))
        {
            _avatarAccountKey = accountKey;
            AvatarUri = null;
            OnPropertyChanged(nameof(AvatarAutomationName));
        }
        if (account.State != AuthenticationState.SignedIn)
        {
            if (AvatarUri is not null) AvatarUri = null;
            return;
        }

        // Defensive validation at the display boundary: the provider already
        // rejects anything that is not an HTTPS huggingface.co (subdomain) URL
        // without embedded credentials. Never build a request from anything
        // else; the image loader performs an anonymous GET only.
        Uri? next = null;
        if (Uri.TryCreate(account.Profile?.AvatarUrl, UriKind.Absolute, out Uri? candidate)
            && candidate.Scheme == Uri.UriSchemeHttps
            && string.IsNullOrEmpty(candidate.UserInfo)
            && (candidate.Host.Equals("huggingface.co", StringComparison.OrdinalIgnoreCase)
                || candidate.Host.EndsWith(".huggingface.co", StringComparison.OrdinalIgnoreCase)))
        {
            next = candidate;
        }
        if (AvatarUri != next) AvatarUri = next;
    }

    // ── Data loading (bounded, cancellable, stale-guarded) ───────────────

    private void CancelLoad()
    {
        _loadCts?.Cancel();
        _loadCts?.Dispose();
        _loadCts = null;
    }

    /// <summary>Reloads activity, issues and history for the current selection.</summary>
    private Task ReloadSelectionAsync(CancellationToken cancellationToken)
    {
        _historySeen.Clear();
        _historyCursor = null;
        _historyLoaded = false;
        HistoryItems.Clear();
        _conflictsSeen.Clear();
        _conflictsCursor = null;
        _conflictRecords.Clear();
        _activitySeen.Clear();
        _activityCursor = null;
        _activityPagedBeyondFirst = false;
        _activityAcceptedFor = null;
        if (_session.State != ProviderConnectionState.Ready || SelectedConnection is null)
        {
            ActivityItems.Clear();
            HistoryItems.Clear();
            RebuildIssues();
            return Task.CompletedTask;
        }
        return LoadSelectionAsync(replaceActivity: true, cancellationToken);
    }

    private async Task LoadSelectionAsync(bool replaceActivity, CancellationToken cancellationToken)
    {
        if (SelectedConnection is not { } row || _session.State != ProviderConnectionState.Ready) return;
        Guid connectionId = row.Status.ConnectionId;
        long generation = _session.Generation;
        CancelLoad();
        var cts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _loadCts = cts;
        try
        {
            await LoadActivityPageAsync(connectionId, generation, cursor: null, replace: replaceActivity, cts.Token).ConfigureAwait(true);
            await LoadConflictsPageAsync(connectionId, generation, cursor: null, cts.Token).ConfigureAwait(true);
            if (!_historyLoaded)
                await LoadHistoryPageAsync(connectionId, generation, cursor: null, cts.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        finally
        {
            if (ReferenceEquals(_loadCts, cts))
            {
                _loadCts = null;
                cts.Dispose();
            }
        }
    }

    private bool IsStale(long generation, Guid connectionId) =>
        generation != _session.Generation
        || SelectedConnection?.Status.ConnectionId != connectionId
        || _disposed;

    private async Task LoadActivityPageAsync(Guid connectionId, long generation, string? cursor, bool replace, CancellationToken cancellationToken)
    {
        if (!HasListActivityFeature)
        {
            IsFeatureUnavailable = true;
            FeatureUnavailableText =
                "This provider does not report live sync activity. Restart HF Drive (or update it) to see the files and folders that are currently syncing.";
            RebuildIssues();
            return;
        }

        IsFeatureUnavailable = false;
        FeatureUnavailableText = string.Empty;
        TrayRequestStamp stamp = _requestErrors.BeginRequest(connectionId, TrayRequestKind.Activity, generation);
        IsActivityLoading = true;
        UpdateActivityStateText();
        try
        {
            ListActivityResult page = await _session.SendAsync(Commands.ListActivity, new ListActivityRequest
            {
                ConnectionId = connectionId,
                Cursor = cursor,
                Limit = PageSize,
            }, cancellationToken).ConfigureAwait(true);
            // A superseded request (an older page from before a newer request
            // of this kind) is dead: it may not clear the slot's error or apply
            // page data. The current request's fresh success clears only its
            // own recorded failure and stamps the accepted page for its exact
            // connection/generation even if the selection has since moved on.
            if (!_requestErrors.IsCurrent(stamp)) return;
            if (generation == _session.Generation && !_disposed)
            {
                _requestErrors.ClearFreshSuccess(stamp);
                _activityAcceptedFor = (connectionId, generation);
            }
            if (IsStale(generation, connectionId)) return;

            // A bounded idle probe (one record slot) is recorded from the first
            // page only: a paged-away tail can be empty while earlier pages hold
            // active work, so cursor pages never count as readiness evidence.
            // Idle is proven only by an empty first page with no continuation
            // cursor; anything else is unfinished or unproven.
            if (cursor is null)
            {
                _readinessProbes[connectionId] = new TrayActivityProbe(
                    connectionId,
                    generation,
                    hasItems: page.Items.Count > 0,
                    hasMore: page.NextCursor is not null);
            }

            if (replace)
            {
                _activitySeen.Clear();
                ActivityItems.Clear();
            }
            foreach (ActivityRecord record in page.Items)
            {
                if (_activitySeen.Add(record.ActivityId))
                    ActivityItems.Add(new TrayActivityRow(record));
            }
            _activityCursor = page.NextCursor;
            HasMoreActivity = page.NextCursor is not null;
            if (cursor is not null) _activityPagedBeyondFirst = true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cancellation means the activity state is unknown again: never
            // reuse the previous success as current evidence. A superseded
            // request may not erase the newer request's recorded evidence.
            if (_requestErrors.IsCurrent(stamp) && generation == _session.Generation)
                _readinessProbes.Remove(connectionId);
        }
        catch (Exception ex)
        {
            if (generation != _session.Generation || _disposed) return;
            // A superseded request's late failure is dead on arrival: the
            // newer request's outcome stands.
            if (!_requestErrors.IsCurrent(stamp)) return;
            // A failed activity query is not evidence of idle: record the
            // failure so readiness can never celebrate on stale success, even
            // if the selection has since moved to another connection.
            _readinessProbes[connectionId] = TrayActivityProbe.FailedProbe(connectionId, generation);
            _requestErrors.RecordFailure(stamp, TrayObservedError.FromException(ex));
            if (IsStale(generation, connectionId)) return;
        }
        finally
        {
            if (_requestErrors.IsCurrent(stamp)) IsActivityLoading = false;
            RebuildIssues();
            UpdateAllSynced();
        }
    }

    private async Task LoadConflictsPageAsync(Guid connectionId, long generation, string? cursor, CancellationToken cancellationToken)
    {
        TrayRequestStamp stamp = _requestErrors.BeginRequest(connectionId, TrayRequestKind.Conflicts, generation);
        IsIssuesLoading = true;
        try
        {
            ListConflictsResult page = await _session.SendAsync(Commands.ListConflicts, new ListConflictsRequest
            {
                ConnectionId = connectionId,
                Cursor = cursor,
                Limit = PageSize,
            }, cancellationToken).ConfigureAwait(true);
            // A superseded request is dead: it may not clear the slot's error
            // or apply page data. The current request's fresh accepted page
            // (even an empty one) clears only this request's recorded failure;
            // connection and other request errors are untouched and stay
            // visible until their own data recovers.
            if (!_requestErrors.IsCurrent(stamp)) return;
            if (generation == _session.Generation && !_disposed)
                _requestErrors.ClearFreshSuccess(stamp);
            if (IsStale(generation, connectionId)) return;

            foreach (ConflictRecord record in page.Items)
            {
                if (_conflictsSeen.Add(record.ConflictId))
                    _conflictRecords.Add(record);
            }
            _conflictsCursor = page.NextCursor;
            HasMoreIssues = page.NextCursor is not null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (generation != _session.Generation || _disposed) return;
            // A superseded request's late failure is dead on arrival.
            if (!_requestErrors.IsCurrent(stamp)) return;
            _requestErrors.RecordFailure(stamp, TrayObservedError.FromException(ex));
            if (IsStale(generation, connectionId)) return;
        }
        finally
        {
            if (_requestErrors.IsCurrent(stamp)) IsIssuesLoading = false;
            RebuildIssues();
        }
    }

    private async Task LoadHistoryPageAsync(Guid connectionId, long generation, string? cursor, CancellationToken cancellationToken)
    {
        TrayRequestStamp stamp = _requestErrors.BeginRequest(connectionId, TrayRequestKind.History, generation);
        IsHistoryLoading = true;
        UpdateHistoryStateText();
        try
        {
            ListHistoryResult page = await _session.SendAsync(Commands.ListHistory, new ListHistoryRequest
            {
                ConnectionId = connectionId,
                Cursor = cursor,
                Limit = PageSize,
            }, cancellationToken).ConfigureAwait(true);
            // A superseded request is dead: it may not clear the slot's error
            // or apply page data. The current request's fresh accepted page
            // clears only this request's recorded failure.
            if (!_requestErrors.IsCurrent(stamp)) return;
            if (generation == _session.Generation && !_disposed)
                _requestErrors.ClearFreshSuccess(stamp);
            if (IsStale(generation, connectionId)) return;

            foreach (HistoryRecord record in page.Items)
            {
                if (_historySeen.Add(record.CommitId))
                    HistoryItems.Add(new TrayHistoryRow(record));
            }
            _historyCursor = page.NextCursor;
            HasMoreHistory = page.NextCursor is not null;
            _historyLoaded = true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (generation != _session.Generation || _disposed) return;
            // A superseded request's late failure is dead on arrival.
            if (!_requestErrors.IsCurrent(stamp)) return;
            _requestErrors.RecordFailure(stamp, TrayObservedError.FromException(ex));
            if (IsStale(generation, connectionId)) return;
        }
        finally
        {
            if (_requestErrors.IsCurrent(stamp)) IsHistoryLoading = false;
            RebuildIssues();
        }
    }

    private bool CanLoadMoreActivity() => HasMoreActivity && !IsActivityLoading && SelectedConnection is not null;

    [RelayCommand(CanExecute = nameof(CanLoadMoreActivity))]
    private async Task LoadMoreActivityAsync(CancellationToken cancellationToken)
    {
        if (SelectedConnection is not { } row || _activityCursor is not { } cursor) return;
        await LoadActivityPageAsync(row.Status.ConnectionId, _session.Generation, cursor, replace: false, cancellationToken).ConfigureAwait(true);
    }

    private bool CanLoadMoreHistory() => HasMoreHistory && !IsHistoryLoading && SelectedConnection is not null;

    [RelayCommand(CanExecute = nameof(CanLoadMoreHistory))]
    private async Task LoadMoreHistoryAsync(CancellationToken cancellationToken)
    {
        if (SelectedConnection is not { } row || _historyCursor is not { } cursor) return;
        await LoadHistoryPageAsync(row.Status.ConnectionId, _session.Generation, cursor, cancellationToken).ConfigureAwait(true);
    }

    private bool CanLoadMoreIssues() => HasMoreIssues && !IsIssuesLoading && SelectedConnection is not null;

    [RelayCommand(CanExecute = nameof(CanLoadMoreIssues))]
    private async Task LoadMoreIssuesAsync(CancellationToken cancellationToken)
    {
        if (SelectedConnection is not { } row || _conflictsCursor is not { } cursor) return;
        await LoadConflictsPageAsync(row.Status.ConnectionId, _session.Generation, cursor, cancellationToken).ConfigureAwait(true);
    }

    /// <summary>Explicit refresh of everything shown in the panel.</summary>
    [RelayCommand]
    private Task RefreshAsync(CancellationToken cancellationToken) => ReloadSelectionAsync(cancellationToken);

    /// <summary>
    /// One bounded poll pass for the current selection: the displayed activity
    /// page (kept intact, never destroyed by polling) plus the bounded idle
    /// probe every configured connection needs before the tray may celebrate.
    /// Called only while the panel is visible; the caller's cancellation stops it.
    /// </summary>
    public async Task PollAsync(CancellationToken cancellationToken)
    {
        if (_isPolling || _disposed) return;
        if (PanelState != TrayPanelState.Ready) return;
        long generation = _session.Generation;
        _isPolling = true;
        try
        {
            if (SelectedConnection is { } row)
            {
                Guid connectionId = row.Status.ConnectionId;
                if (!_activityPagedBeyondFirst)
                    await LoadActivityPageAsync(connectionId, generation, cursor: null, replace: true, cancellationToken).ConfigureAwait(true);
                if (IsStale(generation, connectionId)) return;
                await LoadConflictsPageAsync(connectionId, generation, cursor: null, cancellationToken).ConfigureAwait(true);
            }

            await RefreshSyncReadinessAsync(generation, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            _isPolling = false;
        }
    }

    /// <summary>
    /// Issues one bounded <c>list_activity</c> probe (<see cref="TraySyncReadiness.IdleProbeLimit"/>)
    /// per configured connection on every poll, so "no unfinished work" is
    /// current evidence for every drive independently of the displayed
    /// activity pagination. Probes are per connection and never touch the
    /// paged activity list.
    /// </summary>
    private async Task RefreshSyncReadinessAsync(long generation, CancellationToken cancellationToken)
    {
        if (_session.State != ProviderConnectionState.Ready || !_haveStatus || _statusGeneration != generation) return;

        foreach (Guid connectionId in _connectionRecords.Keys.ToList())
        {
            if (cancellationToken.IsCancellationRequested || _disposed || generation != _session.Generation) return;
            await ProbeSyncReadinessAsync(connectionId, generation, cancellationToken).ConfigureAwait(true);
        }
    }

    /// <summary>
    /// One bounded idle probe for one connection. Failures remove the probe
    /// (readiness never reuses stale success); stale responses are ignored and
    /// invalidated by the session/connection generation guards.
    /// </summary>
    private async Task ProbeSyncReadinessAsync(Guid connectionId, long generation, CancellationToken cancellationToken)
    {
        try
        {
            ListActivityResult probePage = await _session.SendAsync(Commands.ListActivity, new ListActivityRequest
            {
                ConnectionId = connectionId,
                Cursor = null,
                Limit = TraySyncReadiness.IdleProbeLimit,
            }, cancellationToken).ConfigureAwait(true);
            if (generation != _session.Generation || _disposed) return;
            if (!_connectionRecords.ContainsKey(connectionId)) return;
            _readinessProbes[connectionId] = new TrayActivityProbe(
                connectionId,
                generation,
                hasItems: probePage.Items.Count > 0,
                hasMore: probePage.NextCursor is not null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Cancelled probe: the drive's work state is unknown again, so the
            // previous result must not be reused as current evidence.
            if (generation == _session.Generation) _readinessProbes.Remove(connectionId);
        }
        catch (Exception)
        {
            if (generation != _session.Generation || _disposed) return;
            // A failed probe invalidates readiness with an explicit failure
            // rather than leaving stale success behind.
            _readinessProbes[connectionId] = TrayActivityProbe.FailedProbe(connectionId, generation);
        }
        UpdateAllSynced();
    }

    // ── Issues ──────────────────────────────────────────────────────────

    private void RebuildIssues()
    {
        IReadOnlyList<TrayIssueRow> rows = TrayIssueProjection.Build(
            _connectionRecords.Values.OrderBy(c => c.RootPath, StringComparer.OrdinalIgnoreCase).ToList(),
            _requestErrors,
            _session.Generation,
            _conflictRecords,
            ActivityItems.Select(row => row.Record).ToList(),
            SelectedConnection?.Status.ConnectionId);

        FileIssueItems.Clear();
        TrayIssueRow? connectionIssue = null;
        int connectionIssueCount = 0;
        foreach (TrayIssueRow row in rows)
        {
            if (row.Kind == TrayIssueKind.File)
            {
                FileIssueItems.Add(row);
                continue;
            }
            connectionIssue ??= row;
            connectionIssueCount++;
        }

        ConnectionIssue = connectionIssue;
        ConnectionIssueTitle = connectionIssueCount switch
        {
            0 => string.Empty,
            1 => connectionIssue!.Title,
            _ => $"{connectionIssue!.Title} (+{connectionIssueCount - 1} more)",
        };
        UpdateActivityStateText();
        UpdateHistoryStateText();
    }

    /// <summary>
    /// Recomputes the sync-activity section text from observed state only:
    /// real counts, a blocked-aware empty state and an explicit unavailable
    /// state — an empty queue while sync is blocked never looks healthy.
    /// </summary>
    private void UpdateActivityStateText()
    {
        Guid? selectedId = SelectedConnection?.Status.ConnectionId;
        bool requestFailed = !IsActivityLoading && selectedId is { } id
            && _requestErrors.FailuresFor(id, _session.Generation).Any(failure => failure.Kind == TrayRequestKind.Activity);
        bool accepted = selectedId is { } acceptedId && _activityAcceptedFor == (acceptedId, _session.Generation);
        ActivityStateText = TrayIssueProjection.ActivityStateText(
            featureAvailable: !IsFeatureUnavailable,
            responseAccepted: accepted,
            requestFailed: requestFailed,
            activityCount: ActivityItems.Count,
            activeCount: ActivityItems.Count(row => row.IsActive),
            syncBlocked: TrayIssueProjection.IsSyncBlocked(
                SelectedConnection?.Status, _requestErrors, _session.Generation,
                _conflictRecords, ActivityItems.Select(row => row.Record).ToList()));
    }

    /// <summary>
    /// Recomputes the committed-history section text from observed state only;
    /// a failed request stays visible until a fresh accepted page replaces it.
    /// </summary>
    private void UpdateHistoryStateText()
    {
        Guid? selectedId = SelectedConnection?.Status.ConnectionId;
        bool requestFailed = !IsHistoryLoading && selectedId is { } id
            && _requestErrors.FailuresFor(id, _session.Generation).Any(failure => failure.Kind == TrayRequestKind.History);
        HistoryStateText = TrayIssueProjection.HistoryStateText(HistoryItems.Count, _historyLoaded, requestFailed);
    }

    // ── All-synced evaluation ───────────────────────────────────────────

    private void UpdateAllSynced()
    {
        // Stale evidence never counts: a reconnect clears every probe, and
        // readiness also checks the probe's own session generation.
        if (_statusGeneration != _session.Generation || _session.State != ProviderConnectionState.Ready)
        {
            _readinessProbes.Clear();
        }

        var evidence = new TraySyncEvidence
        {
            HasAcceptedStatus = _haveStatus && _session.State == ProviderConnectionState.Ready,
            AccountState = _account?.State ?? AuthenticationState.SignedOut,
            SessionGeneration = _session.Generation,
            SessionMatches = _statusGeneration == _session.Generation && !_disposed,
            ActivityFeatureAvailable = HasListActivityFeature,
        };
        foreach (TrayActivityProbe probe in _readinessProbes.Values)
            evidence.SetActivityProbe(probe);

        IReadOnlyList<ConnectionStatus> statuses =
            _connectionRecords.Values.OrderBy(c => c.RootPath, StringComparer.OrdinalIgnoreCase).ToList();

        TrayReadinessResult result = TraySyncReadiness.Evaluate(statuses, evidence);
        IsAllSynced = result.Ready;
        ReadinessFailure = result.Ready ? null : result.Failure;
    }

    // ── Pause / resume and retry (real provider mutations) ──────────────

    private void UpdatePauseResume()
    {
        bool anyUnpaused = Connections.Any(c => c.Status.State != ConnectionState.WriteSyncPaused);
        PauseResumeText = anyUnpaused ? "Pause syncing" : "Resume syncing";
    }

    [RelayCommand]
    private async Task TogglePauseResumeAsync(CancellationToken cancellationToken)
    {
        if (_session.State != ProviderConnectionState.Ready || Connections.Count == 0 || IsCommandBusy) return;
        bool pause = Connections.Any(c => c.Status.State != ConnectionState.WriteSyncPaused);
        IsCommandBusy = true;
        try
        {
            if (pause)
            {
                PauseResult result = await _session.SendAsync(Commands.Pause, new PauseRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = null,
                }, cancellationToken).ConfigureAwait(true);
                LastActionText = $"Paused {result.PausedConnectionIds.Count} connection(s).";
            }
            else
            {
                ResumeResult result = await _session.SendAsync(Commands.Resume, new ResumeRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = null,
                }, cancellationToken).ConfigureAwait(true);
                LastActionText = $"Resumed {result.ResumedConnectionIds.Count} connection(s).";
            }
            await ReloadSelectionAsync(cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            LastActionText = $"Pause/resume failed: {ErrorMessage(ex)}";
        }
        finally
        {
            IsCommandBusy = false;
            UpdatePauseResume();
        }
    }

    /// <summary>Reconnects the shared session (used by the disconnected surface).</summary>
    [RelayCommand]
    private async Task ReconnectAsync(CancellationToken cancellationToken)
    {
        IsCommandBusy = true;
        try
        {
            await _session.ConnectAsync(cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            WarningText = $"Reconnect failed: {ErrorMessage(ex)}";
        }
        finally
        {
            IsCommandBusy = false;
            ApplySessionState();
        }
    }

    /// <summary>Selected connection changed: restart the per-connection loads.
    /// While the panel is hidden the load is deferred until it is shown again,
    /// so a hidden panel performs no background refresh.</summary>
    partial void OnSelectedConnectionChanged(TrayConnectionRow? value)
    {
        OnPropertyChanged(nameof(HasConnectionSelector));
        if (value is null) return;
        if (IsPanelVisible) _ = ReloadSelectionAsync(_lifetime.Token);
        else _selectionDirty = true;
    }

    /// <summary>Called by the panel when it becomes visible: performs any load
    /// deferred while hidden.</summary>
    public void EnsureSelectionLoaded()
    {
        if (_disposed) return;
        if (_selectionDirty || HistoryItems.Count == 0)
        {
            _selectionDirty = false;
            _ = ReloadSelectionAsync(_lifetime.Token);
        }
    }

    /// <summary>True while the tray panel is visible; hidden panels never poll
    /// or reload.</summary>
    public bool IsPanelVisible { get; set; }

    private static string ErrorMessage(Exception error) => error is ProtocolException protocol
        ? $"{protocol.Error.Code}: {protocol.Error.Message}"
        : error.Message;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.StateChanged -= OnSessionChanged;
        _session.StatusChanged -= OnStatusChanged;
        CancelLoad();
        _lifetime.Cancel();
        _lifetime.Dispose();
    }
}
