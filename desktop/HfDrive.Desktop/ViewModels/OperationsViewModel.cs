using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HfDrive.Desktop.Services;
using HfDrive.Protocol;
using Microsoft.UI.Dispatching;

namespace HfDrive.Desktop.ViewModels;

/// <summary>One committed history entry rendered for the Operations page.</summary>
public sealed class HistoryRow
{
    public HistoryRow(HistoryRecord record) => Record = record;

    public HistoryRecord Record { get; }

    public string Display
    {
        get
        {
            string generation = Record.Generation?.ToString() ?? "unknown";
            string parent = Record.ParentCommitId?.ToString() ?? "none (initial commit)";
            var changes = Record.Changes.Select(change =>
            {
                string parentText = change.ParentId?.ToString() ?? "root";
                return $"  {change.Kind}: \"{change.Name}\" (item {change.ItemId}, parent {parentText})";
            });
            return $"Commit {Record.CommitId}\nGeneration: {generation}\nDevice: {Record.DeviceId}\nTime (display only): {Record.CreatedAt}\nParent: {parent}\n"
                 + (Record.Changes.Count == 0 ? "  (no item changes recorded)" : string.Join("\n", changes));
        }
    }
}

/// <summary>One recorded conflict rendered for the Operations page.</summary>
public sealed class ConflictRow
{
    public ConflictRow(ConflictRecord record) => Record = record;

    public ConflictRecord Record { get; }

    public string Display =>
        $"Conflict {Record.ConflictId} — {Record.Kind} — item {Record.ItemId}\n"
      + $"Detected (display only): {Record.DetectedAt} — resolution: {Record.ResolutionState}";

    public string DetailText =>
        $"Conflict ID: {Record.ConflictId}\n"
      + $"Item ID: {Record.ItemId}\n"
      + $"Kind: {Record.Kind}\n"
      + $"Competing operations: {Join(Record.CompetingOperationIds)}\n"
      + $"Revisions: {Join(Record.Revisions)}\n"
      + $"Original names/locations: {(Record.OriginalNames.Count == 0 ? "(none recorded)" : string.Join(" | ", Record.OriginalNames))}\n"
      + $"Detected (display only): {Record.DetectedAt}\n"
      + $"Resolution state: {Record.ResolutionState}";

    private static string Join(IReadOnlyList<Guid> values) =>
        values.Count == 0 ? "(none recorded)" : string.Join(", ", values);
}

/// <summary>
/// The Operations page. Every action here is a real provider RPC over the
/// shared <see cref="ProviderSession"/>; every displayed value comes from the
/// provider's typed response or error. Nothing on this page is synthesized.
/// </summary>
public sealed partial class OperationsViewModel : ObservableObject, IDisposable
{
    /// <summary>Scope identifier the provider accepts for the six global settings.</summary>
    private const string GlobalScopeId = "global";

    private readonly ProviderSession _session;
    private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly CancellationTokenSource _lifetime = new();
    private bool _disposed;

    // Settings revision actually observed from the provider's UpdateSettings
    // empty-patch read (or from an applied update). 0 is only the starting
    // value until a read has happened.
    private ulong _settingsRevision;
    private bool _settingsRevisionKnown;

    // History paging state; the seen-set guarantees a page append never
    // repeats a commit already displayed.
    private string? _historyCursor;
    private readonly HashSet<Guid> _historySeen = new();

    // Conflict paging state; same no-repeat guarantee.
    private string? _conflictsCursor;
    private readonly HashSet<Guid> _conflictsSeen = new();

    /// <summary>
    /// Conflict id requested by the tray bridge; consumed only when an accepted
    /// provider row with exactly that id arrives (never a synthetic row).
    /// </summary>
    private Guid? _pendingConflictSelection;

    public OperationsViewModel(ProviderSession session)
    {
        _session = session;
        _session.StateChanged += OnSessionChanged;
        SessionStateText = _session.StatusText;
    }

    // ── Shared busy/error plumbing ────────────────────────────────────────

    [ObservableProperty]
    private string _sessionStateText = "Not connected";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(
        nameof(ReloadSettingsCommand), nameof(ApplySettingsCommand),
        nameof(PauseCommand), nameof(ResumeCommand),
        nameof(PinCommand), nameof(UnpinCommand),
        nameof(FreeAllCommand), nameof(FreeExceptPinnedCommand),
        nameof(ApplySelectiveSyncCommand), nameof(ExportDiagnosticsCommand),
        nameof(LoadHistoryCommand), nameof(LoadMoreHistoryCommand), nameof(RestoreCommand),
        nameof(LoadConflictsCommand), nameof(LoadMoreConflictsCommand),
        nameof(ResolveKeepLocalCommand), nameof(ResolveKeepRemoteCommand), nameof(ResolveKeepBothCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _busyText = string.Empty;

    // ── Settings ─────────────────────────────────────────────────────────

    [ObservableProperty] private string _settingsUploadBpsText = string.Empty;
    [ObservableProperty] private string _settingsDownloadBpsText = string.Empty;
    [ObservableProperty] private string _settingsTransferMemoryText = string.Empty;
    [ObservableProperty] private string _settingsRangeCacheText = string.Empty;
    [ObservableProperty] private string _settingsStagingAdmissionText = string.Empty;
    [ObservableProperty] private string _settingsMinimumFreeText = string.Empty;

    [ObservableProperty] private string _settingsRevisionText = "Revision: not read from the provider yet.";

    [ObservableProperty] private string _settingsResultText = string.Empty;

    [ObservableProperty] private string? _settingsErrorText;

    // ── Connection controls ──────────────────────────────────────────────

    [ObservableProperty] private string _connectionIdText = string.Empty;
    [ObservableProperty] private string _controlItemIdText = string.Empty;
    [ObservableProperty] private string _selectiveSyncItemIdsText = string.Empty;
    [ObservableProperty] private string _connectionResultText = string.Empty;
    [ObservableProperty] private string? _connectionErrorText;

    // ── Diagnostics ─────────────────────────────────────────────────────

    [ObservableProperty] private string _diagnosticsPathText = string.Empty;
    [ObservableProperty] private string _diagnosticsResultText = string.Empty;
    [ObservableProperty] private string? _diagnosticsErrorText;

    // ── History and restore ─────────────────────────────────────────────

    [ObservableProperty] private string _historyItemIdText = string.Empty;
    [ObservableProperty] private string _restoreItemIdText = string.Empty;
    [ObservableProperty] private string _restoreVersionIdText = string.Empty;
    [ObservableProperty] private string _historyResultText = string.Empty;
    [ObservableProperty] private string? _historyErrorText;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreHistoryCommand))]
    private bool _hasMoreHistory;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(
        nameof(ResolveKeepLocalCommand), nameof(ResolveKeepRemoteCommand), nameof(ResolveKeepBothCommand))]
    private ConflictRow? _selectedConflict;

    public ObservableCollection<HistoryRow> History { get; } = new();

    // ── Conflicts ───────────────────────────────────────────────────────

    [ObservableProperty] private string _conflictsResultText = string.Empty;
    [ObservableProperty] private string? _conflictsErrorText;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreConflictsCommand))]
    private bool _hasMoreConflicts;

    public ObservableCollection<ConflictRow> Conflicts { get; } = new();

    /// <summary>Detail text for the selected conflict; explicit selection is required to resolve.</summary>
    public string SelectedConflictDetailText { get; private set; } =
        "Select a conflict record to see its kind, competing operations, revisions and original names.";

    partial void OnSelectedConflictChanged(ConflictRow? value)
    {
        SelectedConflictDetailText = value is null
            ? "Select a conflict record to see its kind, competing operations, revisions and original names."
            : value.DetailText;
        OnPropertyChanged(nameof(SelectedConflictDetailText));
    }

    // ── Stale-response suppression ───────────────────────────────────────

    private long BeginScope() => _session.Generation;

    private bool IsScopeStale(long scope) => scope != _session.Generation;

    // ── Settings commands ────────────────────────────────────────────────

    [RelayCommand]
    private Task ReloadSettingsAsync(CancellationToken cancellationToken) =>
        ReadSettingsAsync(true, cancellationToken);

    /// <summary>
    /// Reads the provider's actual settings revision and resolved values once,
    /// the first time the Operations page is opened. Later navigations reuse
    /// the tracked revision; "Reload settings" refetches it explicitly.
    /// </summary>
    public Task EnsureSettingsLoadedAsync() =>
        _settingsRevisionKnown || IsBusy
            ? Task.CompletedTask
            : ReadSettingsAsync(false, CancellationToken.None);

    private async Task ReadSettingsAsync(bool isReload, CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Reading current settings from the provider…";
        SettingsErrorText = null;
        try
        {
            UpdateSettingsResult result = await _session.SendAsync(
                Commands.UpdateSettings,
                new UpdateSettingsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ScopeId = GlobalScopeId,
                    ExpectedRevision = _settingsRevisionKnown ? _settingsRevision : 0,
                    Settings = Array.Empty<SettingsPatch>(),
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ApplySettingsResult(result);
            SettingsResultText = isReload
                ? "Settings reloaded from the provider (empty patch; nothing was changed)."
                : "Current settings read from the provider (empty patch; nothing was changed).";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                SettingsErrorText = ErrorMessage(ex);
                SettingsResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    private void ApplySettingsResult(UpdateSettingsResult result)
    {
        _settingsRevision = result.Revision;
        _settingsRevisionKnown = true;
        SettingsRevisionText = $"Revision: {result.Revision} (expected revision for the next update).";
        SettingsUploadBpsText = ValueOf(result.Settings, "upload_bytes_per_second");
        SettingsDownloadBpsText = ValueOf(result.Settings, "download_bytes_per_second");
        SettingsTransferMemoryText = ValueOf(result.Settings, "transfer_memory_bytes");
        SettingsRangeCacheText = ValueOf(result.Settings, "range_cache_bytes");
        SettingsStagingAdmissionText = ValueOf(result.Settings, "staging_admission_bytes");
        SettingsMinimumFreeText = ValueOf(result.Settings, "minimum_free_bytes");
    }

    private static string ValueOf(IReadOnlyList<SettingsEntry> settings, string key) =>
        settings.FirstOrDefault(entry => entry.Key == key)?.ValueJson ?? string.Empty;

    [RelayCommand]
    private async Task ApplySettingsAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        var patch = new List<SettingsPatch>();
        var error = CollectSetting(SettingsUploadBpsText, "upload_bytes_per_second", patch)
                 ?? CollectSetting(SettingsDownloadBpsText, "download_bytes_per_second", patch)
                 ?? CollectSetting(SettingsTransferMemoryText, "transfer_memory_bytes", patch)
                 ?? CollectSetting(SettingsRangeCacheText, "range_cache_bytes", patch)
                 ?? CollectSetting(SettingsStagingAdmissionText, "staging_admission_bytes", patch)
                 ?? CollectSetting(SettingsMinimumFreeText, "minimum_free_bytes", patch);
        if (error is not null)
        {
            SettingsErrorText = error;
            SettingsResultText = string.Empty;
            return;
        }
        if (patch.Count == 0)
        {
            SettingsErrorText = "Enter at least one nonnegative integer value to update.";
            SettingsResultText = string.Empty;
            return;
        }
        if (!_settingsRevisionKnown)
        {
            SettingsErrorText = "Read the current settings first so the expected revision is known.";
            SettingsResultText = string.Empty;
            return;
        }

        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Applying settings…";
        SettingsErrorText = null;
        try
        {
            UpdateSettingsResult result = await _session.SendAsync(
                Commands.UpdateSettings,
                new UpdateSettingsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ScopeId = GlobalScopeId,
                    ExpectedRevision = _settingsRevision,
                    Settings = patch,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ApplySettingsResult(result);
            SettingsResultText =
                $"Applied revision {result.Revision}. Resolved settings: {Describe(result.Settings)}";
        }
        catch (ProtocolException ex) when (ex.Error.Code == ProtocolErrorCode.Conflict)
        {
            if (IsScopeStale(scope)) return;
            await ReloadAfterConflictAsync(scope, request.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                SettingsErrorText = ErrorMessage(ex);
                SettingsResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    /// <summary>
    /// A revision conflict means another client changed the settings. Reload
    /// them through the same UpdateSettings empty-patch read and show the
    /// actual revision plus resolved values so the user can reapply.
    /// </summary>
    private async Task ReloadAfterConflictAsync(long scope, CancellationToken cancellationToken)
    {
        ulong expected = _settingsRevision;
        BusyText = "Settings changed elsewhere; reloading the actual revision and values…";
        try
        {
            UpdateSettingsResult reloaded = await _session.SendAsync(
                Commands.UpdateSettings,
                new UpdateSettingsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ScopeId = GlobalScopeId,
                    ExpectedRevision = 0,
                    Settings = Array.Empty<SettingsPatch>(),
                },
                cancellationToken).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ApplySettingsResult(reloaded);
            SettingsErrorText =
                $"Settings changed since they were loaded (expected revision {expected}); the update was not applied.";
            SettingsResultText =
                $"Reloaded actual revision {reloaded.Revision}. Resolved settings: {Describe(reloaded.Settings)}";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
                SettingsErrorText = $"The settings update hit a revision conflict (expected {expected}) and the reload also failed: {ErrorMessage(ex)}";
        }
    }

    private static string? CollectSetting(string text, string key, List<SettingsPatch> patch)
    {
        string trimmed = text.Trim();
        if (trimmed.Length == 0) return null;
        if (!ulong.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out ulong value))
            return $"{key} must be a nonnegative integer (decimal digits only); \"{trimmed}\" is not one.";
        // Canonical decimal JSON number (no leading zeros) as required for u64 values.
        patch.Add(new SettingsPatch { Key = key, ValueJson = value.ToString(CultureInfo.InvariantCulture) });
        return null;
    }

    private static string Describe(IReadOnlyList<SettingsEntry> settings) =>
        settings.Count == 0
            ? "(no keys stored)"
            : string.Join(", ", settings.Select(entry => $"{entry.Key}={entry.ValueJson}"));

    // ── Connection controls ──────────────────────────────────────────────

    [RelayCommand]
    private Task PauseAsync(CancellationToken cancellationToken) =>
        PauseResumeAsync(pause: true, cancellationToken);

    [RelayCommand]
    private Task ResumeAsync(CancellationToken cancellationToken) =>
        PauseResumeAsync(pause: false, cancellationToken);

    private async Task PauseResumeAsync(bool pause, CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadOptionalConnectionId(out Guid? connectionId, out string? error))
        {
            ConnectionErrorText = error;
            ConnectionResultText = string.Empty;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = pause ? "Pausing… " : "Resuming…";
        ConnectionErrorText = null;
        try
        {
            if (pause)
            {
                PauseResult result = await _session.SendAsync(
                    Commands.Pause,
                    new PauseRequest { OperationId = Guid.NewGuid(), ConnectionId = connectionId },
                    request.Token).ConfigureAwait(true);
                if (IsScopeStale(scope)) return;
                ConnectionResultText = result.PausedConnectionIds.Count == 0
                    ? "Pause accepted; the provider reported no connections entering the paused state."
                    : $"Paused connections: {string.Join(", ", result.PausedConnectionIds)}";
            }
            else
            {
                ResumeResult result = await _session.SendAsync(
                    Commands.Resume,
                    new ResumeRequest { OperationId = Guid.NewGuid(), ConnectionId = connectionId },
                    request.Token).ConfigureAwait(true);
                if (IsScopeStale(scope)) return;
                ConnectionResultText = result.ResumedConnectionIds.Count == 0
                    ? "Resume accepted; the provider reported no connections leaving the paused state."
                    : $"Resumed connections: {string.Join(", ", result.ResumedConnectionIds)}";
            }
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConnectionErrorText = ErrorMessage(ex);
                ConnectionResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand]
    private Task PinAsync(CancellationToken cancellationToken) => SetPinAsync(PinMode.Pin, cancellationToken);

    [RelayCommand]
    private Task UnpinAsync(CancellationToken cancellationToken) => SetPinAsync(PinMode.Unpin, cancellationToken);

    private async Task SetPinAsync(PinMode mode, CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            ConnectionErrorText = connectionError;
            ConnectionResultText = string.Empty;
            return;
        }
        if (!TryReadOptionalId(ControlItemIdText, "item ID", out Guid? itemId, out string? itemError))
        {
            ConnectionErrorText = itemError;
            ConnectionResultText = string.Empty;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = mode == PinMode.Pin ? "Pinning…" : "Unpinning…";
        ConnectionErrorText = null;
        try
        {
            SetPinResult result = await _session.SendAsync(
                Commands.SetPin,
                new SetPinRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    ItemId = itemId,
                    Mode = mode,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ConnectionResultText =
                $"Pin state: {result.PinState}. Files fully hydrated for the pin: {result.PinnedFiles}.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConnectionErrorText = ErrorMessage(ex);
                ConnectionResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand]
    private Task FreeAllAsync(CancellationToken cancellationToken) => FreeSpaceAsync(FreeSpaceMode.All, cancellationToken);

    [RelayCommand]
    private Task FreeExceptPinnedAsync(CancellationToken cancellationToken) =>
        FreeSpaceAsync(FreeSpaceMode.ExceptPinned, cancellationToken);

    private async Task FreeSpaceAsync(FreeSpaceMode mode, CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            ConnectionErrorText = connectionError;
            ConnectionResultText = string.Empty;
            return;
        }
        if (!TryReadOptionalId(ControlItemIdText, "item ID", out Guid? itemId, out string? itemError))
        {
            ConnectionErrorText = itemError;
            ConnectionResultText = string.Empty;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = mode == FreeSpaceMode.All ? "Freeing local space…" : "Freeing local space except pinned…";
        ConnectionErrorText = null;
        try
        {
            FreeSpaceResult result = await _session.SendAsync(
                Commands.FreeSpace,
                new FreeSpaceRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    ItemId = itemId,
                    Mode = mode,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ConnectionResultText =
                $"Freed {result.FreedBytes.ToString(CultureInfo.InvariantCulture)} logical bytes "
              + $"from {result.DehydratedFiles.ToString(CultureInfo.InvariantCulture)} dehydrated files.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConnectionErrorText = ErrorMessage(ex);
                ConnectionResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand]
    private async Task ApplySelectiveSyncAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            ConnectionErrorText = connectionError;
            ConnectionResultText = string.Empty;
            return;
        }
        var exclusions = new List<Guid>();
        foreach (string token in SelectiveSyncItemIdsText.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' },
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!Guid.TryParseExact(token, "D", out Guid item))
            {
                ConnectionErrorText =
                    $"\"{token}\" is not a complete UUID (8-4-4-4-12 hex). Enter the full selective-exclusion item IDs.";
                ConnectionResultText = string.Empty;
                return;
            }
            exclusions.Add(item);
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Applying selective-sync exclusions…";
        ConnectionErrorText = null;
        try
        {
            SetSelectiveSyncResult result = await _session.SendAsync(
                Commands.SetSelectiveSync,
                new SetSelectiveSyncRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    ExcludeItemIds = exclusions,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ConnectionResultText =
                $"Effective exclusions: {JoinIds(result.ExcludedItemIds)}\n"
              + $"Items retained locally because they hold unsynchronized work: {JoinIds(result.RetainedDirtyItemIds)}";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConnectionErrorText = ErrorMessage(ex);
                ConnectionResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    private static string JoinIds(IReadOnlyList<Guid> values) =>
        values.Count == 0 ? "(none)" : string.Join(", ", values);

    // ── Diagnostics ─────────────────────────────────────────────────────

    [RelayCommand]
    private async Task ExportDiagnosticsAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        string destination = DiagnosticsPathText.Trim();
        if (destination.Length == 0 || !Path.IsPathFullyQualified(destination))
        {
            DiagnosticsErrorText = "Enter an absolute destination path for the diagnostics archive.";
            DiagnosticsResultText = string.Empty;
            return;
        }
        Guid? connectionId = null;
        if (ConnectionIdText.Trim().Length != 0)
        {
            if (!TryReadConnectionId(out Guid parsed, out string? error))
            {
                DiagnosticsErrorText = error;
                DiagnosticsResultText = string.Empty;
                return;
            }
            connectionId = parsed;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Exporting diagnostics…";
        DiagnosticsErrorText = null;
        try
        {
            ExportDiagnosticsResult result = await _session.SendAsync(
                Commands.ExportDiagnostics,
                new ExportDiagnosticsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    DestinationPath = destination,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            DiagnosticsResultText =
                $"Diagnostics archive written to: {result.ArchivePath}\n"
              + $"Redacted (stable per-export aliases applied to user paths/names): {(result.Redacted ? "yes" : "no")}";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                DiagnosticsErrorText = ErrorMessage(ex);
                DiagnosticsResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    // ── History and restore ─────────────────────────────────────────────

    [RelayCommand]
    private Task LoadHistoryAsync(CancellationToken cancellationToken) =>
        LoadHistoryCoreAsync(replace: true, cancellationToken);

    [RelayCommand(CanExecute = nameof(CanLoadMoreHistory))]
    private Task LoadMoreHistoryAsync(CancellationToken cancellationToken) =>
        LoadHistoryCoreAsync(replace: false, cancellationToken);

    private bool CanLoadMoreHistory() => !IsBusy && HasMoreHistory;

    private async Task LoadHistoryCoreAsync(bool replace, CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            HistoryErrorText = connectionError;
            HistoryResultText = string.Empty;
            return;
        }
        if (!TryReadOptionalId(HistoryItemIdText, "subtree item ID", out Guid? itemId, out string? itemError))
        {
            HistoryErrorText = itemError;
            HistoryResultText = string.Empty;
            return;
        }
        if (replace)
        {
            _historyCursor = null;
            _historySeen.Clear();
            History.Clear();
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Loading history…";
        HistoryErrorText = null;
        try
        {
            ListHistoryResult result = await _session.SendAsync(
                Commands.ListHistory,
                new ListHistoryRequest
                {
                    ConnectionId = connectionId,
                    ItemId = itemId,
                    Cursor = replace ? null : _historyCursor,
                    Limit = ProtocolConstants.MaxPageLimit,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            int added = 0;
            foreach (HistoryRecord record in result.Items)
            {
                if (_historySeen.Add(record.CommitId))
                {
                    History.Add(new HistoryRow(record));
                    added++;
                }
            }
            _historyCursor = result.NextCursor;
            HasMoreHistory = result.NextCursor is not null;
            HistoryResultText =
                $"Loaded {result.Items.Count.ToString(CultureInfo.InvariantCulture)} records "
              + $"({added.ToString(CultureInfo.InvariantCulture)} new; duplicates are never re-shown). "
              + (result.NextCursor is null
                    ? "No further pages."
                    : $"Next cursor: {result.NextCursor}");
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                HistoryErrorText = ErrorMessage(ex);
                HistoryResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand]
    private async Task RestoreAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            HistoryErrorText = connectionError;
            HistoryResultText = string.Empty;
            return;
        }
        if (!Guid.TryParseExact(RestoreItemIdText.Trim(), "D", out Guid itemId))
        {
            HistoryErrorText = "Enter the complete item UUID (8-4-4-4-12 hex) to restore.";
            HistoryResultText = string.Empty;
            return;
        }
        if (!Guid.TryParseExact(RestoreVersionIdText.Trim(), "D", out Guid versionId))
        {
            HistoryErrorText = "Enter the complete version UUID (8-4-4-4-12 hex) to restore.";
            HistoryResultText = string.Empty;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Restoring…";
        HistoryErrorText = null;
        try
        {
            RestoreResult result = await _session.SendAsync(
                Commands.Restore,
                new RestoreRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    ItemId = itemId,
                    VersionId = versionId,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ConnectionStatus status = result.Status;
            HistoryResultText =
                $"Restore accepted. Operation ID: {result.OperationId}\n"
              + $"Connection state: {StatusDisplayText.Get(status.State)} — "
              + $"{status.PendingFiles} pending, {status.DirtyFiles} dirty, {status.ConflictFiles} conflicts, "
              + $"{status.OnlineOnlyFiles} online-only, {status.PinnedFiles} pinned.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                HistoryErrorText = ErrorMessage(ex);
                HistoryResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    // ── Conflicts ───────────────────────────────────────────────────────

    [RelayCommand]
    private Task LoadConflictsAsync(CancellationToken cancellationToken) =>
        LoadConflictsCoreAsync(replace: true, cancellationToken);

    [RelayCommand(CanExecute = nameof(CanLoadMoreConflicts))]
    private Task LoadMoreConflictsAsync(CancellationToken cancellationToken) =>
        LoadConflictsCoreAsync(replace: false, cancellationToken);

    private bool CanLoadMoreConflicts() => !IsBusy && HasMoreConflicts;

    /// <summary>Outcome of one conflicts page load; the tray bridge's bounded
    /// search continues only on <see cref="Loaded"/>.</summary>
    private enum ConflictsPageResult { NotLoaded, Loaded, EndOfPages }

    private async Task<ConflictsPageResult> LoadConflictsCoreAsync(bool replace, CancellationToken cancellationToken)
    {
        if (IsBusy) return ConflictsPageResult.NotLoaded;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            ConflictsErrorText = connectionError;
            ConflictsResultText = string.Empty;
            return ConflictsPageResult.NotLoaded;
        }
        if (replace)
        {
            _conflictsCursor = null;
            _conflictsSeen.Clear();
            Conflicts.Clear();
            SelectedConflict = null;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Loading conflicts…";
        ConflictsErrorText = null;
        try
        {
            ListConflictsResult result = await _session.SendAsync(
                Commands.ListConflicts,
                new ListConflictsRequest
                {
                    ConnectionId = connectionId,
                    Cursor = replace ? null : _conflictsCursor,
                    Limit = ProtocolConstants.MaxPageLimit,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return ConflictsPageResult.NotLoaded;
            int added = 0;
            foreach (ConflictRecord record in result.Items)
            {
                if (_conflictsSeen.Add(record.ConflictId))
                {
                    Conflicts.Add(new ConflictRow(record));
                    added++;
                }
            }
            _conflictsCursor = result.NextCursor;
            HasMoreConflicts = result.NextCursor is not null;
            ConflictsResultText =
                $"Loaded {result.Items.Count.ToString(CultureInfo.InvariantCulture)} records "
              + $"({added.ToString(CultureInfo.InvariantCulture)} new; duplicates are never re-shown). "
              + (result.NextCursor is null ? "No further pages." : $"Next cursor: {result.NextCursor}");
            TryApplyPendingConflictSelection();
            return result.NextCursor is null ? ConflictsPageResult.EndOfPages : ConflictsPageResult.Loaded;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { return ConflictsPageResult.NotLoaded; }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConflictsErrorText = ErrorMessage(ex);
                ConflictsResultText = string.Empty;
            }
            return ConflictsPageResult.NotLoaded;
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    [RelayCommand(CanExecute = nameof(CanResolve))]
    private Task ResolveKeepLocalAsync(CancellationToken cancellationToken) =>
        ResolveAsync(ConflictResolution.KeepLocal, cancellationToken);

    [RelayCommand(CanExecute = nameof(CanResolve))]
    private Task ResolveKeepRemoteAsync(CancellationToken cancellationToken) =>
        ResolveAsync(ConflictResolution.KeepRemote, cancellationToken);

    [RelayCommand(CanExecute = nameof(CanResolve))]
    private Task ResolveKeepBothAsync(CancellationToken cancellationToken) =>
        ResolveAsync(ConflictResolution.KeepBoth, cancellationToken);

    /// <summary>Resolution is impossible without a selected conflict record.</summary>
    private bool CanResolve() => !IsBusy && SelectedConflict is not null;

    private async Task ResolveAsync(ConflictResolution resolution, CancellationToken cancellationToken)
    {
        if (IsBusy || SelectedConflict is not { } selected) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            ConflictsErrorText = connectionError;
            ConflictsResultText = string.Empty;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        Guid conflictId = selected.Record.ConflictId;
        IsBusy = true;
        BusyText = $"Resolving conflict ({resolution})…";
        ConflictsErrorText = null;
        try
        {
            ResolveConflictResult result = await _session.SendAsync(
                Commands.ResolveConflict,
                new ResolveConflictRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    ConflictId = conflictId,
                    Resolution = resolution,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            // Reflect the provider's real resulting resolution state in the row
            // and the detail pane, not just the result line.
            ConflictRecord updated = selected.Record with { ResolutionState = result.ResolutionState };
            int index = Conflicts.IndexOf(selected);
            if (index >= 0)
            {
                var row = new ConflictRow(updated);
                Conflicts[index] = row;
                SelectedConflict = row;
            }
            ConflictsResultText =
                $"Conflict {result.ConflictId}: resolution state is now {result.ResolutionState}.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                ConflictsErrorText = ErrorMessage(ex);
                ConflictsResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    // ── Tray bridge (typed, explicit; no automatic resolution) ──────────

    /// <summary>
    /// Scopes every connection-scoped operation on this surface to the given
    /// connection (the same <see cref="ConnectionIdText"/> the page already
    /// binds), optionally paging the real conflict records until the exact
    /// conflict id arrives and selecting that accepted row for the user to
    /// resolve explicitly. Only provider-returned rows are ever selected; if
    /// the id is not in the records the result is an honest message and no
    /// selection. Each request is bounded to the wire page limit (200 rows);
    /// the search itself has no total narrowing — it continues until the exact
    /// row is found, the provider reports a terminal cursor, the request is
    /// cancelled or superseded by a newer scoped request, or a page fails or
    /// reports the list busy.
    /// </summary>
    /// <returns>True when the conflict row was found and selected.</returns>
    public async Task<bool> LoadConflictsForConnectionAsync(Guid connectionId, Guid? conflictId, CancellationToken cancellationToken)
    {
        // Same exact "D" format TryParseExact requires (8-4-4-4-12 hex).
        ConnectionIdText = connectionId.ToString("D");
        _pendingConflictSelection = conflictId;
        if (conflictId is null)
        {
            await LoadConflictsCoreAsync(replace: true, cancellationToken).ConfigureAwait(true);
            return false;
        }

        bool anyPageLoaded = false;
        ConflictsPageResult lastOutcome = ConflictsPageResult.NotLoaded;
        while (!cancellationToken.IsCancellationRequested)
        {
            lastOutcome = await LoadConflictsCoreAsync(replace: !anyPageLoaded, cancellationToken).ConfigureAwait(true);
            if (lastOutcome == ConflictsPageResult.Loaded) anyPageLoaded = true;
            if (SelectedConflict is { } selected && selected.Record.ConflictId == conflictId.Value)
                return true;
            if (lastOutcome != ConflictsPageResult.Loaded)
                break;
        }

        // Terminal end: never fabricate a selection. The pending id is dropped
        // so a later manual load cannot silently select a stale target; a newer
        // scoped request owns the pending id and gets no message here. On
        // cancellation the existing guards already stop quietly.
        if (_pendingConflictSelection == conflictId)
        {
            _pendingConflictSelection = null;
            if (!cancellationToken.IsCancellationRequested)
            {
                ConflictsErrorText = lastOutcome switch
                {
                    ConflictsPageResult.EndOfPages =>
                        $"Conflict {conflictId} is not in this connection's conflict records; it may already be resolved.",
                    _ => anyPageLoaded
                        ? $"Loading conflicts stopped before conflict {conflictId} was found (a request failed or the list is busy). Open Manage again to resume the search."
                        : "The conflicts list is busy or failed to load; open Manage again to select this conflict.",
                };
            }
        }
        return false;
    }

    /// <summary>
    /// Selects the pending tray-requested conflict id when an accepted provider
    /// row with exactly that id is present; never selects by index or fabricates
    /// a row. Clears the pending id once matched so repeated loads do not steal
    /// the user's later explicit selection.
    /// </summary>
    private void TryApplyPendingConflictSelection()
    {
        if (_pendingConflictSelection is not { } wanted) return;
        foreach (ConflictRow row in Conflicts)
        {
            if (row.Record.ConflictId == wanted)
            {
                _pendingConflictSelection = null;
                SelectedConflict = row;
                return;
            }
        }
    }

    // ── Shared helpers ───────────────────────────────────────────────────

    /// <summary>Required connection UUID; every connection-scoped action uses this.</summary>
    private bool TryReadConnectionId(out Guid connectionId, out string? error)
    {
        if (TryParseExact(ConnectionIdText, "connection UUID", out Guid parsed, out error))
        {
            connectionId = parsed;
            return true;
        }
        connectionId = Guid.Empty;
        return false;
    }

    /// <summary>
    /// Optional connection UUID for Pause/Resume; leaving the field empty lets
    /// the provider pause or resume every connection (ConnectionId null).
    /// </summary>
    private bool TryReadOptionalConnectionId(out Guid? connectionId, out string? error)
    {
        if (ConnectionIdText.Trim().Length == 0)
        {
            connectionId = null;
            error = null;
            return true;
        }
        if (TryParseExact(ConnectionIdText, "connection UUID", out Guid parsed, out error))
        {
            connectionId = parsed;
            return true;
        }
        connectionId = null;
        return false;
    }

    private static bool TryParseExact(string text, string label, out Guid value, out string? error)
    {
        string trimmed = text.Trim();
        if (!Guid.TryParseExact(trimmed, "D", out value))
        {
            error = $"\"{trimmed}\" is not a complete {label} (8-4-4-4-12 hex).";
            return false;
        }
        error = null;
        return true;
    }

    private static bool TryReadOptionalId(string text, string label, out Guid? id, out string? error)
    {
        string trimmed = text.Trim();
        if (trimmed.Length == 0)
        {
            id = null;
            error = null;
            return true;
        }
        if (!Guid.TryParseExact(trimmed, "D", out Guid parsed))
        {
            id = null;
            error = $"\"{trimmed}\" is not a complete {label} (8-4-4-4-12 hex).";
            return false;
        }
        id = parsed;
        error = null;
        return true;
    }

    private static string ErrorMessage(Exception error) => error is ProtocolException protocol
        ? $"{protocol.Error.Code}: {protocol.Error.Message}"
        : error.Message;

    // ── Session events (marshalled through the DispatcherQueue) ──────────

    private void OnSessionChanged(object? sender, EventArgs args) =>
        _dispatcher.TryEnqueue(() =>
        {
            if (_disposed) return;
            SessionStateText = _session.StatusText;
        });

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.StateChanged -= OnSessionChanged;
        _lifetime.Cancel();
        _lifetime.Dispose();
    }
}
