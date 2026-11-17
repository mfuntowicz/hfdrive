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

/// <summary>One file affected by a removal preview, rendered on the Operations page.</summary>
public sealed class UnlinkFileRow
{
    public UnlinkFileRow(UnlinkFileResult file) => File = file;

    public UnlinkFileResult File { get; }

    public string Display =>
        $"{File.Path} — {ConnectionViewModel.FormatBytes(File.Size)} ({(File.Partial ? "partially resident" : "not resident")})";
}

/// <summary>One removal mode offered by the remove-connection section.</summary>
public sealed record UnlinkModeChoice(UnlinkMode Mode, string Display);

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
        _selectedUnlinkMode = UnlinkModes[0];
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
        nameof(ResolveKeepLocalCommand), nameof(ResolveKeepRemoteCommand), nameof(ResolveKeepBothCommand),
        nameof(ConfirmUnlinkCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _busyText = string.Empty;

    // ── Settings ─────────────────────────────────────────────────────────

    // Draft text exactly as the user typed it (or as the provider's stored
    // value formats). A reload never silently overwrites a dirty draft.
    [ObservableProperty] private string _settingsUploadBpsText = string.Empty;
    [ObservableProperty] private string _settingsDownloadBpsText = string.Empty;
    [ObservableProperty] private string _settingsTransferMemoryText = string.Empty;
    [ObservableProperty] private string _settingsRangeCacheText = string.Empty;
    [ObservableProperty] private string _settingsStagingAdmissionText = string.Empty;
    [ObservableProperty] private string _settingsMinimumFreeText = string.Empty;

    [ObservableProperty] private string _settingsRevisionText = "Revision: not read yet.";

    [ObservableProperty] private string _settingsResultText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSettingsErrorText))]
    private string? _settingsErrorText;

    /// <summary>True once the provider's actual settings and revision are known for this session.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplySettingsCommand))]
    [NotifyPropertyChangedFor(nameof(IsSettingsEditingEnabled), nameof(SettingsNotReadyText), nameof(HasSettingsNotReadyText))]
    private bool _isSettingsReady;

    /// <summary>True while any field differs from the last observed provider value.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApplySettingsCommand))]
    [NotifyPropertyChangedFor(nameof(SettingsDirtyText))]
    private bool _isSettingsDirty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ReloadSettingsCommand), nameof(ApplySettingsCommand))]
    private bool _settingsHasError;

    [ObservableProperty] private bool _settingsHasSuccess;

    /// <summary>Fields are editable only with observed values and no busy work.</summary>
    public bool IsSettingsEditingEnabled => IsSettingsReady && !IsBusy;

    public string SettingsNotReadyText => IsSettingsReady
        ? string.Empty
        : "The values below are not loaded yet. Use Reload settings to read them.";

    /// <summary>True while the not-ready notice should take footer space.</summary>
    public bool HasSettingsNotReadyText => SettingsNotReadyText.Length != 0;

    /// <summary>True while a save/reload feedback message should take footer space.</summary>
    public bool HasSettingsResultText => SettingsResultText.Length != 0;

    /// <summary>True while a provider error should take footer space.</summary>
    public bool HasSettingsErrorText => !string.IsNullOrEmpty(SettingsErrorText);

    public string SettingsDirtyText => IsSettingsDirty
        ? "You have unsaved changes."
        : "No unsaved changes.";

    public string SettingsRateExamplesText =>
        $"Examples: 10 MiB/s, 250 KiB/s, {SettingsQuantity.UnlimitedWord} (= 0, no limit). Plain digits mean bytes per second.";

    public string SettingsSizeExamplesText =>
        "Examples: 512 MiB, 10 GiB, 0 B. Units are binary (IEC): 1 KiB = 1024 B; B, KiB, MiB, GiB, TiB.";

    /// <summary>Provider values as last observed; null when the provider has no stored entry for the key.</summary>
    private readonly Dictionary<string, ulong?> _settingsLoadedValues = new();

    /// <summary>Session generation the loaded settings belong to; a change invalidates readiness.</summary>
    private long _settingsReadGeneration = -1;

    private bool _settingsWriteInFlight;
    private int _settingsOpSerial;

    /// <summary>The six provider-wide settings keys, in display order.</summary>
    private static readonly string[] SettingsKeys =
    {
        "upload_bytes_per_second", "download_bytes_per_second", "transfer_memory_bytes",
        "range_cache_bytes", "staging_admission_bytes", "minimum_free_bytes",
    };

    /// <summary>Draft text for one settings key.</summary>
    private string SettingsTextFor(string key) => key switch
    {
        "upload_bytes_per_second" => SettingsUploadBpsText,
        "download_bytes_per_second" => SettingsDownloadBpsText,
        "transfer_memory_bytes" => SettingsTransferMemoryText,
        "range_cache_bytes" => SettingsRangeCacheText,
        "staging_admission_bytes" => SettingsStagingAdmissionText,
        "minimum_free_bytes" => SettingsMinimumFreeText,
        _ => string.Empty,
    };

    /// <summary>Writes one field's draft text through the generated property.</summary>
    private void SetSettingsText(string key, string text)
    {
        switch (key)
        {
            case "upload_bytes_per_second": SettingsUploadBpsText = text; break;
            case "download_bytes_per_second": SettingsDownloadBpsText = text; break;
            case "transfer_memory_bytes": SettingsTransferMemoryText = text; break;
            case "range_cache_bytes": SettingsRangeCacheText = text; break;
            case "staging_admission_bytes": SettingsStagingAdmissionText = text; break;
            case "minimum_free_bytes": SettingsMinimumFreeText = text; break;
        }
    }

    /// <summary>Human label for one settings key.</summary>
    private static string LabelFor(string key) => key switch
    {
        "upload_bytes_per_second" => "Upload speed",
        "download_bytes_per_second" => "Download speed",
        "transfer_memory_bytes" => "Transfer memory",
        "range_cache_bytes" => "Range cache size",
        "staging_admission_bytes" => "Staging limit",
        "minimum_free_bytes" => "Free space reserve",
        _ => key,
    };

    /// <summary>Only the two transfer speeds accept "Unlimited" (zero means no limit).</summary>
    private static SettingsQuantityKind KindFor(string key) =>
        key is "upload_bytes_per_second" or "download_bytes_per_second"
            ? SettingsQuantityKind.Rate
            : SettingsQuantityKind.Size;

    // ── Connection controls ──────────────────────────────────────────────

    [ObservableProperty] private string _connectionIdText = string.Empty;
    [ObservableProperty] private string _controlItemIdText = string.Empty;
    [ObservableProperty] private string _selectiveSyncItemIdsText = string.Empty;
    [ObservableProperty] private string _connectionResultText = string.Empty;
    [ObservableProperty] private string? _connectionErrorText;

    partial void OnConnectionIdTextChanged(string value) => InvalidateUnlinkPreview("The connection ID changed; prepare the removal preview again.");

    // ── Remove connection ────────────────────────────────────────────────

    /// <summary>
    /// Removal modes the user can choose explicitly. Safe remove is first and
    /// default; the lossy mode is only ever selected deliberately.
    /// </summary>
    public IReadOnlyList<UnlinkModeChoice> UnlinkModes { get; } = new[]
    {
        new UnlinkModeChoice(UnlinkMode.SafeRemove,
            "Safe remove — hydrate or export every file first, then remove the connection"),
        new UnlinkModeChoice(UnlinkMode.RemoveUnavailable,
            "Remove unavailable too — discard bytes that cannot be made resident (irreversible local loss)"),
    };

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConfirmUnlinkCommand))]
    [NotifyPropertyChangedFor(nameof(UnlinkPreviewVisibility), nameof(HasUnlinkResultText))]
    private UnlinkModeChoice _selectedUnlinkMode;

    /// <summary>
    /// Preview returned by the provider for the currently displayed mode. It
    /// is invalidated whenever the reviewed inputs (connection, mode or
    /// provider session) change and on <c>PreviewChanged</c>.
    /// </summary>
    private PrepareUnlinkResult? _unlinkPreview;

    /// <summary>Session generation the preview was produced under.</summary>
    private long _unlinkPreviewGeneration = -1;

    /// <summary>Mode the preview was requested under; <see cref="PrepareUnlinkResult"/> carries no mode.</summary>
    private UnlinkMode _unlinkPreviewMode;

    /// <summary>Connection the preview was requested under; <see cref="PrepareUnlinkResult"/> carries no connection.</summary>
    private Guid _unlinkPreviewConnectionId;

    /// <summary>Reviewed preview currently on screen, or null (never a stale one).</summary>
    public PrepareUnlinkResult? UnlinkPreview => _unlinkPreview;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UnlinkPreviewVisibility), nameof(HasUnlinkResultText))]
    private string _unlinkResultText = string.Empty;

    /// <summary>True when a removal result message is on screen.</summary>
    public bool HasUnlinkResultText => UnlinkResultText.Length != 0;

    /// <summary>Provider blocking reasons for the reviewed preview, empty when none.</summary>
    public string UnlinkBlockingReasonsText =>
        _unlinkPreview is { } preview && preview.BlockingReasons.Count != 0
            ? "Blocking reasons:\n" + string.Join("\n", preview.BlockingReasons.Select(reason => $"- {reason}"))
            : string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UnlinkPreviewVisibility))]
    private string? _unlinkErrorText;

    /// <summary>Explicit consent to the previewed irreversible loss, shown only when required.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConfirmUnlinkCommand))]
    private bool _unlinkConsent;

    public ObservableCollection<UnlinkFileRow> UnlinkAffectedFiles { get; } = new();

    /// <summary>Warning text shown whenever the previewed removal discards bytes.</summary>
    public string UnlinkWarningText
    {
        get
        {
            if (_unlinkPreview is not { OnlineOnlyDataLoss: true }) return string.Empty;
            return "This removal permanently discards the unavailable bytes of the affected files "
                 + "listed below on this device. They cannot be recovered without re-syncing from the "
                 + "remote content.";
        }
    }

    /// <summary>True when the previewed removal discards unavailable bytes.</summary>
    public bool HasUnlinkWarning => UnlinkWarningText.Length != 0;

    /// <summary>Consent is shown only when the reviewed preview requires it.</summary>
    public Microsoft.UI.Xaml.Visibility UnlinkConsentVisibility =>
        _unlinkPreview is { OnlineOnlyDataLoss: true }
            ? Microsoft.UI.Xaml.Visibility.Visible
            : Microsoft.UI.Xaml.Visibility.Collapsed;

    public Microsoft.UI.Xaml.Visibility UnlinkPreviewVisibility =>
        _unlinkPreview is not null || UnlinkErrorText is not null || UnlinkResultText.Length != 0
            ? Microsoft.UI.Xaml.Visibility.Visible
            : Microsoft.UI.Xaml.Visibility.Collapsed;

    /// <summary>
    /// True when the reviewed preview is current: same connection, same mode,
    /// same provider session. A change of any of these invalidates the preview
    /// and any consent given for it.
    /// </summary>
    private bool HasCurrentUnlinkPreview =>
        _unlinkPreview is not null
        && _unlinkPreviewGeneration == _session.Generation
        && _unlinkPreviewMode == SelectedUnlinkMode.Mode
        && Guid.TryParseExact(ConnectionIdText.Trim(), "D", out Guid current)
        && current == _unlinkPreviewConnectionId;

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

    [RelayCommand(CanExecute = nameof(CanReloadSettings))]
    private Task ReloadSettingsAsync(CancellationToken cancellationToken) =>
        ReadSettingsAsync(isReload: true, discardDraft: false, cancellationToken);

    /// <summary>
    /// Explicit review path: discards the draft text (the page asks first) and
    /// reads the provider's current values again. Without this, a reload never
    /// silently destroys what the user has typed.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanReloadSettings))]
    private Task DiscardAndReloadSettingsAsync(CancellationToken cancellationToken) =>
        ReadSettingsAsync(isReload: true, discardDraft: true, cancellationToken);

    private bool CanReloadSettings() => !_settingsWriteInFlight && !IsBusy;

    /// <summary>
    /// Reads the provider's actual settings revision and resolved values once,
    /// the first time the Settings page is opened. Later navigations reuse the
    /// tracked revision; "Reload settings" refetches it explicitly. A dirty
    /// draft is never overwritten by this automatic load.
    /// </summary>
    public Task EnsureSettingsLoadedAsync() =>
        (_settingsRevisionKnown && _settingsReadGeneration == _session.Generation) || _settingsWriteInFlight || IsBusy
            ? Task.CompletedTask
            : ReadSettingsAsync(isReload: false, discardDraft: false, CancellationToken.None);

    private async Task ReadSettingsAsync(bool isReload, bool discardDraft, CancellationToken cancellationToken)
    {
        if (_settingsWriteInFlight || IsBusy) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        int serial = ++_settingsOpSerial;
        IsBusy = true;
        BusyText = "Loading settings…";
        SetSettingsError(null);
        try
        {
            // An empty patch is the provider's read: it returns the resolved
            // settings and revision without mutation (the expected revision is
            // not checked on this path).
            UpdateSettingsResult result = await _session.SendAsync(
                Commands.UpdateSettings,
                new UpdateSettingsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ScopeId = GlobalScopeId,
                    ExpectedRevision = 0,
                    Settings = Array.Empty<SettingsPatch>(),
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope) || serial != _settingsOpSerial) return;
            bool keptDraft = ApplyLoadedSettings(result, discardDraft);
            SettingsHasSuccess = false;
            SettingsResultText = keptDraft
                ? (isReload ? "Settings reloaded." : "Settings loaded.") + " Your unsaved entries were kept."
                : string.Empty;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope) && serial == _settingsOpSerial)
            {
                SetSettingsError(ErrorMessage(ex));
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
    /// Adopts one provider response as the observed baseline: revision and
    /// exact stored values. Per field, only an unsaved change against the
    /// previous baseline keeps its exact text (including invalid text the user
    /// still has to correct); every other field adopts the fresh provider
    /// value, so an untouched field can never become an edit of a stale value.
    /// </summary>
    /// <returns>True when any field kept unsaved user text.</returns>
    private bool ApplyLoadedSettings(UpdateSettingsResult result, bool discardDraft)
    {
        // Dirty intent is evaluated against the PREVIOUS baseline, before the
        // baseline is replaced by the new provider values.
        var previousValues = new ulong?[SettingsKeys.Length];
        var keepText = new bool[SettingsKeys.Length];
        for (int i = 0; i < SettingsKeys.Length; i++)
        {
            previousValues[i] = StoredFor(SettingsKeys[i]);
            keepText[i] = SettingsQuantity.DiffersFrom(
                SettingsTextFor(SettingsKeys[i]), KindFor(SettingsKeys[i]), previousValues[i]);
        }

        _settingsRevision = result.Revision;
        _settingsRevisionKnown = true;
        _settingsReadGeneration = _session.Generation;
        IsSettingsReady = true;
        _settingsLoadedValues.Clear();
        foreach (string key in SettingsKeys)
        {
            string? valueJson = ValueOf(result.Settings, key);
            // The provider encodes each u64 as canonical decimal JSON. A key
            // the provider did not return is not stored (the provider uses its
            // own default) and is never touched by a save.
            _settingsLoadedValues[key] = valueJson is not null
                && ulong.TryParse(valueJson, NumberStyles.None, CultureInfo.InvariantCulture, out ulong stored)
                    ? stored
                    : null;
        }
        for (int i = 0; i < SettingsKeys.Length; i++)
        {
            string key = SettingsKeys[i];
            // Discarding is rebase of an empty draft: the field adopts the
            // fresh stored value whatever it was holding.
            string draft = discardDraft ? string.Empty : SettingsTextFor(key);
            SetSettingsText(key, SettingsQuantity.RebaseDraft(
                draft, KindFor(key), previousValues[i], _settingsLoadedValues[key]));
        }
        SettingsRevisionText = $"Revision: {result.Revision}";
        UpdateSettingsDirty();
        return !discardDraft && keepText.Any(static kept => kept);
    }

    /// <summary>Stored value as last observed for one key; null when not stored.</summary>
    private ulong? StoredFor(string key) =>
        _settingsLoadedValues.TryGetValue(key, out ulong? stored) ? stored : null;

    /// <summary>The provider's raw JSON value for one key, or null when not stored.</summary>
    private static string? ValueOf(IReadOnlyList<SettingsEntry> settings, string key) =>
        settings.FirstOrDefault(entry => entry.Key == key)?.ValueJson;

    /// <summary>True when one field's text would change or add a stored value.</summary>
    private bool FieldDiffers(string key) =>
        SettingsQuantity.DiffersFrom(SettingsTextFor(key), KindFor(key), StoredFor(key));

    private void UpdateSettingsDirty()
    {
        foreach (string key in SettingsKeys)
        {
            if (FieldDiffers(key))
            {
                IsSettingsDirty = true;
                return;
            }
        }
        IsSettingsDirty = false;
    }

    partial void OnSettingsUploadBpsTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsDownloadBpsTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsTransferMemoryTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsRangeCacheTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsStagingAdmissionTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsMinimumFreeTextChanged(string value) => UpdateSettingsDirty();
    partial void OnSettingsResultTextChanged(string value) =>
        OnPropertyChanged(nameof(HasSettingsResultText));

    [RelayCommand(CanExecute = nameof(CanApplySettings))]
    private async Task ApplySettingsAsync(CancellationToken cancellationToken)
    {
        if (_settingsWriteInFlight || IsBusy) return;
        var patch = new List<SettingsPatch>();
        var error = CollectSetting(SettingsUploadBpsText, "upload_bytes_per_second", patch)
                 ?? CollectSetting(SettingsDownloadBpsText, "download_bytes_per_second", patch)
                 ?? CollectSetting(SettingsTransferMemoryText, "transfer_memory_bytes", patch)
                 ?? CollectSetting(SettingsRangeCacheText, "range_cache_bytes", patch)
                 ?? CollectSetting(SettingsStagingAdmissionText, "staging_admission_bytes", patch)
                 ?? CollectSetting(SettingsMinimumFreeText, "minimum_free_bytes", patch);
        if (error is not null)
        {
            // Malformed input never produces a request; the whole save stops.
            SetSettingsError(error);
            SettingsResultText = string.Empty;
            return;
        }
        if (patch.Count == 0)
        {
            SetSettingsError(null);
            SettingsResultText = "Nothing to save: every field matches the stored values.";
            return;
        }
        if (!_settingsRevisionKnown || _settingsReadGeneration != _session.Generation)
        {
            SetSettingsError("The provider connection changed. Reload settings before saving.");
            SettingsResultText = string.Empty;
            return;
        }

        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        int serial = ++_settingsOpSerial;
        SetSettingsWriteInFlight(true);
        IsBusy = true;
        BusyText = "Saving settings…";
        SetSettingsError(null);
        SettingsHasSuccess = false;
        try
        {
            UpdateSettingsResult result = await _session.SendAsync(
                Commands.UpdateSettings,
                new UpdateSettingsRequest
                {
                    OperationId = Guid.NewGuid(),
                    ScopeId = GlobalScopeId,
                    // The revision actually observed from the provider's read;
                    // a write against any other revision is rejected there.
                    ExpectedRevision = _settingsRevision,
                    Settings = patch,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope) || serial != _settingsOpSerial) return;
            ApplyLoadedSettings(result, discardDraft: true);
            // Success is reported only after the provider's response arrived.
            SettingsHasSuccess = true;
            SettingsResultText = "Settings saved.";
        }
        catch (ProtocolException ex) when (ex.Error.Code == ProtocolErrorCode.Conflict)
        {
            if (IsScopeStale(scope) || serial != _settingsOpSerial) return;
            await ReloadAfterConflictAsync(scope, request.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope) && serial == _settingsOpSerial)
            {
                SetSettingsError(ErrorMessage(ex));
                SettingsResultText = string.Empty;
            }
        }
        finally
        {
            SetSettingsWriteInFlight(false);
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    private bool CanApplySettings() => IsSettingsReady && IsSettingsDirty && !_settingsWriteInFlight && !IsBusy;

    /// <summary>
    /// A revision conflict means another client changed the settings. Reload
    /// the actual revision and values, keep every dirty draft exactly as typed
    /// and require the user to review it against the reloaded values before
    /// saving again — a conflicting write is never blindly retried.
    /// </summary>
    private async Task ReloadAfterConflictAsync(long scope, CancellationToken cancellationToken)
    {
        BusyText = "Settings changed elsewhere; reloading…";
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
            // Per-field rebase: only fields that actually carry unsaved text
            // keep it; untouched fields adopt the fresh provider values.
            bool keptDraft = ApplyLoadedSettings(reloaded, discardDraft: false);
            SettingsHasSuccess = false;
            SetSettingsError(
                "Settings changed elsewhere, so your changes were not saved. "
              + (keptDraft
                    ? "Your entries were kept — review them and save again."
                    : "The latest values are now shown — review them, then save again."));
            SettingsResultText = "Settings reloaded.";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                SettingsHasSuccess = false;
                SetSettingsError(
                    $"Settings changed elsewhere and reloading also failed: {ErrorMessage(ex)}. "
                  + "Your entries were kept.");
                SettingsResultText = string.Empty;
            }
        }
    }

    /// <summary>
    /// Converts one draft field into a patch entry. Empty text keeps the
    /// stored value (no entry); text that resolves to the stored value is
    /// never resent. Malformed, negative, fractional-byte or overflowing text
    /// fails the whole save before any request is sent.
    /// </summary>
    private string? CollectSetting(string text, string key, List<SettingsPatch> patch)
    {
        string trimmed = text.Trim();
        if (trimmed.Length == 0) return null;
        if (!SettingsQuantity.TryParse(trimmed, KindFor(key), out ulong value, out SettingsQuantityError error))
            return $"{LabelFor(key)}: {DescribeQuantityError(error, trimmed)}";
        if (_settingsLoadedValues.TryGetValue(key, out ulong? stored) && stored == value)
            return null; // identical to the stored value: nothing to submit
        // Canonical decimal JSON number (no leading zeros) as the provider
        // requires for u64 values.
        patch.Add(new SettingsPatch { Key = key, ValueJson = value.ToString(CultureInfo.InvariantCulture) });
        return null;
    }

    private static string DescribeQuantityError(SettingsQuantityError error, string text) => error switch
    {
        SettingsQuantityError.Negative =>
            $"\"{text}\" is negative; settings cannot be negative.",
        SettingsQuantityError.FractionalBytes =>
            $"\"{text}\" is a fraction of one byte; use whole bytes (for example 1.5 KiB = 1536 B).",
        SettingsQuantityError.Overflow =>
            $"\"{text}\" is larger than the provider's maximum 18446744073709551615.",
        SettingsQuantityError.UnlimitedNotAllowed =>
            $"\"{text}\" is only valid for transfer speeds; this field is a byte amount.",
        _ => $"\"{text}\" is not a valid quantity. Use IEC units like 512 MiB, 10 GiB or 10 MiB/s, "
           + $"or plain bytes; {SettingsQuantity.UnlimitedWord} is only for transfer speeds.",
    };

    private void SetSettingsError(string? message)
    {
        SettingsErrorText = message;
        SettingsHasError = message is not null;
    }

    private void SetSettingsWriteInFlight(bool value)
    {
        _settingsWriteInFlight = value;
        ReloadSettingsCommand.NotifyCanExecuteChanged();
        DiscardAndReloadSettingsCommand.NotifyCanExecuteChanged();
        ApplySettingsCommand.NotifyCanExecuteChanged();
    }

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

    // ── Remove connection (prepare → review → confirm) ─────────────────

    partial void OnSelectedUnlinkModeChanged(UnlinkModeChoice value) =>
        InvalidateUnlinkPreview("The removal mode changed; prepare the removal preview again.");

    /// <summary>
    /// Drops the reviewed preview and any consent given for it. Called whenever
    /// an input the preview binds (connection, mode, provider session) changes,
    /// and when the provider reports <c>PreviewChanged</c>.
    /// </summary>
    private void InvalidateUnlinkPreview(string? message = null)
    {
        bool hadPreview = _unlinkPreview is not null;
        _unlinkPreview = null;
        _unlinkPreviewMode = default;
        _unlinkPreviewConnectionId = default;
        _unlinkPreviewGeneration = -1;
        UnlinkAffectedFiles.Clear();
        UnlinkConsent = false;
        ConfirmUnlinkCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(UnlinkPreviewVisibility));
        OnPropertyChanged(nameof(UnlinkWarningText));
        OnPropertyChanged(nameof(HasUnlinkWarning));
        OnPropertyChanged(nameof(UnlinkConsentVisibility));
        OnPropertyChanged(nameof(UnlinkBlockingReasonsText));
        if (message is not null && (hadPreview || UnlinkResultText.Length != 0 || UnlinkErrorText is not null))
        {
            // The generated property setter raises the change notification.
            UnlinkErrorText = message;
            OnPropertyChanged(nameof(UnlinkPreviewVisibility));
        }
    }

    [RelayCommand]
    private async Task PrepareUnlinkAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryReadConnectionId(out Guid connectionId, out string? connectionError))
        {
            UnlinkErrorText = connectionError;
            UnlinkResultText = string.Empty;
            return;
        }
        UnlinkMode mode = SelectedUnlinkMode.Mode;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        IsBusy = true;
        BusyText = "Preparing removal preview…";
        UnlinkErrorText = null;
        UnlinkResultText = string.Empty;
        try
        {
            PrepareUnlinkResult preview = await _session.SendAsync(
                Commands.PrepareUnlink,
                new PrepareUnlinkRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    Mode = mode,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            // Only a fresh accepted preview ever becomes the reviewed one.
            _unlinkPreview = preview;
            _unlinkPreviewMode = mode;
            _unlinkPreviewConnectionId = connectionId;
            _unlinkPreviewGeneration = scope;
            UnlinkAffectedFiles.Clear();
            foreach (UnlinkFileResult file in preview.AffectedFiles)
                UnlinkAffectedFiles.Add(new UnlinkFileRow(file));
            UnlinkConsent = false;
            ConfirmUnlinkCommand.NotifyCanExecuteChanged();
            OnPropertyChanged(nameof(UnlinkPreviewVisibility));
            OnPropertyChanged(nameof(UnlinkWarningText));
            OnPropertyChanged(nameof(HasUnlinkWarning));
            OnPropertyChanged(nameof(UnlinkConsentVisibility));
            OnPropertyChanged(nameof(UnlinkBlockingReasonsText));
            UnlinkResultText =
                $"Preview {preview.PreviewId} (fingerprint {preview.PreviewFingerprint}) — "
              + $"this is a preview only; the connection has not been removed.\n"
              + $"Online-only: {preview.OnlineOnlyFiles}, partial: {preview.PartialFiles}, "
              + $"dirty: {preview.DirtyFiles}, conflicts: {preview.ConflictFiles}, "
              + $"export bytes: {preview.RequiredExportBytes.ToString(CultureInfo.InvariantCulture)}. "
              + (preview.SafeToUnlink ? "Safe to proceed under this mode." : "Review the blocking reasons below.")
              + (preview.AffectedFiles.Count == 0
                    ? string.Empty
                    : $"\nAffected files ({preview.AffectedFiles.Count.ToString(CultureInfo.InvariantCulture)}) listed below.");
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                InvalidateUnlinkPreview();
                UnlinkErrorText = ErrorMessage(ex);
                UnlinkResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    /// <summary>
    /// Confirms the exact reviewed preview. Requires a current preview and —
    /// when the previewed removal discards unavailable bytes — explicit
    /// consent. The durable operation id is fresh and distinct from the preview
    /// id. A <c>PreviewChanged</c> error invalidates the preview and consent.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanConfirmUnlink))]
    private async Task ConfirmUnlinkAsync(CancellationToken cancellationToken)
    {
        if (IsBusy || !HasCurrentUnlinkPreview || _unlinkPreview is not { } preview) return;
        if (preview.OnlineOnlyDataLoss && !UnlinkConsent) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        long scope = BeginScope();
        Guid connectionId = _unlinkPreviewConnectionId;
        UnlinkMode mode = _unlinkPreviewMode;
        IsBusy = true;
        BusyText = mode == UnlinkMode.SafeRemove ? "Removing connection…" : "Removing connection (discarding unavailable bytes)…";
        UnlinkErrorText = null;
        UnlinkResultText = string.Empty;
        try
        {
            UnlinkResult result = await _session.SendAsync(
                Commands.Unlink,
                new UnlinkRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = connectionId,
                    Mode = mode,
                    PreviewId = preview.PreviewId,
                    AcceptOnlineOnlyDataLoss = UnlinkConsent,
                },
                request.Token).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            InvalidateUnlinkPreview();
            // Removal is only ever claimed from the provider's unlink result.
            if (result.Unregistered)
                UnlinkResultText = $"Connection {result.ConnectionId} was removed and its registration unregistered.";
            else if (result.RetainedForRecovery)
                UnlinkResultText =
                    $"Connection {result.ConnectionId} was disconnected, but its binding and registration were "
                  + "retained for recovery. This is not a completed removal; reconnect to finish it later.";
            else
                UnlinkResultText =
                    $"The provider did not report a completed removal for connection {result.ConnectionId}. "
                  + "Inspect the connection state below before assuming it is gone.";
            await RefreshConnectionStateAfterUnlinkAsync(connectionId, scope, request.Token).ConfigureAwait(true);
        }
        catch (ProtocolException ex) when (ex.Error.Code == ProtocolErrorCode.PreviewChanged)
        {
            if (IsScopeStale(scope)) return;
            InvalidateUnlinkPreview();
            UnlinkErrorText =
                "The removal preview changed since it was prepared; nothing was removed. "
              + "Prepare the preview again and review the current contents before confirming.";
            UnlinkResultText = string.Empty;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                InvalidateUnlinkPreview();
                UnlinkErrorText = ErrorMessage(ex);
                UnlinkResultText = string.Empty;
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
        }
    }

    /// <summary>Confirmation needs a current reviewed preview and, for a lossy removal, consent.</summary>
    private bool CanConfirmUnlink() =>
        !IsBusy && HasCurrentUnlinkPreview && (!UnlinkPreview!.OnlineOnlyDataLoss || UnlinkConsent);

    partial void OnUnlinkConsentChanged(bool value) => ConfirmUnlinkCommand.NotifyCanExecuteChanged();

    /// <summary>
    /// Re-reads the provider's real connection state after a confirmed removal
    /// so the page reports observed state, not the request that was sent.
    /// </summary>
    private async Task RefreshConnectionStateAfterUnlinkAsync(Guid connectionId, long scope, CancellationToken cancellationToken)
    {
        try
        {
            GetStatusResult status = await _session.SendAsync(
                Commands.GetStatus, new GetStatusRequest(), cancellationToken).ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ConnectionStatus? connection = status.Connections.FirstOrDefault(c => c.ConnectionId == connectionId);
            UnlinkResultText += connection is null
                ? "\nThe provider no longer lists that connection."
                : $"\nCurrent provider state: {StatusDisplayText.Get(connection.State)}, "
                  + $"{connection.OnlineOnlyFiles} online-only, {connection.DirtyFiles} dirty files remaining in view.";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
                UnlinkResultText += $"\nReading the refreshed connection state failed: {ErrorMessage(ex)}";
        }
    }

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
            // A provider session change invalidates every reviewed removal
            // preview and its consent; the new session must re-review.
            InvalidateUnlinkPreview("The provider session changed; prepare the removal preview again.");
            if (_settingsReadGeneration != _session.Generation)
            {
                // The provider connection changed underneath the settings
                // read: the revision and values are no longer trustworthy, so
                // editing/saving needs a fresh read first. Dirty drafts stay.
                IsSettingsReady = false;
                SettingsRevisionText = "Revision: reload required — the provider connection changed.";
            }
        });

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(IsSettingsEditingEnabled));
        OnPropertyChanged(nameof(SettingsNotReadyText));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.StateChanged -= OnSessionChanged;
        _lifetime.Cancel();
        _lifetime.Dispose();
    }
}
