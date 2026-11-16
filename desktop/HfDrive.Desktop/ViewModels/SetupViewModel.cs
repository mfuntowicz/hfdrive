using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HfDrive.Desktop.Interop;
using HfDrive.Desktop.Services;
using HfDrive.Protocol;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using XamlVisibility = Microsoft.UI.Xaml.Visibility;

namespace HfDrive.Desktop.ViewModels;

/// <summary>Which binding source the user selected on the inspection step.</summary>
public enum SetupSource
{
    /// <summary>Attach to a managed drive that already exists at the prefix.</summary>
    ExistingManagedDrive,

    /// <summary>Initialize a new managed drive inside an empty prefix.</summary>
    InitializeNewManagedDrive,
}

/// <summary>Combo-box entry for the binding source.</summary>
public sealed class SourceChoice
{
    public required SetupSource Source { get; init; }
    public required string Display { get; init; }
    public required string Description { get; init; }
}

/// <summary>Combo-box entry for the connection access mode.</summary>
public sealed class ModeChoice
{
    public required ConnectionMode Mode { get; init; }
    public required string Display { get; init; }
    public required string Description { get; init; }
}

/// <summary>One probe check returned by <c>probe_storage</c>.</summary>
public sealed class ProbeCheckRow
{
    public ProbeCheckRow(ProbeCheck check) => Check = check;

    public ProbeCheck Check { get; }

    public string KindDisplay => Check.Kind switch
    {
        ProbeCheckKind.NativeUploadVisibleNatively => "Native upload visible natively",
        ProbeCheckKind.NativeUploadVisibleS3 => "Native upload visible through S3",
        ProbeCheckKind.GetBodyEtagCoherence => "GET body and ETag coherence",
        ProbeCheckKind.GuardedCreate => "Guarded initial create",
        ProbeCheckKind.ConcurrentSameEtag => "Concurrent writers with the same ETag",
        ProbeCheckKind.StaleOverwriteRejected => "Stale ETag overwrite rejected",
        ProbeCheckKind.AmbiguousCasRecovery => "Ambiguous CAS response recovered through ancestry",
        ProbeCheckKind.XetRangeReads => "Xet range reads equal the source slices",
        _ => Check.Kind.ToString(),
    };

    public string OutcomeDisplay => Check.Outcome switch
    {
        ProbeOutcome.Passed => "Passed",
        ProbeOutcome.Failed => "Failed",
        ProbeOutcome.NotRun => "Not run",
        _ => Check.Outcome.ToString(),
    };

    public string ExpectationDisplay => $"Expected: {Check.Expected}";

    public string ObservationDisplay => string.IsNullOrEmpty(Check.Detail)
        ? $"Observed: {Check.Observed}"
        : $"Observed: {Check.Observed} ({Check.Detail})";
}

/// <summary>One collision-category count from <c>preview_connect</c>.</summary>
public sealed class CollisionSummaryRow
{
    public CollisionSummaryRow(CollisionCategorySummary summary) => Summary = summary;

    public CollisionCategorySummary Summary { get; }

    public string Display => $"{Summary.Kind}: {Summary.Count}";
}

/// <summary>One representative collision from <c>preview_connect</c>.</summary>
public sealed class CollisionRow
{
    public CollisionRow(Collision collision) => Collision = collision;

    public Collision Collision { get; }

    public string Display => $"{Collision.Kind} — {Collision.RelativePath} — proposed: {Collision.ProposedAction}";
}

/// <summary>One representative proposed action from <c>preview_connect</c>.</summary>
public sealed class ProposedActionRow
{
    public ProposedActionRow(ProposedActionRecord action) => Action = action;

    public ProposedActionRecord Action { get; }

    public string Display => $"{Action.Action} — {Action.Description}";
}

/// <summary>One browsable item returned by <c>inspect_drive</c>.</summary>
public sealed class InspectItemRow
{
    public InspectItemRow(InspectItem item) => Item = item;

    public InspectItem Item { get; }

    public string Display =>
        $"{(Item.Kind == ItemKind.Directory ? "Directory" : "File")} {Item.Name} — item {Item.ItemId}, revision {Item.ItemRevision}";
}

/// <summary>
/// The setup wizard. Every value it shows comes from a real provider response
/// (<c>get_status</c>, <c>list_owners</c>, <c>list_buckets</c>,
/// <c>create_bucket</c>, <c>inspect_drive</c>, <c>begin_setup</c>,
/// <c>set_publication_credentials</c>, <c>probe_storage</c>,
/// <c>preview_connect</c>, <c>connect</c>). The only identifier this class
/// generates is the workspace UUID required to initialize a new empty managed
/// prefix, and that only happens after explicit user consent. No owner, bucket,
/// workspace or connection identifier is invented, and no credential material
/// is kept after the protected request is sent.
/// </summary>
public sealed partial class SetupViewModel : ObservableObject, IDisposable
{
    /// <summary>Sign in, bucket, folder/access, and review.</summary>
    public const int StepCount = 4;

    private readonly ProviderSession _session;
    private readonly MainViewModel _main;
    private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly List<SourceChoice> _sourceChoices;
    private readonly List<ModeChoice> _modeChoices;
    private CancellationTokenSource? _ownersRequest;
    private CancellationTokenSource? _bucketsRequest;
    private CancellationTokenSource? _inspectRequest;
    private string? _accountKey;
    private bool _accountObserved;
    private bool _settingPrefix;
    private bool _disposed;
    private bool _isContinuing;
    private AuthenticationState _authenticationState = AuthenticationState.SignedOut;
    private IReadOnlyList<string>? _grantedScopes;
    private string? _accountNamespace;

    // Inspect evidence for the current owner/bucket/prefix/source.
    private bool _inspectValid;
    private RemoteBinding? _inspectedBinding;
    private bool _inspectedManaged;
    private bool _inspectedPrefixEmpty;
    private Guid _newWorkspaceId;

    // Durable setup reservation from begin_setup.
    private bool _setupValid;
    private Guid _connectionId;
    private PublicationProtectionContext? _protectionContext;

    // Publication credentials and capability probe (writable mode only).
    private bool _credentialsStored;
    private bool _probePassed;

    // Persisted connect preview.
    private bool _previewValid;
    private Guid _previewId;
    private PreviewConnectResult? _preview;

    // Private bucket creation feeding begin_setup provenance.
    private Guid? _createdBucketOperationId;
    private Bucket? _createdBucket;

    private bool _connected;
    private bool _probeAttempted;

    public SetupViewModel(ProviderSession session, MainViewModel main)
    {
        _session = session;
        _main = main;
        _sourceChoices =
        [
            new SourceChoice
            {
                Source = SetupSource.ExistingManagedDrive,
                Display = "Use an existing HF Drive",
                Description = "Connect a workspace that has already been set up in this bucket.",
            },
            new SourceChoice
            {
                Source = SetupSource.InitializeNewManagedDrive,
                Display = "Create a new HF Drive",
                Description = "Use a separate, empty location inside your bucket. Existing bucket files stay untouched.",
            },
        ];
        _modeChoices =
        [
            new ModeChoice
            {
                Mode = ConnectionMode.ReadOnly,
                Display = "Browse only",
                Description = "Open and download committed files. Local changes are never uploaded.",
            },
            new ModeChoice
            {
                Mode = ConnectionMode.Writable,
                Display = "Two-way sync",
                Description = "Keep local changes and your bucket in sync. Requires write permission and storage access keys.",
            },
        ];
        _newWorkspaceId = Guid.NewGuid();
        SelectedSource = _sourceChoices[1];
        SelectedMode = _modeChoices[1];
        _session.StateChanged += OnSessionChanged;
        _main.PropertyChanged += OnMainPropertyChanged;
        UpdateStepText();
        // Seed the new-managed-drive workspace/prefix defaults without
        // contradicting the currently selected source.
        RegenerateWorkspaceId(resetPrefix: true);
        if (SelectedSource.Source == SetupSource.ExistingManagedDrive)
            WorkspaceIdText = "The workspace identifier is discovered by the inspection and is never assumed.";
        OnPropertyChanged(nameof(StepProgressText));
    }

    public ObservableCollection<OwnerViewModel> Owners { get; } = new();

    public ObservableCollection<Bucket> Buckets { get; } = new();

    public IReadOnlyList<SourceChoice> SourceChoices => _sourceChoices;

    public IReadOnlyList<ModeChoice> ModeChoices => _modeChoices;

    public ObservableCollection<InspectItemRow> InspectItems { get; } = new();

    public ObservableCollection<ProbeCheckRow> ProbeChecks { get; } = new();

    public ObservableCollection<CollisionSummaryRow> CollisionSummary { get; } = new();

    public ObservableCollection<CollisionRow> Collisions { get; } = new();

    public ObservableCollection<ProposedActionRow> ProposedActions { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(
        nameof(IsAccountStepVisible), nameof(IsOwnerStepVisible),
        nameof(IsLocalStepVisible), nameof(IsReviewStepVisible),
        nameof(StepProgressText), nameof(ProgressValue))]
    private int _currentStep;

    [ObservableProperty]
    private string _stepTitle = string.Empty;

    [ObservableProperty]
    private string _stepDescription = string.Empty;

    [ObservableProperty]
    private string _statusText = string.Empty;

    [ObservableProperty]
    private string? _errorText;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(
        nameof(BackCommand), nameof(RefreshAccountCommand),
        nameof(LoadMoreOwnersCommand), nameof(LoadMoreBucketsCommand), nameof(CreateBucketCommand),
        nameof(InspectCommand), nameof(LoadMoreInspectItemsCommand), nameof(BeginSetupCommand),
        nameof(ProbeCommand), nameof(PreviewCommand), nameof(ConnectCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _busyText = string.Empty;

    public XamlVisibility IsAccountStepVisible => StepVisible(0);
    public XamlVisibility IsOwnerStepVisible => StepVisible(1);
    public XamlVisibility IsLocalStepVisible => StepVisible(2);
    public XamlVisibility IsReviewStepVisible => StepVisible(3);
    public XamlVisibility IsCredentialsVisible => IsWritable && !NeedsWriteConsent && !_connected
        ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility IsInitializeVisible => SelectedSource.Source == SetupSource.InitializeNewManagedDrive && !_connected
        ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility IsCollisionReviewVisible => RequiresReview && !_connected
        ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility IsSuccessVisible => _connected ? XamlVisibility.Visible : XamlVisibility.Collapsed;

    private XamlVisibility StepVisible(int step) => CurrentStep == step ? XamlVisibility.Visible : XamlVisibility.Collapsed;

    public string StepProgressText => _connected ? "All set" : $"Step {CurrentStep + 1} of {StepCount}";
    public double ProgressValue => _connected ? 100 : CurrentStep * 100.0 / StepCount;
    public bool IsComplete => _connected;
    public bool IsSetupWorking => _connected && _main.HasObservedStatus && _main.Connections.Any(row =>
        row.Status.ConnectionId == _connectionId && row.Status.LastError is null && row.Status.ConflictFiles == 0
        && row.Status.Capability is CapabilityState.Writable or CapabilityState.ReadOnly
        && row.Status.State is ConnectionState.UpToDate or ConnectionState.PendingUpload
            or ConnectionState.Uploading or ConnectionState.PublishingChanges or ConnectionState.Downloading);
    public bool IsWorking => IsBusy || _isContinuing || _main.IsBusy || _main.IsAccountCommandBusy || _main.IsStartingProvider;
    public bool CanEdit => !IsWorking;
    public bool CanGoBack => !IsWorking && !_connected && CurrentStep > 0;
    public bool HasError => !string.IsNullOrWhiteSpace(ErrorText);
    public bool PrimaryActionEnabled => CanContinue();
    public string PrimaryActionText => _main.IsLoginPending ? "Waiting for sign-in…" : CurrentStep switch
    {
        0 when !_main.IsConnected => "Connect to HF Drive",
        0 when !AccountReady => "Sign in with Hugging Face",
        0 when NeedsReadConsent => "Allow bucket access",
        2 when NeedsWriteConsent => "Allow write access",
        2 => "Check & review",
        3 when _connected => "Open HF Drive",
        3 => "Connect drive",
        _ => "Continue",
    };
    public string AccountSummaryText => AccountReady
        ? $"Signed in as {_accountNamespace}"
        : _main.AccountStateText;
    public string ReviewBucketText => SelectedBucket is { } bucket ? $"{bucket.Namespace}/{bucket.Name}" : string.Empty;
    public string ReviewFolderText => RootPathText.Trim();
    public string ReviewLocationText => _preview?.Binding.Prefix ?? PrefixText.Trim();
    public string ReviewModeText => SelectedMode?.Display ?? string.Empty;
    public string PreviewSummaryText => _preview is { } preview
        ? $"{preview.ProposedActionCount} planned actions · {preview.CollisionSummary.Aggregate(0UL, (total, category) => total + category.Count)} collisions"
        : "Your files download when you open them in File Explorer.";

    public event EventHandler? Finished;

    partial void OnIsBusyChanged(bool value) => WizardStateChanged();
    partial void OnErrorTextChanged(string? value) => OnPropertyChanged(nameof(HasError));
    partial void OnInitializeConsentChanged(bool value) => WizardStateChanged();
    partial void OnReviewConsentChanged(bool value) => WizardStateChanged();
    partial void OnIsOwnersLoadingChanged(bool value) => WizardStateChanged();
    partial void OnIsBucketsLoadingChanged(bool value) => WizardStateChanged();
    public XamlVisibility OwnerPagingVisibility => HasMoreOwners || IsOwnersLoading || Owners.Count == 0 ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility BucketPagingVisibility => HasMoreBuckets || IsBucketsLoading || (SelectedOwner is not null && Buckets.Count == 0) ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility InspectPagingVisibility => HasMoreInspectItems ? XamlVisibility.Visible : XamlVisibility.Collapsed;
    public XamlVisibility StorageCheckDetailsVisibility => _probeAttempted ? XamlVisibility.Visible : XamlVisibility.Collapsed;

    // ── Step 0: account ────────────────────────────────────────────────────

    [ObservableProperty]
    private string _accountStateText = "Account status has not been read from the provider.";

    [ObservableProperty]
    private string _accountDetailText = "No verified profile has been received from the provider.";

    /// <summary>The signed-in command surface is shared with the Account page.</summary>
    public MainViewModel Main => _main;

    // ── Step 1: owner and bucket ───────────────────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreOwnersCommand))]
    private bool _hasMoreOwners;

    [ObservableProperty]
    private bool _isOwnersLoading;
    [ObservableProperty]
    private string _ownersEmptyText = "No owner identities have been received from the provider.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreBucketsCommand))]
    private bool _hasMoreBuckets;

    [ObservableProperty]
    private bool _isBucketsLoading;

    [ObservableProperty]
    private string _bucketsEmptyText = "Select an owner to load its buckets.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InspectCommand), nameof(CreateBucketCommand))]
    private OwnerViewModel? _selectedOwner;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InspectCommand))]
    private Bucket? _selectedBucket;

    [ObservableProperty]
    private string _selectedOwnerIdentityText = "No owner selected.";

    [ObservableProperty]
    private string _selectedBucketIdentityText = "No bucket selected.";

    [ObservableProperty]
    private string _newBucketName = string.Empty;

    [ObservableProperty]
    private string _selectedRegion = "Service default";

    public IReadOnlyList<string> RegionChoices { get; } = ["Service default", "us", "eu"];

    [ObservableProperty]
    private string _createdBucketText = "No private bucket has been created in this session.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasCreationError))]
    private string? _creationErrorText;

    public bool HasCreationError => !string.IsNullOrWhiteSpace(CreationErrorText);

    // ── Step 2: inspection ─────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InspectCommand))]
    private SourceChoice _selectedSource = null!;

    [ObservableProperty]
    private string _prefixText = string.Empty;

    [ObservableProperty]
    private string _workspaceIdText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(BeginSetupCommand))]
    private bool _initializeConsent;

    [ObservableProperty]
    private string _inspectStatusText = "No prefix has been inspected yet.";

    [ObservableProperty]
    private string _inspectItemsEmptyText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreInspectItemsCommand))]
    private bool _hasMoreInspectItems;

    // ── Step 3: durable setup ──────────────────────────────────────────────

    [ObservableProperty]
    private string _setupStatusText = "No setup has been reserved yet.";

    // ── Step 4: publication credentials ────────────────────────────────────

    [ObservableProperty]
    private string _credentialsStatusText = "No supplemental publication credentials have been stored.";

    // ── Step 5: capability probe ───────────────────────────────────────────

    [ObservableProperty]
    private string _probeRunIdText = "A fresh run UUID is generated each time the probe starts.";

    [ObservableProperty]
    private string _probeStatusText = "No storage probe has been run for this setup.";

    [ObservableProperty]
    private string _probeCapabilityText = "Capability: not probed.";

    [ObservableProperty]
    private string _probeReportPathText = "Report path: none.";

    // ── Step 6: local root, mode and preview ───────────────────────────────

    [ObservableProperty]
    private string _rootPathText = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PreviewCommand))]
    private ModeChoice _selectedMode = null!;

    [ObservableProperty]
    private string _previewStatusText = "No connect preview has been produced yet.";

    [ObservableProperty]
    private string _collisionSummaryEmptyText = string.Empty;

    // ── Step 7: review ─────────────────────────────────────────────────────

    [ObservableProperty]
    private string _reviewText = "Nothing to review yet.";

    [ObservableProperty]
    private bool _requiresReview;

    [ObservableProperty]
    private bool _reviewConsent;

    // ── Step 8: connect ────────────────────────────────────────────────────

    [ObservableProperty]
    private string _connectStatusText = "The folder has not been connected yet.";

    // ── Selection change handling ──────────────────────────────────────────

    partial void OnSelectedOwnerChanged(OwnerViewModel? value)
    {
        SelectedOwnerIdentityText = value is null
            ? "No owner selected."
            : $"Owner ID: {value.Owner.OwnerId} · kind: {value.Owner.OwnerKind} · namespace: {value.Owner.Namespace ?? "not reported"}";
        InvalidateFrom(1);
        if (value?.Owner.Namespace is not null && !_disposed)
            _ = LoadBucketsCoreAsync(null, true, _lifetime.Token);
    }

    partial void OnSelectedBucketChanged(Bucket? value)
    {
        SelectedBucketIdentityText = value is null
            ? "No bucket selected."
            : $"Bucket ID: {value.BucketId} · name: {value.Name} · namespace: {value.Namespace} · visibility: {value.Visibility}";
        if (_createdBucket is not null && value?.BucketId != _createdBucket.BucketId)
        {
            _createdBucketOperationId = null;
            CreatedBucketText = "A different bucket is now selected; the earlier creation is no longer this setup's provenance.";
        }
        InvalidateFrom(2);
    }

    partial void OnSelectedSourceChanged(SourceChoice value)
    {
        if (value.Source == SetupSource.InitializeNewManagedDrive)
        {
            RegenerateWorkspaceId(resetPrefix: true);
            SelectedMode = _modeChoices[1];
        }
        else
        {
            WorkspaceIdText = "Discovered from the existing drive.";
            SelectedMode = _modeChoices[0];
        }
        InvalidateFrom(2);
    }

    partial void OnPrefixTextChanged(string value)
    {
        if (_settingPrefix) return;
        InvalidateFrom(2);
    }

    partial void OnSelectedModeChanged(ModeChoice value)
    {
        // Credentials and probe evidence belong to the reserved connection, so
        // they survive a mode change; only the local preview is mode-specific.
        InvalidateFrom(6);
    }

    partial void OnRootPathTextChanged(string value) => InvalidateFrom(6);

    partial void OnCurrentStepChanged(int value)
    {
        UpdateStepText();
        StatusText = string.Empty;
        if (value == 1 && Owners.Count == 0 && AccountReady && !IsBusy)
            _ = LoadOwnersCoreAsync(null, true, _lifetime.Token);
        WizardStateChanged();
    }

    // ── Step transitions ───────────────────────────────────────────────────

    private static readonly string[] StepTitles =
    [
        "Your buckets, now in Explorer.",
        "Choose a bucket.",
        "Make yourself at home.",
        "Ready to connect?",
    ];

    private static readonly string[] StepDescriptions =
    [
        "Connect your Hugging Face account to bring your storage to Windows.",
        "Use a personal bucket or one from your organization.",
        "Choose where your drive appears and how you want to use it.",
        "Check your choices. Files download when you open them.",
    ];

    private void UpdateStepText()
    {
        int step = Math.Clamp(CurrentStep, 0, StepCount - 1);
        StepTitle = _connected ? "You're all set." : StepTitles[step];
        StepDescription = _connected ? "Your Hugging Face drive is ready in File Explorer." : StepDescriptions[step];
    }

    private bool IsWritable => SelectedMode?.Mode == ConnectionMode.Writable;
    private bool AccountReady => _authenticationState == AuthenticationState.SignedIn && _accountKey is not null;
    private bool NeedsReadConsent => AccountReady && _grantedScopes is not null
        && !_grantedScopes.Contains("read-repos") && !_grantedScopes.Contains("write-repos");
    private bool NeedsWriteConsent => IsWritable && AccountReady && _grantedScopes is not null
        && !_grantedScopes.Contains("write-repos");
    private bool NeedsCreateConsent => AccountReady && _grantedScopes is not null
        && !_grantedScopes.Contains("manage-repos");
    private bool InspectionIsCompatible => _inspectValid
        && (SelectedSource.Source == SetupSource.ExistingManagedDrive ? _inspectedManaged : _inspectedPrefixEmpty);

    private bool CanContinue() => !_disposed && !IsWorking && !_main.IsLoginPending && (CurrentStep switch
    {
        0 => true,
        1 => _main.IsConnected && !IsOwnersLoading && !IsBucketsLoading
            && SelectedOwner?.Owner.Namespace is not null && SelectedBucket is not null,
        2 => _main.IsConnected && RootPathText.Trim().Length != 0,
        3 => _connected || (_main.IsConnected && CanConnect()),
        _ => false,
    });

    [RelayCommand(CanExecute = nameof(CanMoveBack))]
    private void Back()
    {
        ErrorText = null;
        StatusText = string.Empty;
        CurrentStep--;
    }

    private bool CanMoveBack() => CanGoBack;

    /// <summary>Runs the required provider stages without exposing their bookkeeping as wizard pages.</summary>
    public async Task ContinueAsync(string keyId, string secretKey)
    {
        if (!CanContinue()) return;
        _isContinuing = true;
        ErrorText = null;
        StatusText = string.Empty;
        WizardStateChanged();
        try
        {
            switch (CurrentStep)
            {
                case 0:
                    if (!_main.IsConnected)
                        await _main.ConnectCommand.ExecuteAsync(null).ConfigureAwait(true);
                    if (!_main.IsConnected)
                    {
                        ErrorText = _main.ErrorText ?? _main.ConnectionDetailText;
                        return;
                    }
                    if (_main.Account is { } account) ApplyAccount(account);
                    if (!AccountReady || NeedsReadConsent)
                        await RequestStorageLoginAsync(LoginFlow.Pkce, LoginPurpose.ReadStorage).ConfigureAwait(true);
                    if (AccountReady && !NeedsReadConsent) CurrentStep = 1;
                    break;
                case 1:
                    if (!_inspectValid) await InspectAsync(_lifetime.Token).ConfigureAwait(true);
                    if (!InspectionIsCompatible)
                    {
                        ErrorText ??= SelectedSource.Source == SetupSource.ExistingManagedDrive
                            ? "No HF Drive was found here. Check the drive location under Advanced, or create a new drive."
                            : "This location isn't empty. Choose a different drive location under Advanced.";
                        return;
                    }
                    CurrentStep = 2;
                    break;
                case 2:
                    if (!Path.IsPathFullyQualified(RootPathText.Trim()))
                    {
                        ErrorText = "Choose a folder using its full Windows path.";
                        return;
                    }
                    if (SelectedSource.Source == SetupSource.InitializeNewManagedDrive && !IsWritable)
                    {
                        ErrorText = "Creating a new drive needs two-way access. Browse-only is available for an existing HF Drive.";
                        return;
                    }
                    if (NeedsWriteConsent)
                    {
                        await RequestStorageLoginAsync(LoginFlow.Pkce, LoginPurpose.WriteStorage).ConfigureAwait(true);
                        return;
                    }
                    if (!_setupValid) await BeginSetupAsync(_lifetime.Token).ConfigureAwait(true);
                    if (!_setupValid) return;
                    if (IsWritable && (!_credentialsStored || keyId.Length != 0 || secretKey.Length != 0))
                    {
                        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrEmpty(secretKey))
                        {
                            ErrorText = "Enter your Hugging Face storage access key and secret to enable two-way sync.";
                            return;
                        }
                        Task store = StoreCredentialsAsync(keyId.Trim(), secretKey);
                        keyId = secretKey = string.Empty;
                        await store.ConfigureAwait(true);
                        if (!_credentialsStored) return;
                    }
                    if (IsWritable && !_probePassed)
                    {
                        await ProbeAsync(_lifetime.Token).ConfigureAwait(true);
                        if (!_probePassed)
                        {
                            ErrorText ??= "Storage checks couldn't confirm safe two-way sync. Expand check details for the result.";
                            return;
                        }
                    }
                    Directory.CreateDirectory(RootPathText.Trim());
                    if (!_previewValid) await PreviewAsync(_lifetime.Token).ConfigureAwait(true);
                    if (_previewValid) CurrentStep = 3;
                    break;
                case 3 when _connected:
                    Finished?.Invoke(this, EventArgs.Empty);
                    break;
                case 3:
                    await ConnectAsync(_lifetime.Token).ConfigureAwait(true);
                    break;
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally
        {
            keyId = secretKey = string.Empty;
            _isContinuing = false;
            if (!_disposed && CurrentStep == 1 && Owners.Count == 0 && AccountReady && !IsOwnersLoading)
                _ = LoadOwnersCoreAsync(null, true, _lifetime.Token);
            WizardStateChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanUseDeviceLogin))]
    private Task UseDeviceLoginAsync() => RequestStorageLoginAsync(LoginFlow.Device,
        CurrentStep == 2 && IsWritable ? LoginPurpose.WriteStorage : LoginPurpose.ReadStorage);

    private bool CanUseDeviceLogin() => !IsWorking && _main.IsConnected && !_main.IsLoginPending;

    private async Task RequestStorageLoginAsync(LoginFlow flow, LoginPurpose purpose, string? organizationId = null)
    {
        await _main.SignInForStorageAsync(flow, purpose, _lifetime.Token, organizationId).ConfigureAwait(true);
        if (_disposed) return;
        if (_main.Account is { } account) ApplyAccount(account);
        if (!string.IsNullOrWhiteSpace(_main.ErrorText)) ErrorText = _main.ErrorText;
    }

    /// <summary>Starts an add-drive flow without deleting any durable setup, connection, or local file.</summary>
    public void StartNewSetup()
    {
        if (IsBusy || _isContinuing) return;
        InvalidateFrom(1);
        SelectedOwner = null;
        SelectedSource = _sourceChoices[1];
        RegenerateWorkspaceId(resetPrefix: true);
        SelectedMode = _modeChoices[1];
        RootPathText = string.Empty;
        ErrorText = null;
        CreationErrorText = null;
        StatusText = string.Empty;
        CurrentStep = AccountReady && !NeedsReadConsent ? 1 : 0;
        SelectPersonalOwner();
        UpdateStepText();
        WizardStateChanged();
    }

    private string NextBlockedReason(int step) => step switch
    {
        0 => "Sign in to continue. Your existing local files are kept.",
        1 => "Choose a bucket, then continue to check its drive location.",
        2 => "Choose a local folder and complete the storage checks.",
        3 => "Review the choices above before connecting.",
        _ => string.Empty,
    };

    private void WizardStateChanged()
    {
        BackCommand.NotifyCanExecuteChanged();
        RefreshAccountCommand.NotifyCanExecuteChanged();
        LoadMoreOwnersCommand.NotifyCanExecuteChanged();
        LoadMoreBucketsCommand.NotifyCanExecuteChanged();
        CreateBucketCommand.NotifyCanExecuteChanged();
        InspectCommand.NotifyCanExecuteChanged();
        LoadMoreInspectItemsCommand.NotifyCanExecuteChanged();
        BeginSetupCommand.NotifyCanExecuteChanged();
        ProbeCommand.NotifyCanExecuteChanged();
        PreviewCommand.NotifyCanExecuteChanged();
        ConnectCommand.NotifyCanExecuteChanged();
        UseDeviceLoginCommand.NotifyCanExecuteChanged();
        OnPropertyChanged(nameof(IsWorking));
        OnPropertyChanged(nameof(CanEdit));
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(PrimaryActionEnabled));
        OnPropertyChanged(nameof(PrimaryActionText));
        OnPropertyChanged(nameof(IsCredentialsVisible));
        OnPropertyChanged(nameof(IsInitializeVisible));
        OnPropertyChanged(nameof(IsCollisionReviewVisible));
        OnPropertyChanged(nameof(IsSuccessVisible));
        OnPropertyChanged(nameof(IsComplete));
        OnPropertyChanged(nameof(IsSetupWorking));
        OnPropertyChanged(nameof(ProgressValue));
        OnPropertyChanged(nameof(StepProgressText));
        OnPropertyChanged(nameof(AccountSummaryText));
        OnPropertyChanged(nameof(ReviewBucketText));
        OnPropertyChanged(nameof(ReviewFolderText));
        OnPropertyChanged(nameof(ReviewModeText));
        OnPropertyChanged(nameof(ReviewLocationText));
        OnPropertyChanged(nameof(PreviewSummaryText));
        OnPropertyChanged(nameof(OwnerPagingVisibility));
        OnPropertyChanged(nameof(BucketPagingVisibility));
        OnPropertyChanged(nameof(InspectPagingVisibility));
        OnPropertyChanged(nameof(StorageCheckDetailsVisibility));
    }

    /// <summary>Clears every wizard result from <paramref name="step"/> onward.</summary>
    private void InvalidateFrom(int step)
    {
        if (_disposed) return;
        if (step <= 1)
        {
            Buckets.Clear();
            SelectedBucket = null;
            _createdBucket = null;
            _createdBucketOperationId = null;
            CreatedBucketText = "No private bucket has been created in this session.";
            _bucketsCursor = null;
            HasMoreBuckets = false;
            BucketsEmptyText = "Select an owner to load its buckets.";
        }
        if (step <= 2)
        {
            _inspectValid = false;
            _inspectedBinding = null;
            _inspectedManaged = false;
            _inspectedPrefixEmpty = false;
            InspectStatusText = "No prefix has been inspected yet.";
            InspectItems.Clear();
            InspectItemsEmptyText = string.Empty;
            _inspectCursor = null;
            HasMoreInspectItems = false;
            InitializeConsent = false;
        }
        if (step <= 3)
        {
            _setupValid = false;
            _connectionId = Guid.Empty;
            _protectionContext = null;
            SetupStatusText = "No setup has been reserved yet.";
        }
        if (step <= 4)
        {
            _credentialsStored = false;
            CredentialsStatusText = "No supplemental publication credentials have been stored.";
        }
        if (step <= 5)
        {
            _probePassed = false;
            _probeAttempted = false;
            ProbeChecks.Clear();
            ProbeRunIdText = "A fresh run UUID is generated each time the probe starts.";
            ProbeStatusText = "No storage probe has been run for this setup.";
            ProbeCapabilityText = "Capability: not probed.";
            ProbeReportPathText = "Report path: none.";
        }
        if (step <= 6)
        {
            _previewValid = false;
            _previewId = Guid.Empty;
            _preview = null;
            PreviewStatusText = "No connect preview has been produced yet.";
            CollisionSummary.Clear();
            Collisions.Clear();
            ProposedActions.Clear();
            CollisionSummaryEmptyText = string.Empty;
        }
        if (step <= 7)
        {
            RequiresReview = false;
            ReviewConsent = false;
            ReviewText = "Nothing to review yet.";
        }
        if (step <= 8)
        {
            _connected = false;
            ConnectStatusText = "The folder has not been connected yet.";
        }
        WizardStateChanged();
    }

    // ── Stale-response suppression ─────────────────────────────────────────

    private (long Generation, string? AccountKey) BeginScope() => (_session.Generation, _accountKey);

    private bool IsScopeStale((long Generation, string? AccountKey) scope) =>
        _disposed || scope.Generation != _session.Generation || scope.AccountKey != _accountKey;

    // ── Step 0: account status ─────────────────────────────────────────────

    [RelayCommand]
    private Task RefreshAccountAsync(CancellationToken cancellationToken) => RefreshAccountCoreAsync(cancellationToken);

    private async Task RefreshAccountCoreAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        IsBusy = true;
        BusyText = "Reading account status…";
        ErrorText = null;
        try
        {
            GetStatusResult status = await _session
                .SendAsync(Commands.GetStatus, new GetStatusRequest(), request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ApplyAccount(status.Account);
            StatusText = "Account status refreshed from the provider.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            AdvanceAfterSignIn();
            WizardStateChanged();
        }
    }

    private void ApplyAccount(AccountStatus account)
    {
        string? key = account.Profile?.AccountKey
            ?? (account.State == AuthenticationState.SigningIn ? _accountKey : null);
        if (_accountObserved && key != _accountKey)
        {
            // A different person (or sign-out) invalidates every selection that
            // was made for the previous account identity.
            ResetWizardForAccountChange();
        }
        _accountObserved = true;
        _accountKey = key;
        _authenticationState = account.State;
        if (account.Profile is { } currentProfile)
        {
            _grantedScopes = currentProfile.GrantedScopes;
            _accountNamespace = currentProfile.Namespace;
        }
        else if (account.State != AuthenticationState.SigningIn)
        {
            _grantedScopes = null;
            _accountNamespace = null;
        }
        AccountStateText = account.State switch
        {
            AuthenticationState.SignedOut => "Not signed in.",
            AuthenticationState.SigningIn => "Waiting for authorization.",
            AuthenticationState.SignedIn => $"Signed in as {account.Profile?.DisplayName} ({account.Profile?.Namespace}).",
            AuthenticationState.NeedsSignIn => "Sign-in required. Existing local work is retained.",
            _ => account.State.ToString(),
        };
        AccountDetailText = account.Profile is { } profile
            ? $"Account key: {profile.AccountKey}\nIssuer: {profile.Issuer}\nSubject: {profile.Subject}\nNamespace: {profile.Namespace}\n"
              + $"Granted scopes: {(profile.GrantedScopes is { Count: > 0 } scopes ? string.Join(" ", scopes) : "not reported")}"
            : "No verified profile has been received from the provider.";
        if (account.LastError is { } error)
            ErrorText = $"{error.Code}: {error.Message}";
        else if (AccountReady && CurrentStep == 0)
            ErrorText = null;
        AdvanceAfterSignIn();
        WizardStateChanged();
    }

    private void AdvanceAfterSignIn()
    {
        if (CurrentStep == 0 && AccountReady && !NeedsReadConsent && !_main.IsLoginPending)
            CurrentStep = 1;
        if (CurrentStep == 1 && Owners.Count == 0 && AccountReady && !IsBusy && !IsOwnersLoading)
            _ = LoadOwnersCoreAsync(null, true, _lifetime.Token);
    }

    private void SelectPersonalOwner()
    {
        if (SelectedOwner is not null) return;
        SelectedOwner = Owners.FirstOrDefault(owner => owner.Owner.Namespace == _accountNamespace)
            ?? (Owners.Count == 1 ? Owners[0] : null);
    }

    private void ResetWizardForAccountChange()
    {
        _ownersRequest?.Cancel();
        _bucketsRequest?.Cancel();
        _inspectRequest?.Cancel();
        Owners.Clear();
        _ownersCursor = null;
        HasMoreOwners = false;
        OwnersEmptyText = "Sign in to load verified personal and organization owners.";
        SelectedOwner = null;
        RootPathText = string.Empty;
        CurrentStep = 0;
        InvalidateFrom(1);
        StatusText = "The signed-in account changed; the setup wizard state was reset.";
    }

    // ── Step 1: owners and buckets ─────────────────────────────────────────

    private string? _ownersCursor;
    private string? _bucketsCursor;
    private string? _inspectCursor;

    [RelayCommand(CanExecute = nameof(CanLoadMoreOwners))]
    private Task LoadMoreOwnersAsync(CancellationToken cancellationToken) => LoadOwnersCoreAsync(_ownersCursor, false, cancellationToken);

    private bool CanLoadMoreOwners() => !IsBusy && HasMoreOwners;

    private async Task LoadOwnersCoreAsync(string? cursor, bool replace, CancellationToken cancellationToken)
    {
        if ((!replace && IsOwnersLoading) || (replace && IsBusy)) return;
        var scope = BeginScope();
        string? requestedFor = scope.AccountKey;
        if (replace) _ownersRequest?.Cancel();
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _ownersRequest = request;
        IsOwnersLoading = true;
        try
        {
            ListOwnersResult page = await _session
                .SendAsync(Commands.ListOwners, new ListOwnersRequest { Cursor = cursor, Limit = ProtocolConstants.MaxPageLimit }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope) || (replace && !ReferenceEquals(request, _ownersRequest))) return;
            if (replace) Owners.Clear();
            foreach (Owner owner in page.Items) Owners.Add(new OwnerViewModel(owner));
            _ownersCursor = page.NextCursor;
            HasMoreOwners = page.NextCursor is not null;
            OwnersEmptyText = Owners.Count == 0
                ? (requestedFor is null ? "Sign in to load verified owners." : "The provider reported no verified owners.")
                : string.Empty;
            SelectPersonalOwner();
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            if (ReferenceEquals(request, _ownersRequest))
            {
                _ownersRequest = null;
                IsOwnersLoading = false;
            }
            WizardStateChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanLoadMoreBuckets))]
    private Task LoadMoreBucketsAsync(CancellationToken cancellationToken) => LoadBucketsCoreAsync(_bucketsCursor, false, cancellationToken);

    private bool CanLoadMoreBuckets() => !IsBusy && HasMoreBuckets;

    private async Task LoadBucketsCoreAsync(string? cursor, bool replace, CancellationToken cancellationToken)
    {
        string? ownerNamespace = SelectedOwner?.Owner.Namespace;
        if (ownerNamespace is null || (!replace && IsBucketsLoading) || (replace && IsBusy)) return;
        var scope = BeginScope();
        var ownerIdentity = (SelectedOwner!.Owner.OwnerId, ownerNamespace);
        if (replace) _bucketsRequest?.Cancel();
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _bucketsRequest = request;
        IsBucketsLoading = true;
        try
        {
            ListBucketsResult page = await _session
                .SendAsync(Commands.ListBuckets, new ListBucketsRequest
                {
                    OwnerNamespace = ownerNamespace,
                    Cursor = cursor,
                    Limit = ProtocolConstants.MaxPageLimit,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope) || (replace && !ReferenceEquals(request, _bucketsRequest))) return;
            if (ownerIdentity != (SelectedOwner?.Owner.OwnerId, SelectedOwner?.Owner.Namespace)) return;
            if (replace) Buckets.Clear();
            foreach (Bucket bucket in page.Items) Buckets.Add(bucket);
            _bucketsCursor = page.NextCursor;
            HasMoreBuckets = page.NextCursor is not null;
            BucketsEmptyText = Buckets.Count == 0
                ? "The provider reported no buckets for this owner."
                : string.Empty;
            if (SelectedBucket is null && Buckets.Count == 1 && !HasMoreBuckets)
                SelectedBucket = Buckets[0];
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            if (ReferenceEquals(request, _bucketsRequest))
            {
                _bucketsRequest = null;
                IsBucketsLoading = false;
            }
            WizardStateChanged();
        }
    }

    [RelayCommand(CanExecute = nameof(CanCreateBucket))]
    private async Task CreateBucketAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        OwnerViewModel? owner = SelectedOwner;
        if (owner?.Owner.Namespace is not { } ownerNamespace) return;
        string bucketName = NewBucketName.Trim();
        if (bucketName.Length == 0) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        IsBusy = true;
        BusyText = $"Creating private bucket {bucketName}…";
        ErrorText = null;
        CreationErrorText = null;
        try
        {
            if (NeedsCreateConsent)
            {
                StatusText = "Allow Manage repositories in Hugging Face, then select Create private bucket again.";
                string? organizationId = owner.Owner.OwnerKind == OwnerKind.Organization ? owner.Owner.OwnerId : null;
                await RequestStorageLoginAsync(LoginFlow.Pkce, LoginPurpose.CreateStorage, organizationId).ConfigureAwait(true);
                if (!string.IsNullOrWhiteSpace(ErrorText))
                {
                    CreationErrorText = $"Bucket creation authorization failed: {ErrorText}";
                    ErrorText = null;
                    StatusText = "Private bucket creation was not authorized.";
                }
                return;
            }

            Guid operationId = Guid.NewGuid();
            CreateBucketResult result = await _session
                .SendAsync(Commands.CreateBucket, new CreateBucketRequest
                {
                    OperationId = operationId,
                    OwnerId = owner.Owner.OwnerId,
                    OwnerKind = owner.Owner.OwnerKind,
                    OwnerNamespace = ownerNamespace,
                    BucketName = bucketName,
                    Region = SelectedRegion is "us" or "eu" ? SelectedRegion : null,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            _createdBucket = result.Bucket;
            _createdBucketOperationId = operationId;
            if (!Buckets.Any(existing => existing.BucketId == result.Bucket.BucketId))
                Buckets.Add(result.Bucket);
            SelectedBucket = result.Bucket;
            NewBucketName = string.Empty;
            CreatedBucketText = result.Completed
                ? $"Created private bucket {result.Bucket.Name} (ID {result.Bucket.BucketId}) with creation operation {operationId}."
                : $"Bucket creation did not complete fully. The provider recorded the created resources under operation {operationId}; created resources remain visible and this setup cannot proceed until creation completes.";
            if (!result.Completed)
            {
                _createdBucketOperationId = null;
                CreationErrorText = "The provider did not complete bucket creation; the partial creation is recorded in the setup intent.";
            }
            StatusText = result.Completed ? "Private bucket creation finished." : "Private bucket creation needs attention.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope))
            {
                string message = ErrorMessage(ex);
                CreationErrorText = ex is ProtocolException protocol && protocol.Error.Code == ProtocolErrorCode.PermissionDenied
                    ? $"Hugging Face denied bucket creation for {ownerNamespace}. Your account needs Manage repositories consent and permission to create buckets for this owner. No bucket was created. ({message})"
                    : $"Bucket creation failed: {message}";
                StatusText = "Private bucket creation failed.";
            }
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanCreateBucket() =>
        !IsBusy && SelectedOwner?.Owner.Namespace is not null && NewBucketName.Trim().Length != 0;

    partial void OnNewBucketNameChanged(string value)
    {
        CreationErrorText = null;
        WizardStateChanged();
    }

    // ── Step 2: inspection ─────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanInspect))]
    private async Task InspectAsync(CancellationToken cancellationToken)
    {
        if (IsBusy) return;
        if (!TryBuildLocation(out RemoteLocation location, out string? validationError))
        {
            ErrorText = validationError;
            return;
        }
        var scope = BeginScope();
        var locationKey = (location.OwnerId, location.BucketId, location.Prefix);
        _inspectRequest?.Cancel();
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _inspectRequest = request;
        IsBusy = true;
        BusyText = "Inspecting the target prefix…";
        ErrorText = null;
        try
        {
            InspectDriveResult result = await _session
                .SendAsync(Commands.InspectDrive, new InspectDriveRequest
                {
                    ConnectionId = null,
                    Location = location,
                    Cursor = null,
                    Limit = ProtocolConstants.MaxPageLimit,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope) || !ReferenceEquals(request, _inspectRequest)) return;
            if (locationKey != (SelectedOwner?.Owner.OwnerId, SelectedBucket?.BucketId, PrefixText.Trim())) return;
            ApplyInspection(result);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            if (ReferenceEquals(request, _inspectRequest)) _inspectRequest = null;
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanInspect() => !IsBusy && SelectedOwner?.Owner.Namespace is not null && SelectedBucket is not null;

    private bool TryBuildLocation(out RemoteLocation location, out string? validationError)
    {
        location = null!;
        validationError = null;
        OwnerViewModel? owner = SelectedOwner;
        Bucket? bucket = SelectedBucket;
        if (owner?.Owner.Namespace is not { } ownerNamespace)
        {
            validationError = "Select an owner with a canonical namespace before inspecting.";
            return false;
        }
        if (bucket is null)
        {
            validationError = "Select a bucket before inspecting.";
            return false;
        }
        string prefix = PrefixText.Trim();
        if (prefix.Contains('\\') || prefix.StartsWith('/') || prefix.Contains(".."))
        {
            validationError = "The prefix must be a relative key prefix without root, backslashes or traversal segments.";
            return false;
        }
        location = new RemoteLocation
        {
            OwnerNamespace = ownerNamespace,
            OwnerId = owner.Owner.OwnerId,
            OwnerKind = owner.Owner.OwnerKind,
            Bucket = bucket.Name,
            BucketId = bucket.BucketId,
            Prefix = prefix,
        };
        return true;
    }

    private void ApplyInspection(InspectDriveResult result)
    {
        _inspectedBinding = result.Binding;
        _inspectedManaged = result.IsManagedDrive;
        _inspectedPrefixEmpty = result.PrefixEmpty;
        _inspectCursor = result.NextCursor;
        HasMoreInspectItems = result.NextCursor is not null;
        InspectItems.Clear();
        foreach (InspectItem item in result.Items) InspectItems.Add(new InspectItemRow(item));
        InspectItemsEmptyText = InspectItems.Count == 0 ? "The provider returned no item records for this prefix." : string.Empty;

        var summary = new List<string>();
        if (result.IsManagedDrive)
        {
            summary.Add("A compatible managed drive exists at this prefix.");
            if (result.Binding is { } binding)
                summary.Add(
                    $"Managed identity: owner {binding.OwnerId} ({binding.OwnerKind}, {binding.OwnerNamespace}), "
                    + $"bucket {binding.Bucket} (ID {binding.BucketId}), prefix \"{binding.Prefix}\", workspace {binding.WorkspaceId}.");
            summary.Add(result.HeadGeneration is { } generation
                ? $"Remote HEAD generation: {generation}."
                : "No HEAD generation was reported for this managed drive.");
        }
        else if (result.PrefixEmpty)
        {
            summary.Add("The prefix is empty and has no managed drive.");
        }
        else
        {
            summary.Add("The prefix contains ordinary objects and is not a managed drive.");
            summary.Add("HF Drive manages a prefix whose raw bucket layout differs from your Explorer folders. Ordinary objects are never imported automatically into a managed drive. To upload selected files or folders into a bucket, right-click them in Explorer and choose Hugging Face Drive, then the destination bucket. Raw imports go under hfdrive-imports/<import-id> and do not create a managed workspace.");
        }
        InspectStatusText = string.Join("\n", summary);
        _inspectValid = true;
        ErrorText = null;
        StatusText = "Inspection finished.";

        // The inspection can contradict or update the selection the user picked.
        if (SelectedSource.Source == SetupSource.InitializeNewManagedDrive && result.IsManagedDrive)
        {
            summary.Add("An HF Drive already exists here. Choose \"Use an existing HF Drive\" to connect it.");
            InspectStatusText = string.Join("\n", summary);
        }
        else if (SelectedSource.Source == SetupSource.ExistingManagedDrive && !result.IsManagedDrive && result.PrefixEmpty)
        {
            summary.Add("No HF Drive exists here yet. Choose \"Create a new HF Drive\" to set one up.");
            InspectStatusText = string.Join("\n", summary);
        }
        if (SelectedSource.Source == SetupSource.ExistingManagedDrive && result.IsManagedDrive && result.Binding is not null)
        {
            _settingPrefix = true;
            PrefixText = result.Binding.Prefix;
            WorkspaceIdText = $"Workspace ID: {result.Binding.WorkspaceId} (discovered by the inspection).";
            _settingPrefix = false;
        }
        else if (SelectedSource.Source == SetupSource.InitializeNewManagedDrive && result.PrefixEmpty)
        {
            WorkspaceIdText = $"Workspace ID: {_newWorkspaceId} (generated for this new managed drive; the provider initializes it at Connect).";
        }
        WizardStateChanged();
    }

    [RelayCommand(CanExecute = nameof(CanLoadMoreInspectItems))]
    private async Task LoadMoreInspectItemsAsync(CancellationToken cancellationToken)
    {
        if (IsBusy || !_inspectValid || _inspectCursor is not { } cursor) return;
        if (!TryBuildLocation(out RemoteLocation location, out _)) return;
        var scope = BeginScope();
        _inspectRequest?.Cancel();
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _inspectRequest = request;
        IsBusy = true;
        BusyText = "Loading more item records…";
        try
        {
            InspectDriveResult result = await _session
                .SendAsync(Commands.InspectDrive, new InspectDriveRequest
                {
                    ConnectionId = null,
                    Location = location,
                    Cursor = cursor,
                    Limit = ProtocolConstants.MaxPageLimit,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope) || !ReferenceEquals(request, _inspectRequest)) return;
            foreach (InspectItem item in result.Items) InspectItems.Add(new InspectItemRow(item));
            _inspectCursor = result.NextCursor;
            HasMoreInspectItems = result.NextCursor is not null;
            InspectItemsEmptyText = InspectItems.Count == 0 ? "The provider returned no item records for this prefix." : string.Empty;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            if (ReferenceEquals(request, _inspectRequest)) _inspectRequest = null;
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanLoadMoreInspectItems() => !IsBusy && HasMoreInspectItems;

    private void RegenerateWorkspaceId(bool resetPrefix)
    {
        _newWorkspaceId = Guid.NewGuid();
        if (resetPrefix)
        {
            _settingPrefix = true;
            PrefixText = $"hfdrive/{_newWorkspaceId:D}";
            _settingPrefix = false;
        }
        WorkspaceIdText = $"Workspace ID: {_newWorkspaceId} (generated for this new managed drive; the provider initializes it at Connect).";
    }

    // ── Step 3: durable setup reservation ──────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanBeginSetup))]
    private async Task BeginSetupAsync(CancellationToken cancellationToken)
    {
        if (!CanBeginSetup()) return;
        if (_accountKey is not { } accountKey)
        {
            ErrorText = "The provider has not reported a signed-in account; refresh the account step first.";
            return;
        }
        if (!TryBuildBinding(out RemoteBinding binding, out string? validationError))
        {
            ErrorText = validationError;
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        IsBusy = true;
        BusyText = "Reserving the setup in the provider…";
        ErrorText = null;
        try
        {
            BeginSetupResult result = await _session
                .SendAsync(Commands.BeginSetup, new BeginSetupRequest
                {
                    OperationId = Guid.NewGuid(),
                    AccountKey = accountKey,
                    Binding = binding,
                    Initialize = SelectedSource.Source == SetupSource.InitializeNewManagedDrive,
                    BucketCreationOperationId = _createdBucketOperationId,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            _connectionId = result.ConnectionId;
            _protectionContext = result.ProtectionContext;
            _setupValid = true;
            PublicationProtectionContext context = result.ProtectionContext;
            SetupStatusText =
                $"Setup reserved.\nSetup ID: {result.SetupId}\nReserved connection ID: {result.ConnectionId}\n"
                + $"Binding: owner {result.Binding.OwnerId} ({result.Binding.OwnerKind}, {result.Binding.OwnerNamespace}), "
                + $"bucket {result.Binding.Bucket} (ID {result.Binding.BucketId}), prefix \"{result.Binding.Prefix}\", workspace {result.Binding.WorkspaceId}\n"
                + $"Protection context (nonsecret confirmation only): connection {context.ConnectionId}, account {context.AccountKey}, "
                + $"issuer {context.Issuer}, subject {context.Subject}, owner {context.OwnerId} ({context.OwnerKind}), "
                + $"bucket {context.BucketId}, workspace {context.WorkspaceId}, prefix \"{context.Prefix}\".\n"
                + $"Initialized by this setup: {(SelectedSource.Source == SetupSource.InitializeNewManagedDrive ? "yes, at Connect" : "no, existing managed drive")}";
            StatusText = "Setup reserved durably in the provider.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanBeginSetup() => !IsBusy && InspectionIsCompatible && AccountReady;

    private bool TryBuildBinding(out RemoteBinding binding, out string? validationError)
    {
        binding = null!;
        validationError = null;
        if (SelectedSource.Source == SetupSource.ExistingManagedDrive)
        {
            if (_inspectedBinding is not { } inspected)
            {
                validationError = "The inspection did not return a managed binding; inspect the prefix again.";
                return false;
            }
            binding = inspected;
            return true;
        }
        if (!TryBuildLocation(out RemoteLocation location, out validationError))
            return false;
        binding = new RemoteBinding
        {
            OwnerNamespace = location.OwnerNamespace,
            OwnerId = location.OwnerId,
            OwnerKind = location.OwnerKind,
            Bucket = location.Bucket,
            BucketId = location.BucketId,
            Prefix = location.Prefix,
            WorkspaceId = _newWorkspaceId,
        };
        return true;
    }

    // ── Step 4: supplemental publication credentials ───────────────────────

    /// <summary>
    /// Protects the form input and sends it to the provider. The caller clears
    /// the input fields immediately. The DPAPI ciphertext is never displayed,
    /// stored in this view model or logged. Immutable .NET strings cannot be
    /// guaranteed erased; their lifetime is only minimized.
    /// </summary>
    public async Task StoreCredentialsAsync(string keyId, string secretKey)
    {
        if (IsBusy || !_setupValid || _protectionContext is not { } context) return;
        var scope = BeginScope();
        _credentialsStored = false;
        InvalidateFrom(5);
        IsBusy = true;
        BusyText = "Protecting and storing the publication credentials…";
        ErrorText = null;
        try
        {
            Guid operationId = Guid.NewGuid();
            SetPublicationCredentialsRequest request =
                PublicationCredentialProtection.CreateRequest(context, operationId, keyId, secretKey);
            keyId = secretKey = string.Empty;
            SetPublicationCredentialsResult result = await _session
                .SendAsync(Commands.SetPublicationCredentials, request, _lifetime.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            _credentialsStored = result.Stored;
            CredentialsStatusText = result.Stored
                ? $"Supplemental publication credentials stored for connection {context.ConnectionId}. Capability: {result.Capability}. The ciphertext is never displayed."
                : "The provider did not store the protected credential record.";
            StatusText = result.Stored ? "Publication credentials stored." : "Publication credentials were not stored.";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    // ── Step 5: capability probe ───────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanProbe))]
    private async Task ProbeAsync(CancellationToken cancellationToken)
    {
        if (IsBusy || !_setupValid) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        Guid runId = Guid.NewGuid();
        IsBusy = true;
        BusyText = "Running the full storage probe…";
        ErrorText = null;
        ProbeRunIdText = $"Probe run ID: {runId}";
        _probeAttempted = true;
        OnPropertyChanged(nameof(StorageCheckDetailsVisibility));
        try
        {
            ProbeStorageResult result = await _session
                .SendAsync(Commands.ProbeStorage, new ProbeStorageRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = _connectionId,
                    RunId = runId,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            ProbeChecks.Clear();
            foreach (ProbeCheck check in result.Checks) ProbeChecks.Add(new ProbeCheckRow(check));
            ProbeCapabilityText = $"Capability after the probe: {result.Capability}";
            ProbeReportPathText = string.IsNullOrEmpty(result.ReportPath)
                ? "Report path: the provider did not report one."
                : $"Report path: {result.ReportPath}";
            bool allPassed = result.Checks.Count != 0 && result.Checks.All(check => check.Outcome == ProbeOutcome.Passed);
            _probePassed = result.RunId == runId && allPassed && result.Capability == CapabilityState.Writable;
            ProbeStatusText = _probePassed
                ? "All probe checks passed; this connection can publish."
                : "The probe did not prove writable publication. Writable mode cannot be used until every check passes.";
            StatusText = _probePassed ? "Storage probe passed." : "Storage probe finished without proving writable publication.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanProbe() => !IsBusy && _setupValid && _credentialsStored && IsWritable;

    // ── Step 6: local root, mode and preview ───────────────────────────────

    [RelayCommand(CanExecute = nameof(CanPreview))]
    private async Task PreviewAsync(CancellationToken cancellationToken)
    {
        if (IsBusy || !_setupValid) return;
        string rootPath = RootPathText.Trim();
        if (rootPath.Length == 0)
        {
            ErrorText = "Enter the absolute local folder to synchronize.";
            return;
        }
        if (!Path.IsPathRooted(rootPath))
        {
            ErrorText = "The local folder must be an absolute path.";
            return;
        }
        if (IsWritable && !_probePassed)
        {
            ErrorText = "Writable mode requires supplemental publication credentials and a successful full probe first.";
            return;
        }
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        IsBusy = true;
        BusyText = "Scanning the local folder and building the connect preview…";
        ErrorText = null;
        try
        {
            PreviewConnectResult result = await _session
                .SendAsync(Commands.PreviewConnect, new PreviewConnectRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = _connectionId,
                    RootPath = rootPath,
                    Mode = SelectedMode.Mode,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            if (result.ConnectionId != _connectionId)
            {
                ErrorText = "The provider returned a preview for a different reserved connection; the preview was discarded.";
                return;
            }
            ApplyPreview(result);
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanPreview() => !IsBusy && _setupValid && RootPathText.Trim().Length != 0 && (!IsWritable || _probePassed);

    private void ApplyPreview(PreviewConnectResult result)
    {
        _preview = result;
        _previewId = result.PreviewId;
        _previewValid = true;
        RequiresReview = result.RequiresReview;
        ReviewConsent = false;

        CollisionSummary.Clear();
        foreach (CollisionCategorySummary summary in result.CollisionSummary) CollisionSummary.Add(new CollisionSummaryRow(summary));
        Collisions.Clear();
        foreach (Collision collision in result.Collisions) Collisions.Add(new CollisionRow(collision));
        ProposedActions.Clear();
        foreach (ProposedActionRecord action in result.ProposedActions) ProposedActions.Add(new ProposedActionRow(action));
        CollisionSummaryEmptyText = result.CollisionSummary.Count == 0
            ? "The preview recorded no collisions between the local folder and the remote drive."
            : string.Empty;

        PreviewStatusText =
            $"Preview ID: {result.PreviewId}\n"
            + $"HEAD generation: {(result.HeadGeneration is { } generation ? generation.ToString() : "none — this setup explicitly initializes a new managed drive")}\n"
            + $"Local scan generation: {result.LocalScanGeneration}\n"
            + $"Proposed actions: {result.ProposedActionCount} total, {result.ProposedActions.Count} shown\n"
            + $"Collisions: {result.Collisions.Count} shown of the recorded categories below\n"
            + $"Visibility: {result.Visibility}\n"
            + $"Review required: {(result.RequiresReview ? "yes — every collision category must be reviewed before connecting" : "no")}";

        ReviewText =
            $"Owner ID: {result.Binding.OwnerId} · kind: {result.Binding.OwnerKind} · namespace: {result.Binding.OwnerNamespace}\n"
            + $"Bucket ID: {result.Binding.BucketId} · name: {result.Binding.Bucket}\n"
            + $"Managed prefix: \"{result.Binding.Prefix}\" · workspace: {result.Binding.WorkspaceId}\n"
            + $"Visibility: {result.Visibility}\n"
            + $"Local folder: {RootPathText.Trim()}\n"
            + $"Access mode: {(SelectedMode.Mode == ConnectionMode.ReadOnly ? "Read-only" : "Writable")}\n"
            + $"HEAD generation: {(result.HeadGeneration is { } g ? g.ToString() : "none — explicit initialization")}\n"
            + "HF Drive manages this prefix; its raw bucket layout differs from your Explorer folders.";

        StatusText = "Connect preview produced from the persisted scan.";
    }

    // ── Step 8: connect ────────────────────────────────────────────────────

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task ConnectAsync(CancellationToken cancellationToken)
    {
        if (!CanConnect()) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        Guid previewId = _previewId;
        IsBusy = true;
        BusyText = "Connecting the local folder…";
        ErrorText = null;
        try
        {
            ConnectResult result = await _session
                .SendAsync(Commands.Connect, new ConnectRequest
                {
                    OperationId = Guid.NewGuid(),
                    PreviewId = previewId,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            _connected = true;
            ConnectStatusText = "Connected. Provider-returned connection status:\n" + DescribeStatus(result.Status);
            StatusText = string.Empty;
            UpdateStepText();
        }
        catch (ProtocolException ex) when (ex.Error.Code == ProtocolErrorCode.PreviewChanged)
        {
            if (IsScopeStale(scope)) return;
            ErrorText = "The preview inputs changed; the refreshed preview below must be reviewed before connecting.";
            await RefreshPreviewAfterChangeAsync(cancellationToken).ConfigureAwait(true);
            return;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            if (_connected) await RefreshSharedStatusAsync(cancellationToken).ConfigureAwait(true);
            IsBusy = false;
            BusyText = string.Empty;
            WizardStateChanged();
        }
    }

    private bool CanConnect() => !IsBusy && _previewValid && (!IsWritable || _probePassed)
        && (!RequiresReview || ReviewConsent)
        && (SelectedSource.Source != SetupSource.InitializeNewManagedDrive || InitializeConsent) && !_connected;

    private async Task RefreshPreviewAfterChangeAsync(CancellationToken cancellationToken)
    {
        if (_preview is null || !_setupValid) return;
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        var scope = BeginScope();
        try
        {
            PreviewConnectResult result = await _session
                .SendAsync(Commands.PreviewConnect, new PreviewConnectRequest
                {
                    OperationId = Guid.NewGuid(),
                    ConnectionId = _connectionId,
                    RootPath = RootPathText.Trim(),
                    Mode = SelectedMode.Mode,
                }, request.Token)
                .ConfigureAwait(true);
            if (IsScopeStale(scope)) return;
            if (result.ConnectionId != _connectionId) return;
            ApplyPreview(result);
            StatusText = "The preview was refreshed because its inputs changed. Review it again before connecting.";
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!IsScopeStale(scope)) ShowError(ex);
        }
        finally
        {
            // Stale consent must never survive a refreshed preview.
            ReviewConsent = false;
            CurrentStep = 3;
            WizardStateChanged();
        }
    }

    private async Task RefreshSharedStatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _main.RefreshCommand.ExecuteAsync(null).ConfigureAwait(true);
            ConnectStatusText += "\nShared account/connection status refreshed from the provider.";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            ConnectStatusText += $"\nThe shared status refresh failed: {ErrorMessage(ex)}";
        }
    }

    private static string DescribeStatus(ConnectionStatus status)
    {
        string owner = $"{status.Owner.DisplayName} (ID {status.Owner.OwnerId}, {status.Owner.OwnerKind}, {status.Owner.Namespace ?? "namespace not reported"})";
        return
            $"Connection ID: {status.ConnectionId}\n"
            + $"Workspace: {status.WorkspaceId}\n"
            + $"Owner: {owner}\n"
            + $"Bucket: {status.Bucket.Name} (ID {status.Bucket.BucketId}, {status.Bucket.Visibility})\n"
            + $"Managed prefix: \"{status.Prefix}\"\n"
            + $"Local folder: {status.RootPath}\n"
            + $"Mode: {(status.Mode == ConnectionMode.ReadOnly ? "Read-only" : "Writable")}\n"
            + $"Capability: {status.Capability}\n"
            + $"State: {StatusDisplayText.Get(status.State)}\n"
            + $"Last observed commit: {status.ObservedCommit?.ToString() ?? "none"}\n"
            + $"Published commit: {status.PublishedCommit?.ToString() ?? "none"}\n"
            + $"Applied commit: {status.AppliedCommit?.ToString() ?? "none"}\n"
            + $"Files: {status.PendingFiles} pending, {status.DirtyFiles} local changes, {status.ConflictFiles} conflicts, {status.OnlineOnlyFiles} online-only, {status.PinnedFiles} pinned\n"
            + $"Updated: {status.UpdatedAt}"
            + (status.LastError is { } error ? $"\nLast error: {error.Code}: {error.Message}" : string.Empty);
    }

    // ── Session events ─────────────────────────────────────────────────────

    private void OnSessionChanged(object? sender, EventArgs args) =>
        _dispatcher.TryEnqueue(() =>
        {
            if (_disposed) return;
            if (_session.State != ProviderConnectionState.Ready)
                StatusText = "The provider connection is not ready; reconnect before continuing the wizard.";
            WizardStateChanged();
        });

    private void OnMainPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs args)
    {
        if (_disposed) return;
        if (args.PropertyName == nameof(MainViewModel.Account) && _main.HasObservedStatus && _main.Account is { } account)
            ApplyAccount(account);
        WizardStateChanged();
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static string ErrorMessage(Exception error) => error is ProtocolException protocol
        ? $"{protocol.Error.Code}: {protocol.Error.Message}"
        : error.Message;

    private void ShowError(Exception error)
    {
        string message = ErrorMessage(error);
        ErrorText = message;
        StatusText = NextBlockedReason(CurrentStep);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.StateChanged -= OnSessionChanged;
        _main.PropertyChanged -= OnMainPropertyChanged;
        _lifetime.Cancel();
        _ownersRequest?.Cancel();
        _bucketsRequest?.Cancel();
        _inspectRequest?.Cancel();
        _lifetime.Dispose();
    }
}
