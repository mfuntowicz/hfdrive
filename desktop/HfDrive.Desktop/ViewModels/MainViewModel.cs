using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HfDrive.Desktop.Services;
using HfDrive.Protocol;
using Microsoft.UI.Dispatching;

namespace HfDrive.Desktop.ViewModels;

/// <summary>UI-thread projection of the provider's verified identity and observed state.</summary>
public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ProviderSession _session;
    private readonly DispatcherQueue _dispatcher = DispatcherQueue.GetForCurrentThread();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<Guid, ConnectionStatus> _connectionRecords = new();
    private readonly Dictionary<Guid, int> _connectionIndices = new();
    private readonly HashSet<Guid> _changedConnectionIds = new();
    private CancellationTokenSource? _ownerRequest;
    private AccountStatus? _account;
    private string? _ownersCursor;
    private long _statusGeneration = -1;
    private ulong _statusSequence;
    private bool _haveStatus;
    private bool _disposed;

    public MainViewModel(ProviderSession session)
    {
        _session = session;
        _session.StateChanged += OnSessionChanged;
        _session.StatusChanged += OnStatusChanged;
    }

    public ObservableCollection<ConnectionViewModel> Connections { get; } = new();

    public ObservableCollection<OwnerViewModel> Owners { get; } = new();

    [ObservableProperty]
    private string _connectionStateText = "Disconnected";

    [ObservableProperty]
    private string _connectionDetailText = "HF Drive is not connected to the provider.";

    [ObservableProperty]
    private string? _errorText;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _isStartingProvider;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand), nameof(DeviceLoginCommand), nameof(CancelLoginCommand), nameof(SignOutCommand), nameof(LoadMoreOwnersCommand))]
    private bool _isConnected;

    [ObservableProperty]
    private bool _isDisconnected = true;

    [ObservableProperty]
    private string _providerVersionText = "Provider version: not available";

    [ObservableProperty]
    private string _providerFeaturesText = string.Empty;

    [ObservableProperty]
    private string _peerVerificationText = "Provider process verification: not run";

    [ObservableProperty]
    private string _accountStateText = "Connect to the provider to load your account.";

    [ObservableProperty]
    private string _ownersEmptyText = "No owner identities have been received from the provider.";

    [ObservableProperty]
    private string _connectionsEmptyText = "No connection status has been received from the provider.";

    public string PipeNameDisplay => ProviderPipeName.DisplayPath;

    /// <summary>Most recently accepted provider account status, or null before one arrives.</summary>
    public AccountStatus? Account => _account;

    /// <summary>
    /// True only for the current authenticated provider session after an actual
    /// accepted status. A disconnect is not an empty configuration: this stays
    /// false while the live session has delivered no accepted status, and it
    /// never reports last-observed data as current state.
    /// </summary>
    public bool HasObservedStatus => _haveStatus && _statusGeneration == _session.Generation
        && _session.State == ProviderConnectionState.Ready;

    /// <summary>
    /// True only when an accepted status of the current session reports zero
    /// configured connections. Never inferred from a disconnection or a failed
    /// provider start.
    /// </summary>
    public bool NeedsSetup => HasObservedStatus && Connections.Count == 0;

    /// <summary>Notifies the three freshness properties after any state change.</summary>
    private void NotifyStatusFreshness()
    {
        OnPropertyChanged(nameof(Account));
        OnPropertyChanged(nameof(HasObservedStatus));
        OnPropertyChanged(nameof(NeedsSetup));
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand), nameof(DeviceLoginCommand), nameof(CancelLoginCommand))]
    private bool _isLoginPending;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignInCommand), nameof(DeviceLoginCommand), nameof(CancelLoginCommand), nameof(SignOutCommand))]
    private bool _isAccountCommandBusy;

    [ObservableProperty]
    private string _loginInstructions = string.Empty;

    /// <summary>
    /// Shows the cancel control only while a sign-in attempt is actually
    /// pending; the command keeps its own cancellation guards.
    /// </summary>
    public Microsoft.UI.Xaml.Visibility CancelLoginVisibility =>
        IsLoginPending ? Microsoft.UI.Xaml.Visibility.Visible : Microsoft.UI.Xaml.Visibility.Collapsed;

    partial void OnIsLoginPendingChanged(bool value) =>
        OnPropertyChanged(nameof(CancelLoginVisibility));

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreOwnersCommand))]
    private bool _isOwnersLoading;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LoadMoreOwnersCommand))]
    private bool _hasMoreOwners;

    private bool CanBeginLogin() => IsConnected && !IsLoginPending && !IsAccountCommandBusy;
    private bool CanCancelLogin() => IsConnected && IsLoginPending && !IsAccountCommandBusy;
    private bool CanSignOut() => IsConnected && !IsAccountCommandBusy;
    private bool CanLoadMoreOwners() => IsConnected && HasMoreOwners && !IsOwnersLoading;

    [RelayCommand]
    private async Task ConnectAsync(CancellationToken cancellationToken)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        ErrorText = null;
        try
        {
            await _session.ConnectAsync(cancellationToken).ConfigureAwait(true);
            if (_session.Hello is { } hello)
            {
                ProviderVersionText = $"Provider version: {hello.ProviderVersion}";
                ProviderFeaturesText = hello.SupportedFeatures.Count == 0
                    ? "Provider features: none reported"
                    : $"Provider features: {string.Join(", ", hello.SupportedFeatures)}";
            }

            PeerVerificationText = $"Provider process verification: {_session.PeerVerificationDetail ?? "not run"}";
            await RefreshCoreAsync(false, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally
        {
            ApplySessionState();
            IsBusy = false;
        }
    }

    [RelayCommand]
    private Task RefreshAsync(CancellationToken cancellationToken) => RefreshCoreAsync(true, cancellationToken);

    private async Task RefreshCoreAsync(bool refreshOwners, CancellationToken cancellationToken)
    {
        if (_session.State != ProviderConnectionState.Ready) return;
        IsBusy = true;
        long generation = _session.Generation;
        try
        {
            GetStatusResult status = await _session.SendAsync(Commands.GetStatus, new GetStatusRequest(), cancellationToken).ConfigureAwait(true);
            ApplyStatus(generation, new StatusChangedEvent
            {
                Sequence = status.EventSequence, Snapshot = true,
                Account = status.Account, Changes = status.Connections,
            });
            if (refreshOwners && _account?.State == AuthenticationState.SignedIn && !IsOwnersLoading)
                await LoadOwnerPageAsync(null, true, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally
        {
            ApplySessionState();
            IsBusy = false;
        }
    }

    private async Task LoadOwnerPageAsync(string? cursor, bool replace, CancellationToken cancellationToken)
    {
        if (_account?.State != AuthenticationState.SignedIn) return;
        string? accountKey = _account.Profile?.AccountKey;
        long generation = _session.Generation;
        _ownerRequest?.Cancel();
        using var request = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        _ownerRequest = request;
        IsOwnersLoading = true;
        try
        {
            ListOwnersResult page = await _session.SendAsync(
                Commands.ListOwners, new ListOwnersRequest { Cursor = cursor, Limit = ProtocolConstants.MaxPageLimit }, request.Token).ConfigureAwait(true);
            if (!ReferenceEquals(request, _ownerRequest) || generation != _session.Generation
                || accountKey != _account?.Profile?.AccountKey) return;
            if (replace) Owners.Clear();
            foreach (Owner owner in page.Items) Owners.Add(new OwnerViewModel(owner));
            _ownersCursor = page.NextCursor;
            HasMoreOwners = page.NextCursor is not null;
            OwnersEmptyText = Owners.Count == 0 ? "The provider reported no verified owners." : string.Empty;
        }
        catch (OperationCanceledException) when (request.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (ReferenceEquals(request, _ownerRequest))
                OwnersEmptyText = $"Owner identities unavailable: {ErrorMessage(ex)}";
        }
        finally
        {
            if (ReferenceEquals(request, _ownerRequest))
            {
                _ownerRequest = null;
                IsOwnersLoading = false;
            }
        }
    }

    [RelayCommand(CanExecute = nameof(CanLoadMoreOwners))]
    private Task LoadMoreOwnersAsync(CancellationToken cancellationToken) =>
        LoadOwnerPageAsync(_ownersCursor, false, cancellationToken);

    /// <summary>Mirrors the session's observed state into the observable properties.</summary>
    public void ApplySessionState()
    {
        ConnectionStateText = _session.State switch
        {
            ProviderConnectionState.Disconnected => "Disconnected",
            ProviderConnectionState.Connecting => "Connecting…",
            ProviderConnectionState.Ready => "Connected to provider",
            ProviderConnectionState.Failed => "Provider connection failed",
            _ => _session.State.ToString(),
        };
        ConnectionDetailText = _session.StatusText;
        IsConnected = _session.State == ProviderConnectionState.Ready;
        IsDisconnected = !IsConnected;
        NotifyStatusFreshness();
        if (!IsConnected)
        {
            AccountStateText = "Account status unavailable; reconnect to the provider.";
            IsLoginPending = false;
            LoginInstructions = string.Empty;
            if (Connections.Count != 0) ConnectionDetailText += " Connection rows are last observed, not live.";
        }
        if (_session.LastError is not null)
        {
            ErrorText = _session.LastError;
        }
    }

    [RelayCommand(CanExecute = nameof(CanBeginLogin))]
    private Task SignInAsync(CancellationToken cancellationToken) => BeginLoginAsync(LoginFlow.Pkce, LoginPurpose.Signin, cancellationToken);

    [RelayCommand(CanExecute = nameof(CanBeginLogin))]
    private Task DeviceLoginAsync(CancellationToken cancellationToken) => BeginLoginAsync(LoginFlow.Device, LoginPurpose.Signin, cancellationToken);

    /// <summary>
    /// Explicit storage sign-in for the setup model: requests read, write, or
    /// create scope for the interactive flow the user chose. Never started
    /// automatically — the setup model invokes this from a user CTA only.
    /// </summary>
    /// <param name="flow">The login flow chosen by the user.</param>
    /// <param name="purpose">The exact storage permission being requested.</param>
    /// <param name="token">Cancellation for the login attempt.</param>
    /// <param name="organizationId">Organization to re-consent, when creating for an organization.</param>
    public Task SignInForStorageAsync(LoginFlow flow, LoginPurpose purpose, CancellationToken token, string? organizationId = null)
        => BeginLoginAsync(flow, purpose, token, organizationId);

    private async Task BeginLoginAsync(LoginFlow flow, LoginPurpose purpose, CancellationToken cancellationToken, string? organizationId = null)
    {
        IsAccountCommandBusy = true;
        ErrorText = null;
        LoginInstructions = string.Empty;
        try
        {
            StartLoginResult login = await _session.SendAsync(Commands.StartLogin, new StartLoginRequest
            {
                OperationId = Guid.NewGuid(), Flow = flow, Purpose = purpose,
                OrganizationId = organizationId,
            }, cancellationToken).ConfigureAwait(true);
            if (_account?.Login is not { } observed || observed.SessionId != login.SessionId || observed.Phase == LoginPhase.Pending)
                LoginInstructions = flow == LoginFlow.Device
                    ? $"Open {login.VerificationUri} and enter {login.UserCode}. Expires {login.ExpiresAt}."
                    : "Complete sign-in in your system browser.";
            await RefreshCoreAsync(false, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally { IsAccountCommandBusy = false; }
    }

    [RelayCommand(CanExecute = nameof(CanCancelLogin))]
    private async Task CancelLoginAsync(CancellationToken cancellationToken)
    {
        if (_account?.Login is not { Phase: LoginPhase.Pending } login) return;
        IsAccountCommandBusy = true;
        try
        {
            await _session.SendAsync(Commands.CancelLogin, new CancelLoginRequest
            {
                OperationId = Guid.NewGuid(), SessionId = login.SessionId,
            }, cancellationToken).ConfigureAwait(true);
            await RefreshCoreAsync(false, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally { IsAccountCommandBusy = false; }
    }

    [RelayCommand(CanExecute = nameof(CanSignOut))]
    private async Task SignOutAsync(CancellationToken cancellationToken)
    {
        IsAccountCommandBusy = true;
        ErrorText = null;
        try
        {
            SignOutResult result = await _session.SendAsync(Commands.SignOut,
                new SignOutRequest { OperationId = Guid.NewGuid() }, cancellationToken).ConfigureAwait(true);
            if (!result.SignedOut) { ErrorText = "The provider did not acknowledge sign-out."; return; }
            LoginInstructions = string.Empty;
            await RefreshCoreAsync(false, cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ShowError(ex); }
        finally { IsAccountCommandBusy = false; }
    }

    private void OnSessionChanged(object? sender, EventArgs args) =>
        _dispatcher.TryEnqueue(() => { if (!_disposed) ApplySessionState(); });

    private void OnStatusChanged(long generation, StatusChangedEvent status) =>
        _dispatcher.TryEnqueue(() => { if (!_disposed) ApplyStatus(generation, status); });

    private void ApplyStatus(long generation, StatusChangedEvent status)
    {
        if (generation != _session.Generation) return;
        if (_statusGeneration != generation) { _statusGeneration = generation; _haveStatus = false; }
        if (_haveStatus && status.Sequence < _statusSequence) return;
        _haveStatus = true;
        _statusSequence = status.Sequence;
        AccountStatus? previous = _account;
        _account = status.Account;
        IsLoginPending = status.Account.Login?.Phase == LoginPhase.Pending;
        if (!IsLoginPending) LoginInstructions = string.Empty;
        AccountStateText = status.Account.State switch
        {
            AuthenticationState.SignedOut => "Not signed in.",
            AuthenticationState.SigningIn => "Waiting for authorization.",
            AuthenticationState.SignedIn => $"Signed in as {status.Account.Profile?.DisplayName} ({status.Account.Profile?.Namespace}).",
            AuthenticationState.NeedsSignIn => $"Sign-in required for {status.Account.Profile?.Namespace ?? "the selected account"}. Existing local work is retained.",
            _ => throw new InvalidOperationException("Unknown account state."),
        };
        if (status.Account.LastError is { } error)
            ErrorText = $"{error.Code}: {error.Message}";
        if (status.Account.State != AuthenticationState.SignedIn)
        {
            _ownerRequest?.Cancel();
            Owners.Clear();
            HasMoreOwners = false;
            _ownersCursor = null;
            OwnersEmptyText = "Sign in to load verified personal and organization owners.";
        }
        else if (previous?.State != AuthenticationState.SignedIn
            || previous.Profile?.AccountKey != status.Account.Profile?.AccountKey
            || (status.Account.Login?.Phase == LoginPhase.Completed && previous.Login != status.Account.Login))
        {
            ErrorText = null;
            _ = LoadOwnerPageAsync(null, true, _lifetime.Token);
        }
        _changedConnectionIds.Clear();
        if (status.Snapshot)
            foreach (ConnectionStatus connection in status.Changes) _changedConnectionIds.Add(connection.ConnectionId);
        else
            foreach (Guid removed in status.RemovedConnectionIds) _changedConnectionIds.Add(removed);
        bool removedRows = false;
        if (status.Snapshot || _changedConnectionIds.Count != 0)
        {
            for (int index = Connections.Count - 1; index >= 0; index--)
            {
                Guid id = Connections[index].Status.ConnectionId;
                if (status.Snapshot ? _changedConnectionIds.Contains(id) : !_changedConnectionIds.Contains(id)) continue;
                Connections.RemoveAt(index);
                _connectionRecords.Remove(id);
                _connectionIndices.Remove(id);
                removedRows = true;
            }
        }
        if (removedRows)
            for (int index = 0; index < Connections.Count; index++) _connectionIndices[Connections[index].Status.ConnectionId] = index;
        foreach (ConnectionStatus changed in status.Changes)
        {
            if (_connectionRecords.TryGetValue(changed.ConnectionId, out var previousConnection) && previousConnection == changed) continue;
            _connectionRecords[changed.ConnectionId] = changed;
            var row = new ConnectionViewModel(changed);
            if (_connectionIndices.TryGetValue(changed.ConnectionId, out int index)) Connections[index] = row;
            else
            {
                _connectionIndices.Add(changed.ConnectionId, Connections.Count);
                Connections.Add(row);
            }
        }
        ConnectionsEmptyText = Connections.Count == 0 ? "The provider reports no connected folders." : string.Empty;
        NotifyStatusFreshness();
    }

    private static string ErrorMessage(Exception error) => error is ProtocolException protocol
        ? $"{protocol.Error.Code}: {protocol.Error.Message}" : error.Message;
    private void ShowError(Exception error) => ErrorText = ErrorMessage(error);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _session.StateChanged -= OnSessionChanged;
        _session.StatusChanged -= OnStatusChanged;
        _lifetime.Cancel();
        _ownerRequest?.Cancel();
        _lifetime.Dispose();
    }
}
