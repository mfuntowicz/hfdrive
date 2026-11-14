using System.ComponentModel;
using HfDrive.Desktop.Services;
using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Graphics;
using Windows.Win32;

namespace HfDrive.Desktop;

/// <summary>
/// Lifecycle shell of the desktop application.
///
/// Surface selection: the window always starts with the compact onboarding
/// surface (the shared SetupPage, no navigation pane) while authenticating and
/// loading state — there is never a full-dashboard flash first. When an
/// accepted provider status of the live session shows at least one configured
/// connection, the window switches to the full normal shell. A compact wizard
/// is only reset when an accepted status truly reports zero connections (a
/// disconnect is not an empty configuration); a successful setup screen stays
/// until the setup model raises <c>Finished</c>. "Setup" navigation and
/// Add drive open the same compact shared SetupPage.
///
/// Provider startup: on launch the window connects to an existing provider
/// pipe first; if none is listening it starts exactly the packaged (or, in
/// debug builds, allowlisted development) provider image once through
/// <see cref="ProviderLauncher"/> with a bounded startup, then connects. The
/// window never weakens peer identity verification, inspects credentials, or
/// stops processes. Startup failures stay visible with a retry action and are
/// never reported as an empty configuration.
/// </summary>
public sealed partial class MainWindow : Window
{
    /// <summary>Compact onboarding size in logical pixels (contract).</summary>
    private const double CompactWidth = 660;
    private const double CompactHeight = 760;

    /// <summary>Normal shell size in logical pixels (clamped to the work area).</summary>
    private const double NormalWidth = 1100;
    private const double NormalHeight = 820;

    private readonly ProviderSession _session;
    private readonly MainViewModel _viewModel;
    private readonly SetupViewModel _setupViewModel;
    private readonly OperationsViewModel _operationsViewModel;

    private NavigationView? _navigation;
    private Frame? _contentFrame;
    private Frame? _compactFrame;
    private string _lastNormalTag = "account";
    private bool _isCompact;
    private bool _hasNormalShell;
    private bool _startupDecisionMade;
    private bool _startupCompleted;
    private bool _startupRunning;
    private bool _closed;
    private bool _previousNeedsSetup;
    private string? _lastLaunchDetail;
    private readonly CancellationTokenSource _windowLifetime = new();

    public MainWindow(MainViewModel viewModel)
    {
        _viewModel = viewModel;
        // The window and every page share the application's one provider session.
        var app = (App)Application.Current;
        _session = app.Session;
        _setupViewModel = new SetupViewModel(_session, viewModel);
        _operationsViewModel = new OperationsViewModel(_session);
        InitializeComponent();
        ExtendsContentIntoTitleBar = false;

        _setupViewModel.Finished += OnSetupFinished;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _session.StateChanged += OnSessionStateChanged;

        // Compact first: the onboarding surface shows the real connection and
        // login state as it arrives; the normal shell appears only for a
        // configured account.
        ShowCompactShell();
        _viewModel.ApplySessionState();

        RootLayout.Loaded += (_, _) =>
        {
            // Re-apply bounds once the HWND exists; sizing is presentation-only.
            ApplyWindowSize(_isCompact);
            _ = RunStartupAsync();
        };
        Closed += (_, _) =>
        {
            _closed = true;
            _windowLifetime.Cancel();
            _windowLifetime.Dispose();
            _setupViewModel.Finished -= OnSetupFinished;
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            _session.StateChanged -= OnSessionStateChanged;
            _setupViewModel.Dispose();
            _operationsViewModel.Dispose();
        };
    }

    // ------------------------------------------------------------------
    // Shell switching
    // ------------------------------------------------------------------

    private void ShowCompactShell()
    {
        _isCompact = true;
        _compactFrame ??= CreateSetupFrame();
        ShellHost.Children.Clear();
        ShellHost.Children.Add(_compactFrame);
        // A way back exists only once a normal shell has been established.
        CompactHeader.Visibility = _hasNormalShell ? Visibility.Visible : Visibility.Collapsed;
        ApplyWindowSize(compact: true);
    }

    private void ShowNormalShell()
    {
        _hasNormalShell = true;
        _isCompact = false;
        EnsureNormalShell();
        ShellHost.Children.Clear();
        ShellHost.Children.Add(_navigation!);
        CompactHeader.Visibility = Visibility.Collapsed;

        // Restore the page the user was on before entering the compact flow.
        NavigationViewItem target = _navigation!.MenuItems
            .OfType<NavigationViewItem>()
            .FirstOrDefault(item => (string?)item.Tag == _lastNormalTag)
            ?? (NavigationViewItem)_navigation.MenuItems[0];
        if (!ReferenceEquals(_navigation.SelectedItem, target))
        {
            _navigation.SelectedItem = target;
        }
        NavigateToTag((string)target.Tag);

        ApplyWindowSize(compact: false);
    }

    private Frame CreateSetupFrame()
    {
        var frame = new Frame();
        frame.Navigate(typeof(SetupPage), Tuple.Create(_viewModel, _setupViewModel));
        return frame;
    }

    private void EnsureNormalShell()
    {
        if (_navigation is not null)
        {
            return;
        }

        _contentFrame = new Frame();
        _navigation = new NavigationView
        {
            IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed,
            IsSettingsVisible = false,
            PaneDisplayMode = NavigationViewPaneDisplayMode.Left,
            Content = _contentFrame,
        };
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Account", Tag = "account" });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Connections", Tag = "connections" });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Operations", Tag = "operations" });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Add drive", Tag = "setup" });
        _navigation.SelectionChanged += OnNavigationSelectionChanged;
        _navigation.SelectedItem = _navigation.MenuItems[0];
        _contentFrame.Navigate(typeof(AccountPage), _viewModel);
    }

    private void OnNavigationSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem { Tag: string tag })
        {
            return;
        }

        if (tag == "setup")
        {
            // "Setup" (Add drive) opens the same compact shared SetupPage flow,
            // starting from a freshly reset ephemeral wizard.
            OpenAddDriveFlow();
            return;
        }

        NavigateToTag(tag);
    }

    private void NavigateToTag(string tag)
    {
        _lastNormalTag = tag;
        Type pageType;
        object parameter;
        switch (tag)
        {
            case "connections":
                pageType = typeof(ConnectionsPage);
                parameter = _viewModel;
                break;
            case "operations":
                pageType = typeof(OperationsPage);
                parameter = _operationsViewModel;
                break;
            default:
                pageType = typeof(AccountPage);
                parameter = _viewModel;
                break;
        }

        if (_contentFrame!.CurrentSourcePageType != pageType)
        {
            _contentFrame.Navigate(pageType, parameter);
        }
    }

    /// <summary>Add drive / Setup navigation: reset only ephemeral wizard input, then show the compact flow.</summary>
    private void OpenAddDriveFlow()
    {
        _setupViewModel.StartNewSetup();
        ShowCompactShell();
    }

    /// <summary>The setup model reports a successful connect; return to the normal shell.</summary>
    private void OnSetupFinished(object? sender, EventArgs e)
    {
        _startupDecisionMade = true;
        _lastNormalTag = "connections";
        ShowNormalShell();
        Activate();
    }

    private void OnBackToShellClick(object sender, RoutedEventArgs e)
    {
        if (_hasNormalShell)
        {
            ShowNormalShell();
        }
    }

    // ------------------------------------------------------------------
    // Surface selection from observed provider status
    // ------------------------------------------------------------------

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is not (nameof(MainViewModel.NeedsSetup) or nameof(MainViewModel.HasObservedStatus)))
        {
            return;
        }

        if (!_viewModel.HasObservedStatus) return;
        if (!_startupDecisionMade)
        {
            // Only an accepted status of the live session decides the surface.
            // Disconnection or a failed provider start is never "empty config".
            if (!_viewModel.HasObservedStatus)
            {
                return;
            }

            _startupDecisionMade = true;
            _previousNeedsSetup = _viewModel.NeedsSetup;
            if (!_viewModel.NeedsSetup)
            {
                ShowNormalShell();
            }
            return;
        }

        // Reset the ephemeral wizard only when the last connection is truly
        // removed by an accepted provider status: a transition from configured
        // to zero connections. A first-observed empty status (startup) and a
        // disconnect never count as a reset.
        bool needsSetup = _viewModel.NeedsSetup;
        if (needsSetup && !_previousNeedsSetup && !_isCompact)
        {
            OpenAddDriveFlow();
        }

        _previousNeedsSetup = needsSetup;
    }

    // ------------------------------------------------------------------
    // Bounded provider startup with visible retry
    // ------------------------------------------------------------------

    private async Task RunStartupAsync()
    {
        if (_startupRunning || _closed) return;
        _startupRunning = true;
        _viewModel.IsStartingProvider = true;
        _lastLaunchDetail = null;
        UpdateStartupSurface();
        try
        {
            // A missing or busy pipe can race another launch. The provider's
            // per-user writer lease makes an extra launch join the owner;
            // the following handshake still authenticates the actual peer.
            bool listening = PInvoke.WaitNamedPipe(ProviderPipeName.DisplayPath, 1);
            if (!listening)
            {
                if (!ProviderLauncher.TryStartProvider(out string detail))
                {
                    _lastLaunchDetail = detail;
                    return;
                }
            }

            // ConnectAsync itself waits for the newly launched pipe. One
            // bounded handshake, no polling/relaunch loop or auth bypass.
            // The handshake already publishes the authoritative snapshot.
            // Do not queue another status request behind owner/bucket loading.
            await TrySessionConnectAsync(TimeSpan.FromSeconds(15));
        }
        catch (OperationCanceledException) when (_closed) { }
        catch (Exception ex)
        {
            _lastLaunchDetail = ex.Message;
        }
        finally
        {
            _startupCompleted = true;
            _startupRunning = false;
            _viewModel.IsStartingProvider = false;
            if (!_closed) UpdateStartupSurface();
        }
    }

    /// <summary>
    /// One bounded connect attempt against the provider session. Never throws;
    /// returns whether the session reached the ready state.
    /// </summary>
    private async Task<bool> TrySessionConnectAsync(TimeSpan timeout)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_windowLifetime.Token);
        cts.CancelAfter(timeout);
        try
        {
            await _session.ConnectAsync(cts.Token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            // ProviderSession records its own errors; keep this defensive copy
            // nonsecret (message only) for the startup surface.
            _lastLaunchDetail ??= ex.Message;
        }

        return _session.State == ProviderConnectionState.Ready;
    }

    private void OnStartupRetryClick(object sender, RoutedEventArgs e) => _ = RunStartupAsync();

    private void OnSessionStateChanged(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => { if (!_closed) UpdateStartupSurface(); });

    /// <summary>
    /// Startup failures stay visible with a retry action; a disconnect after a
    /// successful start is surfaced the same way. Never shown while the
    /// bounded startup is still running.
    /// </summary>
    private void UpdateStartupSurface()
    {
        bool show = _startupCompleted && !_startupRunning && _session.State != ProviderConnectionState.Ready;
        if (!show)
        {
            StartupErrorBanner.Visibility = Visibility.Collapsed;
            return;
        }

        string text = _session.LastError ?? _session.StatusText;
        if (!string.IsNullOrEmpty(_lastLaunchDetail))
        {
            text = $"{text} {_lastLaunchDetail}".Trim();
        }

        StartupErrorText.Text = text;
        StartupErrorBanner.Visibility = Visibility.Visible;
    }

    // ------------------------------------------------------------------
    // Window sizing: AppWindow over the display work area, DPI aware
    // ------------------------------------------------------------------

    private void ApplyWindowSize(bool compact)
    {
        var appWindow = this.AppWindow;
        DisplayArea displayArea = DisplayArea.GetFromWindowId(appWindow.Id, DisplayAreaFallback.Nearest);
        RectInt32 workArea = displayArea.WorkArea;
        double scale = RootLayout.XamlRoot?.RasterizationScale ?? 1.0;
        int width = Math.Min((int)Math.Round((compact ? CompactWidth : NormalWidth) * scale), workArea.Width);
        int height = Math.Min((int)Math.Round((compact ? CompactHeight : NormalHeight) * scale), workArea.Height);
        int x = workArea.X + Math.Max(0, (workArea.Width - width) / 2);
        int y = workArea.Y + Math.Max(0, (workArea.Height - height) / 2);
        if (appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsResizable = !compact;
            presenter.IsMaximizable = !compact;
        }
        appWindow.MoveAndResize(new RectInt32(x, y, width, height));
    }

}
