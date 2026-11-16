using System.ComponentModel;
using HfDrive.Desktop.Interop;
using HfDrive.Desktop.Services;
using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.Graphics;
using Windows.Win32;
using Windows.Win32.Foundation;

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
///
/// Window chrome: the window always owns its caption
/// (<c>ExtendsContentIntoTitleBar</c>), so no separate title strip ever
/// paints. While the compact onboarding surface is shown
/// <c>OverlappedPresenter.SetBorderAndTitleBar(false,false)</c> removes the
/// nonclient frame as well; DWM rounding/shadow come from the explicit corner
/// opt-in in <see cref="WindowChrome.ApplyFluentFrame"/>. Exactly one
/// accessible close control ("Close setup") replaces the caption buttons. The
/// configured shell shows the branded CatchingHuggy caption row and keeps the
/// native resize frame and min/max/close window controls in the caption's
/// right inset. In both modes the caption row (AutomationIds
/// <c>SetupDragHeader</c> / <c>ShellDragHeader</c>) is designated as the OS
/// caption drag region through <see cref="InputNonClientPointerSource"/>, so
/// dragging it moves the window (never a screen-coordinate drag loop) and
/// caption gestures keep their native semantics (the compact presenter has
/// no maximize box, so its header double-click cannot maximize). Closing
/// follows the existing
/// <c>AppWindow.Closing</c> close-to-tray semantics: the window's WM_CLOSE is
/// posted and App cancels the close and hides; the wizard and provider
/// session are untouched.
/// </summary>
public sealed partial class MainWindow : Window
{
    /// <summary>Compact onboarding size in logical pixels (contract).</summary>
    private const double CompactWidth = 660;
    private const double CompactHeight = 760;

    /// <summary>Normal shell size in logical pixels (clamped to the work area).</summary>
    private const double NormalWidth = 1100;
    private const double NormalHeight = 820;

    /// <summary>Native caption-button inset width in DIP (the OS window-caption
    /// layout contract), clamped to the documented 100–160 range.</summary>
    private const int CaptionButtonWidth = 138;
    private const int CaptionButtonWidthMax = 160;
    private const int CaptionButtonWidthMin = 100;

    private readonly ProviderSession _session;
    private readonly MainViewModel _viewModel;
    private readonly SetupViewModel _setupViewModel;
    private readonly OperationsViewModel _operationsViewModel;

    private NavigationView? _navigation;
    private Frame? _contentFrame;
    private Frame? _compactFrame;
    private string _lastNormalTag = "settings";
    private bool _isCompact;
    private bool _hasNormalShell;
    private bool _startupDecisionMade;
    private bool _startupCompleted;
    private bool _startupRunning;
    private bool _closed;
    private bool _previousNeedsSetup;
    /// <summary>True while the compact flow was opened explicitly by the user
    /// (Add drive); automatic onboarding keeps it false.</summary>
    private bool _explicitAddDrive;
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
        // Mica owns the shell backdrop; transparent page/caption/navigation
        // resources expose it while content uses default Fluent brushes.
        SystemBackdrop = new MicaBackdrop();
        AppWindow.SetIcon(System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "CatchingHuggy.ico"));

        // Setup chrome before the first show: the window starts compact and
        // ShowCompactShell applies the caption-free chrome here in the
        // constructor, so the first activation never paints a system caption
        // strip. The drag region is client-relative physical pixels and is
        // recomputed whenever the caption row lays out or the window resizes
        // (a DPI/monitor change relayouts and therefore re-registers too).
        RootLayout.SizeChanged += (_, _) => UpdateCaptionDragRegion();
        SetupCaptionBar.LayoutUpdated += (_, _) => UpdateCaptionDragRegion();
        ShellCaptionBar.LayoutUpdated += (_, _) => UpdateCaptionDragRegion();

        // WinUI can reapply the presenter frame styles on activation, undoing
        // the borderless setup frame. Re-run only the shared frame cleanup +
        // DWM attributes on each real activation (never the presenter flags,
        // which would churn the window).
        Activated += OnWindowActivated;

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
            // The HWND exists now: re-apply the chrome so the DWM frame helper
            // runs on a real handle and the drag region registers.
            ApplyShellChrome(_isCompact);
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

    /// <summary>Opens a tray-requested section without discarding an unfinished setup.</summary>
    public void OpenSection(string tag) => OpenSection(tag, null, null);

    /// <summary>
    /// Opens a tray-requested section, optionally scoped to one connection and,
    /// for the operations surface, explicitly selecting one recorded conflict
    /// for the user to resolve. Preserves an unfinished setup exactly like the
    /// unscoped overload: no selection is applied until the operations surface
    /// is actually shown, and no conflict is ever resolved here.
    /// </summary>
    /// <param name="tag">Section tag (settings, account, connections, operations, setup).</param>
    /// <param name="connectionId">Connection to scope the surface's operations to.</param>
    /// <param name="conflictId">Recorded conflict to load and select (requires
    /// the operations surface); consumed only when a real provider row with
    /// exactly this id arrives.</param>
    public void OpenSection(string tag, Guid? connectionId, Guid? conflictId)
    {
        if (tag == "setup" && _viewModel.HasObservedStatus && !_viewModel.NeedsSetup)
            OpenAddDriveFlow(explicitRequest: true);
        else if (_viewModel.NeedsSetup || (!_hasNormalShell && !_viewModel.HasObservedStatus))
            ShowCompactShell();
        else
        {
            _lastNormalTag = tag is "settings" or "connections" or "operations" ? tag : "account";
            ShowNormalShell();
            if (tag == "operations" && connectionId is { } scoped)
                _ = ApplyOperationsScopeAsync(scoped, conflictId);
        }
        AppWindow.Show();
        Activate();
    }

    /// <summary>
    /// Scopes the operations surface to one connection (its existing connection
    /// ID scope box) and, when given, pages the real conflict records until the
    /// exact conflict id arrives and selects that provider row for explicit
    /// user resolution. Bounded and cancellable; the window lifetime cancels it
    /// on close. Never resolves or mutates anything.
    /// </summary>
    private async Task ApplyOperationsScopeAsync(Guid connectionId, Guid? conflictId)
    {
        try
        {
            await _operationsViewModel.LoadConflictsForConnectionAsync(connectionId, conflictId, _windowLifetime.Token)
                .ConfigureAwait(true);
        }
        catch (OperationCanceledException) when (_windowLifetime.IsCancellationRequested) { }
    }

    // ------------------------------------------------------------------
    // Shell switching
    // ------------------------------------------------------------------

    private void ShowCompactShell()
    {
        _isCompact = true;
        // Caption-free setup chrome (idempotent). Applied here, the window
        // never paints a system caption strip — this call runs before the
        // first activation while the window is constructed compact.
        ApplyShellChrome(compact: true);
        _compactFrame ??= CreateSetupFrame();
        ShellHost.Children.Clear();
        ShellHost.Children.Add(_compactFrame);
        // A way back exists only once a normal shell has been established.
        CompactHeader.Visibility = _hasNormalShell ? Visibility.Visible : Visibility.Collapsed;
        ApplyWindowSize(compact: true);
        UpdateCaptionDragRegion();
    }

    private void ShowNormalShell()
    {
        _hasNormalShell = true;
        _isCompact = false;
        // Themed branded caption chrome (idempotent): the window keeps its
        // native resize frame and min/max/close window controls while the
        // branded caption row owns dragging. Wizard state is untouched.
        ApplyShellChrome(compact: false);
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
            // Adaptive: full left pane at desktop widths, compact/minimal for
            // narrower windows instead of clipping the items.
            PaneDisplayMode = NavigationViewPaneDisplayMode.Auto,
            OpenPaneLength = 220,
            Content = _contentFrame,
        };
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Settings", Tag = "settings", Icon = new FontIcon { Glyph = "\uE713" } });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Account", Tag = "account", Icon = new FontIcon { Glyph = "\uE77B" } });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Connections", Tag = "connections", Icon = new FontIcon { Glyph = "\uE8B7" } });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Advanced", Tag = "operations", Icon = new FontIcon { Glyph = "\uE90F" } });
        _navigation.MenuItems.Add(new NavigationViewItem { Content = "Add drive", Tag = "setup", Icon = new FontIcon { Glyph = "\uE710" } });
        _navigation.SelectionChanged += OnNavigationSelectionChanged;
        _navigation.SelectedItem = _navigation.MenuItems[0];
        _contentFrame.Navigate(typeof(SettingsPage), _operationsViewModel);
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
            OpenAddDriveFlow(explicitRequest: true);
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
            case "settings":
                pageType = typeof(SettingsPage);
                parameter = _operationsViewModel;
                break;
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
    private void OpenAddDriveFlow(bool explicitRequest)
    {
        // An explicit Add drive stays open until the user finishes or goes
        // back; automatic onboarding (last connection removed) may be left by
        // a later accepted status that reports a configured account.
        _explicitAddDrive = explicitRequest;
        _setupViewModel.StartNewSetup();
        ShowCompactShell();
    }

    /// <summary>The setup model reports a successful connect; return to the normal shell.</summary>
    private void OnSetupFinished(object? sender, EventArgs e)
    {
        _startupDecisionMade = true;
        _explicitAddDrive = false;
        _lastNormalTag = "connections";
        ShowNormalShell();
        Activate();
    }

    private void OnBackToShellClick(object sender, RoutedEventArgs e)
    {
        _explicitAddDrive = false;
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
        // disconnect never count as a reset. That reset is automatic onboarding,
        // not a user request.
        bool needsSetup = _viewModel.NeedsSetup;
        if (needsSetup && !_previousNeedsSetup && !_isCompact)
        {
            OpenAddDriveFlow(explicitRequest: false);
        }
        else if (!needsSetup && _previousNeedsSetup && _isCompact && !_explicitAddDrive)
        {
            // Empty -> configured: an early status snapshot can precede the
            // local connection status; when a later accepted status reports a
            // configured account, automatic onboarding returns to the normal
            // shell. An explicitly requested Add drive wizard stays open.
            ShowNormalShell();
        }

        _previousNeedsSetup = needsSetup;
    }

    // ------------------------------------------------------------------
    // Bounded provider startup with visible retry
    // ------------------------------------------------------------------

    /// <summary>Starts/joins the provider without showing this window.</summary>
    internal void StartProviderSession() => _ = RunStartupAsync();

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
    // Window chrome: branded caption + OS drag region + close
    // ------------------------------------------------------------------

    /// <summary>The compact setup presenter: fully borderless, no caption
    /// controls, fixed size. Configured once.</summary>
    private OverlappedPresenter? _compactPresenter;
    /// <summary>The normal shell presenter: no painted caption/border (the
    /// branded caption row replaces the title strip) but native resize frame
    /// and min/max/close window controls. Configured once.</summary>
    private OverlappedPresenter? _normalPresenter;
    /// <summary>Mode of the presenter currently set on the AppWindow (null =
    /// none yet); SetPresenter runs only on an actual mode change.</summary>
    private bool? _appliedPresenterCompact;

    /// <summary>
    /// Applies the window's native chrome, idempotently. The window always
    /// owns its caption (<c>ExtendsContentIntoTitleBar</c>), so no separate
    /// title strip ever paints. Compact removes the nonclient frame and
    /// caption buttons entirely (the one custom close control shows, the
    /// setup header registers as the OS caption drag region). The configured
    /// shell keeps the native resize frame and min/max/close window controls
    /// in the caption's right inset, paints no title strip, and registers the
    /// branded header as the drag region. Each mode owns its own
    /// <see cref="OverlappedPresenter"/> instance: mutating one reused
    /// instance between the two flag sets can retain the compact nonclient
    /// state.
    /// </summary>
    private void ApplyShellChrome(bool compact)
    {
        if (_closed) return;

        // Switch presenters only on an actual mode change. Each instance is
        // configured once in its factory (flags first, then SetBorderAndTitleBar
        // — the tray window's proven order). Compact is fully borderless with
        // no maximize box (a header double-click can never maximize); the
        // configured shell keeps the resize frame and min/max/close controls.
        if (_appliedPresenterCompact != compact)
        {
            OverlappedPresenter presenter;
            if (compact)
            {
                _compactPresenter ??= CreateSetupPresenter();
                presenter = _compactPresenter;
            }
            else
            {
                _normalPresenter ??= CreateShellPresenter();
                presenter = _normalPresenter;
            }
            AppWindow.SetPresenter(presenter);
            _appliedPresenterCompact = compact;
        }

        // The branded caption row replaces the system title strip in both
        // modes: content extends into the caption area and the visible
        // caption row supplies the drag region (registered per row through
        // InputNonClientPointerSource, so interactive caption controls keep
        // their input). Native min/max/close window buttons remain in the
        // caption's right inset.
        ExtendsContentIntoTitleBar = true;

        // The HWND exists from construction (AppWindow.SetIcon above already
        // uses it), but guard so a pre-show call never hits a null handle; the
        // Loaded re-apply covers the real handle either way.
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (hwnd != 0)
        {
            WindowChrome.ApplyFluentFrame(hwnd, suppressBorder: compact);
        }

        SetupCaptionBar.Visibility = compact ? Visibility.Visible : Visibility.Collapsed;
        ShellCaptionBar.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        UpdateCaptionDragRegion();
    }

    /// <summary>The compact setup presenter: fully borderless (false,false),
    /// no caption controls, fixed size. Configured once.</summary>
    private static OverlappedPresenter CreateSetupPresenter()
    {
        // Flags first, then SetBorderAndTitleBar — the tray window's proven
        // presenter order.
        var presenter = OverlappedPresenter.CreateForContextMenu();
        presenter.IsResizable = false;
        presenter.IsMaximizable = false;
        presenter.IsMinimizable = false;
        presenter.SetBorderAndTitleBar(false, false);
        return presenter;
    }

    /// <summary>The normal shell presenter: no painted caption/border (the
    /// branded caption row replaces the title strip through
    /// ExtendsContentIntoTitleBar) but native resize frame and
    /// min/max/close window buttons. Configured once.</summary>
    private static OverlappedPresenter CreateShellPresenter()
    {
        var presenter = OverlappedPresenter.Create();
        presenter.IsResizable = true;
        presenter.IsMaximizable = true;
        presenter.IsMinimizable = true;
        // Keep the caption band's window buttons and the resize frame while
        // WinUI paints the branded row into the caption area.
        presenter.SetBorderAndTitleBar(true, true);
        return presenter;
    }

    /// <summary>
    /// Re-applies only the shared frame cleanup + DWM attributes after a real
    /// activation: WinUI can reapply the presenter's frame styles when the
    /// window is activated, which would paint a separate nonclient caption
    /// edge over the branded row again. Never touches presenter flags or
    /// chrome state (no regeneration loop); deactivation is ignored.
    /// Presenter/chrome changes remain owned by <see cref="ApplyShellChrome"/>.
    /// </summary>
    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        if (_closed || args.WindowActivationState == WindowActivationState.Deactivated) return;
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (hwnd != 0)
        {
            WindowChrome.ApplyFluentFrame(hwnd, suppressBorder: _isCompact);
        }
    }

    /// <summary>The single caption drag rect; reused so LayoutUpdated never
    /// allocates a new array per layout pass.</summary>
    private readonly RectInt32[] _dragRegionBuffer = new RectInt32[1];
    /// <summary>Physical rect currently registered as the Caption region.</summary>
    private RectInt32 _dragRegionApplied;
    /// <summary>True while a Caption region is registered.</summary>
    private bool _dragRegionRegistered;

    /// <summary>
    /// Registers the active caption row's drag header (AutomationId
    /// <c>SetupDragHeader</c> compact, <c>ShellDragHeader</c> configured) as
    /// the window's caption drag region in physical pixels, recomputed on
    /// layout, resize and DPI change. Only the drag header is registered, so
    /// the compact close button and any other caption content stay
    /// interactive client content. The OS moves the window for the region and
    /// keeps its native caption gestures (the compact presenter has no
    /// maximize box).
    /// </summary>
    private void UpdateCaptionDragRegion()
    {
        if (_closed) return;

        // Lifecycle guard: the constructor calls this before the XAML tree is
        // loaded. The non-client source is window-scoped, but no region can be
        // computed until the real root exists; Loaded/LayoutUpdated recompute
        // after real layout, so skipping here never loses the registration.
        if (!RootLayout.IsLoaded || RootLayout.XamlRoot is null) return;

        FrameworkElement? dragHeader = _isCompact
            ? (SetupCaptionBar.Visibility == Visibility.Visible ? SetupDragHeader : null)
            : (ShellCaptionBar.Visibility == Visibility.Visible ? ShellDragHeader : null);
        if (dragHeader is null)
        {
            // No caption row owns dragging (e.g. mid mode switch): clear the
            // stale region so an invisible row can never swallow input.
            if (_dragRegionRegistered)
            {
                InputNonClientPointerSource.GetForWindowId(AppWindow.Id)
                    .ClearRegionRects(NonClientRegionKind.Caption);
                _dragRegionRegistered = false;
            }
            return;
        }

        // The header must be attached and arranged before TransformToVisual
        // on it (an unattached/pre-layout element throws). LayoutUpdated
        // retries once real layout exists.
        if (!dragHeader.IsLoaded
            || dragHeader.ActualWidth <= 0
            || dragHeader.ActualHeight <= 0)
        {
            return;
        }

        double scale = RootLayout.XamlRoot.RasterizationScale;
        GeneralTransform transform = dragHeader.TransformToVisual(null);
        Rect bounds = transform.TransformBounds(new Rect(0, 0, dragHeader.ActualWidth, dragHeader.ActualHeight));
        var drag = new RectInt32(
            (int)Math.Round(bounds.X * scale),
            (int)Math.Round(bounds.Y * scale),
            (int)Math.Round(bounds.Width * scale),
            (int)Math.Round(bounds.Height * scale));

        // The configured shell reserves the native caption-button inset at the
        // window's right edge (the caption buttons draw there). The strip is
        // the OS caption layout's 138-DIP button width, clamped to the
        // contract's 100–160 DIP range and never past half the window, and it
        // scales with the display DPI; the drag region stops before it so the
        // buttons always accept input.
        if (!_isCompact)
        {
            int clientWidth = (int)Math.Round(RootLayout.ActualWidth * scale);
            int inset = (int)Math.Round(CaptionButtonWidth * scale);
            int maxInset = Math.Min((int)Math.Round(CaptionButtonWidthMax * scale), Math.Max(0, clientWidth / 2));
            int minInset = Math.Min((int)Math.Round(CaptionButtonWidthMin * scale), maxInset);
            inset = Math.Clamp(inset, minInset, maxInset);
            int maxX = Math.Max(0, clientWidth - inset);
            int clippedWidth = Math.Min(drag.X + drag.Width, maxX) - drag.X;
            drag = new RectInt32(drag.X, drag.Y, Math.Max(0, clippedWidth), drag.Height);
        }
        if (drag.Width <= 0 || drag.Height <= 0) return;

        // LayoutUpdated fires on every layout pass: skip the native round-trip
        // unless the physical rectangle actually changed.
        if (_dragRegionRegistered
            && drag.X == _dragRegionApplied.X && drag.Y == _dragRegionApplied.Y
            && drag.Width == _dragRegionApplied.Width && drag.Height == _dragRegionApplied.Height)
        {
            return;
        }

        _dragRegionBuffer[0] = drag;
        InputNonClientPointerSource source = InputNonClientPointerSource.GetForWindowId(AppWindow.Id);
        source.ClearRegionRects(NonClientRegionKind.Caption);
        source.SetRegionRects(NonClientRegionKind.Caption, _dragRegionBuffer);
        _dragRegionApplied = drag;
        _dragRegionRegistered = true;
    }

    /// <summary>
    /// The custom close control. Follows the existing <c>AppWindow.Closing</c>
    /// close-to-tray semantics by posting the window's WM_CLOSE, which
    /// <c>App.OnMainWindowClosing</c> cancels and turns into a hide to the
    /// tray. Never disposes the shared session or stops the provider; the
    /// setup wizard and tray survive the hide.
    /// </summary>
    private void OnSetupCloseClick(object sender, RoutedEventArgs e)
    {
        nint hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (hwnd != 0)
        {
            PInvoke.PostMessage(new HWND(hwnd), PInvoke.WM_CLOSE, default, default);
        }
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
        // Presenter configuration lives in the mode-specific cached presenters
        // (ApplyShellChrome); this method only places the window.
        appWindow.MoveAndResize(new RectInt32(x, y, width, height));
    }

}
