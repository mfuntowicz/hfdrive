using System.Diagnostics;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Foundation;
using Windows.Graphics;
using Windows.UI.ViewManagement;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.WindowsAndMessaging;
using HfDrive.Desktop.Services;
using HfDrive.Desktop.ViewModels;

namespace HfDrive.Desktop;

/// <summary>Maps a boolean state to <see cref="Visibility"/> (true = visible).</summary>
public sealed class BoolToVisibilityConverter : Microsoft.UI.Xaml.Data.IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, string language) =>
        value is Visibility.Visible;
}

/// <summary>
/// The OneDrive-style tray panel: a borderless tool-window panel whose native
/// rounded corners and shadow are enabled through
/// <c>Interop.WindowChrome.ApplyFluentFrame</c>, anchored to the notification
/// icon's monitor work area. Every displayed value comes from
/// the shared provider session through <see cref="TrayViewModel"/>; there is no
/// synthetic sync state here. The panel polls only while visible, pauses the
/// VibingHuggy celebration (within its fixed two-play budget) whenever it is
/// hidden or the system disables animations, and shows explicit
/// loading/disconnected/setup/unavailable/empty and failed states. Escape or
/// deactivation hides it; the window never takes a taskbar/Alt-Tab entry
/// (WS_EX_TOOLWINDOW).
/// </summary>
public sealed partial class TrayWindow : Window
{
    /// <summary>Logical width (DIP) of the panel's content viewport.</summary>
    private const double PanelWidth = 400;

    /// <summary>Minimum logical height (DIP) when the display cannot fit the preferred viewport.</summary>
    private const double PanelMinHeight = 240;

    /// <summary>Maximum logical height (DIP) of the panel's content viewport —
    /// the design 400x620-DIP content including the footer.</summary>
    private const double PanelMaxHeight = 620;

    /// <summary>Gap between the tray icon and the panel, in physical pixels.</summary>
    private const int PanelGap = 8;

    /// <summary>How long an accepted status may stay absent before the panel
    /// reports the status as unavailable instead of loading forever.</summary>
    private static readonly TimeSpan StatusUnavailableTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Bounded refresh cadence while the panel is visible.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly TrayViewModel _viewModel;
    private readonly UISettings _uiSettings = new();
    private readonly TypedEventHandler<UISettings, UISettingsAnimationsEnabledChangedEventArgs> _animationsEnabledChangedHandler;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _pollTimer;
    private CancellationTokenSource? _pollCts;
    private TrayService? _tray;
    private TypedEventHandler<XamlRoot, XamlRootChangedEventArgs>? _xamlRootChangedHandler;
    private XamlRoot? _subscribedXamlRoot;
    private DateTime _loadingSinceUtc;
    private bool _isShown;
    private bool _isPlacing;
    private bool _disposed;
    /// <summary>Current activation state of the panel window, maintained from
    /// real <see cref="Window.Activated"/> events (set true when shown).</summary>
    private bool _isPanelActive;
    /// <summary>End of the legitimate Shell-open activation grace: the tray
    /// click's activation hand-off may bounce deactivation through the panel.</summary>
    private DateTime _suppressDeactivateHideUntilUtc;
    /// <summary>Single bounded one-shot dismissal timer. A deactivation is
    /// never dropped: the dismissal decision is deferred to the end of the
    /// activation grace and taken only if the panel is still inactive. The
    /// projected <c>DispatcherQueueTimer</c> has no Dispose/Close (Start, Stop
    /// and Tick only), so lifecycle control is Stop on hide plus
    /// Stop/detach/drop at disposal.</summary>
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _dismissTimer;
    /// <summary>
    /// Celebration playback budget for one continuous all-synced state: the
    /// VibingHuggy asset is 121 frames × 40 ms = 4.84 s per play, so exactly
    /// two plays are 9.68 s of animated playback. The budget is measured by
    /// <see cref="_celebrationElapsed"/> (a Stopwatch that runs only while the
    /// GIF is actually playing), never by wall clock or restart counts.
    /// </summary>
    private static readonly TimeSpan CelebrationBudget = TimeSpan.FromMilliseconds(9_680);

    /// <summary>Watchdog cadence that stops playback exactly at the budget
    /// boundary even when no other UI event fires.</summary>
    private static readonly TimeSpan CelebrationTick = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Elapsed animated playback of the current celebration cycle. Runs only
    /// while the GIF plays: hiding the panel or disabling animations stops it
    /// (pause), and resuming continues the same budget — never a restart.
    /// </summary>
    private readonly Stopwatch _celebrationElapsed = new();

    /// <summary>True from a genuine non-all-synced → all-synced transition
    /// until <see cref="TrayViewModel.IsAllSynced"/> turns false again; only
    /// such a transition starts a fresh two-play budget.</summary>
    private bool _celebrationCycleActive;

    /// <summary>True while the GIF is playing within the current budget.</summary>
    private bool _celebrationPlaying;

    /// <summary>Repeating watchdog for the celebration budget. The projected
    /// <c>DispatcherQueueTimer</c> has no Dispose: lifecycle is Stop on pause
    /// plus Stop/detach/drop at disposal.</summary>
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _celebrationTimer;

    /// <summary>
    /// Avatar bitmap currently assigned as the account image source. Late
    /// decode events for an older source are ignored, so a previous account's
    /// picture can never appear for the current account. The image request is
    /// anonymous (no credential is attached to it).
    /// </summary>
    private BitmapImage? _avatarImageSource;

    /// <summary>Cached one-shot placement after Show has settled the live DPI/layout.</summary>
    private readonly Microsoft.UI.Dispatching.DispatcherQueueHandler _finalShowPlacementHandler;
    private bool _finalShowPlacementQueued;

    public TrayWindow(TrayViewModel viewModel)
    {
        _viewModel = viewModel;
        _finalShowPlacementHandler = OnFinalShowPlacement;
        InitializeComponent();

        // The state-surface Visibility bindings are plain {Binding} (see
        // TrayWindow.xaml): the XAML compiler resolves x:Bind
        // Converter={StaticResource} through a FrameworkElement lookup root,
        // and a Window root is not one (CS1503 in generated code). RootPanel's
        // DataContext supplies the view model for those runtime bindings;
        // strongly typed x:Bind stays everywhere else.
        RootPanel.DataContext = _viewModel;

        // Tool window: no taskbar button, no Alt-Tab entry, no caption.
        // The extended style (applied on the real HWND) also keeps it out of
        // Alt-Tab even if a presenter ever re-enables the caption.
        // SetBorderAndTitleBar is the supported API for these read-only
        // presenter properties. (true, false) + DWM border-color none still
        // paints a 1px bright nonclient frame around the client, so the
        // presenter stays fully borderless with (false, false); the native
        // rounded corners/shadow come from the shared
        // WindowChrome.ApplyFluentFrame opt-in below.
        // Tool-window presenters retain a dialog frame in WinUI; start from
        // popup chrome, then apply the explicit tool-window/taskbar policy.
        var presenter = OverlappedPresenter.CreateForContextMenu();
        presenter.IsAlwaysOnTop = true;
        presenter.IsResizable = false;
        presenter.IsMaximizable = false;
        presenter.IsMinimizable = false;
        presenter.SetBorderAndTitleBar(false, false);
        AppWindow.SetPresenter(presenter);

        Title = "HF Drive";
        RootPanel.KeyDown += OnRootKeyDown;
        RootPanel.SizeChanged += (_, _) => PlacePanel();
        Activated += OnWindowActivated;
        Closed += OnClosed;

        _viewModel.PropertyChanged += OnViewModelPropertyChanged;

        // Explicit handler instance so the subscription can be removed
        // idempotently at close/disposal; the callback itself only marshals to
        // the UI thread and touches XAML there.
        _animationsEnabledChangedHandler = OnAnimationsEnabledChanged;
        _uiSettings.AnimationsEnabledChanged += _animationsEnabledChangedHandler;

        // Initialize the hidden HWND before applying tool-window policy.
        // The popup presenter owns the borderless frame; DWM owns rounding.
        Activate();
        AppWindow.Hide();
        EnsureNativeWindowStyle();
        Interop.WindowChrome.ApplyFluentFrame(
            WinRT.Interop.WindowNative.GetWindowHandle(this), suppressBorder: true);

        // Rasterization scale changes when the panel moves between monitors
        // (100–200% DPI); recompute physical placement from the new scale.
        // The XamlRoot exists only after activation, so subscribe here and
        // remember the exact root to unsubscribe idempotently at disposal.
        if (RootPanel.XamlRoot is { } xamlRoot)
        {
            _xamlRootChangedHandler = OnXamlRootChanged;
            _subscribedXamlRoot = xamlRoot;
            xamlRoot.Changed += _xamlRootChangedHandler;
        }

        // Reflect any avatar URI already observed before this window existed;
        // later changes arrive through PropertyChanged.
        UpdateAvatarImage();
    }

    /// <summary>The panel's view model (session-backed, provider-observed data).</summary>
    public TrayViewModel ViewModel => _viewModel;

    /// <summary>Wires the native tray icon's actions to this panel and the app
    /// shell. Same-assembly (App) wiring; <see cref="TrayService"/> is
    /// internal, so this member cannot be public (CS0051).</summary>
    internal void AttachTray(TrayService tray)
    {
        _tray = tray;
        tray.PanelToggleRequested += TogglePanel;
        tray.OpenMainRequested += OpenMainWindow;
        tray.OpenSectionRequested += OpenSection;
        tray.OpenFolderRequested += OpenFolder;
        tray.PauseResumeRequested += OnPauseResume;
        tray.ExitUiRequested += OnExitUi;
        tray.ExitProviderRequested += OnExitProvider;
        UpdateTooltip();
    }

    // ── Panel visibility lifecycle ───────────────────────────────────────

    /// <summary>Shows or hides the panel (tray click and keyboard toggle).</summary>
    public void TogglePanel()
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_isShown) HidePanel();
            else ShowPanel();
        });
    }

    /// <summary>Positions the panel at the tray icon's monitor work area and shows it.</summary>
    public void ShowPanel()
    {
        if (_disposed || _isShown) return;
        // Coalesce placement across a hide/reopen before the dispatcher runs.
        bool placementPending = _finalShowPlacementQueued;
        _finalShowPlacementQueued = true;
        AppWindow.Show();
        EnsureNativeWindowStyle();
        _isShown = true;
        // Opening takes focus; any pending deferred dismissal is void. The
        // Shell-open grace still covers the activation hand-off's bounce.
        _isPanelActive = true;
        CancelDeferredDismissal();
        _suppressDeactivateHideUntilUtc = DateTime.UtcNow.AddMilliseconds(400);
        _loadingSinceUtc = DateTime.UtcNow;
        _viewModel.IsPanelVisible = true;
        _viewModel.EnsureSelectionLoaded();
        StartPolling();
        UpdateAnimation();
        // Keyboard users land in the panel immediately.
        TrayRefreshButton.Focus(FocusState.Programmatic);

        // Position once after the show-time DPI/layout transition.
        if (!placementPending && !DispatcherQueue.TryEnqueue(_finalShowPlacementHandler))
        {
            _finalShowPlacementQueued = false;
        }
    }

    /// <summary>Places the panel after Show unless it was hidden or disposed in the meantime.</summary>
    private void OnFinalShowPlacement()
    {
        _finalShowPlacementQueued = false;
        if (_disposed || !_isShown) return;
        PlacePanel();
    }

    /// <summary>Hides the panel; polling, the celebration animation and any
    /// deferred dismissal stop.</summary>
    public void HidePanel()
    {
        if (!_isShown) return;
        _isShown = false;
        _isPanelActive = false;
        _viewModel.IsPanelVisible = false;
        AppWindow.Hide();
        StopPolling();
        CancelDeferredDismissal();
        UpdateAnimation();
    }

    /// <summary>Releases the panel's polling, animation and dismissal state
    /// before the app exits.</summary>
    public void DisposePanel()
    {
        if (_disposed) return;
        _disposed = true;
        StopPolling();

        // Stop and detach the one-shot dismissal timer (the projected type has
        // no Dispose; Stop plus detaching Tick and dropping the reference is
        // the full lifecycle surface) so no later callback can fire into the
        // disposed panel.
        if (_dismissTimer is { } dismissTimer)
        {
            dismissTimer.Stop();
            dismissTimer.Tick -= OnDismissTimerTick;
            _dismissTimer = null;
        }

        // Idempotent unsubscription: the animation-preference and DPI handlers
        // must never outlive the panel or touch its XAML tree again.
        if (_xamlRootChangedHandler is not null && _subscribedXamlRoot is not null)
        {
            _subscribedXamlRoot.Changed -= _xamlRootChangedHandler;
            _xamlRootChangedHandler = null;
            _subscribedXamlRoot = null;
        }
        _uiSettings.AnimationsEnabledChanged -= _animationsEnabledChangedHandler;

        // Celebration lifecycle teardown: stop playback, freeze the budget
        // Stopwatch and stop/detach/drop the watchdog timer (the projected
        // type has no Dispose) so no later callback fires into the panel.
        AllSyncedAnimationSource.Stop();
        _celebrationPlaying = false;
        _celebrationElapsed.Reset();
        if (_celebrationTimer is { } celebrationTimer)
        {
            celebrationTimer.Stop();
            celebrationTimer.Tick -= OnCelebrationTick;
            _celebrationTimer = null;
        }

        // Drop the avatar source so a late decode event cannot re-show it.
        if (_avatarImageSource is { } avatarSource)
        {
            DetachAvatarSource(avatarSource);
            TrayAvatarBrush.ImageSource = null;
            _avatarImageSource = null;
        }
    }

    /// <summary>
    /// OneDrive-style behavior: losing activation dismisses the panel. The
    /// tray click's Shell-open activation hand-off can bounce deactivation
    /// through the panel, and a click on the Shell's own surfaces (taskbar
    /// overflow) may deactivate the panel during that grace while the
    /// always-on-top panel keeps covering the physical icon. A deactivation is
    /// therefore never dropped: it is deferred to the end of the grace by the
    /// single one-shot timer and the panel hides only if it is still inactive
    /// then. Any reactivation (including clicking back into the panel)
    /// cancels the pending dismissal.
    /// </summary>
    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        if (_disposed || !_isShown) return;
        // WinUI states are Deactivated, CodeActivated and PointerActivated
        // (there is no "Activated" member): any non-Deactivated state means the
        // panel holds activation — keyboard (CodeActivated) and pointer
        // (PointerActivated) both cancel a pending dismissal.
        if (args.WindowActivationState != WindowActivationState.Deactivated)
        {
            _isPanelActive = true;
            CancelDeferredDismissal();
            return;
        }
        _isPanelActive = false;
        ScheduleDeferredDismissal();
    }

    /// <summary>Arms (or re-arms) the bounded one-shot dismissal check for the
    /// end of the activation grace. One timer instance, one callback: no
    /// recurring retry and no native foreground manipulation.</summary>
    private void ScheduleDeferredDismissal()
    {
        if (_disposed || !_isShown) return;
        // The grace end is fixed at show time; the countdown always targets
        // that moment. A one-millisecond floor keeps Interval positive (zero
        // is not a documented-safe DispatcherQueueTimer value), and Stop before
        // Start guarantees a fresh countdown when re-armed.
        TimeSpan delay = _suppressDeactivateHideUntilUtc - DateTime.UtcNow;
        if (delay < TimeSpan.FromMilliseconds(1)) delay = TimeSpan.FromMilliseconds(1);
        var timer = _dismissTimer ??= CreateDismissTimer();
        timer.Stop();
        timer.Interval = delay;
        timer.Start();
    }

    /// <summary>Stops the pending dismissal check, if any.</summary>
    private void CancelDeferredDismissal() => _dismissTimer?.Stop();

    private Microsoft.UI.Dispatching.DispatcherQueueTimer CreateDismissTimer()
    {
        var timer = DispatcherQueue.CreateTimer();
        timer.IsRepeating = false;
        timer.Tick += OnDismissTimerTick;
        return timer;
    }

    /// <summary>Runs once per armed dismissal: hides the panel only when the
    /// grace has elapsed and the panel is still inactive (never reactivated).</summary>
    private void OnDismissTimerTick(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args)
    {
        sender.Stop();
        if (_disposed || !_isShown || _isPanelActive) return;
        HidePanel();
    }

    private void OnRootKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (args.Key == Windows.System.VirtualKey.Escape)
        {
            HidePanel();
            args.Handled = true;
        }
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        DisposePanel();
        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
    }

    /// <summary>
    /// Animation preference changes arrive on a background WinRT callback
    /// thread; they must never touch XAML there. Marshal onto the panel's
    /// dispatcher and act only while the panel is still alive and visible.
    /// </summary>
    private void OnAnimationsEnabledChanged(UISettings sender, UISettingsAnimationsEnabledChangedEventArgs args) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_disposed) return;
            UpdateAnimation();
        });

    /// <summary>Re-places the panel when the rasterization scale changes
    /// (moving between monitors at 100–200% DPI), so physical bounds stay
    /// inside the actual work area without clipping the fixed-DIP panel.</summary>
    private void OnXamlRootChanged(XamlRoot sender, XamlRootChangedEventArgs args)
    {
        if (_disposed || _isPlacing) return;
        PlacePanel();
    }

    // ── Native window style: no taskbar/Alt-Tab entry ────────────────────

    private void EnsureNativeWindowStyle()
    {
        HWND hwnd = Hwnd;
        if (hwnd.IsNull) return;
        nint style = PInvoke.GetWindowLongPtr(hwnd, WINDOW_LONG_PTR_INDEX.GWL_EXSTYLE);
        nint wanted = (style | (nint)WINDOW_EX_STYLE.WS_EX_TOOLWINDOW) & ~(nint)WINDOW_EX_STYLE.WS_EX_APPWINDOW;
        if (wanted == style) return;
        PInvoke.SetWindowLongPtr(hwnd, WINDOW_LONG_PTR_INDEX.GWL_EXSTYLE, wanted);
        PInvoke.SetWindowPos(hwnd, default, 0, 0, 0, 0,
            SET_WINDOW_POS_FLAGS.SWP_NOMOVE | SET_WINDOW_POS_FLAGS.SWP_NOSIZE
            | SET_WINDOW_POS_FLAGS.SWP_NOZORDER | SET_WINDOW_POS_FLAGS.SWP_NOACTIVATE
            | SET_WINDOW_POS_FLAGS.SWP_FRAMECHANGED);
    }

    /// <summary>The real panel HWND from WinRT interop (never a title lookup).</summary>
    private HWND Hwnd => new(WinRT.Interop.WindowNative.GetWindowHandle(this));

    // ── Placement: the actual tray icon's monitor work area, DPI-aware ───

    /// <summary>Taskbar edge the tray icon sits on, derived from the icon
    /// rect against its display's real work area.</summary>
    private enum TrayTaskbarEdge { Bottom, Top, Left, Right }

    /// <summary>Real placement anchor: the tray icon rect (when the shell
    /// supplied one) or the pointer position.</summary>
    private readonly record struct PanelAnchor(PointInt32 Point, RectInt32 IconRect, TrayTaskbarEdge Edge)
    {
        public bool HasIcon => IconRect.Width > 0 && IconRect.Height > 0;
    }

    /// <summary>
    /// Places the panel inside the real work area of the tray icon's monitor
    /// (the pointer's monitor when the icon rect is unavailable). All bounds
    /// are physical pixels: the fixed-DIP panel is scaled by the live window
    /// scale and clamped to the observed work area, so 100–200% DPI never
    /// clips the panel or lets it leave the work area. There is no hardcoded
    /// display geometry anywhere in this path; without real display evidence
    /// the panel simply keeps its current position.
    /// </summary>
    private void PlacePanel()
    {
        if (_disposed || _isPlacing) return;
        if (GetAnchor() is not { } anchor) return;

        DisplayArea display = DisplayArea.GetFromPoint(anchor.Point, DisplayAreaFallback.Nearest);
        RectInt32 work = display.WorkArea;
        if (work.Width <= 0 || work.Height <= 0) return;

        double scale = WindowScale();
        int margin = Math.Max(2, (int)Math.Round(4 * scale));
        int gap = Math.Max(2, (int)Math.Round(PanelGap * scale));

        // Popup chrome has no nonclient inset. DWM's shadow does not consume
        // any of the content viewport.
        int availableWidth = work.Width - 2 * margin;
        int availableHeight = work.Height - 2 * margin;
        if (availableWidth < 1 || availableHeight < 1) return;

        // Keep the preferred DIP viewport independent of its current height.
        // On small displays the scroll body yields before the header/footer.
        int width = Math.Clamp((int)Math.Ceiling(PanelWidth * scale), 1, availableWidth);
        int preferredHeight = (int)Math.Ceiling(PanelMaxHeight * scale);
        int minHeight = Math.Min((int)Math.Ceiling(PanelMinHeight * scale), availableHeight);
        int height = Math.Clamp(preferredHeight, minHeight, availableHeight);

        // Keep the panel on the icon's taskbar side (bottom, top, right or
        // left taskbar), or just above the pointer when no icon rect exists.
        int x;
        int y;
        if (anchor.HasIcon)
        {
            RectInt32 icon = anchor.IconRect;
            x = anchor.Edge switch
            {
                TrayTaskbarEdge.Top or TrayTaskbarEdge.Bottom => icon.X + icon.Width / 2 - width / 2,
                TrayTaskbarEdge.Right => icon.X - gap - width,
                _ => icon.X + icon.Width + gap,
            };
            y = anchor.Edge switch
            {
                TrayTaskbarEdge.Top => icon.Y + icon.Height + gap,
                TrayTaskbarEdge.Bottom => icon.Y - gap - height,
                _ => icon.Y + icon.Height / 2 - height / 2,
            };
        }
        else
        {
            x = anchor.Point.X - width / 2;
            y = anchor.Point.Y - gap - height;
        }

        // Clamp inside the real work area with a small DPI-scaled margin.
        x = Math.Clamp(x, work.X + margin, work.X + work.Width - width - margin);
        y = Math.Clamp(y, work.Y + margin, work.Y + work.Height - height - margin);

        _isPlacing = true;
        try
        {
            AppWindow.MoveAndResize(new RectInt32(x, y, width, height));
        }
        finally
        {
            _isPlacing = false;
        }
    }

    /// <summary>
    /// Current window scale factor (physical pixels per DIP) from the live
    /// <see cref="XamlRoot"/> rasterization scale. Placement re-runs whenever
    /// that scale changes (moving between monitors), so a value observed on
    /// the previous monitor is corrected immediately on arrival; before any
    /// scale evidence exists the panel keeps unit scale and the first real
    /// scale event re-places it.
    /// </summary>
    private double WindowScale()
    {
        double scale = RootPanel.XamlRoot?.RasterizationScale ?? 0.0;
        return scale > 0 ? scale : 1.0;
    }

    /// <summary>
    /// Screen anchor for placement: the tray icon rect when the shell reports
    /// one (with its taskbar edge), otherwise the pointer position, otherwise
    /// the primary display's real work-area center. Returns null when no
    /// display evidence is available at all — placement then keeps the
    /// panel's current position instead of inventing geometry.
    /// </summary>
    private PanelAnchor? GetAnchor()
    {
        unsafe
        {
            var identifier = new NOTIFYICONIDENTIFIER
            {
                cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NOTIFYICONIDENTIFIER>(),
                hWnd = Hwnd,
                uID = 1,
                guidItem = TrayService.TrayGuid,
            };
            RECT icon = default;
            // Raw extern shape: HRESULT Shell_NotifyIconGetRect(const
            // NOTIFYICONIDENTIFIER*, RECT*); a failure just means no icon rect.
            try
            {
                PInvoke.Shell_NotifyIconGetRect(&identifier, &icon).ThrowOnFailure();
                if (icon.left != 0 || icon.top != 0 || icon.right != 0 || icon.bottom != 0)
                {
                    var rect = new RectInt32(icon.left, icon.top,
                        icon.right - icon.left, icon.bottom - icon.top);
                    var center = new PointInt32(rect.X + rect.Width / 2, rect.Y + rect.Height / 2);
                    DisplayArea iconDisplay = DisplayArea.GetFromPoint(center, DisplayAreaFallback.Nearest);
                    return new PanelAnchor(center, rect,
                        ClassifyTaskbarEdge(iconDisplay.WorkArea, icon));
                }
            }
            catch (Exception)
            {
                // Fall through to the pointer anchor below.
            }

            // GetCursorPos maps lpPoint to System.Drawing.Point (X/Y) in the
            // generated raw extern; no Windows.Win32 POINT type is generated.
            System.Drawing.Point pointer = default;
            if (PInvoke.GetCursorPos(&pointer))
                return new PanelAnchor(new PointInt32(pointer.X, pointer.Y), default, TrayTaskbarEdge.Bottom);
        }

        // Real display evidence only: the primary display's work area.
        if (DisplayArea.Primary is { } primary
            && primary.WorkArea is { Width: > 0, Height: > 0 } work)
        {
            return new PanelAnchor(
                new PointInt32(work.X + work.Width / 2, work.Y + work.Height / 2),
                default, TrayTaskbarEdge.Bottom);
        }
        return null;
    }

    /// <summary>Classifies the taskbar edge from the icon rect's position
    /// against its display's real work area (bottom, top, right or left).</summary>
    private static TrayTaskbarEdge ClassifyTaskbarEdge(RectInt32 work, RECT icon)
    {
        int workBottom = work.Y + work.Height;
        int workRight = work.X + work.Width;
        if (icon.top >= workBottom - 2) return TrayTaskbarEdge.Bottom;
        if (icon.bottom <= work.Y + 2) return TrayTaskbarEdge.Top;
        if (icon.left >= workRight - 2) return TrayTaskbarEdge.Right;
        return TrayTaskbarEdge.Left;
    }

    // ── Celebration animation (only the truthful all-synced state) ───────

    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TrayViewModel.IsAllSynced))
        {
            UpdateAnimation();
            UpdateTooltip();
        }
        else if (e.PropertyName == nameof(TrayViewModel.IsSyncingTabSelected))
        {
            UpdateAnimation();
        }
        else if (e.PropertyName == nameof(TrayViewModel.AvatarUri))
        {
            UpdateAvatarImage();
        }
        else if (e.PropertyName == nameof(TrayViewModel.PanelState))
        {
            if (_viewModel.PanelState == TrayPanelState.Loading) _loadingSinceUtc = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Plays VibingHuggy only while the panel's Syncing tab is visible, the
    /// system allows animations and <see cref="TrayViewModel.IsAllSynced"/>
    /// proves every configured connection is genuinely up to date. Within one
    /// continuous all-synced state the celebration plays exactly twice — the
    /// asset is 121 frames × 40 ms = 4.84 s per play, so the total budget is
    /// 9.68 s of animated playback. Hiding the panel, selecting Recent activity,
    /// or disabling animations pauses playback without discarding elapsed
    /// playback; resuming continues the same budget and can never exceed it.
    /// Ordinary PropertyChanged and
    /// status polls call this repeatedly and never restart playback; only a
    /// genuine non-all-synced → all-synced transition starts a fresh two plays.
    /// </summary>
    private void UpdateAnimation()
    {
        if (_disposed || !_viewModel.IsAllSynced)
        {
            // Leaving the all-synced truth ends the cycle; the next genuine
            // non-all-synced → all-synced transition earns a fresh two plays.
            _celebrationCycleActive = false;
            _celebrationElapsed.Reset();
            SetCelebrationPlaying(false);
            return;
        }

        if (!_celebrationCycleActive)
        {
            // First eligibility of a fresh cycle: reset the budget now. While
            // the state stays all-synced, repeated calls keep this budget.
            _celebrationCycleActive = true;
            _celebrationElapsed.Reset();
        }

        bool eligible = _isShown
            && _viewModel.IsSyncingTabSelected
            && _uiSettings.AnimationsEnabled
            && AllSyncedAnimationSource.IsAnimatedBitmap;
        if (!eligible || _celebrationElapsed.Elapsed >= CelebrationBudget)
        {
            // Pause (or finished): the elapsed playback is retained so a later
            // resume continues the same budget instead of restarting it.
            SetCelebrationPlaying(false);
            return;
        }
        SetCelebrationPlaying(true);
    }

    /// <summary>
    /// Starts/stops the GIF playback, the elapsed-playback Stopwatch and the
    /// budget watchdog together. Idempotent: repeated state refreshes with an
    /// unchanged decision are no-ops and never restart playback.
    /// </summary>
    private void SetCelebrationPlaying(bool play)
    {
        if (play == _celebrationPlaying) return;
        _celebrationPlaying = play;
        if (play)
        {
            AllSyncedAnimationSource.Play();
            _celebrationElapsed.Start();
            var timer = _celebrationTimer ??= CreateCelebrationTimer();
            timer.Start();
        }
        else
        {
            AllSyncedAnimationSource.Stop();
            _celebrationElapsed.Stop();
            _celebrationTimer?.Stop();
        }
    }

    private Microsoft.UI.Dispatching.DispatcherQueueTimer CreateCelebrationTimer()
    {
        var timer = DispatcherQueue.CreateTimer();
        timer.Interval = CelebrationTick;
        timer.Tick += OnCelebrationTick;
        return timer;
    }

    /// <summary>
    /// Watchdog for the two-play budget: stops playback exactly when the
    /// accumulated animated playback reaches 9.68 s, even when no other UI
    /// event fires at that moment.
    /// </summary>
    private void OnCelebrationTick(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args)
    {
        if (_disposed || !_celebrationPlaying) return;
        if (_celebrationElapsed.Elapsed < CelebrationBudget) return;
        SetCelebrationPlaying(false);
    }

    private void OnAllSyncedImageOpened(object sender, RoutedEventArgs e)
    {
        // The animated bitmap is fully decoded now; start playback only if the
        // truthful all-synced state (and animation preference) still allows it.
        UpdateAnimation();
    }

    // ── Account avatar (CatchingHuggy fallback; anonymous requests) ─────

    /// <summary>
    /// Swaps the header avatar to the view model's validated account URI.
    /// CatchingHuggy stays visible whenever there is no URI (loading, signed
    /// out, missing/invalid URI) or until the remote image actually opens; a
    /// decode failure or a source for a previous account falls back to
    /// CatchingHuggy instead of showing a stale picture. The bitmap request is
    /// anonymous: no credential is ever attached to it.
    /// </summary>
    private void UpdateAvatarImage()
    {
        if (_disposed) return;
        Uri? uri = _viewModel.AvatarUri;
        if (uri is null)
        {
            TrayAvatarBrush.ImageSource = null;
            _avatarImageSource = null;
            TrayAvatarShape.Visibility = Visibility.Collapsed;
            TrayAvatarFallbackShape.Visibility = Visibility.Visible;
            return;
        }

        // A fresh BitmapImage per account URI. BitmapImage carries
        // ImageOpened/ImageFailed itself, so late events from an older
        // account's image are recognized and ignored.
        var image = new BitmapImage(uri);
        image.ImageOpened += OnAvatarImageOpened;
        image.ImageFailed += OnAvatarImageFailed;
        _avatarImageSource = image;
        TrayAvatarBrush.ImageSource = image;
        // Fallback stays visible until this exact source opens successfully.
        TrayAvatarShape.Visibility = Visibility.Visible;
        TrayAvatarFallbackShape.Visibility = Visibility.Visible;
    }

    private void OnAvatarImageOpened(object sender, RoutedEventArgs e)
    {
        // Only the current source may replace the fallback; a late open from a
        // previous account's image must never show that account's picture.
        if (_disposed || sender is not BitmapImage source
            || !ReferenceEquals(source, _avatarImageSource))
        {
            return;
        }
        TrayAvatarFallbackShape.Visibility = Visibility.Collapsed;
    }

    private void OnAvatarImageFailed(object sender, ExceptionRoutedEventArgs e)
    {
        // Missing/unreachable/invalid image data: keep CatchingHuggy. The
        // account identity itself is unaffected — an avatar failure is never
        // an identity or login failure.
        if (_disposed || sender is not BitmapImage source) return;
        DetachAvatarSource(source);
        if (ReferenceEquals(source, _avatarImageSource))
        {
            TrayAvatarBrush.ImageSource = null;
            _avatarImageSource = null;
            TrayAvatarShape.Visibility = Visibility.Collapsed;
            TrayAvatarFallbackShape.Visibility = Visibility.Visible;
        }
    }

    /// <summary>Detaches the avatar bitmap's event handlers idempotently.</summary>
    private void DetachAvatarSource(BitmapImage source)
    {
        source.ImageOpened -= OnAvatarImageOpened;
        source.ImageFailed -= OnAvatarImageFailed;
    }

    private void UpdateTooltip() =>
        _tray?.SetTooltip(_viewModel.IsAllSynced ? "HF Drive — everything is up to date" : "HF Drive");

    // ── Bounded, cancellable refresh while visible ───────────────────────

    private void StartPolling()
    {
        StopPolling();
        _pollCts = new CancellationTokenSource();
        _pollTimer ??= CreatePollTimer();
        _pollTimer.Interval = PollInterval;
        _pollTimer.Start();
    }

    private void StopPolling()
    {
        _pollTimer?.Stop();
        _pollCts?.Cancel();
        _pollCts?.Dispose();
        _pollCts = null;
    }

    private Microsoft.UI.Dispatching.DispatcherQueueTimer CreatePollTimer()
    {
        var timer = DispatcherQueue.CreateTimer();
        timer.Tick += OnPollTick;
        return timer;
    }

    private void OnPollTick(Microsoft.UI.Dispatching.DispatcherQueueTimer sender, object args)
    {
        if (!_isShown || _disposed) return;
        if (_viewModel.PanelState == TrayPanelState.Loading
            && DateTime.UtcNow - _loadingSinceUtc > StatusUnavailableTimeout)
        {
            // The live session has accepted no status for too long: say so
            // explicitly instead of spinning or claiming an empty drive list.
            _viewModel.MarkStatusUnavailable();
            return;
        }
        if (_pollCts is { IsCancellationRequested: false } cts)
            _ = _viewModel.PollAsync(cts.Token);
    }

    // ── Tray/app actions (no local mutations; all real commands) ─────────

    private void OpenMainWindow()
    {
        HidePanel();
        ((App)Application.Current).OpenMainWindow();
    }

    private void OpenSection(string tag)
    {
        HidePanel();
        ((App)Application.Current).OpenMainSection(tag);
    }

    private void OpenFolder()
    {
        HidePanel();
        string? root = _viewModel.SelectedConnection?.RootPath;
        if (string.IsNullOrEmpty(root)) return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + root + "\"",
                UseShellExecute = true,
            });
        }
        catch (Exception)
        {
            // The folder may be unavailable; the main window shows the real
            // connection state where the user can retry.
            ((App)Application.Current).OpenMainSection("connections");
        }
    }

    private void OnPauseResume()
    {
        if (_viewModel.TogglePauseResumeCommand.CanExecute(null))
            _viewModel.TogglePauseResumeCommand.Execute(null);
    }

    private void OnExitUi() => ((App)Application.Current).ExitUi();

    private void OnExitProvider() => _ = ((App)Application.Current).ExitProviderAsync();

    // ── Panel surface events ─────────────────────────────────────────────

    private void OnRefreshClick(object sender, RoutedEventArgs e)
    {
        if (_viewModel.RefreshCommand.CanExecute(null))
            _viewModel.RefreshCommand.Execute(null);
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => HidePanel();

    private void OnSetupClick(object sender, RoutedEventArgs e) => OpenSection("setup");

    /// <summary>
    /// Footer "+": opens the existing bucket setup section only. It never
    /// creates a bucket, never starts consent and never mutates provider state.
    /// </summary>
    private void OnAddBucketClick(object sender, RoutedEventArgs e) => OpenSection("setup");

    private void OnOpenHFDriveClick(object sender, RoutedEventArgs e) => OpenMainWindow();

    private void OnIssueActionClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: TrayIssueRow row })
        {
            // Carry the row's real connection (and, for a conflict, its exact
            // conflict id) into the existing management surface: the operations
            // page scopes to that connection and selects that recorded conflict
            // for explicit user resolution. Nothing is resolved here.
            ((App)Application.Current).OpenMainSection(row.SectionTag, row.ConnectionId, row.ConflictId);
        }
    }
}
