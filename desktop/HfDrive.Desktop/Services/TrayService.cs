using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Graphics.GdiPlus;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.WindowsAndMessaging;

namespace HfDrive.Desktop.Services;

/// <summary>
/// Native notification-icon lifecycle for the HF Drive desktop: fixed icon
/// GUID, version-4 callback decoding, TaskbarCreated restoration and the
/// existing right-click menu. The icon subclasses the actual desktop window
/// handle obtained through <c>WinRT.Interop.WindowNative.GetWindowHandle</c>
/// (never a title lookup). The icon owns no provider lifetime: "Exit UI"
/// releases only this process, and provider exit is a separate confirmed menu
/// action routed to the application shell.
/// </summary>
internal sealed class TrayService : IDisposable
{
    internal static readonly Guid TrayGuid = new("fad69391-1ff4-454e-a0c3-387d0063e1a1");
    internal const uint TrayCallback = 0x8000 + 1;

    private const uint WmNull = 0x0000;
    private const uint WmDestroy = 0x0002;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmContextMenu = 0x007B;
    private const uint NinSelect = 0x0400;          // WM_USER + 0
    private const uint NinKeySelect = NinSelect | 0x0001;
    private const uint NinPopupOpen = 0x0406;       // WM_USER + 6
    private const uint NinPopupClose = 0x0407;      // WM_USER + 7

    // NOTIFYICONDATA flags (shellapi.h), from the generated
    // NOTIFY_ICON_DATA_FLAGS members (never raw bit values):
    // NIF_MESSAGE|NIF_ICON|NIF_TIP|NIF_GUID|NIF_SHOWTIP.
    internal const NOTIFY_ICON_DATA_FLAGS NifFlags =
        NOTIFY_ICON_DATA_FLAGS.NIF_MESSAGE
        | NOTIFY_ICON_DATA_FLAGS.NIF_ICON
        | NOTIFY_ICON_DATA_FLAGS.NIF_TIP
        | NOTIFY_ICON_DATA_FLAGS.NIF_GUID
        | NOTIFY_ICON_DATA_FLAGS.NIF_SHOWTIP;
    private const uint NotifyIconVersion4 = 4;

    private const uint OpenCommand = 1;
    private const uint OpenFolderCommand = 2;
    private const uint StatusCommand = 3;
    private const uint SettingsCommand = 4;
    private const uint PauseResumeCommand = 5;
    private const uint ExitUiCommand = 6;
    private const uint ExitProviderCommand = 7;
    private const uint ConfirmExitProviderCommand = 8;

    private const nuint SubclassId = 1;

    private readonly HWND _hwnd;
    private readonly SUBCLASSPROC _subclass;
    private readonly uint _taskbarCreatedMessage;
    private nuint _gdiplusToken;
    private HICON _icon;
    private HMENU _menu;
    private bool _registered;
    private bool _disposed;
    /// <summary>True when the shell accepted <c>NOTIFYICON_VERSION_4</c>
    /// (selection/context-menu notifications). When false, callbacks arrive in
    /// the legacy mouse-message shape.</summary>
    private bool _version4Notifications;
    /// <summary>Set once a v4 selection notification proves the shell uses the
    /// version-4 shape; from then on <c>WM_LBUTTONUP</c> is only the duplicate
    /// mouse message of a click and never an activation.</summary>
    private bool _sawVersion4Selection;
    /// <summary>Armed by an accepted legacy <c>WM_LBUTTONUP</c> while the
    /// version-4 shape is negotiated, and consumed by that gesture's duplicate
    /// <c>NIN_SELECT</c> (one physical click delivered through both shapes).</summary>
    private bool _suppressNextSelection;
    /// <summary>Set once a <c>WM_CONTEXTMENU</c> proves the version-4 menu
    /// shape; from then on <c>WM_RBUTTONUP</c> is only the duplicate mouse
    /// message of the same right-click.</summary>
    private bool _sawVersion4ContextMenu;
    /// <summary>Armed by a menu opened from a legacy <c>WM_RBUTTONUP</c> while
    /// the version-4 shape is negotiated, and consumed by that gesture's
    /// duplicate <c>WM_CONTEXTMENU</c> (one right-click, one menu).</summary>
    private bool _suppressNextContextMenu;
    /// <summary>True while a popup menu is being tracked. The shell can deliver
    /// one right-click through two notifications, and the menu's modal loop
    /// re-dispatches the duplicate to this subclass: a re-entrant
    /// <see cref="ShowMenu"/> must never call <c>TrackPopupMenu</c> on the same
    /// handle while it is already tracked.</summary>
    private bool _menuShowing;
    private string _tooltip = "HF Drive";

    /// <summary>Mouse or keyboard activation (never hover): toggle the tray panel.</summary>
    public event Action? PanelToggleRequested;

    /// <summary>Reopen the current main-window surface without changing its navigation.</summary>
    public event Action? OpenMainRequested;

    /// <summary>Open the main window at a section tag (account/connections/operations/setup).</summary>
    public event Action<string>? OpenSectionRequested;

    /// <summary>Open the selected connection's local folder.</summary>
    public event Action? OpenFolderRequested;

    /// <summary>Pause or resume syncing on every connection.</summary>
    public event Action? PauseResumeRequested;

    /// <summary>Exit only this UI process; the provider keeps running.</summary>
    public event Action? ExitUiRequested;

    /// <summary>Confirmed "Exit provider": stop the provider through its IPC command.</summary>
    public event Action? ExitProviderRequested;

    public TrayService(Window window)
    {
        // The real HWND of this window; never FindWindow-by-title.
        _hwnd = new HWND(WinRT.Interop.WindowNative.GetWindowHandle(window));
        if (_hwnd.IsNull)
            throw new InvalidOperationException("The HF Drive window handle is unavailable.");
        _subclass = OnSubclassMessage;
        _taskbarCreatedMessage = PInvoke.RegisterWindowMessage("TaskbarCreated");
        StartGdiplus();
        try
        {
            _icon = LoadProductIcon();
            _menu = CreateTrayMenu();
            if (!RegisterIcon())
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the tray icon.");
            if (!PInvoke.SetWindowSubclass(_hwnd, _subclass, SubclassId, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to subscribe to tray messages.");
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>Adds the icon and negotiates notification version 4.</summary>
    private bool RegisterIcon()
    {
        if (!Shell_NotifyIconHelper.Add(_hwnd, _icon, _tooltip))
            return false;
        _registered = true;
        // Version 4 delivers the notification in LOWORD(lParam) and the click
        // coordinates in wParam; on negotiation failure the callbacks keep the
        // legacy mouse-message shape. The shell's answer to NIM_SETVERSION
        // selects the decode/activation shape in OnSubclassMessage.
        _version4Notifications = Shell_NotifyIconHelper.SetVersion(_hwnd, NotifyIconVersion4);
        return true;
    }

    /// <summary>Updates the icon tooltip to the current display state.</summary>
    public void SetTooltip(string text)
    {
        if (_disposed || !_registered || text == _tooltip) return;
        _tooltip = text;
        Shell_NotifyIconHelper.ModifyTip(_hwnd, text);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_registered)
        {
            Shell_NotifyIconHelper.Delete(_hwnd);
            _registered = false;
        }
        if (!_hwnd.IsNull)
        {
            PInvoke.RemoveWindowSubclass(_hwnd, _subclass, SubclassId);
        }
        if (!_menu.IsNull)
        {
            PInvoke.DestroyMenu(_menu);
            _menu = default;
        }
        if (!_icon.IsNull)
        {
            PInvoke.DestroyIcon(_icon);
            _icon = default;
        }
        if (_gdiplusToken != 0)
        {
            PInvoke.GdiplusShutdown(_gdiplusToken);
            _gdiplusToken = 0;
        }
    }

    private void StartGdiplus()
    {
        var input = new GdiplusStartupInput { GdiplusVersion = 1 };
        var output = new GdiplusStartupOutput();
        var status = PInvoke.GdiplusStartup(ref _gdiplusToken, in input, ref output);
        if (status != Status.Ok) throw new Win32Exception((int)status, "GDI+ initialization failed.");
    }

    private static unsafe HICON LoadProductIcon()
    {
        // The packaged Square44x44Logo is the CatchingHuggy identity raster;
        // the loader convention is unchanged from the previous tray service.
        string path = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(Process.GetCurrentProcess().MainModule!.FileName)!,
            "assets", "Square44x44Logo.png");
        var bitmap = (GpBitmap*)null;
        var status = PInvoke.GdipCreateBitmapFromFile(path, ref bitmap);
        if (status != Status.Ok) throw new Win32Exception((int)status, "Unable to load the tray logo.");
        try
        {
            var icon = default(HICON);
            status = PInvoke.GdipCreateHICONFromBitmap(bitmap, &icon);
            if (status != Status.Ok) throw new Win32Exception((int)status, "Unable to create the tray icon handle.");
            return icon;
        }
        finally
        {
            PInvoke.GdipDisposeImage((GpImage*)bitmap);
        }
    }

    private static HMENU CreateTrayMenu()
    {
        var menu = PInvoke.CreatePopupMenu();
        if (menu.IsNull) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the tray menu.");
        var safe = new NonOwningMenuHandle(menu);
        if (!PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, OpenCommand, "Open HF Drive")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, OpenFolderCommand, "Open folder")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_SEPARATOR, 0, "")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, StatusCommand, "Status")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, SettingsCommand, "Settings")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, PauseResumeCommand, "Pause / resume syncing")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_SEPARATOR, 0, "")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, ExitUiCommand, "Exit HF Drive")
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, ExitProviderCommand, "Exit provider…"))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to populate the tray menu.");
        return menu;
    }

    private LRESULT OnSubclassMessage(HWND hwnd, uint message, WPARAM wParam, LPARAM lParam, nuint subclass, nuint reference)
    {
        if (message == TrayCallback)
        {
            // NOTIFYICON_VERSION_4: LOWORD(lParam) is the notification message
            // and LOWORD/HIWORD(wParam) are the click coordinates. The legacy
            // shape stores the message directly in lParam; its values are all
            // below 0x10000, so the low word decodes both shapes.
            uint notification = (uint)(lParam.Value.ToInt64() & 0xFFFF);
            switch (notification)
            {
                case NinKeySelect:                  // v4: keyboard activation
                    // Keyboard activation is one unambiguous gesture: always
                    // toggles, and marks the shell as v4-shaped.
                    _sawVersion4Selection = true;
                    PanelToggleRequested?.Invoke();
                    return new LRESULT(0);
                case NinSelect:                     // v4: mouse selection (click)
                    RequestSelectionToggle();
                    return new LRESULT(0);
                case WmLButtonUp:                   // legacy negotiation/shape only
                    RequestLegacyClickToggle();
                    return new LRESULT(0);
                case NinPopupOpen:
                case NinPopupClose:
                    // Shell hover-popup notifications only: never toggle the
                    // OneDrive-style panel.
                    return new LRESULT(0);
                case WmContextMenu:                 // v4 right-click / keyboard menu
                    RequestMenu();
                    return new LRESULT(0);
                case WmRButtonUp:                   // legacy right-click
                    RequestLegacyMenu();
                    return new LRESULT(0);
            }
        }
        else if (_taskbarCreatedMessage != 0 && message == _taskbarCreatedMessage)
        {
            // Explorer restarted: the icon is gone, re-add it and renegotiate.
            if (!_registered && !_icon.IsNull)
            {
                RegisterIcon();
            }
        }
        else if (message == WmDestroy)
        {
            Dispose();
        }
        return PInvoke.DefSubclassProc(hwnd, message, wParam, lParam);
    }

    /// <summary>
    /// <c>NIN_SELECT</c>: the version-4 mouse selection (left click) — an
    /// activation. Marks the shell's notification shape as version 4 and, if
    /// this gesture's legacy mouse message arrived first, consumes its armed
    /// one-shot suppression instead of toggling twice.
    /// </summary>
    private void RequestSelectionToggle()
    {
        _sawVersion4Selection = true;
        if (_suppressNextSelection)
        {
            // The WM_LBUTTONUP half of this click already toggled.
            _suppressNextSelection = false;
            return;
        }
        PanelToggleRequested?.Invoke();
    }

    /// <summary>
    /// <c>WM_LBUTTONUP</c>: activation only for the legacy notification shape.
    /// Once the version-4 shape is known (negotiation agreed or a selection
    /// notification has been seen) it is at most the duplicate mouse half of a
    /// click whose <c>NIN_SELECT</c>/<c>NIN_KEYSELECT</c> already activated, so
    /// it never toggles: a v4 click produces exactly one toggle regardless of
    /// the order the shell delivers the pair in. With a failed negotiation
    /// every click toggles as before.
    /// </summary>
    private void RequestLegacyClickToggle()
    {
        if (_sawVersion4Selection)
        {
            // Version-4 shape proven: selection notifications are the
            // activations and this is the same click's duplicate.
            return;
        }
        PanelToggleRequested?.Invoke();
        if (_version4Notifications)
        {
            // Negotiation agreed but the selection half of this click may
            // still arrive; arm a one-shot suppression for it.
            _suppressNextSelection = true;
        }
    }

    /// <summary>
    /// Opens the context menu at most once per physical right-click. Under the
    /// version-4 shape the shell can report one right-click through both
    /// <c>WM_CONTEXTMENU</c> and <c>WM_RBUTTONUP</c>: the first notification
    /// marks the menu shape and the duplicate half is consumed one-shot,
    /// mirroring the left-click activation routing. While a menu is being
    /// tracked the shell's modal loop re-dispatches the duplicate to the
    /// subclass, so re-entry is ignored outright — a handle must never be
    /// tracked twice.
    /// </summary>
    private void RequestMenu()
    {
        if (_menuShowing) return;
        _sawVersion4ContextMenu = true;
        if (_suppressNextContextMenu)
        {
            _suppressNextContextMenu = false;
            return;
        }
        ShowMenu();
    }

    /// <summary>
    /// <c>WM_RBUTTONUP</c> opens the menu only in the legacy notification
    /// shape. Once <c>WM_CONTEXTMENU</c> has been seen the shell is
    /// version-4-shaped and this is the duplicate half of an already-handled
    /// right-click. With a failed negotiation every right-click opens the menu
    /// as before.
    /// </summary>
    private void RequestLegacyMenu()
    {
        if (_menuShowing) return;
        if (_sawVersion4ContextMenu) return;
        if (_suppressNextContextMenu)
        {
            _suppressNextContextMenu = false;
            return;
        }
        ShowMenu();
        if (_version4Notifications)
        {
            // Negotiation agreed but the menu half of this right-click may
            // still arrive; arm a one-shot suppression for it.
            _suppressNextContextMenu = true;
        }
    }

    private unsafe void ShowMenu()
    {
        if (_menu.IsNull || _menuShowing) return;
        // Required so the popup dismisses on outside clicks.
        PInvoke.SetForegroundWindow(_hwnd);
        var position = PInvoke.GetMessagePos();
        int x = (short)(position & 0xffff);
        int y = (short)((position >> 16) & 0xffff);
        // TPM_RETURNCMD: the BOOL return carries the chosen command id (0 when
        // the menu is cancelled). Convert the real return once to the menu-id
        // type of the case constants; cancel matches no case below.
        uint command;
        _menuShowing = true;
        try
        {
            command = (uint)(int)PInvoke.TrackPopupMenu(_menu, TRACK_POPUP_MENU_FLAGS.TPM_RETURNCMD | TRACK_POPUP_MENU_FLAGS.TPM_RIGHTBUTTON,
                x, y, 0, _hwnd, null);
        }
        finally
        {
            _menuShowing = false;
            // Required notification-icon menu handshake (Microsoft KB135788):
            // after TrackPopupMenu the owner must be posted WM_NULL, or the
            // menu-mode state never clears for a hidden/notification owner and
            // later popup menus render as empty, unusable ghost windows.
            PInvoke.PostMessage(_hwnd, WmNull, default, default);
        }
        switch (command)
        {
            case OpenCommand:
                OpenMainRequested?.Invoke();
                break;
            case OpenFolderCommand:
                OpenFolderRequested?.Invoke();
                break;
            case StatusCommand:
                OpenSectionRequested?.Invoke("connections");
                break;
            case SettingsCommand:
                OpenSectionRequested?.Invoke("operations");
                break;
            case PauseResumeCommand:
                PauseResumeRequested?.Invoke();
                break;
            case ExitUiCommand:
                ExitUiRequested?.Invoke();
                break;
            case ExitProviderCommand:
                if (ConfirmExitProvider(_hwnd, x, y))
                    ExitProviderRequested?.Invoke();
                break;
        }
    }

    /// <summary>
    /// A distinct second native confirmation for the destructive provider exit:
    /// the user must pick an explicit "Stop the provider" item.
    /// </summary>
    private static unsafe bool ConfirmExitProvider(HWND owner, int x, int y)
    {
        var confirm = PInvoke.CreatePopupMenu();
        if (confirm.IsNull) return false;
        var safe = new NonOwningMenuHandle(confirm);
        if (!PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, ConfirmExitProviderCommand,
                "Stop the HF Drive provider (online-only files stay unavailable)"))
        {
            PInvoke.DestroyMenu(confirm);
            return false;
        }
        try
        {
            PInvoke.SetForegroundWindow(owner);
            // TPM_RETURNCMD: the BOOL return carries the chosen command id (0
            // when cancelled); converted once to the menu-id type, so only the
            // explicit confirm item succeeds and cancel/failure never does.
            uint command = (uint)(int)PInvoke.TrackPopupMenu(confirm, TRACK_POPUP_MENU_FLAGS.TPM_RETURNCMD | TRACK_POPUP_MENU_FLAGS.TPM_RIGHTBUTTON,
                x, y, 0, owner, null);
            return command == ConfirmExitProviderCommand;
        }
        finally
        {
            // Same required menu-mode handshake as ShowMenu's tracking.
            PInvoke.PostMessage(owner, WmNull, default, default);
            PInvoke.DestroyMenu(confirm);
        }
    }
}

internal sealed unsafe class NonOwningMenuHandle : SafeHandle
{
    public NonOwningMenuHandle(HMENU menu) : base(IntPtr.Zero, true)
    {
        handle = (IntPtr)menu.Value;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle() => false;
}

/// <summary>Typed wrappers over <c>Shell_NotifyIconW</c> for the fixed GUID icon.</summary>
internal static class Shell_NotifyIconHelper
{
    public static bool Add(HWND hwnd, HICON icon, string tip)
    {
        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = hwnd,
            uID = 1,
            uFlags = TrayService.NifFlags,
            uCallbackMessage = TrayService.TrayCallback,
            guidItem = TrayService.TrayGuid,
            hIcon = icon,
        };
        SetTip(ref data, tip);
        return PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_ADD, in data);
    }

    /// <summary>
    /// Negotiates the notification version (e.g. version 4). Returns the
    /// actual <c>Shell_NotifyIcon(NIM_SETVERSION)</c> verdict — the shell may
    /// refuse, in which case callbacks keep the legacy message shape.
    /// </summary>
    public static bool SetVersion(HWND hwnd, uint version)
    {
        // NIF_GUID from BaseData identifies the fixed-GUID icon and must not
        // be cleared: the shell locates the icon by guidItem for this call too.
        var data = BaseData(hwnd);
        data.Anonymous.uVersion = version;
        return PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_SETVERSION, in data);
    }

    public static void ModifyTip(HWND hwnd, string tip)
    {
        var data = BaseData(hwnd);
        // Preserve the fixed-GUID identity alongside the tip change.
        data.uFlags = NOTIFY_ICON_DATA_FLAGS.NIF_TIP | NOTIFY_ICON_DATA_FLAGS.NIF_GUID;
        SetTip(ref data, tip);
        PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_MODIFY, in data);
    }

    public static void Delete(HWND hwnd)
    {
        var data = BaseData(hwnd);
        PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_DELETE, in data);
    }

    /// <summary>Common fixed-GUID identity data: the same HWND/uID/guidItem
    /// selects the one icon for every lifecycle operation, with NIF_GUID so
    /// the shell identifies it by <see cref="TrayService.TrayGuid"/>.</summary>
    private static NOTIFYICONDATAW BaseData(HWND hwnd) => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
        hWnd = hwnd,
        uID = 1,
        uFlags = NOTIFY_ICON_DATA_FLAGS.NIF_GUID,
        guidItem = TrayService.TrayGuid,
    };

    private static void SetTip(ref NOTIFYICONDATAW data, string text)
    {
        for (var index = 0; index < data.szTip.Length; index++)
            data.szTip[index] = '\0';
        for (var index = 0; index < Math.Min(text.Length, data.szTip.Length - 1); index++)
            data.szTip[index] = text[index];
    }
}
