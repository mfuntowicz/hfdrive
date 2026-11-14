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

/// <summary>Native notification-icon lifecycle for the desktop window.</summary>
internal sealed class TrayService : IDisposable
{
    internal static readonly Guid TrayGuid = new("fad69391-1ff4-454e-a0c3-387d0063e1a1");
    internal const uint TrayCallback = 0x8000 + 1;
    private const uint WmDestroy = 0x0002;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonUp = 0x0205;
    private const uint OpenCommand = 1;
    private const uint ExitCommand = 2;
    private const nuint SubclassId = 1;

    private readonly Window _window;
    private readonly HWND _hwnd;
    private readonly SUBCLASSPROC _subclass;
    private nuint _gdiplusToken;
    private HICON _icon;
    private HMENU _menu;
    private bool _registered;
    private bool _disposed;

    public TrayService(Window window)
    {
        _window = window;
        _hwnd = PInvoke.FindWindow(null, "HF Drive");
        if (_hwnd.IsNull)
            throw new InvalidOperationException("The HF Drive window handle is unavailable.");
        _subclass = OnSubclassMessage;
        StartGdiplus();
        try
        {
            _icon = LoadProductIcon();
            _menu = CreateTrayMenu();
            _registered = Shell_NotifyIconHelper.Add(_hwnd, _icon);
            if (!_registered)
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
            || !PInvoke.AppendMenu(safe, MENU_ITEM_FLAGS.MF_STRING, ExitCommand, "Exit"))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to populate the tray menu.");
        return menu;
    }

    private LRESULT OnSubclassMessage(HWND hwnd, uint message, WPARAM wParam, LPARAM lParam, nuint subclass, nuint reference)
    {
        if (message == TrayCallback)
        {
            switch ((uint)lParam.Value.ToInt64())
            {
                case WmLButtonUp:
                    _window.Activate();
                    PInvoke.SetForegroundWindow(_hwnd);
                    return new LRESULT(0);
                case WmRButtonUp:
                    ShowMenu();
                    return new LRESULT(0);
            }
        }
        else if (message == WmDestroy)
        {
            Dispose();
        }
        return PInvoke.DefSubclassProc(hwnd, message, wParam, lParam);
    }

    private unsafe void ShowMenu()
    {
        if (_menu.IsNull) return;
        PInvoke.SetForegroundWindow(_hwnd);
        var position = PInvoke.GetMessagePos();
        var x = (short)(position & 0xffff);
        var y = (short)(position >> 16);
        var command = PInvoke.TrackPopupMenu(_menu, TRACK_POPUP_MENU_FLAGS.TPM_RETURNCMD,
            x, y, 0, _hwnd, null);
        if (command == OpenCommand)
        {
            _window.Activate();
            PInvoke.SetForegroundWindow(_hwnd);
        }
        else if (command == ExitCommand)
        {
            Application.Current.Exit();
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

internal static class Shell_NotifyIconHelper
{
    public static bool Add(HWND hwnd, HICON icon)
    {
        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = hwnd,
            uID = 1,
            uFlags = (NOTIFY_ICON_DATA_FLAGS)(0x0001 | 0x0002 | 0x0004 | 0x0010), // NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_GUID
            uCallbackMessage = TrayService.TrayCallback,
            guidItem = TrayService.TrayGuid,
            hIcon = icon,
        };
        SetTip(ref data, "HF Drive");
        return PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_ADD, in data);
    }

    public static void Delete(HWND hwnd)
    {
        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = hwnd,
            uID = 1,
            guidItem = TrayService.TrayGuid,
        };
        PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_DELETE, in data);
    }

    private static void SetTip(ref NOTIFYICONDATAW data, string text)
    {
        for (var index = 0; index < data.szTip.Length; index++)
            data.szTip[index] = '\0';
        for (var index = 0; index < Math.Min(text.Length, data.szTip.Length - 1); index++)
            data.szTip[index] = text[index];
    }
}
