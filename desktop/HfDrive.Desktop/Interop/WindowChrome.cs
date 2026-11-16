using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Graphics.Dwm;

namespace HfDrive.Desktop.Interop;

internal static class WindowChrome
{
    // DWM owns corner clipping and shadow. Compact setup and tray windows
    // suppress border paint; the normal shell restores the system border.
    internal static unsafe void ApplyFluentFrame(nint windowHandle, bool suppressBorder)
    {
        var window = new HWND(windowHandle);
        // Leaving compact mode must restore DWM's native nonclient painting,
        // not just the presenter's caption flags.
        var rendering = suppressBorder
            ? DWMNCRENDERINGPOLICY.DWMNCRP_USEWINDOWSTYLE
            : DWMNCRENDERINGPOLICY.DWMNCRP_ENABLED;
        PInvoke.DwmSetWindowAttribute(
            window, DWMWINDOWATTRIBUTE.DWMWA_NCRENDERING_POLICY,
            &rendering, (uint)sizeof(DWMNCRENDERINGPOLICY)).ThrowOnFailure();

        var corners = DWM_WINDOW_CORNER_PREFERENCE.DWMWCP_ROUND;
        PInvoke.DwmSetWindowAttribute(
            window, DWMWINDOWATTRIBUTE.DWMWA_WINDOW_CORNER_PREFERENCE,
            &corners, (uint)sizeof(DWM_WINDOW_CORNER_PREFERENCE)).ThrowOnFailure();

        uint border = suppressBorder ? PInvoke.DWMWA_COLOR_NONE : PInvoke.DWMWA_COLOR_DEFAULT;
        PInvoke.DwmSetWindowAttribute(
            window, DWMWINDOWATTRIBUTE.DWMWA_BORDER_COLOR,
            &border, sizeof(uint)).ThrowOnFailure();
    }
}
