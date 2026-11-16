namespace HfDrive.Desktop.Services;

/// <summary>Screen coordinate and alignment contract for a native tray popup.</summary>
internal readonly record struct TrayMenuPlacement(int X, int Y, bool CenterHorizontal, bool AlignBottom)
{
    /// <summary>Centers the menu over the icon and puts its bottom edge at the icon's top.</summary>
    public static TrayMenuPlacement AboveIcon(int left, int top, int right, int bottom)
    {
        if (right <= left) throw new ArgumentOutOfRangeException(nameof(right));
        if (bottom <= top) throw new ArgumentOutOfRangeException(nameof(bottom));
        return new TrayMenuPlacement(left + (right - left) / 2, top, CenterHorizontal: true, AlignBottom: true);
    }

    /// <summary>Uses a real click point when the shell cannot supply the icon rectangle.</summary>
    public static TrayMenuPlacement AbovePoint(int x, int y) =>
        new(x, y, CenterHorizontal: true, AlignBottom: true);
}
