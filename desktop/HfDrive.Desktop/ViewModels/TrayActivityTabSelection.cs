namespace HfDrive.Desktop.ViewModels;

/// <summary>Content page shown by the tray's activity tabs.</summary>
public enum TrayActivityTab
{
    Syncing,
    History,
}

/// <summary>Radio-button checked/unchecked transitions for one persistent tab selection.</summary>
public static class TrayActivityTabSelection
{
    /// <summary>A checked button selects its tab; an unchecked button never clears the
    /// selection made by the other button. This preserves exactly one visible card
    /// regardless of the order in which WinUI delivers the two bindings.</summary>
    public static TrayActivityTab ApplyChecked(TrayActivityTab current, TrayActivityTab changed, bool isChecked) =>
        isChecked ? changed : current;
}
