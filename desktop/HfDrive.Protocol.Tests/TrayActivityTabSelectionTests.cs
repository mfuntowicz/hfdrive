using HfDrive.Desktop.ViewModels;
using Xunit;

namespace HfDrive.Protocol.Tests;

public sealed class TrayActivityTabSelectionTests
{
    [Fact]
    public void UncheckingSyncingDoesNotClearHistorySelection()
    {
        TrayActivityTab selected = TrayActivityTabSelection.ApplyChecked(
            TrayActivityTab.Syncing, TrayActivityTab.History, isChecked: true);
        selected = TrayActivityTabSelection.ApplyChecked(
            selected, TrayActivityTab.Syncing, isChecked: false);

        Assert.Equal(TrayActivityTab.History, selected);
    }

    [Fact]
    public void UncheckingHistoryDoesNotClearSyncingSelection()
    {
        TrayActivityTab selected = TrayActivityTabSelection.ApplyChecked(
            TrayActivityTab.History, TrayActivityTab.Syncing, isChecked: true);
        selected = TrayActivityTabSelection.ApplyChecked(
            selected, TrayActivityTab.History, isChecked: false);

        Assert.Equal(TrayActivityTab.Syncing, selected);
    }
}
