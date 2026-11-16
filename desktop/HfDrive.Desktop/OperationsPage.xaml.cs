using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HfDrive.Desktop;

/// <summary>
/// Advanced activity and recovery surface: connection controls, conflicts,
/// history/restore and diagnostics. Every command targets the shared provider
/// session; the page itself owns no state beyond the view model handed to it
/// at navigation. Provider-wide settings are owned by SettingsPage.
/// </summary>
public sealed partial class OperationsPage : Page
{
    public OperationsPage()
    {
        InitializeComponent();
    }

    public OperationsViewModel ViewModel { get; private set; } = null!;

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is OperationsViewModel viewModel)
        {
            ViewModel = viewModel;
            Bindings.Update();
        }
    }
}
