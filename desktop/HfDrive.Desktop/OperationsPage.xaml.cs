using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HfDrive.Desktop;

/// <summary>
/// Operations slice: settings, connection controls, diagnostics, history and
/// conflicts. Every command targets the shared provider session; the page
/// itself owns no state beyond the view model handed to it at navigation.
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
            // Fetch the actual settings revision/values from the provider the
            // first time the page is shown, so "Apply settings" always has the
            // expected revision the provider expects.
            _ = ViewModel.EnsureSettingsLoadedAsync();
        }
    }
}
