using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HfDrive.Desktop;

/// <summary>Account slice: provider connection status and honest account state.</summary>
public sealed partial class AccountPage : Page
{
    public AccountPage()
    {
        InitializeComponent();
    }

    public MainViewModel ViewModel { get; private set; } = null!;

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is MainViewModel viewModel)
        {
            ViewModel = viewModel;
            Bindings.Update();
        }
    }
}
