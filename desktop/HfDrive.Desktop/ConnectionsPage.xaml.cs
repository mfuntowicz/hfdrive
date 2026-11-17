using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HfDrive.Desktop;

/// <summary>
/// Connections slice: renders observed per-connection provider status only.
/// </summary>
public sealed partial class ConnectionsPage : Page
{
    public ConnectionsPage()
    {
        InitializeComponent();
    }

    public MainViewModel ViewModel { get; private set; } = null!;

    private void OnRemoveConnectionClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: ConnectionViewModel connection })
        {
            ((App)Application.Current).OpenMainSection("operations", connection.Status.ConnectionId, null);
        }
    }

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
