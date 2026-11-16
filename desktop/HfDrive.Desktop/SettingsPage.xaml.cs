using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HfDrive.Desktop;

/// <summary>
/// Settings slice: the approachable transfer-speed and local-storage surface
/// over the shared <see cref="OperationsViewModel"/>. The page owns no state
/// of its own; every value is the provider's real stored setting and every
/// command is the same typed provider RPC the rest of the app uses.
/// </summary>
public sealed partial class SettingsPage : Page
{
    public SettingsPage()
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
            // Read the provider's actual settings revision/values the first
            // time the page is shown (and again after a reconnect), so Save
            // always uses the revision the provider expects. A dirty draft is
            // never overwritten by this load.
            _ = ViewModel.EnsureSettingsLoadedAsync();
        }
    }

    /// <summary>
    /// Review-and-discard path: destroying the user's typed entries always
    /// needs explicit confirmation; the reload itself is the provider's empty
    /// patch read and changes nothing.
    /// </summary>
    private async void OnDiscardChangesClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel.IsSettingsDirty)
        {
            var dialog = new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "Discard unsaved changes?",
                Content = "Your entries are not saved yet. Discarding reloads the provider's stored values "
                        + "and clears what you typed. Choose “Keep editing” to keep your entries.",
                PrimaryButtonText = "Discard my changes",
                CloseButtonText = "Keep editing",
                DefaultButton = ContentDialogButton.Close,
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary)
                return;
        }
        if (ViewModel.DiscardAndReloadSettingsCommand.CanExecute(null))
            ViewModel.DiscardAndReloadSettingsCommand.Execute(null);
    }
}
