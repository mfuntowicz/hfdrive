using System.ComponentModel;
using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;

namespace HfDrive.Desktop;

/// <summary>
/// Compact four-stage setup form. All displayed values come from observed
/// provider responses; the page only collects the short-lived wizard input.
/// Credential fields are cleared the moment they are read and passed once to
/// <see cref="SetupViewModel.ContinueAsync"/>; the DPAPI ciphertext is never
/// displayed here. The folder picker is a native picker owned by
/// <see cref="App.DesktopWindow"/>; manual path entry always remains available.
/// </summary>
public sealed partial class SetupPage : Page
{
    private string? _suggestedRootPath;

    public SetupPage()
    {
        InitializeComponent();
    }

    public SetupViewModel ViewModel { get; private set; } = null!;

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        if (e.Parameter is Tuple<MainViewModel, SetupViewModel> arguments)
        {
            ViewModel = arguments.Item2;
            ViewModel.PropertyChanged += OnViewModelPropertyChanged;
            Bindings.Update();
            ApplySuggestedRootPath();
        }
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        base.OnNavigatedFrom(e);
        ClearCredentialFields();
        if (ViewModel is not null)
            ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(SetupViewModel.IsLocalStepVisible):
            case nameof(SetupViewModel.SelectedBucket):
                ApplySuggestedRootPath();
                break;
            case nameof(SetupViewModel.IsCredentialsVisible):
                // Publication credentials are only needed while writable access
                // is being set up; drop any typed values as soon as that changes.
                if (ViewModel.IsCredentialsVisible != Visibility.Visible)
                    ClearCredentialFields();
                break;
        }
    }

    /// <summary>
    /// Suggests %USERPROFILE%\HF Drive\&lt;bucket&gt; for the local root. The
    /// suggestion never overwrites an entered path; if the user has not edited
    /// the previous suggestion, it follows a changed bucket selection.
    /// </summary>
    private void ApplySuggestedRootPath()
    {
        if (ViewModel is null || ViewModel.IsLocalStepVisible != Visibility.Visible)
            return;

        string current = ViewModel.RootPathText;
        bool emptyOrUnedited = string.IsNullOrWhiteSpace(current) || current == _suggestedRootPath;
        if (!emptyOrUnedited)
            return;

        string? bucketName = ViewModel.SelectedBucket?.Name;
        if (string.IsNullOrWhiteSpace(bucketName))
            return;

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string safeName = MakePathSafe(bucketName);
        string suggestion = Path.Combine(userProfile, "HF Drive", safeName);
        _suggestedRootPath = suggestion;
        ViewModel.RootPathText = suggestion;
    }

    private static string MakePathSafe(string name)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        char[] buffer = name.ToCharArray();
        for (int i = 0; i < buffer.Length; i++)
        {
            if (Array.IndexOf(invalid, buffer[i]) >= 0)
                buffer[i] = '-';
        }
        return new string(buffer).TrimEnd('.', ' ');
    }

    /// <summary>
    /// Single primary action: reads the credential fields (when present),
    /// clears them immediately, then hands the values to the view model's
    /// ContinueAsync exactly once. The primary label carries the current
    /// meaning: Sign in / Continue / Check &amp; review / Connect / Open HF Drive.
    /// </summary>
    private async void OnPrimaryClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;

        string keyId = S3KeyIdBox.Text;
        string secretKey = S3SecretKeyBox.Password;
        // Clear before any await: immutable strings cannot be guaranteed
        // erased, so their lifetime is only minimized, never lengthened.
        ClearCredentialFields();

        try
        {
            await ViewModel.ContinueAsync(keyId, secretKey);
        }
        catch (Exception ex)
        {
            ViewModel.ErrorText = $"Setup could not continue: {ex.Message}";
        }
    }

    /// <summary>Native folder picker owned by the desktop window.</summary>
    private async void OnBrowseFolderClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        Window? owner = ((App)Application.Current).DesktopWindow;
        if (owner is null)
            return; // Manual path entry remains the fallback.

        try
        {
            var picker = new FolderPicker
            {
                SuggestedStartLocation = PickerLocationId.ComputerFolder,
                CommitButtonText = "Select folder",
            };
            picker.FileTypeFilter.Add("*");
            WinRT.Interop.InitializeWithWindow.Initialize(
                picker, WinRT.Interop.WindowNative.GetWindowHandle(owner));

            var folder = await picker.PickSingleFolderAsync();
            if (folder is not null)
            {
                _suggestedRootPath = null;
                ViewModel.RootPathText = folder.Path;
            }
        }
        catch (Exception ex)
        {
            ViewModel.ErrorText = $"The folder picker could not be opened: {ex.Message}";
        }
    }

    private void ClearCredentialFields()
    {
        S3KeyIdBox.Text = string.Empty;
        S3SecretKeyBox.Password = string.Empty;
    }
}
