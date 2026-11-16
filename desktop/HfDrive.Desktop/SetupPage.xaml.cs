using System.ComponentModel;
using HfDrive.Desktop.ViewModels;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using Windows.UI.ViewManagement;

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
    private string? _suggestedBucketName;
    private readonly UISettings _animationSettings = new();
    private AppWindow? _appWindow;
    private bool _celebrationPlaying;

    public SetupPage()
    {
        InitializeComponent();
        Loaded += OnPageLoaded;
        Unloaded += OnPageUnloaded;
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
        SetupCelebrationSource.Stop();
        _celebrationPlaying = false;
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
            case nameof(SetupViewModel.CreationErrorText):
                if (ViewModel.HasCreationError)
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (ViewModel.HasCreationError)
                            CreationErrorInfoBar.StartBringIntoView();
                    });
                break;
        }
        UpdateCompletionAnimation();
    }

    private void OnPageLoaded(object sender, RoutedEventArgs args)
    {
        _appWindow = ((App)Application.Current).DesktopWindow?.AppWindow;
        if (_appWindow is not null) _appWindow.Changed += OnAppWindowChanged;
        _animationSettings.AnimationsEnabledChanged += OnAnimationsEnabledChanged;
        UpdateCompletionAnimation();
    }

    private void OnPageUnloaded(object sender, RoutedEventArgs args)
    {
        if (_appWindow is not null) _appWindow.Changed -= OnAppWindowChanged;
        _appWindow = null;
        _animationSettings.AnimationsEnabledChanged -= OnAnimationsEnabledChanged;
        SetupCelebrationSource.Stop();
        _celebrationPlaying = false;
    }

    private void OnAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (args.DidVisibilityChange) UpdateCompletionAnimation();
    }

    private void OnAnimationsEnabledChanged(UISettings sender, object args) =>
        DispatcherQueue.TryEnqueue(UpdateCompletionAnimation);

    private void OnSetupCelebrationOpened(object sender, RoutedEventArgs args)
    {
        _celebrationPlaying = false;
        UpdateCompletionAnimation();
    }

    private void UpdateCompletionAnimation()
    {
        bool ready = ViewModel?.IsSetupWorking == true;
        SetupCelebration.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
        bool play = ready && IsLoaded && _appWindow?.IsVisible == true && _animationSettings.AnimationsEnabled;
        if (play == _celebrationPlaying) return;
        _celebrationPlaying = play;
        if (play) SetupCelebrationSource.Play();
        else SetupCelebrationSource.Stop();
    }

    /// <summary>
    /// Suggests an unused %USERPROFILE%\HF Drive\&lt;bucket&gt; folder.
    /// Keeps entered paths and the same bucket's previous suggestion, including
    /// after setup creates that folder; only a changed bucket gets a new default.
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
        if (current == _suggestedRootPath && bucketName == _suggestedBucketName)
            return;

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string safeName = MakePathSafe(bucketName);
        string suggestion = SuggestAvailableRootPath(Path.Combine(userProfile, "HF Drive", safeName));
        _suggestedRootPath = suggestion;
        _suggestedBucketName = bucketName;
        ViewModel.RootPathText = suggestion;
    }

    private static string SuggestAvailableRootPath(string basePath)
    {
        string suggestion = basePath;
        for (int suffix = 2; Path.Exists(suggestion); suffix++)
            suggestion = $"{basePath} ({suffix})";
        return suggestion;
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
