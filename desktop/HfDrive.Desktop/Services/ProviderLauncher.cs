using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace HfDrive.Desktop.Services;

/// <summary>
/// Starts the HF Drive provider when no provider is listening yet, so the
/// desktop never requires manual provider startup. The image policy mirrors
/// <see cref="Interop.PeerVerification"/> exactly: only the canonical
/// <c>provider\hfdrive-provider.exe</c> inside this application's installed
/// package, or — for debug builds running without package identity — the
/// canonical development build output under the compiled-in development root
/// (the same two paths that peer verification accepts). Every other candidate
/// is refused with a nonsecret reason. This helper never inspects credentials,
/// never inspects or stops other processes, and starts at most one process per
/// call.
/// </summary>
internal static class ProviderLauncher
{
    private const string ProviderImageName = "hfdrive-provider.exe";

    /// <summary>
    /// Starts the exact provider image allowed for this build, once.
    /// Returns true when a process was created; <paramref name="detail"/> is
    /// always a nonsecret description suitable for UI display.
    /// </summary>
    public static bool TryStartProvider(out string detail)
    {
        string? image = ResolveProviderImage(out detail);
        if (image is null)
        {
            return false;
        }

        try
        {
            using Process? process = Process.Start(new ProcessStartInfo
            {
                FileName = image,
                WorkingDirectory = Path.GetDirectoryName(image) ?? Environment.CurrentDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                detail = "Windows did not create the provider process.";
                return false;
            }

            detail = "Provider started.";
            return true;
        }
        catch (Exception ex)
        {
            detail = $"The provider could not be started: {ex.Message}";
            return false;
        }
    }

    /// <summary>Resolves the exact provider image this build is allowed to start.</summary>
    private static string? ResolveProviderImage(out string detail)
    {
        // Installed package: the canonical provider executable inside this
        // package's install directory.
        string? installPath = TryGetPackageInstallPath();
        if (installPath is not null)
        {
            string packaged = Path.GetFullPath(Path.Combine(installPath, "provider", ProviderImageName));
            if (File.Exists(packaged))
            {
                detail = string.Empty;
                return packaged;
            }

            detail = "The provider executable is missing from the installed HF Drive package.";
            return null;
        }

#if DEBUG
        // Development fallback (debug builds only): exactly the compiled-in
        // development root's build outputs — the same allowlist that peer
        // verification accepts. Release builds have no development bypass.
        string? root = DevelopmentRoot;
        if (root is null)
        {
            detail = "This build has no compiled development trust root; the provider image cannot be resolved.";
            return null;
        }

        string debugImage = Path.GetFullPath(Path.Combine(root, "target", "x86_64-pc-windows-msvc", "debug", ProviderImageName));
        if (File.Exists(debugImage))
        {
            detail = string.Empty;
            return debugImage;
        }

        detail = "No Debug provider exists at target\\x86_64-pc-windows-msvc\\debug\\hfdrive-provider.exe. Unpackaged development requires the Debug peer-identity policy.";
        return null;
#else
        detail = "HF Drive release builds only start the provider from the installed package.";
        return null;
#endif
    }

    private static string? TryGetPackageInstallPath()
    {
        try
        {
            // Throws InvalidOperationException when the process has no package identity.
            return Windows.ApplicationModel.Package.Current.InstalledLocation.Path;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Development root compiled into Debug builds (see the csproj assembly metadata).</summary>
    private static readonly string? DevelopmentRoot =
        CustomAttributeExtensions.GetCustomAttributes<AssemblyMetadataAttribute>(typeof(ProviderLauncher).Assembly)
        .FirstOrDefault(static attribute => attribute.Key == "HFDriveDevelopmentRoot")?.Value;
}
