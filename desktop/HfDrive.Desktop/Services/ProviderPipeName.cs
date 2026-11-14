using System.Security.Principal;

namespace HfDrive.Desktop.Services;

/// <summary>
/// Builds the provider named pipe name. The provider listens on
/// \\.\pipe\LOCAL\HFDrive.&lt;user-SID&gt;.v1 (approved wire plan); the pipe is
/// local-only and rejects remote clients. The name is derived from the current
/// Windows user's token SID, never from a machine-wide or guessed string.
/// </summary>
public static class ProviderPipeName
{
    /// <summary>Named pipe name without the \\.\pipe\ prefix (NamedPipeClientStream form).</summary>
    public static string Value { get; } = Build();

    /// <summary>Full display form including the \\.\pipe\ prefix (diagnostics only).</summary>
    public static string DisplayPath => $@"\\.\pipe\{Value}";

    private static string Build()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier? sid = identity.User;
        return sid is null
            ? throw new InvalidOperationException("The current Windows token has no user SID; the provider pipe name cannot be derived.")
            : $"LOCAL\\HFDrive.{sid.Value}.v1";
    }
}
