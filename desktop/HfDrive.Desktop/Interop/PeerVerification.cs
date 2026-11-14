using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;

namespace HfDrive.Desktop.Interop;

/// <summary>Result of verifying the identity of the local HF Drive provider process.</summary>
public sealed record PeerVerificationResult(bool Succeeded, uint ProcessId, int SessionId, string Detail);

/// <summary>
/// Desktop-side peer verification for the provider named pipe, built entirely on
/// CsWin32-generated bindings (official Windows SDK metadata). Verified facts:
/// the named pipe server's process id, same Windows session, same user token
/// SID, a nonmissing logon SID (SE_GROUP_LOGON_ID) matching this user's logon
/// SID, integrity level at least medium, matching package family and package
/// install identity, and an allowed provider image path.
/// Verification runs after connect and before any protocol byte (including
/// Hello) is written, so no request is ever sent to an unauthenticated server.
/// Detail strings are nonsecret: they never contain token or credential values.
///
/// All CsWin32 calls use the generated raw extern shapes (HANDLE / pointer
/// parameters) so each call resolves deterministically regardless of friendly
/// overload generation. Every token-information buffer is owned by a SafeHandle
/// backed by unmanaged memory (NativeMemory): the absolute pointers Windows
/// stores inside token information remain valid for the buffer's entire
/// lifetime — no borrowed pointer into movable GC storage is ever used.
/// </summary>
public static unsafe class PeerVerification
{
    private const uint SecurityMandatoryMediumRid = 0x2000;
    private const uint MaxTokenInformationBytes = 4 * 1024 * 1024;
    private const uint MaxTokenGroups = 4096;
    private const uint MaxPackageChars = 1024;
    private const string ProviderImageName = "hfdrive-provider.exe";

    /// <summary>Verifies the provider process at the far end of a connected named pipe.</summary>
    public static PeerVerificationResult VerifyProvider(NamedPipeClientStream connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var pipeHandle = connection.SafePipeHandle;
        if (pipeHandle is null || pipeHandle.IsInvalid)
        {
            return new(false, 0, 0, "The named pipe handle is not valid.");
        }

        uint serverPid;
        if (!PInvoke.GetNamedPipeServerProcessId(new HANDLE(pipeHandle.DangerousGetHandle()), &serverPid))
        {
            return new(false, 0, 0, $"GetNamedPipeServerProcessId failed (Win32 error {Marshal.GetLastPInvokeError()}).");
        }

        GC.KeepAlive(pipeHandle);
        if (serverPid == 0)
        {
            return new(false, 0, 0, "The named pipe server did not report a process id.");
        }

        uint ourSessionId;
        if (!PInvoke.ProcessIdToSessionId(PInvoke.GetCurrentProcessId(), &ourSessionId))
        {
            return new(false, serverPid, 0, $"ProcessIdToSessionId failed for this process (Win32 error {Marshal.GetLastPInvokeError()}).");
        }

        uint peerSessionId;
        if (!PInvoke.ProcessIdToSessionId(serverPid, &peerSessionId))
        {
            return new(false, serverPid, 0, $"ProcessIdToSessionId failed for the provider process (Win32 error {Marshal.GetLastPInvokeError()}).");
        }

        if (peerSessionId != ourSessionId)
        {
            return new(false, serverPid, (int)peerSessionId, "The provider process runs in a different Windows session.");
        }

        Process peerProcess;
        try
        {
            peerProcess = Process.GetProcessById((int)serverPid);
        }
        catch (Exception ex)
        {
            return new(false, serverPid, (int)peerSessionId, $"The provider process could not be opened: {ex.Message}");
        }

        using (peerProcess)
        {
            if (peerProcess.Handle == IntPtr.Zero)
            {
                return new(false, serverPid, (int)peerSessionId, "The provider process handle is not available.");
            }

            HANDLE peerToken;
            if (!PInvoke.OpenProcessToken(new HANDLE(peerProcess.Handle), TOKEN_ACCESS_MASK.TOKEN_QUERY, &peerToken))
            {
                return new(false, serverPid, (int)peerSessionId, $"OpenProcessToken failed for the provider process (Win32 error {Marshal.GetLastPInvokeError()}).");
            }

            try
            {
                using WindowsIdentity ourIdentity = WindowsIdentity.GetCurrent();
                IntPtr ourTokenPtr = ourIdentity.AccessToken.DangerousGetHandle();
                if (ourTokenPtr == IntPtr.Zero)
                {
                    return new(false, serverPid, (int)peerSessionId, "The current user token is not available.");
                }

                HANDLE ourToken = new(ourTokenPtr);

                // ---- User SID (same user required) ----
                using TokenInformationBuffer? ourTokenUser =
                    ReadTokenInformation(ourToken, TOKEN_INFORMATION_CLASS.TokenUser, out string ourUserError);
                if (ourTokenUser is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Current user token: {ourUserError}");
                }

                using TokenInformationBuffer? peerTokenUser =
                    ReadTokenInformation(peerToken, TOKEN_INFORMATION_CLASS.TokenUser, out string peerUserError);
                if (peerTokenUser is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Provider token: {peerUserError}");
                }

                PSID ourUserSid = SidFromTokenUser(ourTokenUser);
                PSID peerUserSid = SidFromTokenUser(peerTokenUser);
                if (ourUserSid.Value is null || peerUserSid.Value is null)
                {
                    return new(false, serverPid, (int)peerSessionId, "A token user SID is not valid.");
                }

                if (!PInvoke.EqualSid(ourUserSid, peerUserSid))
                {
                    return new(false, serverPid, (int)peerSessionId, "The provider process token user SID does not match this user's token.");
                }

                // ---- Logon SID (nonmissing and matching) ----
                using TokenInformationBuffer? ourGroups =
                    ReadTokenInformation(ourToken, TOKEN_INFORMATION_CLASS.TokenGroups, out string ourGroupsError);
                if (ourGroups is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Current user token groups: {ourGroupsError}");
                }

                using TokenInformationBuffer? peerGroups =
                    ReadTokenInformation(peerToken, TOKEN_INFORMATION_CLASS.TokenGroups, out string peerGroupsError);
                if (peerGroups is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Provider token groups: {peerGroupsError}");
                }

                PSID ourLogonSid = FindLogonSid(ourGroups, out string ourLogonError);
                if (ourLogonSid.Value is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Current user token logon SID: {ourLogonError}");
                }

                PSID peerLogonSid = FindLogonSid(peerGroups, out string peerLogonError);
                if (peerLogonSid.Value is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Provider token logon SID: {peerLogonError}");
                }

                if (!PInvoke.EqualSid(ourLogonSid, peerLogonSid))
                {
                    return new(false, serverPid, (int)peerSessionId, "The provider process logon SID does not match this user's logon session.");
                }

                // ---- Integrity level (medium or above) ----
                using TokenInformationBuffer? integrity =
                    ReadTokenInformation(peerToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out string integrityError);
                if (integrity is null)
                {
                    return new(false, serverPid, (int)peerSessionId, $"Provider integrity: {integrityError}");
                }

                PSID integritySid = SidFromMandatoryLabel(integrity);
                if (integritySid.Value is null)
                {
                    return new(false, serverPid, (int)peerSessionId, "The provider token integrity SID is not valid.");
                }

                byte* subAuthorityCount = PInvoke.GetSidSubAuthorityCount(integritySid);
                if (subAuthorityCount is null || *subAuthorityCount == 0)
                {
                    return new(false, serverPid, (int)peerSessionId, "The provider token integrity SID is not valid.");
                }

                uint* ridPtr = PInvoke.GetSidSubAuthority(integritySid, (uint)(*subAuthorityCount - 1));
                if (ridPtr is null)
                {
                    return new(false, serverPid, (int)peerSessionId, "The provider token integrity level RID could not be read.");
                }

                if (*ridPtr < SecurityMandatoryMediumRid)
                {
                    return new(false, serverPid, (int)peerSessionId, $"The provider process integrity level 0x{*ridPtr:X} is below medium.");
                }

                // ---- Package identity / install identity and image policy ----
                string? image = TryGetProcessImage(peerProcess, out string imageError);
                if (image is null)
                {
                    return new(false, serverPid, (int)peerSessionId, imageError);
                }

                string? packageError = VerifyPackageIdentityAndImage(peerProcess, image, out bool unpackagedDebug);
                if (packageError is not null)
                {
                    return new(false, serverPid, (int)peerSessionId, packageError);
                }

                if (unpackagedDebug)
                {
                    if (!IsDevelopmentImageAllowed(image, out string devPolicyError))
                    {
                        return new(false, serverPid, (int)peerSessionId, devPolicyError);
                    }
                }

                return new(true, serverPid, (int)peerSessionId, "Provider process identity verified.");
            }
            finally
            {
                PInvoke.CloseHandle(peerToken);
            }
        }
    }

    // ------------------------------------------------------------------
    // Token information
    // ------------------------------------------------------------------

    /// <summary>
    /// Token-information owner: a SafeHandle over unmanaged memory. Windows
    /// writes absolute pointers into this storage (e.g. TOKEN_USER.User.Sid), so
    /// the allocation must not move and must outlive every pointer dereference —
    /// this type guarantees both for the whole lifetime of the returned buffer.
    /// </summary>
    private sealed class TokenInformationBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        private TokenInformationBuffer()
            : base(ownsHandle: true)
        {
        }

        public nuint Size { get; private set; }

        public void* Pointer => (void*)handle;

        public static TokenInformationBuffer Allocate(uint size)
        {
            var buffer = new TokenInformationBuffer();
            buffer.SetHandle((IntPtr)NativeMemory.AllocZeroed(size));
            buffer.Size = size;
            return buffer;
        }

        protected override bool ReleaseHandle()
        {
            NativeMemory.Free((void*)handle);
            return true;
        }
    }

    /// <summary>Reads a token information class into owned unmanaged memory.</summary>
    private static TokenInformationBuffer? ReadTokenInformation(
        HANDLE token, TOKEN_INFORMATION_CLASS infoClass, out string error)
    {
        uint needed;
        if (!PInvoke.GetTokenInformation(token, infoClass, (void*)null, 0, &needed))
        {
            // Expected first call: fails with ERROR_INSUFFICIENT_BUFFER and reports the size.
            if (needed == 0)
            {
                error = $"GetTokenInformation({infoClass}) did not report a buffer size.";
                return null;
            }
        }
        else
        {
            error = $"GetTokenInformation({infoClass}) unexpectedly succeeded with a zero-length buffer.";
            return null;
        }

        if (needed > MaxTokenInformationBytes)
        {
            error = $"GetTokenInformation({infoClass}) reported an unreasonable buffer size.";
            return null;
        }

        TokenInformationBuffer buffer = TokenInformationBuffer.Allocate(needed);
        if (!PInvoke.GetTokenInformation(token, infoClass, buffer.Pointer, needed, &needed))
        {
            buffer.Dispose();
            error = $"GetTokenInformation({infoClass}) failed (Win32 error {Marshal.GetLastPInvokeError()}).";
            return null;
        }

        error = string.Empty;
        return buffer;
    }

    private static PSID SidFromTokenUser(TokenInformationBuffer buffer)
        => ((TOKEN_USER*)buffer.Pointer)->User.Sid;

    private static PSID SidFromMandatoryLabel(TokenInformationBuffer buffer)
        => ((TOKEN_MANDATORY_LABEL*)buffer.Pointer)->Label.Sid;

    /// <summary>
    /// Finds the logon SID (SE_GROUP_LOGON_ID) in a pinned TokenGroups buffer.
    /// The entry array is addressed by offset arithmetic on the CsWin32-generated
    /// struct sizes — never by a pointer borrowed from movable storage.
    /// </summary>
    private static PSID FindLogonSid(TokenInformationBuffer buffer, out string error)
    {
        error = string.Empty;
        byte* raw = (byte*)buffer.Pointer;
        uint count = *(uint*)raw;
        if (count > MaxTokenGroups)
        {
            error = "The token group count is unreasonable.";
            return default;
        }

        // TOKEN_GROUPS is { u32 GroupCount; SID_AND_ATTRIBUTES Groups[1]; } with
        // natural alignment: the group array starts at the offset implied by the
        // generated struct sizes.
        int headerOffset = sizeof(TOKEN_GROUPS) - sizeof(SID_AND_ATTRIBUTES);
        nuint required = (nuint)headerOffset + ((nuint)count * (nuint)sizeof(SID_AND_ATTRIBUTES));
        if (buffer.Size < required)
        {
            error = "The token groups buffer is smaller than the reported group count.";
            return default;
        }

        uint logonMask = unchecked((uint)PInvoke.SE_GROUP_LOGON_ID);
        SID_AND_ATTRIBUTES* entries = (SID_AND_ATTRIBUTES*)(raw + headerOffset);
        for (uint i = 0; i < count; i++)
        {
            if ((entries[i].Attributes & logonMask) != logonMask)
            {
                continue;
            }

            PSID sid = entries[i].Sid;
            byte* sidCount = PInvoke.GetSidSubAuthorityCount(sid);
            if (sid.Value is null || sidCount is null || *sidCount == 0)
            {
                error = "The token logon SID is not valid.";
                return default;
            }

            return sid;
        }

        error = "The token has no logon SID (no group carries SE_GROUP_LOGON_ID).";
        return default;
    }

    // ------------------------------------------------------------------
    // Package identity / install identity / image policy
    // ------------------------------------------------------------------

    /// <summary>
    /// Verifies package family and package install identity against this
    /// application's own package. In release builds an unpackaged process is a
    /// hard failure (fail closed); in development builds without package
    /// identity the caller falls back to the explicit development image
    /// allowlist. Returns <paramref name="unpackagedDebug"/> = true only for
    /// that development fallback.
    /// </summary>
    private static string? VerifyPackageIdentityAndImage(Process peerProcess, string peerImage, out bool unpackagedDebug)
    {
        unpackagedDebug = false;

        string? ourFamily = QueryCurrentPackageFamilyName(out string ourFamilyError);
        if (ourFamily is null && ourFamilyError != NoPackageIdentity)
        {
            return $"Current package identity: {ourFamilyError}";
        }

        string? peerFamily = QueryProcessPackageFamilyName(peerProcess, out string peerFamilyError);
        if (peerFamily is null && peerFamilyError != NoPackageIdentity)
        {
            return $"Provider package identity: {peerFamilyError}";
        }

        if (ourFamily is null || peerFamily is null)
        {
#if DEBUG
            // Unpackaged development run: the explicit development image
            // allowlist applies instead of package identity.
            unpackagedDebug = true;
            return null;
#else
            return "HF Drive release builds refuse unpackaged processes: this application and the provider must run from the installed package.";
#endif
        }

        if (!string.Equals(ourFamily, peerFamily, StringComparison.OrdinalIgnoreCase))
        {
            return "The provider process package family does not match this application's package family.";
        }

        string? ourFullName = QueryCurrentPackageFullName(out string ourNameError);
        if (ourFullName is null)
        {
            return $"Current package install identity: {ourNameError}";
        }

        string? peerFullName = QueryProcessPackageFullName(peerProcess, out string peerNameError);
        if (peerFullName is null)
        {
            return $"Provider package install identity: {peerNameError}";
        }

        if (!string.Equals(ourFullName, peerFullName, StringComparison.OrdinalIgnoreCase))
        {
            return "The provider process belongs to a different package install of HF Drive.";
        }

        string? installPath = QueryPackagePath(ourFullName, out string pathError);
        if (installPath is null)
        {
            return $"Package install path: {pathError}";
        }

        string canonicalProvider = Path.GetFullPath(Path.Combine(installPath, "provider", ProviderImageName));
        string fullImage = Path.GetFullPath(peerImage);
        if (!string.Equals(
                fullImage.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                canonicalProvider.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                StringComparison.OrdinalIgnoreCase))
        {
            return "The provider process image is not the canonical provider executable inside this application's installed package.";
        }

        return null;
    }

    private const string NoPackageIdentity = "no-package-identity";

    private static string? QueryCurrentPackageFamilyName(out string error)
    {
        uint length = 0;
        WIN32_ERROR first = PInvoke.GetCurrentPackageFamilyName(&length, default(PWSTR));
        return FinishPackageStringQuery(first, length, (uint* len, PWSTR buf) => PInvoke.GetCurrentPackageFamilyName(len, buf), out error);
    }

    private static string? QueryProcessPackageFamilyName(Process peerProcess, out string error)
    {
        uint length = 0;
        HANDLE process = new(peerProcess.Handle);
        WIN32_ERROR first = PInvoke.GetPackageFamilyName(process, &length, default(PWSTR));
        return FinishPackageStringQuery(first, length, (uint* len, PWSTR buf) => PInvoke.GetPackageFamilyName(process, len, buf), out error);
    }

    private static string? QueryCurrentPackageFullName(out string error)
    {
        uint length = 0;
        WIN32_ERROR first = PInvoke.GetCurrentPackageFullName(&length, default(PWSTR));
        return FinishPackageStringQuery(first, length, (uint* len, PWSTR buf) => PInvoke.GetCurrentPackageFullName(len, buf), out error);
    }

    private static string? QueryProcessPackageFullName(Process peerProcess, out string error)
    {
        uint length = 0;
        HANDLE process = new(peerProcess.Handle);
        WIN32_ERROR first = PInvoke.GetPackageFullName(process, &length, default(PWSTR));
        return FinishPackageStringQuery(first, length, (uint* len, PWSTR buf) => PInvoke.GetPackageFullName(process, len, buf), out error);
    }

    private static string? QueryPackagePath(string packageFullName, out string error)
    {
        uint length = 0;
        fixed (char* namePtr = packageFullName)
        {
            PCWSTR name = ToPcstr(namePtr);
            WIN32_ERROR first = PInvoke.GetPackagePathByFullName(name, &length, default(PWSTR));
            return FinishPackageStringQuery(first, length, (uint* len, PWSTR buf) => PInvoke.GetPackagePathByFullName(name, len, buf), out error);
        }
    }

    /// <summary>Package-query delegate for the buffer-sized second call.</summary>
    private delegate WIN32_ERROR PackageQueryString(uint* length, PWSTR buffer);

    private static string? FinishPackageStringQuery(
        WIN32_ERROR first, uint reportedLength, PackageQueryString query, out string error)
    {
        if (first == WIN32_ERROR.APPMODEL_ERROR_NO_PACKAGE)
        {
            error = NoPackageIdentity;
            return null;
        }

        if (first != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER || reportedLength == 0)
        {
            error = $"package query failed (error {(uint)first}).";
            return null;
        }

        if (reportedLength > MaxPackageChars)
        {
            error = "package query reported an unreasonable string length.";
            return null;
        }

        char[] buffer = new char[reportedLength];
        fixed (char* bufferPtr = buffer)
        {
            uint capacity = reportedLength;
            WIN32_ERROR second = query(&capacity, ToPwstr(bufferPtr));
            if (second != WIN32_ERROR.ERROR_SUCCESS)
            {
                error = $"package query failed (error {(uint)second}).";
                return null;
            }
        }

        int terminator = Array.IndexOf(buffer, '\0');
        error = string.Empty;
        return new string(buffer, 0, terminator >= 0 ? terminator : buffer.Length);
    }

    // Reinterpret a char* as the CsWin32 single-pointer string struct without
    // depending on which constructor shapes the generator emitted. Both types
    // are exactly one pointer wide, and &value lives on the stack for the copy.
    private static PWSTR ToPwstr(char* value) => *(PWSTR*)&value;

    private static PCWSTR ToPcstr(char* value) => *(PCWSTR*)&value;

    // ------------------------------------------------------------------
    // Image policy
    // ------------------------------------------------------------------

    private static string? TryGetProcessImage(Process process, out string error)
    {
        try
        {
            string? path = process.MainModule?.FileName;
            if (string.IsNullOrEmpty(path))
            {
                error = "The provider process image path could not be read.";
                return null;
            }

            error = string.Empty;
            return path;
        }
        catch (Exception ex)
        {
            error = $"The provider process image could not be inspected: {ex.Message}";
            return null;
        }
    }

    /// <summary>
    /// Development-only image allowlist: exactly the canonical local build
    /// output paths of the provider from this repository. There is no
    /// release-path bypass; release builds use the installed-package check only.
    /// </summary>
    private static bool IsDevelopmentImageAllowed(string imagePath, out string error)
    {
        string fullPath = Path.GetFullPath(imagePath);
        if (!string.Equals(Path.GetFileName(fullPath), ProviderImageName, StringComparison.OrdinalIgnoreCase))
        {
            error = "The connected process image is not hfdrive-provider.exe.";
            return false;
        }

        string? repoRoot = DevelopmentRoot;
        if (repoRoot is null)
        {
            error = "This build has no compiled development trust root; refusing the provider image.";
            return false;
        }

        string debugImage = Path.GetFullPath(Path.Combine(repoRoot, "target", "x86_64-pc-windows-msvc", "debug", ProviderImageName));
        string releaseImage = Path.GetFullPath(Path.Combine(repoRoot, "target", "x86_64-pc-windows-msvc", "release", ProviderImageName));
        if (PathsEqual(fullPath, debugImage) || PathsEqual(fullPath, releaseImage))
        {
            error = string.Empty;
            return true;
        }

        error = "The provider image is not the canonical development build output (target\\x86_64-pc-windows-msvc\\{debug,release}\\hfdrive-provider.exe).";
        return false;
    }

    private static readonly string? DevelopmentRoot =
        System.Reflection.CustomAttributeExtensions.GetCustomAttributes<System.Reflection.AssemblyMetadataAttribute>(
            typeof(PeerVerification).Assembly)
        .FirstOrDefault(static attribute => attribute.Key == "HFDriveDevelopmentRoot")?.Value;

    private static bool PathsEqual(string left, string right)
        => string.Equals(
            Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);
}
