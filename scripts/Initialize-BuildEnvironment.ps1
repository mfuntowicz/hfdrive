<#
.SYNOPSIS
    Initializes the exact HF Drive build toolchain (VS Build Tools 2026 18.12,
    MSVC v145 14.52.37025, Windows SDK 10.0.28000.0, .NET SDK 11.0.100) and
    returns its verified absolute paths.

.DESCRIPTION
    Discover the Build Tools instance with vswhere restricted to
    Microsoft.VisualStudio.Product.BuildTools in the [18.12,18.13) feature line
    with MSBuild and the x64 MSVC tools required. Enter that instance's developer
    shell (Enter-VsDevShell) with the pinned toolset and SDK versions in this
    process only — machine/user PATH is never mutated, and no component is ever
    installed automatically.

    The selected compiler, linker, MSBuild and Windows SDK tools are verified to
    exist and to come from the pinned versions. A mismatch is a hard failure:
    there is no silent fallback to VS2022, another Build Tools instance, ambient
    PATH-selected MSBuild, or an older Windows SDK. If a developer shell from a
    different instance is already loaded in this process, the script fails with
    an instruction to start a fresh PowerShell process instead of mixing
    toolchains.

.EXAMPLE
    . ./scripts/Initialize-BuildEnvironment.ps1
    $env = Initialize-HfDriveBuildEnvironment
    & $env.MSBuild desktop/HfDrive.sln /restore /t:Build /p:Configuration=Debug /p:Platform=x64
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Pinned toolchain (approved plan). Changing any of these requires an explicit
# approved plan change.
$script:HfDriveToolchainPins = @{
    VsMajorMinorRange   = '[18.12,18.13)'
    VcToolsVersion      = '14.52.37025'
    WindowsSdkVersion   = '10.0.28000.0'
    WindowsSdkServicing = '10.0.28000.2957'
    DotNetSdkVersion    = '11.0.100'
}

function Write-HfDriveInfo([string]$Message) {
    Write-Host "  $Message"
}

function Test-HfDrivePathEqual([string]$Left, [string]$Right) {
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    $l = [System.IO.Path]::GetFullPath($Left).TrimEnd('\', '/')
    $r = [System.IO.Path]::GetFullPath($Right).TrimEnd('\', '/')
    return [string]::Equals($l, $r, [StringComparison]::OrdinalIgnoreCase)
}

function Find-HfDriveBuildToolsInstance {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "vswhere.exe was not found at '$vswhere'; Visual Studio Installer tooling is required to locate Build Tools 2026."
    }

    $queryArgs = @(
        '-latest',
        '-products', 'Microsoft.VisualStudio.Product.BuildTools',
        '-version', $script:HfDriveToolchainPins.VsMajorMinorRange,
        '-requires',
        'Microsoft.Component.MSBuild',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '-format', 'json'
    )
    $raw = & $vswhere @queryArgs
    if ($LASTEXITCODE -ne 0) {
        throw "vswhere failed with exit code $LASTEXITCODE while searching for Build Tools $($script:HfDriveToolchainPins.VsMajorMinorRange)."
    }

    $jsonText = @($raw) -join [Environment]::NewLine
    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        throw ("No complete Visual Studio Build Tools instance in the $($script:HfDriveToolchainPins.VsMajorMinorRange) feature line " +
            'with MSBuild and the x64 MSVC tools was found. Install Visual Studio Build Tools 2026 (18.12 feature line) with the ' +
            'MSVC v145 14.52.37025 toolset and Windows SDK 10.0.28000.0. The build never falls back to Community/VS2022 or other instances.')
    }

    $instances = @($jsonText | ConvertFrom-Json | Where-Object { $_ -ne $null })
    if ($instances.Count -eq 0 -or [string]::IsNullOrWhiteSpace($instances[0].installationPath)) {
        throw ("No complete Visual Studio Build Tools instance in the $($script:HfDriveToolchainPins.VsMajorMinorRange) feature line " +
            'with MSBuild and the x64 MSVC tools was found. Install Visual Studio Build Tools 2026 (18.12 feature line) with the ' +
            'MSVC v145 14.52.37025 toolset and Windows SDK 10.0.28000.0. The build never falls back to Community/VS2022 or other instances.')
    }

    $instance = $instances[0]
    $msbuild = Join-Path $instance.installationPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'
    if (-not (Test-Path -LiteralPath $msbuild)) {
        throw "The selected Build Tools instance '$($instance.installationPath)' does not contain x64 MSBuild at '$msbuild'."
    }
    return [pscustomobject]@{
        InstanceId        = $instance.instanceId
        InstallationPath  = $instance.installationPath
        DisplayName       = $instance.displayName
        InstallationVersion = $instance.installationVersion
        MsBuildExe        = $msbuild
    }
}

function Assert-HfDriveForeignDevShell([object]$Instance) {
    # If this process already runs inside a developer shell from a different
    # Visual Studio instance, mixing toolchains produces unreliable builds;
    # refuse to proceed instead of layering shells.
    $currentVsInstallDir = $env:VSINSTALLDIR
    if ([string]::IsNullOrWhiteSpace($currentVsInstallDir)) {
        return
    }
    if (Test-HfDrivePathEqual $currentVsInstallDir $Instance.InstallationPath) {
        return
    }
    throw ("This PowerShell process already has a developer shell from '$currentVsInstallDir', which is not the selected Build Tools " +
        "instance '$($Instance.InstallationPath)'. Start a fresh PowerShell process and re-run; do not mix toolchains in one process.")
}

function Enter-HfDriveDevShell([object]$Instance) {
    $devShellModule = Join-Path $Instance.InstallationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (-not (Test-Path -LiteralPath $devShellModule)) {
        throw "Enter-VsDevShell module was not found at '$devShellModule'."
    }
    Import-Module $devShellModule

    $devCmdArgs = "-no_logo -vcvars_ver=$($script:HfDriveToolchainPins.VcToolsVersion) -winsdk=$($script:HfDriveToolchainPins.WindowsSdkVersion)"
    Enter-VsDevShell -VsInstanceId $Instance.InstanceId -Arch amd64 -HostArch amd64 `
        -SkipAutomaticLocation -DevCmdArguments $devCmdArgs
}

function Resolve-HfDriveVerifiedTools([object]$Instance) {
    $pins = $script:HfDriveToolchainPins
    $install = $Instance.InstallationPath

    $cl = Join-Path $install "VC\Tools\MSVC\$($pins.VcToolsVersion)\bin\Hostx64\x64\cl.exe"
    $link = Join-Path $install "VC\Tools\MSVC\$($pins.VcToolsVersion)\bin\Hostx64\x64\link.exe"
    foreach ($tool in @($cl, $link)) {
        if (-not (Test-Path -LiteralPath $tool)) {
            throw "Pinned MSVC toolset $($pins.VcToolsVersion) is missing '$tool'. Install MSVC v145 $($pins.VcToolsVersion) (x64 tools)."
        }
    }

    $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10'
    $sdkVersion = $pins.WindowsSdkVersion
    $sdkInclude = Join-Path $kitsRoot "Include\$sdkVersion"
    $sdkLib = Join-Path $kitsRoot "Lib\$sdkVersion"
    $makeAppx = Join-Path $kitsRoot "bin\$sdkVersion\x64\makeappx.exe"
    $makePri = Join-Path $kitsRoot "bin\$sdkVersion\x64\makepri.exe"
    $signTool = Join-Path $kitsRoot "bin\$sdkVersion\x64\signtool.exe"

    foreach ($required in @($sdkInclude, $sdkLib, $makeAppx, $makePri, $signTool)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Windows SDK $sdkVersion (x64) is incomplete: '$required' is missing. Install the Windows 11 SDK $sdkVersion; there is no fallback to another SDK version."
        }
    }

    # CFAPI is a hard dependency of the provider; verify its header/import
    # library come from the pinned native SDK.
    $cfApiHeader = Join-Path $sdkInclude 'um\cfapi.h'
    $cldApiLib = Join-Path $sdkLib 'um\x64\CldApi.lib'
    foreach ($required in @($cfApiHeader, $cldApiLib)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "CFAPI support is missing from the pinned Windows SDK $sdkVersion at '$required'."
        }
    }

    # The SDK servicing release is read from the deployed tool binaries so the
    # provenance record reflects what is actually installed.
    $servicing = (Get-Item -LiteralPath $makeAppx).VersionInfo.ProductVersion
    if ($servicing -ne $pins.WindowsSdkServicing) {
        Write-HfDriveInfo "NOTE: installed Windows SDK $sdkVersion servicing release is '$servicing' (plan records '$($pins.WindowsSdkServicing)')."
    }

    # Verify the SDK tools selected on PATH by the developer shell are the
    # pinned ones — never an ambient earlier SDK.
    foreach ($toolName in @('makeappx.exe', 'makepri.exe', 'signtool.exe')) {
        $resolved = (Get-Command $toolName -ErrorAction SilentlyContinue).Source
        if ($resolved) {
            $expected = switch ($toolName) {
                'makeappx.exe' { $makeAppx }
                'makepri.exe' { $makePri }
                'signtool.exe' { $signTool }
            }
            if (-not (Test-HfDrivePathEqual $resolved $expected)) {
                throw "PATH-selected '$toolName' resolves to '$resolved', which is not the pinned Windows SDK $sdkVersion tool '$expected'. Start a fresh PowerShell process and re-run."
            }
        }
    }

    return [pscustomobject]@{
        ClExe              = $cl
        LinkExe            = $link
        MakeAppx           = $makeAppx
        MakePri            = $makePri
        SignTool           = $signTool
        WindowsSdkRoot     = $kitsRoot
        WindowsSdkVersion  = $sdkVersion
        WindowsSdkServicing = $servicing
    }
}

function Assert-HfDriveDotNetSdk {
    $globalJsonDir = $PSScriptRoot | Split-Path -Parent
    $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    if (-not $dotnet) {
        throw 'dotnet is not available on PATH; install .NET SDK 11.0.100.'
    }
    Push-Location $globalJsonDir
    try {
        $resolved = (& $dotnet --version).Trim()
    }
    finally {
        Pop-Location
    }
    if ($resolved -ne $script:HfDriveToolchainPins.DotNetSdkVersion) {
        throw ("'dotnet --version' resolved to '$resolved' from the repository root, but the pinned SDK is " +
            "$($script:HfDriveToolchainPins.DotNetSdkVersion) (global.json pins it with roll-forward disabled).")
    }
    return $dotnet
}

function Get-HfDriveDesktopExecutable {
    param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug')
    $repoRoot = $PSScriptRoot | Split-Path -Parent
    $project = Join-Path $repoRoot 'desktop\HfDrive.Desktop\HfDrive.Desktop.csproj'
    [xml]$xml = Get-Content -LiteralPath $project
    $target = $xml.SelectSingleNode('/Project/PropertyGroup/TargetFramework')
    $runtime = $xml.SelectSingleNode('/Project/PropertyGroup/RuntimeIdentifier')
    if (-not $target -or -not $runtime) {
        throw "Desktop TargetFramework/RuntimeIdentifier are missing; refusing to guess a trusted executable path."
    }
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot (
        "desktop\HfDrive.Desktop\bin\x64\$Configuration\$($target.InnerText)\$($runtime.InnerText)\HfDrive.Desktop.exe")))
}

function Initialize-HfDriveBuildEnvironment {
    [CmdletBinding()]
    param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug')

    Write-Host 'Initializing HF Drive build environment (pinned toolchain; no fallbacks)…'

    $instance = Find-HfDriveBuildToolsInstance
    Write-HfDriveInfo "Build Tools: $($instance.DisplayName) [$($instance.InstanceId)] $($instance.InstallationVersion)"
    Write-HfDriveInfo "Path: $($instance.InstallationPath)"

    Assert-HfDriveForeignDevShell $instance
    Enter-HfDriveDevShell $instance

    $tools = Resolve-HfDriveVerifiedTools $instance

    # Verify the developer shell actually selected the pinned toolset/SDK.
    if ($env:VCToolsVersion -and $env:VCToolsVersion.TrimEnd('\') -ne $script:HfDriveToolchainPins.VcToolsVersion) {
        throw "The developer shell selected MSVC '$env:VCToolsVersion', but the pinned toolset is $($script:HfDriveToolchainPins.VcToolsVersion)."
    }
    if ($env:WindowsSdkVersion -and $env:WindowsSdkVersion.TrimEnd('\') -ne $script:HfDriveToolchainPins.WindowsSdkVersion) {
        throw "The developer shell selected Windows SDK '$env:WindowsSdkVersion', but the pinned SDK is $($script:HfDriveToolchainPins.WindowsSdkVersion)."
    }

    # Process-local only: native Rust dependencies link with the pinned linker
    # from the selected instance. Nothing is written to machine/user PATH.
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $tools.LinkExe
    $pathCompiler = (Get-Command cl.exe -CommandType Application -ErrorAction Stop).Source
    if (-not (Test-HfDrivePathEqual $pathCompiler $tools.ClExe)) {
        throw "The developer shell did not select the pinned cl.exe; refusing mixed native compilers."
    }
    # BLAKE3 recognizes only the basename in CC when selecting MASM sources.
    # cc-rs still receives the absolute compiler through the target-specific variables.
    $env:CC = 'cl.exe'
    $env:CXX = 'cl.exe'
    $env:CC_x86_64_pc_windows_msvc = $tools.ClExe
    $env:CXX_x86_64_pc_windows_msvc = $tools.ClExe
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
    $env:AWS_LC_SYS_PREBUILT_NASM = '1'
    $env:RUSTUP_AUTO_INSTALL = '0'
    $env:HFDRIVE_DEV_DESKTOP_PATH = Get-HfDriveDesktopExecutable -Configuration $Configuration

    $dotnet = Assert-HfDriveDotNetSdk

    $result = [pscustomobject]@{
        VsInstanceId         = $instance.InstanceId
        VsInstallationPath   = $instance.InstallationPath
        VsDisplayVersion     = $instance.InstallationVersion
        MSBuild              = $instance.MsBuildExe
        ClExe                = $tools.ClExe
        LinkExe              = $tools.LinkExe
        MakeAppx             = $tools.MakeAppx
        MakePri              = $tools.MakePri
        SignTool             = $tools.SignTool
        VcToolsVersion       = $script:HfDriveToolchainPins.VcToolsVersion
        WindowsSdkVersion    = $tools.WindowsSdkVersion
        WindowsSdkServicing  = $tools.WindowsSdkServicing
        DotNetSdkVersion     = $script:HfDriveToolchainPins.DotNetSdkVersion
        DotNetExe            = $dotnet
        CargoLinker          = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER
        DesktopExecutable    = $env:HFDRIVE_DEV_DESKTOP_PATH
    }

    Write-HfDriveInfo "MSBuild:     $($result.MSBuild)"
    Write-HfDriveInfo "cl / link:   $($result.ClExe)"
    Write-HfDriveInfo "Windows SDK: $($result.WindowsSdkVersion) (servicing $($result.WindowsSdkServicing))"
    Write-HfDriveInfo ".NET SDK:    $($result.DotNetSdkVersion)"
    return $result
}

function Get-HfDriveToolchainPins {
    # Read-only view of the pins for provenance reporting.
    return [pscustomobject]@{
        VsMajorMinorRange   = $script:HfDriveToolchainPins.VsMajorMinorRange
        VcToolsVersion      = $script:HfDriveToolchainPins.VcToolsVersion
        WindowsSdkVersion   = $script:HfDriveToolchainPins.WindowsSdkVersion
        WindowsSdkServicing = $script:HfDriveToolchainPins.WindowsSdkServicing
        DotNetSdkVersion    = $script:HfDriveToolchainPins.DotNetSdkVersion
    }
}
