<#
.SYNOPSIS
    Builds the HF Drive workspace (Rust + managed desktop solution) with the
    pinned toolchain and records build provenance.

.DESCRIPTION
    Uses Initialize-HfDriveBuildEnvironment to select the exact Build Tools 2026
    (18.12) MSVC v145 14.52.37025 / Windows SDK 10.0.28000.0 environment and the
    pinned .NET SDK 11.0.100. Rust builds run with --locked against the checked-in
    Cargo.lock; managed restore runs in locked mode against checked-in
    packages.lock.json files. Only -InitializeLocks creates/updates lockfiles,
    and only during that explicit initial run.

    Example first build (creates lockfiles):
      pwsh -NoProfile -File scripts/build.ps1 -Configuration Debug -InitializeLocks

    Subsequent builds (locked):
      pwsh -NoProfile -File scripts/build.ps1 -Configuration Debug -Locked

    A build provenance record (tool paths, versions, lockfile identities) is
    written to artifacts/build/.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    # Create/update lockfiles (Cargo.lock, packages.lock.json). Explicit only.
    [switch]$InitializeLocks,

    # Build in locked-restore mode (default). Cannot be combined with -InitializeLocks.
    [switch]$Locked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($InitializeLocks -and $Locked) {
    throw '-InitializeLocks and -Locked are mutually exclusive: lockfiles are created only by an explicit -InitializeLocks run.'
}

$repoRoot = $PSScriptRoot | Split-Path -Parent
Push-Location $repoRoot
try {
    . (Join-Path $PSScriptRoot 'Initialize-BuildEnvironment.ps1')
    $buildEnv = Initialize-HfDriveBuildEnvironment -Configuration $Configuration
    $pins = Get-HfDriveToolchainPins

    $lockedRestore = -not $InitializeLocks
    if ($Locked -and -not (Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.lock'))) {
        throw 'Cargo.lock is missing. Run once with -InitializeLocks to create lockfiles before using -Locked.'
    }

    # ---- Rust workspace (native toolchain: MSVC v145 / Windows SDK 28000) ----

    $cargoArgs = @('build', '--workspace', '--target', 'x86_64-pc-windows-msvc')
    if ($Configuration -eq 'Release') {
        $cargoArgs += '--release'
    }
    if (-not $InitializeLocks) {
        $cargoArgs += '--locked'
    }
    Write-Host "cargo $($cargoArgs -join ' ')"
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE."
    }

    # ---- Managed desktop solution (Build Tools 2026 x64 MSBuild) ----
    $restoreProps = @(
        "/p:Configuration=$Configuration",
        '/p:Platform=x64',
        '/p:WindowsTargetPlatformVersion=10.0.28000.0'
    )
    if ($lockedRestore) {
        $restoreProps += '/p:RestoreLockedMode=true'
    }

    Write-Host "MSBuild desktop/HfDrive.sln /restore /t:Build /m $($restoreProps -join ' ')"
    & $buildEnv.MSBuild desktop/HfDrive.sln /restore /t:Build /m @restoreProps
    if ($LASTEXITCODE -ne 0) {
        throw "MSBuild failed with exit code $LASTEXITCODE."
    }

    # ---- Rust Explorer COM contract tests -----------------------------------
    # The hfdrive-shell cdylib is built by the Cargo workspace above. These tests
    # exercise the strict shared request/target/path contracts only; they never
    # register COM, load the DLL into Explorer, or contact Hugging Face.
    Write-Host 'Running cargo test -p hfdrive-shell --locked --target x86_64-pc-windows-msvc'
    & cargo test -p hfdrive-shell --locked --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) {
        throw "Rust shell contract tests failed with exit code $LASTEXITCODE."
    }

    # ---- Build provenance ----
    $provenanceDir = Join-Path $repoRoot 'artifacts\build'
    New-Item -ItemType Directory -Force -Path $provenanceDir | Out-Null

    function Get-FileIdentity([string]$Path) {
        if (Test-Path -LiteralPath $Path) {
            return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
        }
        return $null
    }

    $provenance = [ordered]@{
        timestamp_utc        = (Get-Date).ToUniversalTime().ToString('o')
        configuration        = $Configuration
        lock_mode            = if ($InitializeLocks) { 'initialized' } else { 'locked' }
        toolchain_pins       = $pins
        tools                = [ordered]@{
            msbuild           = $buildEnv.MSBuild
            cl                = $buildEnv.ClExe
            link              = $buildEnv.LinkExe
            makeappx          = $buildEnv.MakeAppx
            makepri           = $buildEnv.MakePri
            signtool          = $buildEnv.SignTool
            dotnet            = $buildEnv.DotNetExe
            cargo_linker_env  = $buildEnv.CargoLinker
        }
        versions             = [ordered]@{
            vs_instance_id      = $buildEnv.VsInstanceId
            vs_installation     = $buildEnv.VsInstallationPath
            vs_install_version  = $buildEnv.VsDisplayVersion
            msbuild_version     = (& $buildEnv.MSBuild -version | Select-Object -Last 1).Trim()
            cargo_version       = (& cargo --version).Trim()
            rustc_version       = (& rustc --version).Trim()
            dotnet_sdk          = $buildEnv.DotNetSdkVersion
            windows_sdk         = $buildEnv.WindowsSdkVersion
            windows_sdk_servicing = $buildEnv.WindowsSdkServicing
            vc_tools            = $buildEnv.VcToolsVersion
        }
        lockfiles            = [ordered]@{
            cargo_lock_sha256 = Get-FileIdentity (Join-Path $repoRoot 'Cargo.lock')
            desktop_packages_lock_sha256 = Get-FileIdentity (Join-Path $repoRoot 'desktop\HfDrive.Desktop\packages.lock.json')
            protocol_packages_lock_sha256 = Get-FileIdentity (Join-Path $repoRoot 'desktop\HfDrive.Protocol\packages.lock.json')
            protocol_tests_packages_lock_sha256 = Get-FileIdentity (Join-Path $repoRoot 'desktop\HfDrive.Protocol.Tests\packages.lock.json')
        }
    }

    $provenancePath = Join-Path $provenanceDir "build-provenance-$Configuration.json"
    $provenance | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $provenancePath -Encoding utf8
    Write-Host "Provenance written to $provenancePath"
}
finally {
    Pop-Location
}
