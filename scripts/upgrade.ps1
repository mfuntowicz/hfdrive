<#
.SYNOPSIS
    Coordinated HF Drive package upgrade: provider PrepareUpgrade acknowledgment
    first, then a monotonically higher package version, then provider reactivation.

.DESCRIPTION
    Implements the approved coordinated-update flow:

      1. Validate the new .msix: identity Name/publisher match the installed
         package exactly, the version is strictly higher, and the Authenticode
         signature is valid for that publisher.
      2. Require the RUNNING provider's actual PrepareUpgrade acknowledgment via
         the packaged CLI:
            cli\hfdrive.exe provider prepare-upgrade --json
         which must print one JSON object {"checkpointed": true|false,
         "pending_operations": <uint>} and exit 0. The provider stops scheduling,
         persists uncertainty/intent, checkpoints and exits as part of this
         acknowledgment. If the provider does not acknowledge, the upgrade is
         ABORTED — this script never kills the provider and never claims a
         graceful shutdown it did not observe. (When no provider process exists
         at all, there is nothing to stop and the handshake is honestly recorded
         as skipped.)
      3. Wait (bounded) for the provider process to exit.
      4. Add-AppxPackage with the new version (no -ForceUpdateFromAnyVersion, no
         downgrade).
      5. Reactivate the provider by its packaged application ID
         (<package-family>!Provider) and verify it starts.

    Forced/interrupted upgrade recovery is covered by
    scripts/verify-lifecycle.ps1 and docs/lifecycle.md; an unexpected OS
    termination is handled by the provider's recovery engine, never assumed away.

.EXAMPLE
    pwsh -NoProfile -File scripts/upgrade.ps1 -Package artifacts/package/HFDrive_0.2.0.0_x64.msix
#>
[CmdletBinding()]
param(
    # New, strictly newer, trusted .msix package.
    [Parameter(Mandatory)]
    [string]$Package,

    # Bounded wait for the provider to exit after its PrepareUpgrade acknowledgment.
    [ValidateRange(5, 600)]
    [int]$ProviderExitTimeoutSeconds = 60,

    # Install without reactivating the provider afterwards.
    [switch]$SkipReactivate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

if (-not (Test-Path -LiteralPath $Package)) {
    throw "Package '$Package' does not exist."
}
$Package = Convert-Path -LiteralPath $Package
if ([System.IO.Path]::GetExtension($Package) -ne '.msix') {
    throw "Package '$Package' is not an .msix file."
}

# ---- New package validation ----------------------------------------------
$newIdentity = Get-HfDriveMsixIdentity -PackagePath $Package
if ($newIdentity.Name -ne (Get-HfDrivePackageName)) {
    throw "Package identity Name '$($newIdentity.Name)' is not '$(Get-HfDrivePackageName)'."
}
$newVersion = ConvertTo-HfDriveVersion -Text $newIdentity.Version
if ($newIdentity.ProcessorArchitecture -ne 'x64') {
    throw "Package architecture '$($newIdentity.ProcessorArchitecture)' is not x64."
}
$newSignature = Get-AuthenticodeSignature -LiteralPath $Package
if ($newSignature.Status -ne 'Valid') {
    throw ("Package signature status is '$($newSignature.Status)', not 'Valid'. The upgrade package must be " +
        'signed by a certificate trusted for this user (development trust is a separate user-authorized step; ' +
        'this script never installs or trusts a certificate).')
}
if (-not $newSignature.SignerCertificate -or
    -not (Test-HfDriveDistinguishedNameEqual -Left $newSignature.SignerCertificate.Subject -Right $newIdentity.Publisher)) {
    throw 'The package signer does not match the manifest publisher.'
}

# ---- Installed package validation ----------------------------------------
$installed = Get-HfDrivePackageByIdentityName
if (-not $installed) {
    throw 'No installed HF Drive package found; use scripts/install-dev.ps1 for a first installation.'
}
$installedVersion = ConvertTo-HfDriveVersion -Text $installed.Version
if ($newVersion -le $installedVersion) {
    throw ("New package version $($newIdentity.Version) is not strictly greater than installed version " +
        "$($installed.Version); upgrades must be monotonically higher.")
}

# The installed layout contains AppxManifest.xml as a plain file.
$installedManifestText = Get-Content -LiteralPath (Join-Path $installed.InstallLocation 'AppxManifest.xml') -Raw
$installedXml = [xml]$installedManifestText
$installedPublisher = $installedXml.Package.Identity.Publisher
if (-not (Test-HfDriveDistinguishedNameEqual -Left $newIdentity.Publisher -Right $installedPublisher)) {
    throw ("Upgrade publisher '$($newIdentity.Publisher)' does not match the installed package publisher " +
        "'$installedPublisher'. Identity publisher must remain stable across upgrades.")
}

$family = $installed.PackageFamilyName
$report = [ordered]@{
    timestamp_utc        = (Get-Date).ToUniversalTime().ToString('o')
    package_full_name    = $null
    installed_version    = $installed.Version
    new_version          = $newIdentity.Version
    prepare_upgrade      = $null
    pending_operations   = $null
    provider_exit_observed = $null
    provider_reactivated = $null
}

# ---- PrepareUpgrade acknowledgment (never kill-and-pretend) --------------
$providerProcesses = Get-HfDriveProviderProcess
if ($providerProcesses.Count -eq 0) {
    Write-Host 'No hfdrive-provider process is running; there is nothing to stop (handshake skipped, recorded).'
    $report.prepare_upgrade = 'skipped_provider_not_running'
}
else {
    $cliPath = Join-Path $installed.InstallLocation 'cli\hfdrive.exe'
    if (-not (Test-Path -LiteralPath $cliPath)) {
        throw "Packaged CLI '$cliPath' is missing from the installed package; cannot request PrepareUpgrade."
    }

    Write-Host 'Requesting the provider PrepareUpgrade acknowledgment (checkpoint + exit)…'
    $stdout = & $cliPath provider prepare-upgrade --json 2>&1
    $exitCode = $LASTEXITCODE
    $text = (@($stdout) -join [Environment]::NewLine).Trim()
    if ($exitCode -ne 0) {
        throw ("'hfdrive provider prepare-upgrade --json' failed with exit code $exitCode; the provider did NOT " +
            "acknowledge the upgrade. Output: $text. Refusing to continue (no kill-and-pretend).")
    }

    $ack = $null
    foreach ($candidate in @($text, ($text -split [Environment]::NewLine | Where-Object { $_.Trim() } | Select-Object -Last 1))) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        try { $ack = $candidate | ConvertFrom-Json -ErrorAction Stop; break } catch { }
    }
    if (-not $ack) {
        throw ("'hfdrive provider prepare-upgrade --json' did not print a JSON object. Output: $text. " +
            'Refusing to continue (no kill-and-pretend).')
    }
    $ackProps = @($ack.PSObject.Properties.Name)
    if ($ackProps -notcontains 'checkpointed' -or $ackProps -notcontains 'pending_operations') {
        throw ("PrepareUpgrade JSON must contain 'checkpointed' and 'pending_operations' (got: $($ackProps -join ', ')).")
    }
    if ($ack.checkpointed -isnot [bool]) {
        throw "PrepareUpgrade 'checkpointed' must be a JSON boolean (got: $($ack.checkpointed))."
    }
    if (-not $ack.checkpointed) {
        throw 'The provider did not checkpoint its state (checkpointed=false); refusing to upgrade.'
    }
    $pending = 0
    if (-not [int]::TryParse([string]$ack.pending_operations, [ref]$pending) -or $pending -lt 0) {
        throw "PrepareUpgrade 'pending_operations' must be a nonnegative integer (got: $($ack.pending_operations))."
    }
    $report.prepare_upgrade = 'acknowledged'
    $report.pending_operations = $pending
    Write-Host "Provider acknowledged PrepareUpgrade (checkpointed; $pending pending operation(s) durably recorded)."
}

if ($report.prepare_upgrade -eq 'acknowledged') {
    if (-not (Wait-HfDriveProviderExit -TimeoutSeconds $ProviderExitTimeoutSeconds)) {
        throw ("The provider acknowledged PrepareUpgrade but did not exit within $ProviderExitTimeoutSeconds s; " +
            'refusing to force-kill it. Investigate before retrying.')
    }
    $report.provider_exit_observed = $true
    Write-Host 'Provider exit observed.'
}
else {
    $report.provider_exit_observed = (Get-HfDriveProviderProcess).Count -eq 0
}

# ---- Install the higher version ------------------------------------------
Write-Host "Upgrading $($installed.PackageFullName) -> $($newIdentity.Version)…"
Add-AppxPackage -Path $Package

$upgraded = Get-HfDrivePackageByIdentityName
if (-not $upgraded -or (ConvertTo-HfDriveVersion -Text $upgraded.Version) -ne $newVersion) {
    throw "Upgrade did not register version $($newIdentity.Version)."
}
$report.package_full_name = $upgraded.PackageFullName

# ---- Reactivate the provider ---------------------------------------------
if (-not $SkipReactivate) {
    Write-Host 'Reactivating the provider (packaged application ID)…'
    Start-Process "shell:AppsFolder\$family!Provider"
    if (Wait-HfDriveProviderStart -TimeoutSeconds 30) {
        $report.provider_reactivated = $true
        Write-Host 'Provider is running again; state migration/recovery runs on provider start.'
    }
    else {
        $report.provider_reactivated = $false
        $reportPath = Join-Path $repoRoot 'artifacts\acceptance'
        New-Item -ItemType Directory -Force -Path $reportPath | Out-Null
        $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $reportPath "upgrade-$($newIdentity.Version).json") -Encoding utf8
        throw 'The upgraded package installed, but the provider did not start after reactivation.'
    }
}

$recordDir = Join-Path $repoRoot 'artifacts\acceptance'
New-Item -ItemType Directory -Force -Path $recordDir | Out-Null
$recordPath = Join-Path $recordDir "upgrade-$($newIdentity.Version).json"
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordPath -Encoding utf8

Write-Host ''
Write-Host "Upgraded to: $($upgraded.PackageFullName)"
Write-Host "Record:      $recordPath"
