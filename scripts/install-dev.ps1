<#
.SYNOPSIS
    Installs a development-signed HF Drive MSIX package for the current user.

.DESCRIPTION
    Validates the package before installation — exact identity (Name "HFDrive",
    publisher "CN=HFDrive Development"), four-part version, x64 architecture,
    the three application IDs (HFDrive/Provider/Cli), the hfdrive.exe alias, the
    disabled-by-default HFDrive.Provider startup task and the state-directory
    virtualization exclusion — and verifies the Authenticode signature matches
    the development publisher. Installation is per-user (Add-AppxPackage).

    Fail-closed behaviors:
      - An untrusted/unverified signature aborts with the exact trust command to
        run; this script NEVER installs or trusts a certificate.
      - A same-version package requires the explicit -Reinstall switch.
      - A version other than the installed one must go through scripts/upgrade.ps1,
        which requires the provider's PrepareUpgrade acknowledgment. Downgrades
        are refused.

.EXAMPLE
    pwsh -NoProfile -File scripts/install-dev.ps1 -Package artifacts/package/HFDrive_0.1.0.0_x64.msix
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Package,

    # Remove an existing same-version installation first (explicit; state under
    # %LOCALAPPDATA%\HFDrive is never touched).
    [switch]$Reinstall
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

# ---- Identity and manifest validation ------------------------------------
$identity = Get-HfDriveMsixIdentity -PackagePath $Package
if ($identity.Name -ne (Get-HfDrivePackageName)) {
    throw "Package identity Name '$($identity.Name)' is not '$(Get-HfDrivePackageName)'."
}
$devPublisher = Get-HfDriveDevPublisher
if (-not (Test-HfDriveDistinguishedNameEqual -Left $identity.Publisher -Right $devPublisher)) {
    throw ("install-dev installs development packages only; publisher '$($identity.Publisher)' is not " +
        "'$devPublisher'.")
}
$packageVersion = ConvertTo-HfDriveVersion -Text $identity.Version
if ($identity.ProcessorArchitecture -ne 'x64') {
    throw "Package architecture '$($identity.ProcessorArchitecture)' is not x64."
}

$manifest = $identity.ManifestXml
$appNodes = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Applications/f:Application'
$appIds = @($appNodes | ForEach-Object { $_.GetAttribute('Id') })
foreach ($appId in Get-HfDriveApplicationIds) {
    if ($appIds -notcontains $appId) {
        throw "Manifest is missing application Id '$appId'."
    }
}
$aliasNodes = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath "/f:Package/f:Applications/f:Application[@Id='Cli']/f:Extensions/uap5:Extension/uap5:AppExecutionAlias/uap5:ExecutionAlias"
if (-not ($aliasNodes | Where-Object { $_.GetAttribute('Alias') -eq (Get-HfDriveAppAliasName) })) {
    throw "Manifest does not declare the '$(Get-HfDriveAppAliasName)' execution alias on the Cli application."
}
$startupNodes = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath "/f:Package/f:Applications/f:Application[@Id='Provider']/f:Extensions/uap5:Extension/uap5:StartupTask"
$startup = $startupNodes | Where-Object { $_.GetAttribute('TaskId') -eq (Get-HfDriveStartupTaskId) }
if (-not $startup) {
    throw "Manifest does not declare startup task '$(Get-HfDriveStartupTaskId)'."
}
if ($startup.GetAttribute('Enabled') -ne 'false') {
    throw "Startup task '$(Get-HfDriveStartupTaskId)' must be disabled by default (Enabled=false)."
}
$exclusions = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath '/f:Package/f:Properties/virtualization:FileSystemWriteVirtualization/virtualization:ExcludedDirectories/virtualization:ExcludedDirectory'
if (-not ($exclusions | Where-Object { $_.InnerText.Trim() -eq '$(KnownFolder:LocalAppData)\HFDrive' })) {
    throw 'Manifest is missing the fine-grained unvirtualized state-directory exclusion.'
}

# ---- Signature validation (trust is a separate user-authorized step) ------
$signature = Get-AuthenticodeSignature -LiteralPath $Package
if ($signature.Status -ne 'Valid') {
    throw ("Package signature status is '$($signature.Status)', not 'Valid'. A development-signed package " +
        'requires the separate user-authorized trust step first:' +
        [Environment]::NewLine +
        '  pwsh -NoProfile -File scripts/Install-HfDriveDevCertificateTrust.ps1 -ConfirmTrust' +
        [Environment]::NewLine +
        'This script never installs or trusts a certificate.')
}
if (-not $signature.SignerCertificate -or
    -not (Test-HfDriveDistinguishedNameEqual -Left $signature.SignerCertificate.Subject -Right $devPublisher)) {
    throw 'The package signer does not match the development publisher certificate.'
}

# ---- Existing installation policy ----------------------------------------
$existing = Get-HfDrivePackageByIdentityName
if ($existing) {
    $installedVersion = ConvertTo-HfDriveVersion -Text $existing.Version
    if ($installedVersion -eq $packageVersion) {
        if (-not $Reinstall) {
            throw ("HF Drive $($existing.Version) is already installed. Use -Reinstall to remove and reinstall " +
                'the same version (explicit), or scripts/upgrade.ps1 for a newer package.')
        }
        Write-Host "Removing existing installation $($existing.PackageFullName) (-Reinstall)…"
        Remove-AppxPackage -Package $existing.PackageFullName
    }
    elseif ($installedVersion -gt $packageVersion) {
        throw ("Installed version $($existing.Version) is newer than package version $($identity.Version); " +
            'downgrades are refused.')
    }
    else {
        throw ("HF Drive $($existing.Version) is installed. Upgrades go through scripts/upgrade.ps1, which " +
            'requires the provider PrepareUpgrade acknowledgment; refusing an in-place version change here.')
    }
}

# ---- Install (per user) ---------------------------------------------------
Write-Host "Installing $Package…"
Add-AppxPackage -Path $Package

$installed = Get-HfDrivePackageByIdentityName
if (-not $installed -or $installed.Version -ne $identity.Version) {
    throw 'Package installation did not register the expected identity/version.'
}

$family = $installed.PackageFamilyName
$aumids = [ordered]@{
    Desktop  = "$family!HFDrive"
    Provider = "$family!Provider"
    Cli      = "$family!Cli"
}

$aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\hfdrive.exe'
$aliasPresent = Test-Path -LiteralPath $aliasPath

Write-Host ''
Write-Host "Installed: $($installed.PackageFullName)"
Write-Host "Install location: $($installed.InstallLocation)"
Write-Host "Application IDs:"
Write-Host "  Desktop:  $($aumids.Desktop)"
Write-Host "  Provider: $($aumids.Provider)  (hidden from Start; startup task HFDrive.Provider disabled by default)"
Write-Host "  Cli:      $($aumids.Cli)  (alias 'hfdrive.exe')"
Write-Host "Alias registered: $aliasPresent"
Write-Host ''
Write-Host 'Activate the provider:      Start-Process "shell:AppsFolder\' + $aumids.Provider + '"'
Write-Host 'Open the desktop app:       Start-Process "shell:AppsFolder\' + $aumids.Desktop + '"'

# ---- Install record -------------------------------------------------------
$record = [ordered]@{
    timestamp_utc    = (Get-Date).ToUniversalTime().ToString('o')
    package_path     = $Package
    package_sha256   = Get-HfDriveFileSha256 -Path $Package
    identity         = [ordered]@{
        name    = $identity.Name
        publisher = $identity.Publisher
        version = $identity.Version
        architecture = $identity.ProcessorArchitecture
    }
    signature_status = $signature.Status.ToString()
    signer_thumbprint = $signature.SignerCertificate.Thumbprint
    installed_package_full_name = $installed.PackageFullName
    package_family_name = $family
    application_ids  = $aumids
    alias_registered = $aliasPresent
    reinstall        = [bool]$Reinstall
}
$recordDir = Join-Path $repoRoot 'artifacts\acceptance'
New-Item -ItemType Directory -Force -Path $recordDir | Out-Null
$recordPath = Join-Path $recordDir "install-dev-$($identity.Version).json"
$record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $recordPath -Encoding utf8
Write-Host "Install record: $recordPath"
