<#
.SYNOPSIS
    Trusts the HF Drive development certificate — a separate, explicit,
    user-authorized security action.

.DESCRIPTION
    Imports the public development certificate (created by
    scripts/New-HfDriveDevCertificate.ps1) into the current user's Root store so
    that development-signed MSIX packages can be installed. This is the ONLY
    script that changes certificate trust, and it refuses to run without the
    explicit -ConfirmTrust switch.

    Scope:
      - CurrentUser\Root (default): trusts the certificate for the current user
        only. No elevation required.
      - -LocalMachine: also imports into LocalMachine\Root and therefore requires
        an elevated prompt; it trusts the certificate machine-wide.

    Security note: a trusted root certificate can sign ANY certificate. Only
    trust the HF Drive development certificate on development machines, keep the
    private key non-exportable, and remove the trust when it is no longer needed
    (see docs/build-install.md). Production packages use a real certificate from
    a trusted authority and never require this step.

.EXAMPLE
    pwsh -NoProfile -File scripts/Install-HfDriveDevCertificateTrust.ps1 -ConfirmTrust
#>
[CmdletBinding()]
param(
    # Mandatory explicit user authorization. Without it this script refuses to run.
    [switch]$ConfirmTrust,

    # Public development certificate to trust (default: the artifact exported by
    # scripts/New-HfDriveDevCertificate.ps1).
    [string]$CertificatePath,

    # Also trust machine-wide (requires an elevated prompt).
    [switch]$LocalMachine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ConfirmTrust) {
    throw ('Refusing to change certificate trust without explicit authorization. ' +
        'Trusting a root certificate is a machine/user security decision. If you intend this, re-run with ' +
        '-ConfirmTrust.')
}

$repoRoot = $PSScriptRoot | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
    $CertificatePath = Join-Path $repoRoot 'artifacts\package\certs\HFDrive-Development.cer'
}
if (-not (Test-Path -LiteralPath $CertificatePath)) {
    throw "Development certificate '$CertificatePath' was not found. Run scripts/New-HfDriveDevCertificate.ps1 first."
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Convert-Path -LiteralPath $CertificatePath))
$devPublisher = Get-HfDriveDevPublisher
if (-not (Test-HfDriveDistinguishedNameEqual -Left $cert.Subject -Right $devPublisher)) {
    throw ("Certificate '$CertificatePath' has Subject '$($cert.Subject)', which is not the development " +
        "publisher '$devPublisher'. Refusing to trust a foreign identity as the HF Drive development certificate.")
}
if ($cert.NotAfter -le (Get-Date)) {
    throw "Certificate $($cert.Thumbprint) expired at $($cert.NotAfter.ToString('o'))."
}

Write-Host "Trusting development certificate $($cert.Thumbprint) ($($cert.Subject))…"
Write-Host 'A trusted root can sign any certificate. Trust this on development machines only.'

Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
Write-Host 'Imported into Cert:\CurrentUser\Root (current user).'

if ($LocalMachine) {
    Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Write-Host 'Imported into Cert:\LocalMachine\Root (machine-wide; requires elevation).'
}

Write-Host ''
Write-Host 'Development packages signed by this certificate can now be installed with:'
Write-Host '  pwsh -NoProfile -File scripts/install-dev.ps1 -Package <msix-path>'
Write-Host ''
Write-Host 'To revoke this trust later (development machine hygiene):'
Write-Host "  Remove-Item 'Cert:\CurrentUser\Root\$($cert.Thumbprint)'"
if ($LocalMachine) {
    Write-Host "  Remove-Item 'Cert:\LocalMachine\Root\$($cert.Thumbprint)'"
}
