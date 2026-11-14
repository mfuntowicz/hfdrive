<#
.SYNOPSIS
    Creates the HF Drive development code-signing certificate (certificate
    creation only — it never trusts anything).

.DESCRIPTION
    Explicit, user-authorized creation of a self-signed code-signing certificate
    with Subject "CN=HFDrive Development" (the fixed development package
    publisher) in the current user's certificate store (CurrentUser\My). The
    private key is created non-exportable. The public certificate is exported to
    artifacts\package\certs\HFDrive-Development.cer so that the separate trust
    step can use it.

    Trust is NEVER installed here. Trusting a root certificate is a distinct
    security decision and a separate user-authorized action performed only by
    scripts/Install-HfDriveDevCertificateTrust.ps1. No packaging, install or
    upgrade script runs either script automatically.

    Production signing never uses this certificate; production identity comes
    from a real certificate in the certificate store (HFDRIVE_SIGN_CERT_THUMBPRINT,
    HFDRIVE_PACKAGE_PUBLISHER, HFDRIVE_TIMESTAMP_URL).

.EXAMPLE
    pwsh -NoProfile -File scripts/New-HfDriveDevCertificate.ps1
#>
[CmdletBinding()]
param(
    # Years of validity for the development certificate (default 2).
    [ValidateRange(1, 5)]
    [int]$ValidityYears = 2,

    # Explicitly remove this old development certificate first (thumbprint).
    # Required when an ambiguous/expired development certificate already exists.
    [string]$ReplaceThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

$devPublisher = Get-HfDriveDevPublisher

if ($ReplaceThumbprint) {
    $normalized = $ReplaceThumbprint.Replace(' ', '').ToUpperInvariant()
    $old = Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object { $_.Thumbprint -eq $normalized }
    if (-not $old) {
        throw "No certificate with thumbprint $normalized exists in CurrentUser\My; nothing to replace."
    }
    Write-Host "Removing old development certificate $old ($($old.Subject))…"
    Remove-Item -LiteralPath $old.PSPath
}

# Fail closed if a development certificate already exists: creating a second one
# would make signing ambiguous and would silently invalidate earlier trust.
$existing = @(Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object {
        (Test-HfDriveDistinguishedNameEqual -Left $_.Subject -Right $devPublisher)
    })
if ($existing.Count -gt 0) {
    $list = ($existing | ForEach-Object { "$($_.Thumbprint) (until $($_.NotAfter.ToString('o')))" }) -join '; '
    throw ("A development certificate already exists: $list. Reuse it, or remove a specific one with " +
        "-ReplaceThumbprint <thumbprint>. A second 'CN=HFDrive Development' certificate would make " +
        'package signing ambiguous.')
}

Write-Host "Creating development code-signing certificate '$devPublisher' in CurrentUser\My…"
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $devPublisher `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears($ValidityYears)

$certDir = Join-Path $repoRoot 'artifacts\package\certs'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$cerPath = Join-Path $certDir 'HFDrive-Development.cer'
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null

Write-Host ''
Write-Host "Created development certificate:"
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Valid to:   $($cert.NotAfter.ToString('o'))"
Write-Host "  Public key: $cerPath"
Write-Host ''
Write-Host 'This certificate signs development packages only.'
Write-Host 'Trusting it is a SEPARATE, user-authorized security decision; run explicitly:'
Write-Host '  pwsh -NoProfile -File scripts/Install-HfDriveDevCertificateTrust.ps1 -ConfirmTrust'
Write-Host 'Never grant trust on machines that handle untrusted packages.'
