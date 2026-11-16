<#
.SYNOPSIS
    Shared helpers for HF Drive packaging and lifecycle scripts.

.DESCRIPTION
    Dot-sourced by scripts/package.ps1, scripts/install-dev.ps1,
    scripts/upgrade.ps1 and scripts/verify-lifecycle.ps1. Contains only pure
    helper functions: MSIX identity/manifest inspection, strict version parsing,
    signing-certificate resolution and publisher comparison. Nothing here
    installs, signs, trusts or removes anything.

    Fixed identities (approved plan; see packaging/AppxManifest.xml):
      - Package identity name: HFDrive
      - Application IDs:       HFDrive, Provider, Cli
      - Development publisher: CN=HFDrive Development
      - Shell command CLSID:   3071D4E7-5A86-4356-8BCE-CBB4E4C76734
#>
Set-StrictMode -Version Latest

$script:HfDrivePackageName = 'HFDrive'
$script:HfDriveDevPublisher = 'CN=HFDrive Development'
$script:HfDriveApplicationIds = @('HFDrive', 'Provider', 'Cli')
$script:HfDriveProviderAppId = 'Provider'
$script:HfDriveCliAppId = 'Cli'
$script:HfDriveStartupTaskId = 'HFDrive.Provider'
$script:HfDriveCliAlias = 'hfdrive.exe'
$script:HfDriveShellCommandClsid = '3071D4E7-5A86-4356-8BCE-CBB4E4C76734'

function Get-HfDrivePackageName { return $script:HfDrivePackageName }
function Get-HfDriveDevPublisher { return $script:HfDriveDevPublisher }
function Get-HfDriveApplicationIds { return $script:HfDriveApplicationIds }
function Get-HfDriveStartupTaskId { return $script:HfDriveStartupTaskId }
function Get-HfDriveAppAliasName { return $script:HfDriveCliAlias }
function Get-HfDriveShellCommandClsid { return $script:HfDriveShellCommandClsid }

function ConvertTo-HfDriveVersion {
    # Strict four-part package version (major.minor.patch.build, each 0..65535).
    param([Parameter(Mandatory)][string]$Text)
    if ($Text -notmatch '^\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5}$') {
        throw "Package version '$Text' is not a four-part version (major.minor.patch.build)."
    }
    $parts = @($Text.Split('.') | ForEach-Object { [int]$_ })
    foreach ($p in $parts) {
        if ($p -lt 0 -or $p -gt 65535) {
            throw "Package version '$Text' has a part outside 0..65535."
        }
    }
    return [version]::new($parts[0], $parts[1], $parts[2], $parts[3])
}

function Get-HfDriveMsixEntryText {
    # Reads one entry (e.g. AppxManifest.xml) as UTF-8 text from an .msix.
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$EntryName
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Convert-Path -LiteralPath $PackagePath))
    try {
        $entry = $zip.GetEntry($EntryName)
        if (-not $entry) {
            throw "Package '$PackagePath' does not contain '$EntryName'."
        }
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try { return $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally {
        $zip.Dispose()
    }
}

function Get-HfDriveMsixEntries {
    # Lists all entry names of an .msix.
    param([Parameter(Mandatory)][string]$PackagePath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Convert-Path -LiteralPath $PackagePath))
    try {
        return @($zip.Entries | ForEach-Object { $_.FullName })
    }
    finally {
        $zip.Dispose()
    }
}

function Get-HfDriveMsixIdentity {
    # Parses Identity and the full manifest text from an .msix.
    param([Parameter(Mandatory)][string]$PackagePath)
    $manifestText = Get-HfDriveMsixEntryText -PackagePath $PackagePath -EntryName 'AppxManifest.xml'
    $xml = [xml]$manifestText
    $nsm = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $nsm.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $identity = $xml.SelectSingleNode('/f:Package/f:Identity', $nsm)
    if (-not $identity) {
        throw "Package '$PackagePath' has no Identity element."
    }
    return [pscustomobject]@{
        Name                = $identity.GetAttribute('Name')
        Publisher           = $identity.GetAttribute('Publisher')
        Version             = $identity.GetAttribute('Version')
        ProcessorArchitecture = $identity.GetAttribute('ProcessorArchitecture')
        ManifestText        = $manifestText
        ManifestXml         = $xml
    }
}

function Test-HfDriveDistinguishedNameEqual {
    # Compares two X.500 distinguished names. Identical encodings compare equal;
    # otherwise the sets of relative distinguished names are compared in a
    # normalized form (trimmed, case-insensitive, order-insensitive). This
    # pre-validates identity only — Windows performs the authoritative
    # publisher/Subject match at install time.
    param(
        [Parameter(Mandatory)][string]$Left,
        [Parameter(Mandatory)][string]$Right
    )
    try {
        $a = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Left)
        $b = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Right)
    }
    catch {
        return [string]::Equals($Left.Trim(), $Right.Trim(), [StringComparison]::OrdinalIgnoreCase)
    }
    $ra = $a.RawData
    $rb = $b.RawData
    if ($ra.Length -eq $rb.Length) {
        $equal = $true
        for ($i = 0; $i -lt $ra.Length; $i++) {
            if ($ra[$i] -ne $rb[$i]) { $equal = $false; break }
        }
        if ($equal) { return $true }
    }
    $norm = {
        param($dn)
        @($dn -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object)
    }
    $la = @(& $norm $Left)
    $lb = @(& $norm $Right)
    if ($la.Count -ne $lb.Count) { return $false }
    for ($i = 0; $i -lt $la.Count; $i++) {
        if ($la[$i] -cne $lb[$i]) { return $false }
    }
    return $true
}

function Resolve-HfDriveCodeSigningCertificate {
    # Finds exactly one code-signing certificate by thumbprint and/or subject.
    # Never creates or trusts a certificate; fail-closed when absent or ambiguous.
    param(
        [string]$Thumbprint,
        [string]$Subject
    )
    if ([string]::IsNullOrWhiteSpace($Thumbprint) -and [string]::IsNullOrWhiteSpace($Subject)) {
        throw 'A certificate thumbprint or subject is required; refusing to guess a signing identity.'
    }
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    $codeSigningEku = '1.3.6.1.5.5.7.3.3'
    $matches = foreach ($store in $stores) {
        Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Where-Object {
            if ($Thumbprint -and ($_.Thumbprint -ne $Thumbprint.Replace(' ', '').ToUpperInvariant())) { return $false }
            if ($Subject -and -not (Test-HfDriveDistinguishedNameEqual -Left $_.Subject -Right $Subject)) { return $false }
            if (-not $_.HasPrivateKey) { return $false }
            $eku = @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
            return ($eku -contains $codeSigningEku)
        }
    }
    $matches = @($matches)
    if ($matches.Count -eq 0) {
        throw ("No code-signing certificate with private key matching the requested identity was found in " +
            "CurrentUser\My or LocalMachine\My. Development: run " +
            "pwsh -NoProfile -File scripts/New-HfDriveDevCertificate.ps1 first (it creates the certificate only). " +
            'Production: install the real signing certificate in the certificate store and set ' +
            'HFDRIVE_SIGN_CERT_THUMBPRINT; missing credentials fail closed.')
    }
    if ($matches.Count -gt 1) {
        $list = ($matches | ForEach-Object { "$($_.Thumbprint) ($($_.Subject))" }) -join '; '
        throw "Multiple code-signing certificates match ($list); specify an exact thumbprint to disambiguate."
    }
    $cert = $matches[0]
    if ($cert.NotAfter -le (Get-Date)) {
        throw "Signing certificate $($cert.Thumbprint) ($($cert.Subject)) expired at $($cert.NotAfter.ToString('o'))."
    }
    return [pscustomobject]@{
        Certificate = $cert
        StoreName   = if ($cert.PSPath -like 'Cert:\LocalMachine\*') { 'LocalMachine' } else { 'CurrentUser' }
    }
}

function Test-HfDriveTimestampUrl {
    param([Parameter(Mandatory)][string]$Url)
    $uri = $null
    if (-not [uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
        throw "Timestamp URL '$Url' is not an absolute URI."
    }
    if ($uri.Scheme -ne 'https') {
        throw "Timestamp URL '$Url' must use https."
    }
    return $true
}

function Get-HfDriveManifestNodes {
    # Namespace-aware XPath evaluation over a parsed AppxManifest.xml.
    param(
        [Parameter(Mandatory)][xml]$Manifest,
        [Parameter(Mandatory)][string]$XPath
    )
    $nsm = New-Object System.Xml.XmlNamespaceManager($Manifest.NameTable)
    $nsm.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $nsm.AddNamespace('com', 'http://schemas.microsoft.com/appx/manifest/com/windows10')
    $nsm.AddNamespace('desktop4', 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/4')
    $nsm.AddNamespace('desktop5', 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/5')
    $nsm.AddNamespace('uap', 'http://schemas.microsoft.com/appx/manifest/uap/windows10')
    $nsm.AddNamespace('uap5', 'http://schemas.microsoft.com/appx/manifest/uap/windows10/5')
    $nsm.AddNamespace('uap10', 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10')
    $nsm.AddNamespace('rescap', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities')
    $nsm.AddNamespace('virtualization', 'http://schemas.microsoft.com/appx/manifest/virtualization/windows10')
    return @($Manifest.SelectNodes($XPath, $nsm))
}

function Get-HfDrivePackageByIdentityName {
    # The installed per-user package (or $null).
    param([string]$Name = $script:HfDrivePackageName)
    return @(Get-AppxPackage -Name $Name -ErrorAction SilentlyContinue) | Select-Object -First 1
}

function Get-HfDriveProviderProcess {
    return @(Get-Process -Name 'hfdrive-provider' -ErrorAction SilentlyContinue)
}

function Wait-HfDriveProviderExit {
    param([int]$TimeoutSeconds = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-HfDriveProviderProcess).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return ((Get-HfDriveProviderProcess).Count -eq 0)
}

function Wait-HfDriveProviderStart {
    param([int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-HfDriveProviderProcess).Count -gt 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return ((Get-HfDriveProviderProcess).Count -gt 0)
}

function Get-HfDriveStateDirectory {
    return (Join-Path $env:LOCALAPPDATA 'HFDrive')
}

function Get-HfDriveFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}
