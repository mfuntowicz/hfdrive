<#
.SYNOPSIS
    Static regression tests for the HF Drive packaging surface (no packaging,
    signing, installation or certificate actions are performed).

.DESCRIPTION
    Dot-source and run:
        pwsh -NoProfile -File scripts/tests/Packaging.Tests.ps1
    Exits nonzero by throwing on the first failure. Validates:
      - packaging/AppxManifest.xml well-formedness and the full fixed contract
        (identities, application IDs, alias, disabled startup task, fine-grained
        state virtualization exclusion, exact min/max OS declarations,
        capabilities, ignorable namespaces);
      - every manifest-referenced asset exists in packaging/assets/;
      - PowerShell scripts parse cleanly;
      - certificate create/trust actions exist only in their dedicated,
        explicit scripts;
      - strict version/identity helper behavior.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot | Split-Path -Parent | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

$failures = 0
function Assert-HfDrive([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        $script:failures++
        throw "FAILED: $Message"
    }
}

# ---- Manifest contract ----------------------------------------------------
$manifestPath = Join-Path $repoRoot 'packaging\AppxManifest.xml'
[xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw

$identity = @(Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Identity')[0]
Assert-HfDrive ($identity.GetAttribute('Name') -eq (Get-HfDrivePackageName)) "Identity Name must be '$(Get-HfDrivePackageName)'."
Assert-HfDrive ($identity.GetAttribute('Publisher') -eq '{{HFDRIVE_PACKAGE_PUBLISHER}}') 'Identity Publisher must be the publisher template token.'
Assert-HfDrive ($identity.GetAttribute('Version') -eq '{{HFDRIVE_PACKAGE_VERSION}}') 'Identity Version must be the version template token.'
Assert-HfDrive ($identity.GetAttribute('ProcessorArchitecture') -eq 'x64') 'Identity must be x64.'

$tdf = @(Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Dependencies/f:TargetDeviceFamily')[0]
Assert-HfDrive ($tdf.GetAttribute('MinVersion') -eq '10.0.22621.0') 'TargetDeviceFamily MinVersion must be 10.0.22621.0.'
Assert-HfDrive ($tdf.GetAttribute('MaxVersionTested') -eq '10.0.26100.0') 'TargetDeviceFamily MaxVersionTested must be 10.0.26100.0.'

$appNodes = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Applications/f:Application'
$appIds = @($appNodes | ForEach-Object { $_.GetAttribute('Id') })
foreach ($id in Get-HfDriveApplicationIds) {
    Assert-HfDrive ($appIds -contains $id) "Application Id '$id' must be declared."
}

$alias = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath "/f:Package/f:Applications/f:Application[@Id='Cli']/f:Extensions/uap5:Extension/uap5:AppExecutionAlias/uap5:ExecutionAlias"
Assert-HfDrive (@($alias | Where-Object { $_.GetAttribute('Alias') -eq (Get-HfDriveAppAliasName) }).Count -eq 1) `
    "Cli must declare exactly one '$(Get-HfDriveAppAliasName)' execution alias."

$startup = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath "/f:Package/f:Applications/f:Application[@Id='Provider']/f:Extensions/uap5:Extension/uap5:StartupTask"
Assert-HfDrive (@($startup).Count -eq 1) 'Provider must declare exactly one startup task.'
Assert-HfDrive (@($startup)[0].GetAttribute('TaskId') -eq (Get-HfDriveStartupTaskId)) "Startup task id must be '$(Get-HfDriveStartupTaskId)'."
Assert-HfDrive (@($startup)[0].GetAttribute('Enabled') -eq 'false') 'Startup task must be disabled by default.'

$hidden = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath "/f:Package/f:Applications/f:Application[@Id='Provider' or @Id='Cli']/uap:VisualElements[@AppListEntry='none']"
Assert-HfDrive (@($hidden).Count -eq 2) 'Provider and Cli must be hidden from Start (AppListEntry=none).'

$exclusions = Get-HfDriveManifestNodes -Manifest $manifest `
    -XPath '/f:Package/f:Properties/virtualization:FileSystemWriteVirtualization/virtualization:ExcludedDirectories/virtualization:ExcludedDirectory'
Assert-HfDrive (@($exclusions).Count -eq 1) 'Exactly one virtualization exclusion directory must be declared.'
Assert-HfDrive (@($exclusions)[0].InnerText.Trim() -eq '$(KnownFolder:LocalAppData)\HFDrive') `
    'The state directory must be the only unvirtualized location.'

$caps = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Capabilities/rescap:Capability'
$capNames = @($caps | ForEach-Object { $_.GetAttribute('Name') })
Assert-HfDrive ($capNames -contains 'runFullTrust') 'runFullTrust capability is required.'
Assert-HfDrive ($capNames -contains 'unvirtualizedResources') 'unvirtualizedResources capability is required.'

$ignorable = @(($manifest.Package.IgnorableNamespaces -split '\s+') | Where-Object { $_ })
foreach ($ns in @('uap5', 'uap10', 'rescap', 'virtualization')) {
    Assert-HfDrive ($ignorable -contains $ns) "IgnorableNamespaces must contain '$ns'."
}

# Tokens are rendered at package time; the checked-in template keeps exactly these two.
$template = Get-Content -LiteralPath $manifestPath -Raw
$tokens = @([regex]::Matches($template, '\{\{[A-Z0-9_]+\}\}') | ForEach-Object { $_.Value })
Assert-HfDrive (@($tokens | Sort-Object -Unique) -join ',' -eq '{{HFDRIVE_PACKAGE_PUBLISHER}},{{HFDRIVE_PACKAGE_VERSION}}') `
    'The manifest must contain exactly the publisher and version template tokens.'

# ---- Assets ---------------------------------------------------------------
$assetDir = Join-Path $repoRoot 'packaging\assets'
$assetRefs = @([regex]::Matches($template, 'assets\\[A-Za-z0-9]+\.png') | ForEach-Object { $_.Value })
foreach ($ref in ($assetRefs | Sort-Object -Unique)) {
    Assert-HfDrive (Test-Path -LiteralPath (Join-Path $assetDir ([System.IO.Path]::GetFileName($ref)))) `
        "Manifest asset '$ref' must exist in packaging\assets."
}

# ---- Script parse checks --------------------------------------------------
$scriptFiles = @(
    (Join-Path $repoRoot 'packaging\Packaging.Common.ps1'),
    (Join-Path $repoRoot 'packaging\assets\Generate-HfDriveAssets.ps1'),
    (Join-Path $repoRoot 'scripts\package.ps1'),
    (Join-Path $repoRoot 'scripts\install-dev.ps1'),
    (Join-Path $repoRoot 'scripts\upgrade.ps1'),
    (Join-Path $repoRoot 'scripts\New-HfDriveDevCertificate.ps1'),
    (Join-Path $repoRoot 'scripts\Install-HfDriveDevCertificateTrust.ps1'),
    (Join-Path $repoRoot 'scripts\verify-lifecycle.ps1')
)
foreach ($scriptFile in $scriptFiles) {
    Assert-HfDrive (Test-Path -LiteralPath $scriptFile) "Missing script '$scriptFile'."
    $tokens2 = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($scriptFile, [ref]$tokens2, [ref]$errors)
    Assert-HfDrive (@($errors).Count -eq 0) "Parse errors in '${scriptFile}': $(@($errors | ForEach-Object Message) -join '; ')"
}

# ---- Certificate-action containment --------------------------------------
foreach ($scriptFile in $scriptFiles) {
    $name = [System.IO.Path]::GetFileName($scriptFile)
    $text = Get-Content -LiteralPath $scriptFile -Raw
    if ($name -eq 'New-HfDriveDevCertificate.ps1') { continue }
    Assert-HfDrive ($text -notmatch 'New-SelfSignedCertificate') `
        "'$name' must not create certificates (only New-HfDriveDevCertificate.ps1 may)."
    if ($name -eq 'Install-HfDriveDevCertificateTrust.ps1') { continue }
    Assert-HfDrive ($text -notmatch 'Import-Certificate') `
        "'$name' must not import/trust certificates (only Install-HfDriveDevCertificateTrust.ps1 may)."
}
$trustScript = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\Install-HfDriveDevCertificateTrust.ps1') -Raw
Assert-HfDrive ($trustScript -match 'ConfirmTrust') 'The trust script must require explicit user authorization.'

# ---- Helper behavior ------------------------------------------------------
$good = ConvertTo-HfDriveVersion -Text '0.1.0.0'
Assert-HfDrive ($good.ToString() -eq '0.1.0.0') 'Version parsing must accept a four-part version.'
foreach ($bad in @('1.0.0', '1.0', '1.0.0.0.0', '70000.0.0.0', '1.0.0.-1', 'a.b.c.d', '')) {
    $rejected = $false
    try { $null = ConvertTo-HfDriveVersion -Text $bad } catch { $rejected = $true }
    Assert-HfDrive $rejected "Version parsing must reject '$bad'."
}

Assert-HfDrive (Test-HfDriveDistinguishedNameEqual -Left 'CN=HFDrive Development' -Right 'CN=HFDrive Development') `
    'Identical distinguished names must compare equal.'
Assert-HfDrive (-not (Test-HfDriveDistinguishedNameEqual -Left 'CN=HFDrive Development' -Right 'CN=Other')) `
    'Different distinguished names must not compare equal.'
Assert-HfDrive (Test-HfDriveDistinguishedNameEqual -Left 'CN=A, O=B' -Right 'O=B, CN=A') `
    'Distinguished-name comparison must be order-insensitive.'

$tzRejected = $false
try { Test-HfDriveTimestampUrl -Url 'http://timestamp.example' | Out-Null } catch { $tzRejected = $true }
Assert-HfDrive $tzRejected 'Timestamp URL validation must reject plain http.'
Test-HfDriveTimestampUrl -Url 'https://timestamp.example/rfc3161' | Out-Null

# ---- Unsigned development-only package mode --------------------------------
$packageScript = Get-Content -LiteralPath (Join-Path $repoRoot 'scripts\package.ps1') -Raw
Assert-HfDrive ($packageScript -match '\[switch\]\$Unsigned') 'Unsigned development mode must be explicit.'
Assert-HfDrive ($packageScript -match 'Production packages must be signed and timestamped; -Unsigned is development-only') `
    'Production must reject unsigned packaging.'
Assert-HfDrive ($packageScript -match 'if \(-not \$Unsigned\)') 'Certificate discovery/signing must be conditional on signed mode.'
Assert-HfDrive ($packageScript -match 'Unsigned development package: no certificate discovery, signing, trust, or install') `
    'Unsigned mode must state that no certificate/trust/install action occurs.'
Assert-HfDrive ($packageScript -match 'startIndexAt = ''assets''') `
    'PRI generation must index only application-owned assets and avoid WinUI-internal duplicates.'
$appxManifest = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging\AppxManifest.xml') -Raw
Assert-HfDrive ($appxManifest -match '<uap5:AppExecutionAlias uap10:Subsystem="console">') `
    'Console subsystem must be declared on uap5:AppExecutionAlias, not uap5:Extension or uap5:ExecutionAlias.'
Assert-HfDrive ($appxManifest -match 'uap10:SupportsMultipleInstances="true"') `
    'Console applications must declare SupportsMultipleInstances=true.'

Write-Output "Packaging static regression: passed ($([System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $manifestPath -Raw), [ref]$null).Count) manifest tokens)"
