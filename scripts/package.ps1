<#
.SYNOPSIS
    Builds, assembles, signs and verifies the single multi-executable HF Drive
    MSIX package (HfDrive.Desktop.exe + provider/hfdrive-provider.exe +
    cli/hfdrive.exe + shell/HfDrive.Shell/HfDrive.Shell.dll).

.DESCRIPTION
    Publishes the WinUI desktop application self-contained (.NET 11 runtime
    11.0.0 + Windows App SDK 2.6.5) with the Build Tools 2026 x64 MSBuild,
    assembles the explicit package layout with the app-local release v145 CRT,
    renders packaging/AppxManifest.xml, generates Resources.pri with the pinned
    Windows SDK 10.0.28000.0 MakePri, packs with MakeAppx and signs with SignTool
    (/fd SHA256). A SHA-256 checksum and a provenance/dependency-inventory record
    are written next to the .msix.

    Signing modes (exactly one switch is required):
      -Development  Publisher is fixed "CN=HFDrive Development". The certificate
                    must already exist in CurrentUser\My (created separately by
                    scripts/New-HfDriveDevCertificate.ps1). Trust is a separate
                    user-authorized step (scripts/Install-HfDriveDevCertificateTrust.ps1);
                    this script never installs or trusts a certificate.
      -Production   Requires HFDRIVE_PACKAGE_PUBLISHER, HFDRIVE_SIGN_CERT_THUMBPRINT
                    and HFDRIVE_TIMESTAMP_URL in the environment. The certificate
                    must come from the certificate store, its Subject must exactly
                    match the publisher, and the package is signed and timestamped.
                    Missing credentials fail closed; no production-looking
                    certificate is ever created automatically.

    This script never installs, uninstalls or upgrades a package and never runs
    a certificate creation/trust step. -Unsigned is development-only and skips
    certificate discovery, signing and signature verification while preserving
    the same layout and MSIX build.

.EXAMPLE
    pwsh -NoProfile -File scripts/package.ps1 -Configuration Release -Development -Version 0.1.0.0

.EXAMPLE
    $env:HFDRIVE_PACKAGE_PUBLISHER = 'CN=Your Company'
    $env:HFDRIVE_SIGN_CERT_THUMBPRINT = '0123...ABCD'
    $env:HFDRIVE_TIMESTAMP_URL = 'https://timestamp.digicert.com'
    pwsh -NoProfile -File scripts/package.ps1 -Configuration Release -Production -Version 0.1.0.0
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # Exactly one signing mode must be selected.
    [switch]$Development,
    [switch]$Production,

    # Development-only: build and validate the MSIX layout without signing.
    # Never creates or trusts a certificate and never installs the package.
    [switch]$Unsigned,

    # Four-part package version (major.minor.patch.build). Major.minor.patch must
    # match the desktop project's <Version>.
    [Parameter(Mandatory)]
    [string]$Version,

    # Optional explicit certificate thumbprint. Defaults: development locates the
    # "CN=HFDrive Development" certificate; production reads
    # HFDRIVE_SIGN_CERT_THUMBPRINT.
    [string]$CertificateThumbprint,

    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([bool]$Development -eq [bool]$Production) {
    throw 'Select exactly one signing mode: -Development or -Production.'
}
if ($Production -and $Configuration -ne 'Release') {
    throw 'Production packages are built from the Release configuration only.'
}
if ($Production -and $Unsigned) {
    throw 'Production packages must be signed and timestamped; -Unsigned is development-only.'
}

$repoRoot = $PSScriptRoot | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

Push-Location $repoRoot
try {
    # ---- Toolchain (pinned; no fallback) ------------------------------------
    . (Join-Path $PSScriptRoot 'Initialize-BuildEnvironment.ps1')
    $buildEnv = Initialize-HfDriveBuildEnvironment -Configuration $Configuration
    $pins = Get-HfDriveToolchainPins

    # ---- Exact input validation --------------------------------------------
    $packageVersion = ConvertTo-HfDriveVersion -Text $Version

    [xml]$desktopProject = Get-Content -LiteralPath 'desktop\HfDrive.Desktop\HfDrive.Desktop.csproj'
    $assemblyVersionText = $desktopProject.SelectSingleNode('/Project/PropertyGroup/Version').InnerText
    $assemblyVersion = ConvertTo-HfDriveVersion -Text "$assemblyVersionText.0"
    if ($assemblyVersion.Major -ne $packageVersion.Major -or
        $assemblyVersion.Minor -ne $packageVersion.Minor -or
        $assemblyVersion.Build -ne $packageVersion.Build) {
        throw ("Package version $Version does not match the desktop project's <Version> $assemblyVersionText " +
            '(major.minor.patch must agree). Update both together.')
    }

    if ($Production) {
        $publisher = $env:HFDRIVE_PACKAGE_PUBLISHER
        if ([string]::IsNullOrWhiteSpace($publisher)) {
            throw 'Production packaging requires HFDRIVE_PACKAGE_PUBLISHER (the exact signing-certificate Subject). Missing credentials fail closed.'
        }
        $timestampUrl = $env:HFDRIVE_TIMESTAMP_URL
        if ([string]::IsNullOrWhiteSpace($timestampUrl)) {
            throw 'Production packaging requires HFDRIVE_TIMESTAMP_URL (a trusted RFC 3161 timestamp authority). Missing credentials fail closed.'
        }
        Test-HfDriveTimestampUrl -Url $timestampUrl | Out-Null
        if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            $CertificateThumbprint = $env:HFDRIVE_SIGN_CERT_THUMBPRINT
        }
        if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            throw 'Production packaging requires HFDRIVE_SIGN_CERT_THUMBPRINT (a real code-signing certificate in the certificate store). Missing credentials fail closed.'
        }
    }
    else {
        $publisher = Get-HfDriveDevPublisher
        $timestampUrl = $null
    }

    $certInfo = $null
    if (-not $Unsigned) {
        $certInfo = Resolve-HfDriveCodeSigningCertificate `
            -Thumbprint $CertificateThumbprint -Subject $publisher
        if (-not (Test-HfDriveDistinguishedNameEqual -Left $certInfo.Certificate.Subject -Right $publisher)) {
            throw ("Signing certificate Subject '$($certInfo.Certificate.Subject)' does not match package publisher " +
                "'$publisher'. The manifest Identity Publisher must match the signing certificate.")
        }
    }

    # ---- Required built binaries -------------------------------------------
    $rustProfile = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
    $cargoTargetDir = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        Join-Path $repoRoot 'target'
    } else {
        $env:CARGO_TARGET_DIR
    }
    $rustDir = Join-Path $cargoTargetDir "x86_64-pc-windows-msvc\$rustProfile"
    $providerExe = Join-Path $rustDir 'hfdrive-provider.exe'
    $cliExe = Join-Path $rustDir 'hfdrive.exe'
    $shellDll = Join-Path $rustDir 'hfdrive_shell.dll'
    foreach ($required in @($providerExe, $cliExe, $shellDll)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw ("Required binary '$required' is missing. Build the workspace first: " +
                "pwsh -NoProfile -File scripts/build.ps1 -Configuration $Configuration -Locked")
        }
    }

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = Join-Path $repoRoot 'artifacts\package'
    }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory = Join-Path $repoRoot $OutputDirectory
    }
    $OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
    $stagingDir = Join-Path $OutputDirectory 'staging'
    $publishDir = Join-Path $stagingDir 'desktop\'
    $layoutDir = Join-Path $OutputDirectory 'layout'
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

    # ---- Publish the desktop app self-contained ---------------------------
    if (Test-Path -LiteralPath $stagingDir) { Remove-Item -Recurse -Force -LiteralPath $stagingDir }
    New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

    Write-Host 'Publishing HfDrive.Desktop (self-contained .NET 11 + Windows App SDK)…'
    $publishArgs = @(
        'desktop\HfDrive.Desktop\HfDrive.Desktop.csproj',
        '/restore', '/t:Publish', '/m',
        "/p:Configuration=$Configuration",
        '/p:Platform=x64',
        '/p:RuntimeIdentifier=win-x64',
        '/p:RuntimeIdentifiers=win-x64',
        '/p:SelfContained=true',
        '/p:WindowsAppSDKSelfContained=true',
        "/p:WindowsTargetPlatformVersion=$($pins.WindowsSdkVersion)",
        '/p:RestoreLockedMode=true',
        "/p:PublishDir=$publishDir"
    )
    & $buildEnv.MSBuild @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "MSBuild publish failed with exit code $LASTEXITCODE."
    }

    # ---- Assemble the explicit package layout ------------------------------
    if (Test-Path -LiteralPath $layoutDir) { Remove-Item -Recurse -Force -LiteralPath $layoutDir }
    New-Item -ItemType Directory -Force -Path $layoutDir | Out-Null

    Copy-Item -Path (Join-Path $publishDir '*') -Destination $layoutDir -Recurse -Force
    New-Item -ItemType Directory -Force -Path (Join-Path $layoutDir 'provider') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $layoutDir 'cli') | Out-Null
    # Explorer context-menu COM DLL at the manifest's com:Class/@Path.
    New-Item -ItemType Directory -Force -Path (Join-Path $layoutDir 'shell\HfDrive.Shell') | Out-Null
    Copy-Item -LiteralPath $providerExe -Destination (Join-Path $layoutDir 'provider\hfdrive-provider.exe') -Force
    Copy-Item -LiteralPath $cliExe -Destination (Join-Path $layoutDir 'cli\hfdrive.exe') -Force
    Copy-Item -LiteralPath $shellDll -Destination (Join-Path $layoutDir 'shell\HfDrive.Shell\HfDrive.Shell.dll') -Force

    # App-local release v145 CRT beside every executable group.
    $crtSource = Join-Path $buildEnv.VsInstallationPath `
        "VC\Redist\MSVC\$($buildEnv.VcToolsVersion)\x64\Microsoft.VC145.CRT"
    if (-not (Test-Path -LiteralPath $crtSource)) {
        throw "Release CRT redist '$crtSource' is missing; refusing to package without the app-local v145 CRT."
    }
    $crtFiles = @(Get-ChildItem -LiteralPath $crtSource -Filter '*.dll')
    if ($crtFiles.Count -eq 0) { throw "CRT redist '$crtSource' contains no DLLs." }
    foreach ($dll in $crtFiles) {
        if ($dll.Name -match '(?i)(140d|ucrtbased)') {
            throw "Debug CRT '$($dll.Name)' found in the release redist; debug CRTs are never packaged."
        }
    }
    foreach ($required in @('vcruntime140.dll', 'msvcp140.dll')) {
        if (-not ($crtFiles | Where-Object { $_.Name -ieq $required })) {
            throw "CRT redist '$crtSource' is missing '$required'."
        }
    }
    foreach ($target in @($layoutDir, (Join-Path $layoutDir 'provider'), (Join-Path $layoutDir 'cli'),
            (Join-Path $layoutDir 'shell\HfDrive.Shell'))) {
        Copy-Item -Path (Join-Path $crtSource '*.dll') -Destination $target -Force
    }

    # Assets + rendered manifest.
    $assetDir = Join-Path $layoutDir 'assets'
    New-Item -ItemType Directory -Force -Path $assetDir | Out-Null
    Copy-Item -Path (Join-Path $repoRoot 'packaging\assets\*.png') -Destination $assetDir -Force

    $manifestTemplate = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging\AppxManifest.xml') -Raw
    $renderedManifest = $manifestTemplate.Replace('{{HFDRIVE_PACKAGE_PUBLISHER}}', $publisher)
    $renderedManifest = $renderedManifest.Replace('{{HFDRIVE_PACKAGE_VERSION}}', $Version)
    if ($renderedManifest -match '\{\{') {
        throw 'The rendered AppxManifest.xml still contains template tokens.'
    }
    Set-Content -LiteralPath (Join-Path $layoutDir 'AppxManifest.xml') -Value $renderedManifest -Encoding utf8

    # ---- Self-contained / layout assertions (fail closed) ------------------
    # The shell COM class must reference exactly the DLL path we just staged.
    if ($renderedManifest -notmatch [regex]::Escape('Path="shell\HfDrive.Shell\HfDrive.Shell.dll"')) {
        throw 'The rendered manifest does not register shell\HfDrive.Shell\HfDrive.Shell.dll; layout and manifest disagree.'
    }
    foreach ($required in @(
            (Join-Path $layoutDir 'HfDrive.Desktop.exe'),
            (Join-Path $layoutDir 'provider\hfdrive-provider.exe'),
            (Join-Path $layoutDir 'cli\hfdrive.exe'),
            (Join-Path $layoutDir 'shell\HfDrive.Shell\HfDrive.Shell.dll'),
            (Join-Path $layoutDir 'System.Private.CoreLib.dll'),
            (Join-Path $layoutDir 'Microsoft.WinUI.dll'))) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Package layout is missing '$required'; refusing a non-self-contained or incomplete layout."
        }
    }
    $wasRuntime = @(Get-ChildItem -LiteralPath $layoutDir -Filter 'Microsoft.WindowsAppRuntime*.dll' -Recurse)
    if ($wasRuntime.Count -eq 0) {
        $found = @(Get-ChildItem -LiteralPath $layoutDir -Filter '*.dll' | Select-Object -First 40 | ForEach-Object Name)
        throw ("No Microsoft.WindowsAppRuntime*.dll was published; the Windows App SDK is not app-local " +
            "(found: $($found -join ', ')). Refusing a framework-dependent package.")
    }
    foreach ($moduleDir in @($layoutDir, (Join-Path $layoutDir 'provider'), (Join-Path $layoutDir 'cli'),
            (Join-Path $layoutDir 'shell\HfDrive.Shell'))) {
        if (-not (Test-Path -LiteralPath (Join-Path $moduleDir 'vcruntime140.dll'))) {
            throw "App-local CRT is missing beside '$moduleDir'."
        }
    }
    $debugCrt = @(Get-ChildItem -LiteralPath $layoutDir -Recurse -File | Where-Object { $_.Name -match '(?i)(140d\.dll|ucrtbased)' })
    if ($debugCrt.Count -gt 0) {
        throw "Debug CRT files found in the layout: $(@($debugCrt | ForEach-Object Name) -join ', ')."
    }

    # ---- Framework dependencies (none expected while fully self-contained) --
    $dependenciesDir = Join-Path $OutputDirectory 'Dependencies\x64'
    $frameworkDependencies = @()
    $dependencyCandidates = @(Get-ChildItem -LiteralPath $stagingDir -Recurse -Include '*.msix', '*.appx' -File -ErrorAction SilentlyContinue)
    if ($dependencyCandidates.Count -gt 0) {
        New-Item -ItemType Directory -Force -Path $dependenciesDir | Out-Null
        foreach ($dep in $dependencyCandidates) {
            Copy-Item -LiteralPath $dep.FullName -Destination $dependenciesDir -Force
            $frameworkDependencies += $dep.Name
        }
    }

    # ---- Resources.pri and package ----------------------------------------
    Write-Host 'Generating Resources.pri (pinned Windows SDK MakePri)…'
    $priConfig = Join-Path $stagingDir 'priconfig.xml'
    & $buildEnv.MakePri createconfig /cf $priConfig /dq lang-en-US /o
    if ($LASTEXITCODE -ne 0) { throw "makepri createconfig failed with exit code $LASTEXITCODE." }
    # The desktop publish already contains WinUI's internal resources. Index
    # only application-owned assets; otherwise MakePri sees duplicate entries
    # such as Microsoft.UI.Xaml/Assets/NoiseAsset_256x256_PNG.png. All runtime
    # files remain in the MSIX layout.
    [xml]$priConfigXml = Get-Content -LiteralPath $priConfig
    $priConfigXml.resources.index.startIndexAt = 'assets'
    $priConfigXml.Save($priConfig)
    & $buildEnv.MakePri new /cf $priConfig /pr $layoutDir /in (Get-HfDrivePackageName) `
        /mn (Join-Path $layoutDir 'AppxManifest.xml') /of (Join-Path $layoutDir 'Resources.pri') /o
    if ($LASTEXITCODE -ne 0) { throw "makepri new failed with exit code $LASTEXITCODE." }

    $msixName = "HFDrive_${Version}_x64.msix"
    $msixPath = Join-Path $OutputDirectory $msixName
    Write-Host "Packing $msixName…"
    & $buildEnv.MakeAppx pack /d $layoutDir /p $msixPath /o
    if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE." }

    # ---- Sign / verify (unsigned development skips all certificate work) ----
    $signatureStatus = 'unsigned (development-only)'
    if (-not $Unsigned) {
        Write-Host "Signing with certificate $($certInfo.Certificate.Thumbprint)…"
        $signArgs = @('sign', '/fd', 'SHA256', '/sha1', $certInfo.Certificate.Thumbprint, '/s', 'My')
        if ($certInfo.StoreName -eq 'LocalMachine') { $signArgs += '/sm' }
        if ($Production) {
            $signArgs += @('/tr', $timestampUrl, '/td', 'SHA256')
        }
        $signArgs += $msixPath
        & $buildEnv.SignTool @signArgs
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE." }

        $signature = Get-AuthenticodeSignature -LiteralPath $msixPath
        if (-not $signature.SignerCertificate) {
            throw 'The packed .msix has no signature after signing.'
        }
        if ($signature.SignerCertificate.Thumbprint -ne $certInfo.Certificate.Thumbprint) {
            throw 'The .msix signer does not match the selected signing certificate.'
        }
        $signatureStatus = $signature.Status.ToString()
        if ($Production) {
            & $buildEnv.SignTool verify /pa /tw /all $msixPath
            if ($LASTEXITCODE -ne 0) {
                throw "signtool verify failed with exit code $LASTEXITCODE; a production package must verify and timestamp."
            }
            $signatureStatus = 'Valid'
        }
    }
    else {
        Write-Host 'Unsigned development package: no certificate discovery, signing, trust, or install.'
    }
    # Development: the self-signed certificate chain is untrusted until the
    # separate user-authorized trust step; signature presence and identity are
    # verified here, and the observed status is recorded honestly.

    # ---- Checksum + provenance / dependency inventory ---------------------
    $msixHash = Get-HfDriveFileSha256 -Path $msixPath
    Set-Content -LiteralPath "$msixPath.sha256" -Value "$msixHash  $msixName" -Encoding ascii

    function Get-FileVersionSafe([string]$Path) {
        if (Test-Path -LiteralPath $Path) {
            return (Get-Item -LiteralPath $Path).VersionInfo | ForEach-Object {
                [ordered]@{ file_version = $_.FileVersion; product_version = $_.ProductVersion }
            }
        }
        return $null
    }

    $crtInventory = @($crtFiles | ForEach-Object {
        [ordered]@{
            name    = $_.Name
            version = (Get-Item -LiteralPath $_.FullName).VersionInfo.FileVersion
            sha256  = Get-HfDriveFileSha256 -Path $_.FullName
        }
    })

    $provenance = [ordered]@{
        timestamp_utc   = (Get-Date).ToUniversalTime().ToString('o')
        package         = [ordered]@{
            file        = $msixName
            sha256      = $msixHash
            size_bytes  = (Get-Item -LiteralPath $msixPath).Length
            identity    = [ordered]@{
                name                   = Get-HfDrivePackageName
                publisher              = $publisher
                version                = $Version
                processor_architecture = 'x64'
            }
            applications = [ordered]@{
                HFDrive  = 'HfDrive.Desktop.exe'
                Provider = 'provider\hfdrive-provider.exe'
                Cli      = 'cli\hfdrive.exe'
                Shell    = 'shell\HfDrive.Shell\HfDrive.Shell.dll (Explorer IExplorerCommand parent, CLSID 3071D4E7-5A86-4356-8BCE-CBB4E4C76734)'
            }
        }
        signing         = [ordered]@{
            mode                = if ($Production) { 'production' } else { 'development' }
            algorithm           = 'SHA256'
            certificate_thumbprint = if ($Unsigned) { $null } else { $certInfo.Certificate.Thumbprint }
            certificate_subject = if ($Unsigned) { $null } else { $certInfo.Certificate.Subject }
            certificate_not_after = if ($Unsigned) { $null } else { $certInfo.Certificate.NotAfter.ToUniversalTime().ToString('o') }
            certificate_store   = if ($Unsigned) { 'not_run' } else { "$($certInfo.StoreName)\My" }
            timestamp_url       = $timestampUrl
            observed_signature_status = $signatureStatus
        }
        toolchain       = [ordered]@{
            pins                = $pins
            msbuild             = $buildEnv.MSBuild
            msbuild_version     = (& $buildEnv.MSBuild -version | Select-Object -Last 1).Trim()
            makeappx            = $buildEnv.MakeAppx
            makepri             = $buildEnv.MakePri
            signtool            = $buildEnv.SignTool
            windows_sdk         = $buildEnv.WindowsSdkVersion
            windows_sdk_servicing = $buildEnv.WindowsSdkServicing
            vc_tools            = $buildEnv.VcToolsVersion
            dotnet_sdk          = $buildEnv.DotNetSdkVersion
            dotnet_runtime      = '11.0.0'
            windows_app_sdk     = '2.6.5'
        }
        dependencies    = [ordered]@{
            dotnet_mode             = 'self-contained (runtime 11.0.0 app-local)'
            windows_app_sdk_mode    = 'self-contained (app-local)'
            vc_crt_mode             = "app-local release $($buildEnv.VcToolsVersion) beside HfDrive.Desktop.exe, provider\hfdrive-provider.exe, cli\hfdrive.exe, shell\HfDrive.Shell\HfDrive.Shell.dll"
            framework_dependencies  = $frameworkDependencies
            framework_dependencies_dir = if ($frameworkDependencies.Count -gt 0) { $dependenciesDir } else { $null }
            vc_crt_files            = $crtInventory
            key_file_versions       = [ordered]@{
                HfDrive_Desktop_exe   = Get-FileVersionSafe (Join-Path $layoutDir 'HfDrive.Desktop.exe')
                hfdrive_provider_exe  = Get-FileVersionSafe (Join-Path $layoutDir 'provider\hfdrive-provider.exe')
                hfdrive_exe           = Get-FileVersionSafe (Join-Path $layoutDir 'cli\hfdrive.exe')
                HfDrive_Shell_dll     = Get-FileVersionSafe (Join-Path $layoutDir 'shell\HfDrive.Shell\HfDrive.Shell.dll')
                System_Private_CoreLib_dll = Get-FileVersionSafe (Join-Path $layoutDir 'System.Private.CoreLib.dll')
                Microsoft_WinUI_dll   = Get-FileVersionSafe (Join-Path $layoutDir 'Microsoft.WinUI.dll')
            }
            layout_file_count       = @(Get-ChildItem -LiteralPath $layoutDir -Recurse -File).Count
            layout_total_bytes      = (Get-ChildItem -LiteralPath $layoutDir -Recurse -File | Measure-Object Length -Sum).Sum
        }
        external_gates  = [ordered]@{
            production_signing_identity = if ($Production) { 'passed (store certificate, publisher match, timestamped, verified)' } else { 'not_run (development-signed artifact only)' }
            clean_windows_install       = 'not_run (requires a clean Windows x64 account/VM without preinstalled .NET 11/Windows App Runtime)'
            trust_install               = 'not_run (certificate trust is a separate user-authorized step; never run by packaging)'
        }
    }

    $provenancePath = Join-Path $OutputDirectory "package-provenance-$Version.json"
    $provenance | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $provenancePath -Encoding utf8

    Write-Host ''
    Write-Host "Package:     $msixPath"
    Write-Host "SHA-256:     $msixHash"
    Write-Host "Provenance:  $provenancePath"
    Write-Host "Signing:     $(if ($Production) { 'production (timestamped, verified)' } else { "development ($signatureStatus until the separate trust step)" })"
}
finally {
    Pop-Location
}
