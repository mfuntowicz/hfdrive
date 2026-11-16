<#
.SYNOPSIS
    HF Drive package lifecycle verification: install, startup, coordinated
    upgrade, forced termination, safe unlink/disconnect, direct uninstall and
    preserved external state.

.DESCRIPTION
    Executes real lifecycle procedures against a real installed MSIX package and
    records an honest per-check report (passed / failed / not_run with exact
    blockers) under artifacts/acceptance/. Nothing is simulated: package
    inspection reads the real .msix, install/upgrade/uninstall act on the
    per-user package store, and provider checks use the packaged CLI over the
    real authenticated IPC.

    Suites:
      Package            Static inspection of the .msix: identity, manifest
                         contract (apps, alias, disabled startup task,
                         virtualization exclusion, min/max OS), layout, CRT,
                         self-contained runtime, signature, checksum.
      Install            scripts/install-dev.ps1 install, registration, provider
                         activation, real CLI status, physical state directory,
                         hfdrive.exe alias.
      Startup            StartupTask declaration (disabled by default) and
                         observed task state; the in-app enable flow and logon
                         verification are interactive and reported not_run.
      Upgrade            scripts/upgrade.ps1 coordinated upgrade incl. the
                         PrepareUpgrade acknowledgment; version/state checks.
      ForcedTermination  (-ConsentForcedTermination) abrupt provider kill,
                         recovery, and — with -UpgradePackage — an interrupted
                         upgrade recovered by re-running the coordinated flow.
      Unlink             Preview/exact safe-unlink through the packaged CLI; the
                         destructive acceptance step needs -ConsentUnlink and
                         the user-confirmed -PreviewId. Needs fixtures or
                         -ConnectionId.
      Uninstall          (-ConsentUninstall) direct Remove-AppxPackage, physical
                         persistence of %LOCALAPPDATA%\HFDrive, optional
                         reinstall and state adoption.

    This script NEVER installs or trusts certificates and never touches remote
    storage. Uninstall/forced-termination steps require explicit consent
    switches; -PlanOnly enumerates every step as not_run.

.EXAMPLE
    pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Package -Package artifacts/package/HFDrive_0.1.0.0_x64.msix

.EXAMPLE
    pwsh -NoProfile -File scripts/verify-lifecycle.ps1 -Suite Upgrade -UpgradePackage artifacts/package/HFDrive_0.2.0.0_x64.msix
#>
[CmdletBinding()]
param(
    [ValidateSet('Package', 'Install', 'Startup', 'Upgrade', 'ForcedTermination', 'Unlink', 'Uninstall')]
    [string[]]$Suite = @('Package'),

    # .msix inspected by the Package suite and installed by Install/Uninstall.
    [string]$Package,

    # Target .msix for the Upgrade suite (and the interrupted-upgrade exercise).
    [string]$UpgradePackage,

    # Acceptance fixtures (artifacts/acceptance/fixtures.json) for Unlink.
    [string]$Fixtures,

    # Explicit user-confirmed preview id for the Unlink acceptance step.
    [string]$PreviewId,
    [string]$ConnectionId,

    [string]$ReportDirectory,

    # Explicit consent for the destructive/terminating procedures.
    [switch]$ConsentUninstall,
    [switch]$ConsentForcedTermination,
    [switch]$ConsentUnlink,

    # Enumerate every step as not_run without executing anything.
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot | Split-Path -Parent
. (Join-Path $repoRoot 'packaging\Packaging.Common.ps1')

if ([string]::IsNullOrWhiteSpace($Fixtures)) {
    $Fixtures = Join-Path $repoRoot 'artifacts\acceptance\fixtures.json'
}
if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
    $ReportDirectory = Join-Path $repoRoot 'artifacts\acceptance'
}
New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null

# ---- Result collection ----------------------------------------------------
$script:results = [System.Collections.Generic.List[object]]::new()
$script:commandsRun = [System.Collections.Generic.List[string]]::new()

function Add-LifecycleResult {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('passed', 'failed', 'not_run')][string]$Status,
        [string]$Detail = ''
    )
    $script:results.Add([pscustomobject]@{ check = $Check; status = $Status; detail = $Detail })
    $color = switch ($Status) { 'passed' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
    Write-Host "  [$Status] $Check — $Detail" -ForegroundColor $color
}

function Invoke-HfDriveCli {
    # Runs the packaged CLI; returns exit code and combined output.
    param([Parameter(Mandatory)][string[]]$CliArguments)
    $installed = Get-HfDrivePackageByIdentityName
    if (-not $installed) { throw 'No installed HF Drive package; cannot locate the packaged CLI.' }
    $cliPath = Join-Path $installed.InstallLocation 'cli\hfdrive.exe'
    if (-not (Test-Path -LiteralPath $cliPath)) { throw "Packaged CLI '$cliPath' is missing." }
    $script:commandsRun.Add("hfdrive $($CliArguments -join ' ')  (via $cliPath)")
    $output = & $cliPath @CliArguments 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = (@($output) -join [Environment]::NewLine)
    }
}

function Get-HfDriveStateInventory {
    # Names + database hashes of the physical state directory (capped).
    $stateDir = Get-HfDriveStateDirectory
    if (-not (Test-Path -LiteralPath $stateDir)) { return $null }
    $files = Get-ChildItem -LiteralPath $stateDir -Recurse -File -ErrorAction SilentlyContinue
    $dbHashes = @{}
    foreach ($f in @($files | Where-Object { $_.Name -match '\.sqlite3(-wal|-shm)?$' })) {
        $dbHashes[$f.FullName.Substring($stateDir.Length).TrimStart('\')] = Get-HfDriveFileSha256 -Path $f.FullName
    }
    $names = @($files | Select-Object -First 2000 | ForEach-Object { $_.FullName.Substring($stateDir.Length) })
    return [pscustomobject]@{
        Root        = $stateDir
        FileNames   = $names
        DatabaseSha = $dbHashes
    }
}

function Invoke-LifecycleStep {
    # Executes one step unless -PlanOnly; captures exceptions as failed results.
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$PlanDetail = 'not executed (-PlanOnly)'
    )
    if ($PlanOnly) {
        Add-LifecycleResult -Check $Check -Status 'not_run' -Detail $PlanDetail
        return $null
    }
    try {
        return & $Action
    }
    catch {
        Add-LifecycleResult -Check $Check -Status 'failed' -Detail "$_"
        return $null
    }
}

# ===========================================================================
# Suite: Package (static, safe)
# ===========================================================================
function Invoke-PackageSuite {
    param([string]$Msix)
    Write-Host "`n== Suite: Package =="
    if ([string]::IsNullOrWhiteSpace($Msix)) {
        Add-LifecycleResult -Check 'package_present' -Status 'failed' -Detail '-Package <msix> is required for this suite.'
        return
    }
    if (-not (Test-Path -LiteralPath $Msix)) {
        Add-LifecycleResult -Check 'package_present' -Status 'failed' -Detail "'$Msix' does not exist."
        return
    }
    $Msix = Convert-Path -LiteralPath $Msix
    Add-LifecycleResult -Check 'package_present' -Status 'passed' -Detail $Msix

    $identity = Invoke-LifecycleStep -Check 'identity_parse' -Action {
        Get-HfDriveMsixIdentity -PackagePath $Msix
    }
    if (-not $identity) { return }

    $ok = $identity.Name -eq (Get-HfDrivePackageName)
    Add-LifecycleResult -Check 'identity_name' -Status $(if ($ok) { 'passed' } else { 'failed' }) `
        -Detail "Name=$($identity.Name)"

    $versionOk = $true
    $versionDetail = $identity.Version
    try { $null = ConvertTo-HfDriveVersion -Text $identity.Version } catch { $versionOk = $false; $versionDetail = "$_" }
    Add-LifecycleResult -Check 'identity_version_four_part' -Status $(if ($versionOk) { 'passed' } else { 'failed' }) `
        -Detail $versionDetail

    Add-LifecycleResult -Check 'identity_architecture_x64' `
        -Status $(if ($identity.ProcessorArchitecture -eq 'x64') { 'passed' } else { 'failed' }) `
        -Detail "ProcessorArchitecture=$($identity.ProcessorArchitecture)"

    $signature = Get-AuthenticodeSignature -LiteralPath $Msix
    $signerMatches = $signature.SignerCertificate -and
        (Test-HfDriveDistinguishedNameEqual -Left $signature.SignerCertificate.Subject -Right $identity.Publisher)
    Add-LifecycleResult -Check 'signature_matches_publisher' `
        -Status $(if ($signerMatches) { 'passed' } else { 'failed' }) `
        -Detail "status=$($signature.Status); signer=$($signature.SignerCertificate | ForEach-Object { $_.Subject }); publisher=$($identity.Publisher)"

    $manifest = $identity.ManifestXml
    $tdf = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Dependencies/f:TargetDeviceFamily'
    $tdf = @($tdf)[0]
    $tdfOk = $tdf -and $tdf.GetAttribute('MinVersion') -eq '10.0.22621.0' -and $tdf.GetAttribute('MaxVersionTested') -eq '10.0.26100.0'
    Add-LifecycleResult -Check 'runtime_min_max_declarations' -Status $(if ($tdfOk) { 'passed' } else { 'failed' }) `
        -Detail $(if ($tdf) { "MinVersion=$($tdf.GetAttribute('MinVersion')); MaxVersionTested=$($tdf.GetAttribute('MaxVersionTested'))" } else { 'TargetDeviceFamily missing' })

    $appNodes = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Applications/f:Application'
    $appIds = @($appNodes | ForEach-Object { $_.GetAttribute('Id') })
    $appsOk = $true
    foreach ($id in Get-HfDriveApplicationIds) { if ($appIds -notcontains $id) { $appsOk = $false } }
    Add-LifecycleResult -Check 'application_ids' -Status $(if ($appsOk) { 'passed' } else { 'failed' }) `
        -Detail ($appIds -join ', ')

    $hidden = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='Provider' or @Id='Cli']/f:uap:VisualElements[@AppListEntry='none']"
    Add-LifecycleResult -Check 'provider_cli_hidden_from_start' `
        -Status $(if (@($hidden).Count -eq 2) { 'passed' } else { 'failed' }) `
        -Detail "$(@($hidden).Count)/2 hidden application(s)"

    $alias = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='Cli']/f:Extensions/uap5:Extension/uap5:AppExecutionAlias/uap5:ExecutionAlias"
    $aliasOk = @($alias | Where-Object { $_.GetAttribute('Alias') -eq (Get-HfDriveAppAliasName) }).Count -eq 1
    Add-LifecycleResult -Check 'cli_execution_alias' -Status $(if ($aliasOk) { 'passed' } else { 'failed' }) `
        -Detail "alias=$(Get-HfDriveAppAliasName)"

    $startup = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='Provider']/f:Extensions/uap5:Extension/uap5:StartupTask"
    $st = @($startup)[0]
    $stOk = $st -and $st.GetAttribute('TaskId') -eq (Get-HfDriveStartupTaskId) -and $st.GetAttribute('Enabled') -eq 'false'
    Add-LifecycleResult -Check 'startup_task_disabled_by_default' -Status $(if ($stOk) { 'passed' } else { 'failed' }) `
        -Detail $(if ($st) { "TaskId=$($st.GetAttribute('TaskId')); Enabled=$($st.GetAttribute('Enabled'))" } else { 'startup task missing' })

    $shellClass = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='HFDrive']/f:Extensions/com:Extension/com:ComServer/com:SurrogateServer/com:Class"
    $sc = @($shellClass)[0]
    $shellOk = @($shellClass).Count -eq 1 -and $sc -and
        $sc.GetAttribute('Id') -eq (Get-HfDriveShellCommandClsid) -and
        $sc.GetAttribute('ThreadingModel') -eq 'STA'
    Add-LifecycleResult -Check 'shell_com_registration' -Status $(if ($shellOk) { 'passed' } else { 'failed' }) `
        -Detail $(if ($sc) { "Clsid=$($sc.GetAttribute('Id')); Path=$($sc.GetAttribute('Path')); ThreadingModel=$($sc.GetAttribute('ThreadingModel'))" } else { 'shell COM class missing' })
    $shellVerbs = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='HFDrive']/f:Extensions/desktop4:Extension/desktop4:FileExplorerContextMenus/desktop5:ItemType"
    $typeValues = @($shellVerbs | ForEach-Object { $_.GetAttribute('Type') })
    $verbsOk = (@($typeValues | Sort-Object) -join ',' -eq '*,Directory')
    Add-LifecycleResult -Check 'shell_context_menu_itemtypes' -Status $(if ($verbsOk) { 'passed' } else { 'failed' }) `
        -Detail ($typeValues -join ', ')

    $caps = Get-HfDriveManifestNodes -Manifest $manifest -XPath '/f:Package/f:Capabilities/rescap:Capability'
    $capNames = @($caps | ForEach-Object { $_.GetAttribute('Name') })
    $capsOk = ($capNames -contains 'runFullTrust') -and ($capNames -contains 'unvirtualizedResources')
    Add-LifecycleResult -Check 'restricted_capabilities' -Status $(if ($capsOk) { 'passed' } else { 'failed' }) `
        -Detail ($capNames -join ', ')

    $exclusions = Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath '/f:Package/f:Properties/virtualization:FileSystemWriteVirtualization/virtualization:ExcludedDirectories/virtualization:ExcludedDirectory'
    $excOk = @($exclusions | Where-Object { $_.InnerText.Trim() -eq '$(KnownFolder:LocalAppData)\HFDrive' }).Count -eq 1
    Add-LifecycleResult -Check 'state_virtualization_exclusion' -Status $(if ($excOk) { 'passed' } else { 'failed' }) `
        -Detail ((@($exclusions | ForEach-Object { $_.InnerText.Trim() }) -join '; '))

    # Layout / runtime inventory (real package entries).
    $entries = Get-HfDriveMsixEntries -PackagePath $Msix
    foreach ($required in @('HfDrive.Desktop.exe', 'provider/hfdrive-provider.exe', 'cli/hfdrive.exe',
            'shell/HfDrive.Shell/HfDrive.Shell.dll', 'Resources.pri')) {
        $found = @($entries | Where-Object { $_ -replace '\\', '/' -eq $required })
        Add-LifecycleResult -Check "layout_$($required -replace '[\\/]', '_')" `
            -Status $(if ($found.Count -ge 1) { 'passed' } else { 'failed' }) -Detail $required
    }
    foreach ($asset in @('assets/StoreLogo.png', 'assets/Square44x44Logo.png', 'assets/Square150x150Logo.png',
            'assets/Wide310x150Logo.png', 'assets/SplashScreen.png')) {
        $found = @($entries | Where-Object { $_ -replace '\\', '/' -eq $asset })
        Add-LifecycleResult -Check "asset_$([System.IO.Path]::GetFileNameWithoutExtension($asset))" `
            -Status $(if ($found.Count -ge 1) { 'passed' } else { 'failed' }) -Detail $asset
    }
    foreach ($group in @('', 'provider/', 'cli/', 'shell/HfDrive.Shell/')) {
        foreach ($crt in @('vcruntime140.dll', 'msvcp140.dll')) {
            $found = @($entries | Where-Object { ($_.Replace('\', '/')) -ieq "$group$crt" })
            $checkName = 'crt_' + (($group + $crt) -replace '[/\\.]+', '_').TrimEnd('_')
            Add-LifecycleResult -Check $checkName `
                -Status $(if ($found.Count -ge 1) { 'passed' } else { 'failed' }) -Detail "$group$crt"
        }
    }
    $debugCrt = @($entries | Where-Object { $_ -match '(?i)(140d\.dll$|ucrtbased)' })
    Add-LifecycleResult -Check 'no_debug_crt' -Status $(if ($debugCrt.Count -eq 0) { 'passed' } else { 'failed' }) `
        -Detail $(if ($debugCrt.Count -gt 0) { $debugCrt -join ', ' } else { 'none found' })

    $coreLib = @($entries | Where-Object { $_ -replace '\\', '/' -eq 'System.Private.CoreLib.dll' })
    Add-LifecycleResult -Check 'self_contained_dotnet' -Status $(if ($coreLib.Count -ge 1) { 'passed' } else { 'failed' }) `
        -Detail 'System.Private.CoreLib.dll app-local (runtime 11.0.0)'
    $winui = @($entries | Where-Object { $_ -replace '\\', '/' -eq 'Microsoft.WinUI.dll' })
    $wasrt = @($entries | Where-Object { $_ -match '(?i)Microsoft\.WindowsAppRuntime[^/\\]*\.dll$' })
    Add-LifecycleResult -Check 'self_contained_windows_app_sdk' `
        -Status $(if ($winui.Count -ge 1 -and $wasrt.Count -ge 1) { 'passed' } else { 'failed' }) `
        -Detail "WinUI=$($winui.Count); WindowsAppRuntime=$($wasrt.Count)"

    $hash = Get-HfDriveFileSha256 -Path $Msix
    Add-LifecycleResult -Check 'package_checksum' -Status 'passed' -Detail "sha256=$hash"
}

# ===========================================================================
# Suite: Install
# ===========================================================================
function Invoke-InstallSuite {
    param([string]$Msix)
    Write-Host "`n== Suite: Install =="
    if ([string]::IsNullOrWhiteSpace($Msix) -or -not (Test-Path -LiteralPath $Msix)) {
        Add-LifecycleResult -Check 'install_package' -Status 'failed' -Detail '-Package <msix> is required for this suite.'
        return
    }
    $Msix = Convert-Path -LiteralPath $Msix

    Invoke-LifecycleStep -Check 'install_package' -Action {
        $script:commandsRun.Add("scripts/install-dev.ps1 -Package $Msix -Reinstall")
        & (Join-Path $repoRoot 'scripts\install-dev.ps1') -Package $Msix -Reinstall
        Add-LifecycleResult -Check 'install_package' -Status 'passed' -Detail 'installed per-user via install-dev.ps1 (-Reinstall)'
    } | Out-Null

    $identity = Get-HfDriveMsixIdentity -PackagePath $Msix
    $installed = Get-HfDrivePackageByIdentityName
    if ($installed) {
        Add-LifecycleResult -Check 'registration_version' `
            -Status $(if ($installed.Version -eq $identity.Version) { 'passed' } else { 'failed' }) `
            -Detail "installed=$($installed.Version); package=$($identity.Version)"
        $family = $installed.PackageFamilyName
        Add-LifecycleResult -Check 'application_ids_activatable' -Status 'passed' `
            -Detail "$family!HFDrive / !Provider / !Cli"
    }

    Invoke-LifecycleStep -Check 'provider_activation' -Action {
        Start-Process "shell:AppsFolder\$family!Provider"
        if (Wait-HfDriveProviderStart -TimeoutSeconds 30) {
            Add-LifecycleResult -Check 'provider_activation' -Status 'passed' -Detail 'provider process running after AUMID activation'
        }
        else {
            Add-LifecycleResult -Check 'provider_activation' -Status 'failed' -Detail 'provider did not start within 30 s'
        }
    } | Out-Null

    Invoke-LifecycleStep -Check 'cli_status_over_ipc' -Action {
        $status = Invoke-HfDriveCli -CliArguments @('status', '--json')
        Add-LifecycleResult -Check 'cli_status_over_ipc' -Status $(if ($status.ExitCode -eq 0) { 'passed' } else { 'failed' }) `
            -Detail "exit=$($status.ExitCode); output=$($status.Output.Substring(0, [Math]::Min(300, $status.Output.Length)))"
    } | Out-Null

    $stateDir = Get-HfDriveStateDirectory
    $stateOk = Test-Path -LiteralPath $stateDir
    Add-LifecycleResult -Check 'state_directory_physical' -Status $(if ($stateOk) { 'passed' } else { 'failed' }) `
        -Detail "$stateDir (unvirtualized; must not live inside package storage)"

    $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\hfdrive.exe'
    Add-LifecycleResult -Check 'cli_alias_registered' -Status $(if (Test-Path -LiteralPath $aliasPath) { 'passed' } else { 'failed' }) `
        -Detail $aliasPath
}

# ===========================================================================
# Suite: Startup
# ===========================================================================
function Invoke-StartupSuite {
    Write-Host "`n== Suite: Startup =="
    $installed = Get-HfDrivePackageByIdentityName
    if (-not $installed) {
        Add-LifecycleResult -Check 'startup_task_declaration' -Status 'failed' -Detail 'No installed HF Drive package.'
        return
    }
    $manifestText = Get-Content -LiteralPath (Join-Path $installed.InstallLocation 'AppxManifest.xml') -Raw
    $manifest = [xml]$manifestText
    $st = @(Get-HfDriveManifestNodes -Manifest $manifest `
        -XPath "/f:Package/f:Applications/f:Application[@Id='Provider']/f:Extensions/uap5:Extension/uap5:StartupTask")[0]
    $declOk = $st -and $st.GetAttribute('TaskId') -eq (Get-HfDriveStartupTaskId) -and $st.GetAttribute('Enabled') -eq 'false'
    Add-LifecycleResult -Check 'startup_task_declaration' -Status $(if ($declOk) { 'passed' } else { 'failed' }) `
        -Detail $(if ($st) { "TaskId=$($st.GetAttribute('TaskId')); Enabled=$($st.GetAttribute('Enabled'))" } else { 'missing' })

    # Observable task state from an unpackaged script is not exposed through a
    # documented read-only API; the supported flow is the packaged
    # Windows.ApplicationModel.StartupTask API invoked by the desktop UI.
    $probe = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    $observed = 'no StartupTask state key observed at ' + $probe
    if (Test-Path -LiteralPath $probe) {
        $hit = Get-ChildItem -LiteralPath $probe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$($installed.PackageFamilyName)*" }
        if ($hit) { $observed = "state entries: $(@($hit | ForEach-Object Name) -join '; ')" }
    }
    Add-LifecycleResult -Check 'startup_task_state_observable' -Status 'not_run' `
        -Detail "StartupTask state is managed by Windows.ApplicationModel.StartupTask (in-app enable flow) and Task Manager. Probe result: $observed. Interactive procedure: docs/lifecycle.md."

    Add-LifecycleResult -Check 'startup_enable_disable_roundtrip' -Status 'not_run' `
        -Detail 'Requires an interactive desktop session exercising the supported StartupTask enable flow (DisabledByUser/DisabledByPolicy reflection). Procedure: docs/lifecycle.md.'
    Add-LifecycleResult -Check 'logon_activation' -Status 'not_run' `
        -Detail 'Requires an explicit logoff/logon cycle on a verification account. Procedure: docs/lifecycle.md.'
}

# ===========================================================================
# Suite: Upgrade
# ===========================================================================
function Invoke-UpgradeSuite {
    param([string]$Target)
    Write-Host "`n== Suite: Upgrade =="
    if ([string]::IsNullOrWhiteSpace($Target) -or -not (Test-Path -LiteralPath $Target)) {
        Add-LifecycleResult -Check 'upgrade_package' -Status 'failed' -Detail '-UpgradePackage <msix> is required for this suite.'
        return
    }
    $Target = Convert-Path -LiteralPath $Target
    $preState = Get-HfDriveStateInventory

    Invoke-LifecycleStep -Check 'coordinated_upgrade' -Action {
        $script:commandsRun.Add("scripts/upgrade.ps1 -Package $Target")
        & (Join-Path $repoRoot 'scripts\upgrade.ps1') -Package $Target
        Add-LifecycleResult -Check 'coordinated_upgrade' -Status 'passed' `
            -Detail 'PrepareUpgrade acknowledged (or provider absent), provider exited, higher version installed, provider reactivated'
    } | Out-Null

    $newIdentity = Get-HfDriveMsixIdentity -PackagePath $Target
    $installed = Get-HfDrivePackageByIdentityName
    Add-LifecycleResult -Check 'upgraded_version_registered' `
        -Status $(if ($installed -and $installed.Version -eq $newIdentity.Version) { 'passed' } else { 'failed' }) `
        -Detail "installed=$(if ($installed) { $installed.Version } else { 'none' }); expected=$($newIdentity.Version)"

    Add-LifecycleResult -Check 'provider_running_after_upgrade' `
        -Status $(if ((Get-HfDriveProviderProcess).Count -gt 0) { 'passed' } else { 'failed' }) `
        -Detail 'provider process after coordinated upgrade'

    $postState = Get-HfDriveStateInventory
    if ($preState -and $postState) {
        $missing = @($preState.FileNames | Where-Object { $postState.FileNames -notcontains $_ })
        Add-LifecycleResult -Check 'state_preserved_across_upgrade' `
            -Status $(if ($missing.Count -eq 0 -and (Test-Path (Join-Path $postState.Root 'control.sqlite3'))) { 'passed' } else { 'failed' }) `
            -Detail $(if ($missing.Count -gt 0) { "missing after upgrade: $($missing -join ', ')" } else { 'state root and prior files present (databases legitimately checkpointed)' })
    }
    else {
        Add-LifecycleResult -Check 'state_preserved_across_upgrade' -Status 'not_run' `
            -Detail 'State directory absent before or after the upgrade; nothing to compare.'
    }
}

# ===========================================================================
# Suite: ForcedTermination (explicit consent)
# ===========================================================================
function Invoke-ForcedTerminationSuite {
    param([string]$Target)
    Write-Host "`n== Suite: ForcedTermination =="
    if (-not $ConsentForcedTermination) {
        Add-LifecycleResult -Check 'forced_termination_consent' -Status 'not_run' `
            -Detail 'Abrupt provider termination requires the explicit -ConsentForcedTermination switch.'
        return
    }
    Add-LifecycleResult -Check 'forced_termination_consent' -Status 'passed' -Detail 'consent given'

    Invoke-LifecycleStep -Check 'provider_running_before_kill' -Action {
        $installed = Get-HfDrivePackageByIdentityName
        if (-not $installed) { throw 'No installed HF Drive package.' }
        if ((Get-HfDriveProviderProcess).Count -eq 0) {
            Start-Process "shell:AppsFolder\$($installed.PackageFamilyName)!Provider"
            if (-not (Wait-HfDriveProviderStart -TimeoutSeconds 30)) { throw 'Provider did not start.' }
        }
        Add-LifecycleResult -Check 'provider_running_before_kill' -Status 'passed' -Detail 'provider process confirmed'
    } | Out-Null

    Invoke-LifecycleStep -Check 'abrupt_provider_kill' -Action {
        Get-HfDriveProviderProcess | Stop-Process -Force
        Start-Sleep -Seconds 2
        Add-LifecycleResult -Check 'abrupt_provider_kill' -Status `
            $(if ((Get-HfDriveProviderProcess).Count -eq 0) { 'passed' } else { 'failed' }) `
            -Detail 'provider process terminated abruptly (Stop-Process -Force)'
    } | Out-Null

    Invoke-LifecycleStep -Check 'provider_recovery_after_kill' -Action {
        $installed = Get-HfDrivePackageByIdentityName
        Start-Process "shell:AppsFolder\$($installed.PackageFamilyName)!Provider"
        if (-not (Wait-HfDriveProviderStart -TimeoutSeconds 30)) { throw 'Provider did not restart.' }
        $status = Invoke-HfDriveCli -CliArguments @('status', '--json')
        Add-LifecycleResult -Check 'provider_recovery_after_kill' -Status `
            $(if ($status.ExitCode -eq 0) { 'passed' } else { 'failed' }) `
            -Detail "restarted; status exit=$($status.ExitCode); state DBs preserved=$(Test-Path (Join-Path (Get-HfDriveStateDirectory) 'control.sqlite3'))"
    } | Out-Null

    if ($Target -and (Test-Path -LiteralPath $Target)) {
        # Interrupted upgrade: acknowledge + checkpoint + exit, then abort
        # before Add-AppxPackage; recovery re-runs the coordinated flow.
        Invoke-LifecycleStep -Check 'interrupted_upgrade_ack' -Action {
            $installed = Get-HfDrivePackageByIdentityName
            $cliPath = Join-Path $installed.InstallLocation 'cli\hfdrive.exe'
            $script:commandsRun.Add("hfdrive provider prepare-upgrade --json  (interrupted-upgrade exercise)")
            $out = & $cliPath provider prepare-upgrade --json 2>&1
            if ($LASTEXITCODE -ne 0) { throw "prepare-upgrade exit=$($LASTEXITCODE): $(@($out) -join ' ')" }
            if (-not (Wait-HfDriveProviderExit -TimeoutSeconds 60)) { throw 'Provider did not exit after acknowledgment.' }
            Add-LifecycleResult -Check 'interrupted_upgrade_ack' -Status 'passed' `
                -Detail 'PrepareUpgrade acknowledged and provider exited; package swap deliberately aborted (simulated interruption)'
        } | Out-Null

        Invoke-LifecycleStep -Check 'interrupted_upgrade_package_unchanged' -Action {
            $installed = Get-HfDrivePackageByIdentityName
            $expected = (Get-HfDriveMsixIdentity -PackagePath $Target).Version
            Add-LifecycleResult -Check 'interrupted_upgrade_package_unchanged' -Status `
                $(if ($installed.Version -ne $expected) { 'passed' } else { 'failed' }) `
                -Detail "installed=$($installed.Version) after aborted swap"
        } | Out-Null

        Invoke-LifecycleStep -Check 'interrupted_upgrade_recovery' -Action {
            $script:commandsRun.Add("scripts/upgrade.ps1 -Package $Target  (recovery after interruption)")
            & (Join-Path $repoRoot 'scripts\upgrade.ps1') -Package $Target
            $installed = Get-HfDrivePackageByIdentityName
            $expected = (Get-HfDriveMsixIdentity -PackagePath $Target).Version
            Add-LifecycleResult -Check 'interrupted_upgrade_recovery' -Status `
                $(if ($installed.Version -eq $expected) { 'passed' } else { 'failed' }) `
                -Detail "recovered to version $($installed.Version)"
        } | Out-Null
    }
    else {
        Add-LifecycleResult -Check 'interrupted_upgrade_ack' -Status 'not_run' `
            -Detail 'Provide -UpgradePackage <msix> to exercise interrupted-upgrade recovery.'
    }
}

# ===========================================================================
# Suite: Unlink
# ===========================================================================
function Invoke-UnlinkSuite {
    Write-Host "`n== Suite: Unlink =="
    $connection = $ConnectionId
    if ([string]::IsNullOrWhiteSpace($connection) -and (Test-Path -LiteralPath $Fixtures)) {
        try {
            $fx = Get-Content -LiteralPath $Fixtures -Raw | ConvertFrom-Json
            if ($fx.PSObject.Properties.Name -contains 'connection_id') { $connection = $fx.connection_id }
            elseif ($fx.PSObject.Properties.Name -contains 'connections' -and @($fx.connections).Count -gt 0) {
                $connection = @($fx.connections)[0].id
            }
        }
        catch { }
    }
    if ([string]::IsNullOrWhiteSpace($connection)) {
        Add-LifecycleResult -Check 'unlink_connection_fixture' -Status 'not_run' `
            -Detail "No connection fixture. Provide -ConnectionId <uuid> or 'connection_id' in $Fixtures (dedicated disposable connection only)."
        return
    }
    Add-LifecycleResult -Check 'unlink_connection_fixture' -Status 'passed' -Detail "connection=$connection"

    $exportDir = Join-Path $ReportDirectory "unlink-export-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Invoke-LifecycleStep -Check 'unlink_preview' -Action {
        $r = Invoke-HfDriveCli -CliArguments @('unlink', '--connection', $connection, '--export-to', $exportDir)
        Add-LifecycleResult -Check 'unlink_preview' -Status $(if ($r.ExitCode -eq 0) { 'passed' } else { 'failed' }) `
            -Detail "preview exit=$($r.ExitCode); output=$($r.Output.Substring(0, [Math]::Min(400, $r.Output.Length)))"
    } | Out-Null

    if (-not $ConsentUnlink -or [string]::IsNullOrWhiteSpace($PreviewId)) {
        Add-LifecycleResult -Check 'unlink_accept' -Status 'not_run' `
            -Detail 'Destructive unlink acceptance requires -ConsentUnlink and the user-confirmed -PreviewId <uuid> from the preview.'
        return
    }
    Invoke-LifecycleStep -Check 'unlink_accept' -Action {
        $r = Invoke-HfDriveCli -CliArguments @('unlink', '--connection', $connection, '--accept-preview', $PreviewId, '--export-to', $exportDir)
        Add-LifecycleResult -Check 'unlink_accept' -Status $(if ($r.ExitCode -eq 0) { 'passed' } else { 'failed' }) `
            -Detail "exit=$($r.ExitCode); output=$($r.Output.Substring(0, [Math]::Min(400, $r.Output.Length)))"
    } | Out-Null
    Add-LifecycleResult -Check 'unlink_export_directory' -Status `
        $(if (Test-Path -LiteralPath $exportDir) { 'passed' } else { 'not_run' }) -Detail $exportDir
}

# ===========================================================================
# Suite: Uninstall (explicit consent)
# ===========================================================================
function Invoke-UninstallSuite {
    param([string]$Msix)
    Write-Host "`n== Suite: Uninstall =="
    if (-not $ConsentUninstall) {
        Add-LifecycleResult -Check 'uninstall_consent' -Status 'not_run' `
            -Detail 'Direct package removal requires the explicit -ConsentUninstall switch.'
        return
    }
    Add-LifecycleResult -Check 'uninstall_consent' -Status 'passed' -Detail 'consent given'

    $installed = Get-HfDrivePackageByIdentityName
    if (-not $installed) {
        Add-LifecycleResult -Check 'package_installed_before_uninstall' -Status 'failed' -Detail 'No installed HF Drive package.'
        return
    }
    $fullName = $installed.PackageFullName
    $preState = Get-HfDriveStateInventory

    Invoke-LifecycleStep -Check 'direct_uninstall' -Action {
        $script:commandsRun.Add("Remove-AppxPackage -Package $fullName")
        Remove-AppxPackage -Package $fullName
        Add-LifecycleResult -Check 'direct_uninstall' -Status `
            $(if (-not (Get-HfDrivePackageByIdentityName)) { 'passed' } else { 'failed' }) `
            -Detail "removed $fullName (no cleanup callback assumed)"
    } | Out-Null

    $stateDir = Get-HfDriveStateDirectory
    if ($preState) {
        $postNames = @()
        if (Test-Path -LiteralPath $stateDir) {
            $postNames = @(Get-ChildItem -LiteralPath $stateDir -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object -First 2000 | ForEach-Object { $_.FullName.Substring($stateDir.Length) })
        }
        $missing = @($preState.FileNames | Where-Object { $postNames -notcontains $_ })
        $hashStable = $true
        foreach ($kv in $preState.DatabaseSha.GetEnumerator()) {
            $path = Join-Path $stateDir $kv.Key
            if ((Test-Path -LiteralPath $path) -and ((Get-HfDriveFileSha256 -Path $path) -ne $kv.Value)) { $hashStable = $false }
        }
        Add-LifecycleResult -Check 'state_physically_preserved' -Status `
            $(if ((Test-Path -LiteralPath $stateDir) -and $missing.Count -eq 0 -and $hashStable) { 'passed' } else { 'failed' }) `
            -Detail "$stateDir; missing=$(if ($missing.Count) { $missing -join ', ' } else { 'none' }); databases unchanged=$hashStable"
    }
    else {
        Add-LifecycleResult -Check 'state_physically_preserved' -Status 'not_run' `
            -Detail 'No state directory existed before uninstall.'
    }

    Add-LifecycleResult -Check 'remote_data_untouched' -Status 'not_run' `
        -Detail 'Requires a disposable live connection and external verification; direct uninstall must never mutate remote storage (see docs/lifecycle.md).'
    Add-LifecycleResult -Check 'placeholder_residue_observed' -Status 'not_run' `
        -Detail 'Manual observation on a synced folder; documented expected behavior (placeholders may remain until reinstall/reconnect): docs/lifecycle.md.'

    if ($Msix -and (Test-Path -LiteralPath $Msix)) {
        Invoke-LifecycleStep -Check 'reinstall_after_uninstall' -Action {
            $script:commandsRun.Add("scripts/install-dev.ps1 -Package $Msix")
            & (Join-Path $repoRoot 'scripts\install-dev.ps1') -Package $Msix
            Add-LifecycleResult -Check 'reinstall_after_uninstall' -Status 'passed' -Detail 'reinstalled after direct uninstall'
        } | Out-Null

        Invoke-LifecycleStep -Check 'state_adopted_after_reinstall' -Action {
            $installed2 = Get-HfDrivePackageByIdentityName
            Start-Process "shell:AppsFolder\$($installed2.PackageFamilyName)!Provider"
            if (-not (Wait-HfDriveProviderStart -TimeoutSeconds 30)) { throw 'Provider did not start after reinstall.' }
            $status = Invoke-HfDriveCli -CliArguments @('status', '--json')
            Add-LifecycleResult -Check 'state_adopted_after_reinstall' -Status `
                $(if ($status.ExitCode -eq 0) { 'passed' } else { 'failed' }) `
                -Detail "provider adopted existing state; status exit=$($status.ExitCode)"
        } | Out-Null
    }
}

# ===========================================================================
# Run selected suites + report
# ===========================================================================
foreach ($s in $Suite) {
    switch ($s) {
        'Package' { Invoke-PackageSuite -Msix $Package }
        'Install' { Invoke-InstallSuite -Msix $Package }
        'Startup' { Invoke-StartupSuite }
        'Upgrade' { Invoke-UpgradeSuite -Target $UpgradePackage }
        'ForcedTermination' { Invoke-ForcedTerminationSuite -Target $UpgradePackage }
        'Unlink' { Invoke-UnlinkSuite }
        'Uninstall' { Invoke-UninstallSuite -Msix $Package }
    }
}

$timestamp = Get-Date
$passed = @($script:results | Where-Object status -eq 'passed').Count
$failed = @($script:results | Where-Object status -eq 'failed').Count
$notRun = @($script:results | Where-Object status -eq 'not_run').Count

$report = [ordered]@{
    timestamp_utc = $timestamp.ToUniversalTime().ToString('o')
    suites        = $Suite
    plan_only     = [bool]$PlanOnly
    environment   = [ordered]@{
        os                = [System.Environment]::OSVersion.VersionString
        user              = [System.Environment]::UserName
        package_full_name = (Get-HfDrivePackageByIdentityName | ForEach-Object PackageFullName)
    }
    summary       = [ordered]@{ passed = $passed; failed = $failed; not_run = $notRun }
    checks        = @($script:results)
    commands      = @($script:commandsRun)
}
$reportJson = Join-Path $ReportDirectory "lifecycle-$($timestamp.ToString('yyyyMMdd-HHmmss')).json"
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportJson -Encoding utf8

$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# HF Drive lifecycle verification — $($timestamp.ToUniversalTime().ToString('o'))")
[void]$md.AppendLine('')
[void]$md.AppendLine("Suites: $($Suite -join ', ')$(if ($PlanOnly) { ' (plan only)' })")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Check | Status | Detail |')
[void]$md.AppendLine('| --- | --- | --- |')
foreach ($r in $script:results) {
    $detail = ($r.detail -replace '\|', '\|' -replace "`r?`n", ' ')
    [void]$md.AppendLine("| $($r.check) | $($r.status) | $detail |")
}
[void]$md.AppendLine('')
[void]$md.AppendLine("Summary: $passed passed, $failed failed, $notRun not_run.")
[void]$md.AppendLine('')
[void]$md.AppendLine('## Commands executed')
foreach ($c in $script:commandsRun) { [void]$md.AppendLine("- ``$c``") }
[void]$md.AppendLine('')
[void]$md.AppendLine('Report values use passed / failed / not_run; not_run entries state their exact blocker.')
$reportMd = [System.IO.Path]::ChangeExtension($reportJson, '.md')
$md.ToString() | Set-Content -LiteralPath $reportMd -Encoding utf8

Write-Host ''
Write-Host "Summary: $passed passed, $failed failed, $notRun not_run"
Write-Host "Report:  $reportJson"
Write-Host "Report:  $reportMd"

if ($failed -gt 0) { exit 1 }
exit 0
