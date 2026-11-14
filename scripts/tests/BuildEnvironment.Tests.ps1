$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Initialize-BuildEnvironment.ps1')

$pinned = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\makeappx.exe'
$developerShell = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\\x64\makeappx.exe'
if (-not (Test-HfDrivePathEqual $pinned $developerShell)) {
    throw 'Developer-shell duplicate separators must not reject the pinned SDK executable.'
}
if (-not (Test-HfDrivePathEqual $pinned $pinned.ToUpperInvariant())) {
    throw 'Windows executable identity comparison must ignore path casing.'
}
if (Test-HfDrivePathEqual $pinned ($pinned.Replace('10.0.28000.0', '10.0.26100.0'))) {
    throw 'An older SDK executable must still be rejected.'
}
if (Test-HfDrivePathEqual '' $pinned) {
    throw 'An absent executable must not match the pinned SDK.'
}
Write-Output 'Build environment path-selection regression: passed'
