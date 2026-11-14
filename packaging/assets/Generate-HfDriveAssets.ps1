<#
.SYNOPSIS
    Generates the HF Drive MSIX visual assets (packaging/assets/*.png).

.DESCRIPTION
    Deterministically renders the asset set referenced by packaging/AppxManifest.xml:
      StoreLogo.png, Square44x44Logo.png, Square150x150Logo.png,
      Wide310x150Logo.png, SplashScreen.png and their .scale-100/125/150/200/400
    qualifiers. Re-running replaces only these files. The generated PNGs are
    committed to the repository; this script exists so the set can be reproduced
    or restyled without manual image editing.

.EXAMPLE
    pwsh -NoProfile -File packaging/assets/Generate-HfDriveAssets.ps1
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

$assetDir = $PSScriptRoot

# Name -> @(baseWidth, baseHeight); scale factors follow the Windows asset
# convention (scale-100 is the base size).
$assetSizes = [ordered]@{
    'StoreLogo'        = @(50, 50)
    'Square44x44Logo'  = @(44, 44)
    'Square150x150Logo' = @(150, 150)
    'Wide310x150Logo'  = @(310, 150)
    'SplashScreen'     = @(620, 300)
}
$scales = @(100, 125, 150, 200, 400)

function New-HfDriveAsset([int]$Width, [int]$Height, [string]$Path) {
    $bitmap = [System.Drawing.Bitmap]::new($Width, $Height)
    try {
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $graphics.Clear([System.Drawing.Color]::FromArgb(255, 18, 42, 67))

            # Accent mark: centered circle scaled to the short edge.
            $short = [Math]::Min($Width, $Height)
            $diameter = [int][Math]::Round($short * 0.52)
            $x = [int](($Width - $diameter) / 2)
            $y = [int](($Height - $diameter) / 2)
            $accent = [System.Drawing.SolidBrush]::new(
                [System.Drawing.Color]::FromArgb(255, 255, 210, 30))
            try {
                $graphics.FillEllipse($accent, $x, $y, $diameter, $diameter)
            }
            finally {
                $accent.Dispose()
            }
        }
        finally {
            $graphics.Dispose()
        }
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $bitmap.Dispose()
    }
}

foreach ($entry in $assetSizes.GetEnumerator()) {
    $baseW = $entry.Value[0]
    $baseH = $entry.Value[1]
    foreach ($scale in $scales) {
        $factor = $scale / 100
        $w = [int][Math]::Round($baseW * $factor)
        $h = [int][Math]::Round($baseH * $factor)
        # The unsuffixed file is the scale-100 image, as referenced by the manifest.
        $name = if ($scale -eq 100) { "$($entry.Key).png" } else { "$($entry.Key).scale-$scale.png" }
        $path = Join-Path $assetDir $name
        New-HfDriveAsset -Width $w -Height $h -Path $path
        Write-Host "wrote $name ($w x $h)"
    }
}

Write-Host "HF Drive assets generated in $assetDir"
