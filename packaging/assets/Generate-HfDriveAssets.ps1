<#
.SYNOPSIS
    Generates the HF Drive visual assets from the supplied CatchingHuggy artwork.

.DESCRIPTION
    Deterministically renders the whole derived brand asset set from the
    untouched source artwork
    desktop/HfDrive.Desktop/Assets/CatchingHuggy.png:

      * packaging/assets/StoreLogo.png, Square44x44Logo.png,
        Square150x150Logo.png, Wide310x150Logo.png, SplashScreen.png and their
        .scale-125/150/200/400 qualifiers (the set referenced by
        packaging/AppxManifest.xml; names and scale set are unchanged);
      * desktop/HfDrive.Desktop/Assets/CatchingHuggy.ico with 16/20/24/32/40/
        48/64/128/256 px PNG-compressed entries for the desktop executable
        (ApplicationIcon), window and taskbar identity.

    Rendering crops the transparent padding to the artwork's alpha bounds, then
    fits the artwork into the target canvas with an alpha-weighted
    (premultiplied) Catmull-Rom resample and centers it. Nothing is recolored
    and no background or drop shadow is painted: every generated raster keeps
    the source transparency.

    The supplied originals (CatchingHuggy.png, SuperHuggy.png,
    VibingHuggy.gif, HuggyPop.gif) are read-only inputs and are never written.
    Re-running reproduces the same asset set from the same artwork; the
    generated files are committed to the repository and this script exists so
    the set can be reproduced without manual image editing.

.EXAMPLE
    pwsh -NoProfile -File packaging/assets/Generate-HfDriveAssets.ps1
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Deterministic per-pixel resampling + ICO container writer.
# Plain C# (System types only, C# 5 syntax) so the identical code compiles
# under Windows PowerShell 5.1 and pwsh 7 without referencing
# System.Drawing.Common from the compiler.
# ---------------------------------------------------------------------------
if (-not ('HfDriveAssets.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;

namespace HfDriveAssets
{
    public static class Native
    {
        // Tight alpha bounding box of a BGRA32 image.
        // Returns { x, y, width, height }; falls back to the whole image.
        public static int[] AlphaBounds(byte[] bgra, int width, int height, int threshold)
        {
            int minX = width;
            int minY = height;
            int maxX = -1;
            int maxY = -1;
            for (int y = 0; y < height; y++)
            {
                int row = y * width * 4;
                for (int x = 0; x < width; x++)
                {
                    int a = (int)bgra[row + x * 4 + 3];
                    if (a > threshold)
                    {
                        if (x < minX) { minX = x; }
                        if (x > maxX) { maxX = x; }
                        if (y < minY) { minY = y; }
                        if (y > maxY) { maxY = y; }
                    }
                }
            }
            if (maxX < 0 || maxY < 0)
            {
                return new int[] { 0, 0, width, height };
            }
            return new int[] { minX, minY, maxX - minX + 1, maxY - minY + 1 };
        }

        // Resamples the (sx, sy, cw, ch) region of a BGRA32 source image into a
        // dw x dh BGRA32 image. Two-pass separable Catmull-Rom with the kernel
        // support widened by the reduction ratio (proper area-aware filtering:
        // crisp at mild ratios, alias-free at large reductions). Accumulation
        // runs on premultiplied alpha so transparent pixels cannot darken or
        // fringe the artwork edges.
        public static byte[] Resample(byte[] src, int sw, int sh, int sx, int sy,
                                      int cw, int ch, int dw, int dh)
        {
            double ratioX = (double)cw / (double)dw;
            double ratioY = (double)ch / (double)dh;
            float[] inter = new float[dw * ch * 4];

            for (int y = 0; y < ch; y++)
            {
                int srcRow = (sy + y) * sw * 4;
                int dstRow = y * dw * 4;
                for (int x = 0; x < dw; x++)
                {
                    double center = ((double)x + 0.5) * ratioX - 0.5;
                    double unit = ratioX > 1.0 ? ratioX : 1.0;
                    double reach = 2.0 * unit;
                    int i0 = (int)Math.Floor(center - reach);
                    int i1 = (int)Math.Ceiling(center + reach);
                    float sum = 0.0f;
                    float bb = 0.0f;
                    float gg = 0.0f;
                    float rr = 0.0f;
                    float aa = 0.0f;
                    for (int i = i0; i <= i1; i++)
                    {
                        int ci = i;
                        if (ci < 0) { ci = 0; }
                        if (ci > cw - 1) { ci = cw - 1; }
                        float w = Kernel((float)((ci - center) / unit));
                        if (w == 0.0f) { continue; }
                        int p = srcRow + (sx + ci) * 4;
                        float alpha = (float)src[p + 3] / 255.0f;
                        sum += w;
                        bb += w * (float)src[p] * alpha;
                        gg += w * (float)src[p + 1] * alpha;
                        rr += w * (float)src[p + 2] * alpha;
                        aa += w * alpha;
                    }
                    if (sum == 0.0f) { sum = 1.0f; }
                    inter[dstRow + x * 4] = bb / sum;
                    inter[dstRow + x * 4 + 1] = gg / sum;
                    inter[dstRow + x * 4 + 2] = rr / sum;
                    inter[dstRow + x * 4 + 3] = aa / sum;
                }
            }

            byte[] dst = new byte[dw * dh * 4];
            for (int x = 0; x < dw; x++)
            {
                for (int y = 0; y < dh; y++)
                {
                    double center = ((double)y + 0.5) * ratioY - 0.5;
                    double unit = ratioY > 1.0 ? ratioY : 1.0;
                    double reach = 2.0 * unit;
                    int i0 = (int)Math.Floor(center - reach);
                    int i1 = (int)Math.Ceiling(center + reach);
                    float sum = 0.0f;
                    float bb = 0.0f;
                    float gg = 0.0f;
                    float rr = 0.0f;
                    float aa = 0.0f;
                    for (int i = i0; i <= i1; i++)
                    {
                        int ci = i;
                        if (ci < 0) { ci = 0; }
                        if (ci > ch - 1) { ci = ch - 1; }
                        float w = Kernel((float)((ci - center) / unit));
                        if (w == 0.0f) { continue; }
                        int p = (ci * dw + x) * 4;
                        sum += w;
                        bb += w * inter[p];
                        gg += w * inter[p + 1];
                        rr += w * inter[p + 2];
                        aa += w * inter[p + 3];
                    }
                    if (sum == 0.0f) { sum = 1.0f; }
                    aa = aa / sum;
                    int o = (y * dw + x) * 4;
                    if (aa <= 0.0f)
                    {
                        dst[o] = 0; dst[o + 1] = 0; dst[o + 2] = 0; dst[o + 3] = 0;
                    }
                    else
                    {
                        dst[o] = ClampByte((bb / sum) / aa);
                        dst[o + 1] = ClampByte((gg / sum) / aa);
                        dst[o + 2] = ClampByte((rr / sum) / aa);
                        dst[o + 3] = ClampByte(aa * 255.0f);
                    }
                }
            }
            return dst;
        }

        // Copies a BGRA32 fragment into a (transparent) BGRA32 canvas.
        public static void Blit(byte[] canvas, int canvasW, int canvasH,
                                byte[] art, int artW, int artH, int ox, int oy)
        {
            if (ox < 0 || oy < 0 || ox + artW > canvasW || oy + artH > canvasH)
            {
                throw new ArgumentOutOfRangeException("art", "fragment exceeds canvas");
            }
            for (int y = 0; y < artH; y++)
            {
                Array.Copy(art, y * artW * 4,
                           canvas, ((oy + y) * canvasW + ox) * 4, artW * 4);
            }
        }

        // PNG-compressed ICO container: ICONDIR + ICONDIRENTRY per image.
        // Sizes >= 256 are recorded as 0 per the icon format.
        public static byte[] BuildIco(byte[][] images, int[] sizes)
        {
            if (images.Length != sizes.Length)
            {
                throw new ArgumentException("images/sizes length mismatch");
            }
            int count = images.Length;
            int header = 6 + 16 * count;
            int total = header;
            for (int i = 0; i < count; i++) { total += images[i].Length; }

            byte[] ico = new byte[total];
            ico[0] = 0; ico[1] = 0;           // reserved
            ico[2] = 1; ico[3] = 0;           // type: icon
            ico[4] = (byte)(count & 0xff);
            ico[5] = (byte)((count >> 8) & 0xff);

            int entry = 6;
            int offset = header;
            for (int i = 0; i < count; i++)
            {
                int size = sizes[i];
                byte edge = (byte)(size >= 256 ? 0 : size);
                ico[entry] = edge;
                ico[entry + 1] = edge;
                ico[entry + 2] = 0;           // palette colors
                ico[entry + 3] = 0;           // reserved
                ico[entry + 4] = 1; ico[entry + 5] = 0;   // planes
                ico[entry + 6] = 32; ico[entry + 7] = 0;  // bits per pixel
                WriteU32(ico, entry + 8, images[i].Length);
                WriteU32(ico, entry + 12, offset);
                Array.Copy(images[i], 0, ico, offset, images[i].Length);
                offset += images[i].Length;
                entry += 16;
            }
            return ico;
        }

        private static float Kernel(float x)
        {
            float t = x < 0.0f ? -x : x;
            if (t < 1.0f)
            {
                return 1.5f * t * t * t - 2.5f * t * t + 1.0f;
            }
            if (t < 2.0f)
            {
                return -0.5f * t * t * t + 2.5f * t * t - 4.0f * t + 2.0f;
            }
            return 0.0f;
        }

        private static byte ClampByte(float v)
        {
            if (v < 0.0f) { return 0; }
            if (v > 255.0f) { return 255; }
            return (byte)Math.Round((double)v);
        }

        private static void WriteU32(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)(value & 0xff);
            buffer[offset + 1] = (byte)((value >> 8) & 0xff);
            buffer[offset + 2] = (byte)((value >> 16) & 0xff);
            buffer[offset + 3] = (byte)((value >> 24) & 0xff);
        }
    }
}
'@
}

# ---------------------------------------------------------------------------
# Paths and rendering constants.
# ---------------------------------------------------------------------------
$assetDir = $PSScriptRoot
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $assetDir '..\..')).Path
$desktopAssets = Join-Path $repoRoot 'desktop\HfDrive.Desktop\Assets'
$sourcePath = Join-Path $desktopAssets 'CatchingHuggy.png'
$iconPath = Join-Path $desktopAssets 'CatchingHuggy.ico'

if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "Source artwork '$sourcePath' is missing."
}

# Fit fractions: the fraction of the canvas (short edge for square canvases,
# height for wide canvases) occupied by the artwork's longer side after the
# transparent crop. Chosen so the artwork stays legible at tray/start sizes
# while keeping symmetric breathing room; identical for every scale of a
# given asset so scaled variants match visually.
$SquareFit = 0.84
$WideFit = 0.86
$IconFit = 0.88

# Name -> @(baseWidth, baseHeight, fitMode); scale factors follow the Windows
# asset convention (the unsuffixed file is scale-100).
$assetSizes = [ordered]@{
    'StoreLogo'         = @(50, 50, 'square')
    'Square44x44Logo'   = @(44, 44, 'square')
    'Square150x150Logo' = @(150, 150, 'square')
    'Wide310x150Logo'   = @(310, 150, 'wide')
    'SplashScreen'      = @(620, 300, 'wide')
}
$scales = @(100, 125, 150, 200, 400)

# Icon entry sizes (pixels) for the desktop executable/window icon.
$iconSizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)

# ---------------------------------------------------------------------------
# Source artwork loading (normalized to 32bpp BGRA) and alpha crop.
# ---------------------------------------------------------------------------
function Get-BgraBytes([System.Drawing.Bitmap]$Bitmap) {
    $rect = [System.Drawing.Rectangle]::new(0, 0, $Bitmap.Width, $Bitmap.Height)
    $data = $Bitmap.LockBits(
        $rect,
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        if ($data.Stride -ne $Bitmap.Width * 4) {
            throw "Unexpected pixel stride $($data.Stride) for $($Bitmap.Width) px."
        }
        $bytes = New-Object byte[] ($Bitmap.Width * $Bitmap.Height * 4)
        [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
        return , $bytes
    }
    finally {
        $Bitmap.UnlockBits($data)
    }
}

function New-PngBytes([int]$Width, [int]$Height, [byte[]]$Bytes) {
    $bitmap = [System.Drawing.Bitmap]::new(
        $Width, $Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $rect = [System.Drawing.Rectangle]::new(0, 0, $Width, $Height)
        $data = $bitmap.LockBits(
            $rect,
            [System.Drawing.Imaging.ImageLockMode]::WriteOnly,
            [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            [System.Runtime.InteropServices.Marshal]::Copy($Bytes, 0, $data.Scan0, $Bytes.Length)
        }
        finally {
            $bitmap.UnlockBits($data)
        }
        $stream = [System.IO.MemoryStream]::new()
        try {
            $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
            return , $stream.ToArray()
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $bitmap.Dispose()
    }
}

$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
$sourceBitmap = [System.Drawing.Bitmap]::new(
    $sourceImage.Width, $sourceImage.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($sourceBitmap)
try {
    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::None
    $graphics.DrawImage($sourceImage, 0, 0, $sourceImage.Width, $sourceImage.Height)
}
finally {
    $graphics.Dispose()
    # The bitmap copy keeps the pixels; the file handle is released immediately.
    $sourceImage.Dispose()
}

$srcW = $sourceBitmap.Width
$srcH = $sourceBitmap.Height
$srcBytes = Get-BgraBytes $sourceBitmap
$sourceBitmap.Dispose()

# Tight alpha bounds (crop of transparent padding only).
$bounds = [HfDriveAssets.Native]::AlphaBounds($srcBytes, $srcW, $srcH, 2)
$cropX = $bounds[0]
$cropY = $bounds[1]
$cropW = $bounds[2]
$cropH = $bounds[3]
Write-Host "source: $sourcePath ($srcW x $srcH), artwork bounds $cropW x $cropH at ($cropX, $cropY)"

# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------
function Get-ArtSize([int]$CanvasW, [int]$CanvasH, [string]$FitMode, [double]$Fit) {
    if ($FitMode -eq 'square') {
        $target = $Fit * [Math]::Min($CanvasW, $CanvasH)
    }
    else {
        $target = $Fit * $CanvasH
    }
    $scale = $target / [Math]::Max($script:cropW, $script:cropH)
    $artW = [Math]::Max(1, [int][Math]::Round($script:cropW * $scale))
    $artH = [Math]::Max(1, [int][Math]::Round($script:cropH * $scale))
    return @($artW, $artH)
}

function New-HfDriveAsset([int]$Width, [int]$Height, [string]$FitMode, [double]$Fit) {
    $size = Get-ArtSize -CanvasW $Width -CanvasH $Height -FitMode $FitMode -Fit $Fit
    $artW = $size[0]
    $artH = $size[1]
    $art = [HfDriveAssets.Native]::Resample(
        $script:srcBytes, $script:srcW, $script:srcH,
        $script:cropX, $script:cropY, $script:cropW, $script:cropH,
        $artW, $artH)
    $canvas = New-Object byte[] ($Width * $Height * 4)   # fully transparent
    $offsetX = [int](($Width - $artW) / 2)
    $offsetY = [int](($Height - $artH) / 2)
    [HfDriveAssets.Native]::Blit($canvas, $Width, $Height, $art, $artW, $artH, $offsetX, $offsetY)
    return , (New-PngBytes -Width $Width -Height $Height -Bytes $canvas)
}

foreach ($entry in $assetSizes.GetEnumerator()) {
    $baseW = $entry.Value[0]
    $baseH = $entry.Value[1]
    $fitMode = $entry.Value[2]
    $fit = if ($fitMode -eq 'square') { $SquareFit } else { $WideFit }
    foreach ($scale in $scales) {
        $factor = $scale / 100
        $w = [int][Math]::Round($baseW * $factor)
        $h = [int][Math]::Round($baseH * $factor)
        # The unsuffixed file is the scale-100 image, as referenced by the manifest.
        $name = if ($scale -eq 100) { "$($entry.Key).png" } else { "$($entry.Key).scale-$scale.png" }
        $path = Join-Path $assetDir $name
        if ($path -eq $sourcePath) {
            throw "Refusing to overwrite the supplied source artwork."
        }
        $png = New-HfDriveAsset -Width $w -Height $h -FitMode $fitMode -Fit $fit
        [System.IO.File]::WriteAllBytes($path, $png)
        Write-Host "wrote $name ($w x $h)"
    }
}

# ---------------------------------------------------------------------------
# Multi-resolution desktop/window icon.
# ---------------------------------------------------------------------------
$iconImages = New-Object System.Collections.Generic.List[byte[]]
foreach ($size in $iconSizes) {
    $png = New-HfDriveAsset -Width $size -Height $size -FitMode 'square' -Fit $IconFit
    $iconImages.Add($png)
}
$ico = [HfDriveAssets.Native]::BuildIco($iconImages.ToArray(), $iconSizes)
if ($iconPath -eq $sourcePath) {
    throw "Refusing to overwrite the supplied source artwork."
}
[System.IO.File]::WriteAllBytes($iconPath, $ico)
Write-Host ("wrote {0} ({1} entries: {2} px)" -f `
        (Split-Path -Leaf $iconPath), $iconSizes.Count, ($iconSizes -join '/'))

Write-Host "HF Drive assets generated from CatchingHuggy.png in $assetDir and $desktopAssets"
