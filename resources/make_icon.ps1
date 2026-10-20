Add-Type -AssemblyName System.Drawing
$srcPath = "C:\Qt\myIPproxy\resources\knight-src.png"
$src = [System.Drawing.Bitmap]::FromFile($srcPath)
$bmp = New-Object System.Drawing.Bitmap $src.Width, $src.Height, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.DrawImage($src, 0, 0, $src.Width, $src.Height)
$g.Dispose()
$src.Dispose()

$w = $bmp.Width
$h = $bmp.Height
$rect = New-Object System.Drawing.Rectangle 0, 0, $w, $h
$data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadWrite, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$stride = $data.Stride
$bytes = New-Object byte[] ($stride * $h)
[System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)

function Is-Bg([int]$r, [int]$g, [int]$b) {
    $max = [Math]::Max($r, [Math]::Max($g, $b))
    $min = [Math]::Min($r, [Math]::Min($g, $b))
    return (($max - $min) -le 16 -and $min -ge 214)
}

$seen = New-Object 'bool[]' ($w * $h)
$stack = New-Object 'System.Collections.Generic.Stack[int]'
function Push-Edge([int]$x, [int]$y) {
    $i = $y * $stride + $x * 4
    if (Is-Bg $bytes[$i + 2] $bytes[$i + 1] $bytes[$i]) {
        $stack.Push($y * $w + $x)
    }
}
for ($x = 0; $x -lt $w; $x++) { Push-Edge $x 0; Push-Edge $x ($h - 1) }
for ($y = 0; $y -lt $h; $y++) { Push-Edge 0 $y; Push-Edge ($w - 1) $y }

while ($stack.Count -gt 0) {
    $p = $stack.Pop()
    if ($seen[$p]) { continue }
    $seen[$p] = $true
    $x = $p % $w
    $y = [int][Math]::Floor($p / $w)
    $i = $y * $stride + $x * 4
    $bytes[$i + 3] = 0
    foreach ($delta in @(-1, 1)) {
        $nx = $x + $delta
        if ($nx -ge 0 -and $nx -lt $w) {
            $np = $y * $w + $nx
            if (-not $seen[$np]) {
                $ni = $y * $stride + $nx * 4
                if (Is-Bg $bytes[$ni + 2] $bytes[$ni + 1] $bytes[$ni]) { $stack.Push($np) }
            }
        }
        $ny = $y + $delta
        if ($ny -ge 0 -and $ny -lt $h) {
            $np = $ny * $w + $x
            if (-not $seen[$np]) {
                $ni = $ny * $stride + $x * 4
                if (Is-Bg $bytes[$ni + 2] $bytes[$ni + 1] $bytes[$ni]) { $stack.Push($np) }
            }
        }
    }
}

# Снять светлую кайму, которую оставило сжатие WebP.
for ($pass = 0; $pass -lt 2; $pass++) {
    $kill = New-Object 'System.Collections.Generic.List[int]'
    for ($y = 1; $y -lt $h - 1; $y++) {
        for ($x = 1; $x -lt $w - 1; $x++) {
            $i = $y * $stride + $x * 4
            if ($bytes[$i + 3] -eq 0) { continue }
            $r = $bytes[$i + 2]; $gc = $bytes[$i + 1]; $b = $bytes[$i]
            $max = [Math]::Max($r, [Math]::Max($gc, $b))
            $min = [Math]::Min($r, [Math]::Min($gc, $b))
            if (($max - $min) -gt 22 -or $min -lt 196) { continue }
            $open = 0
            foreach ($delta in @(-1, 1)) {
                $ni = $y * $stride + ($x + $delta) * 4
                if ($bytes[$ni + 3] -eq 0) { $open++ }
                $ni = ($y + $delta) * $stride + $x * 4
                if ($bytes[$ni + 3] -eq 0) { $open++ }
            }
            if ($open -ge 2) { $kill.Add($i) }
        }
    }
    foreach ($i in $kill) { $bytes[$i + 3] = 0 }
}

[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $data.Scan0, $bytes.Length)
$bmp.UnlockBits($data)

$minX = $w; $minY = $h; $maxX = 0; $maxY = 0
for ($y = 0; $y -lt $h; $y++) {
    for ($x = 0; $x -lt $w; $x++) {
        if ($bmp.GetPixel($x, $y).A -eq 0) { continue }
        if ($x -lt $minX) { $minX = $x }
        if ($y -lt $minY) { $minY = $y }
        if ($x -gt $maxX) { $maxX = $x }
        if ($y -gt $maxY) { $maxY = $y }
    }
}
$cw = $maxX - $minX + 1
$ch = $maxY - $minY + 1
$crop = New-Object System.Drawing.Bitmap $cw, $ch, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$cg = [System.Drawing.Graphics]::FromImage($crop)
$cg.Clear([System.Drawing.Color]::Transparent)
$cg.DrawImage($bmp, (New-Object System.Drawing.Rectangle 0, 0, $cw, $ch), (New-Object System.Drawing.Rectangle $minX, $minY, $cw, $ch), [System.Drawing.GraphicsUnit]::Pixel)
$cg.Dispose()
$bmp.Dispose()

$outPng = "C:\Qt\myIPproxy\resources\shield.png"
$crop.Save($outPng, [System.Drawing.Imaging.ImageFormat]::Png)

function New-Scaled([int]$size) {
    $dst = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $sg = [System.Drawing.Graphics]::FromImage($dst)
    $sg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $sg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $sg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $sg.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $sg.Clear([System.Drawing.Color]::Transparent)
    # Ширина фигуры меньше высоты. Заполняем ячейку, но на 20% мельче, чтобы не срезать голову и ноги.
    $scale = [Math]::Max($size / [double]$crop.Width, $size / [double]$crop.Height) * 0.832
    $dw = [int][Math]::Round($crop.Width * $scale)
    $dh = [int][Math]::Round($crop.Height * $scale)
    $dx = [int](($size - $dw) / 2)
    $dy = [int](($size - $dh) / 2)
    $sg.DrawImage($crop, (New-Object System.Drawing.Rectangle $dx, $dy, $dw, $dh))
    $sg.Dispose()
    return $dst
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$bitmaps = foreach ($s in $sizes) { New-Scaled $s }
$pngs = foreach ($b in $bitmaps) {
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $arr = $ms.ToArray()
    $ms.Dispose()
    ,$arr
}
$ico = "C:\Qt\myIPproxy\resources\shield.ico"
$fs = [System.IO.File]::Create($ico)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]$pngs.Count)
$offset = 6 + (16 * $pngs.Count)
for ($i = 0; $i -lt $pngs.Count; $i++) {
    $sidePx = [int]$bitmaps[$i].Width
    $byteW = [byte]$(if ($sidePx -ge 256) { 0 } else { $sidePx })
    $bw.Write($byteW)
    $bw.Write($byteW)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngs[$i].Length)
    $bw.Write([UInt32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
$bw.Close()
foreach ($b in $bitmaps) { $b.Dispose() }
$crop.Dispose()
"icon ready $minX,$minY ${cw}x${ch}"
