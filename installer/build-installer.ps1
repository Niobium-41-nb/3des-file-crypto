# ============================================================================
#  build-installer.ps1 -- one-shot release build for the 3DES file crypto tool
# ---------------------------------------------------------------------------
#  What it does:
#    1. (optionally) rebuilds tdes.exe / tdes_gui.exe with MinGW-w64
#    2. compiles the Inno Setup script  -> dist\3DES-FileCrypto-<ver>-win64-setup.exe
#    3. packs the portable edition      -> dist\3DES-FileCrypto-<ver>-win64-portable.zip
#    4. writes                           dist\SHA256SUMS.txt
#
#  Usage:
#    powershell -NoProfile -ExecutionPolicy Bypass -File installer\build-installer.ps1
#    powershell -NoProfile -ExecutionPolicy Bypass -File installer\build-installer.ps1 -Version 1.0.1 -SkipBuild
#
#  NOTE: this file is intentionally pure ASCII. Windows PowerShell 5.1 reads
#        .ps1 files using the ANSI code page, so UTF-8 CJK would be garbled.
# ============================================================================

param(
    [string]$Version = '1.0.0',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot          # project root (parent of installer\)
$dist = Join-Path $root 'dist'
$name = "3DES-FileCrypto-$Version-win64"

Write-Host "==> project root : $root"
Write-Host "==> version      : $Version"

# ---------------------------------------------------------------- 1. binaries
if (-not $SkipBuild) {
    Write-Host '==> rebuilding binaries (mingw32-make clean all)'
    Push-Location $root
    try {
        & mingw32-make clean  | Out-Null
        & mingw32-make all
        if ($LASTEXITCODE -ne 0) { throw "mingw32-make failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
} else {
    Write-Host '==> skipping build (-SkipBuild)'
}

foreach ($f in 'tdes.exe', 'tdes_gui.exe') {
    $p = Join-Path $root $f
    if (-not (Test-Path $p)) { throw "missing binary: $p (run without -SkipBuild first)" }
}

# ------------------------------------------------------------ 2. Inno Setup
$isccCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    throw 'ISCC.exe (Inno Setup 6) not found. Install it with: winget install --id JRSoftware.InnoSetup -e --source winget --scope user'
}
Write-Host "==> Inno Setup   : $iscc"

New-Item -ItemType Directory -Force $dist | Out-Null

# Both the .iss script and the .isl message file must be UTF-8 *with* BOM,
# otherwise Inno reads CJK bytes as ANSI and the wizard text comes out garbled.
$utf8bom = New-Object System.Text.UTF8Encoding($true)
foreach ($f in '3des.iss', 'ChineseSimplified.isl') {
    $p = Join-Path $PSScriptRoot $f
    $text = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($p, $text, $utf8bom)
}

$iss = Join-Path $PSScriptRoot '3des.iss'
& $iscc "/DMyAppVersion=$Version" $iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

$setup = Join-Path $dist "$name-setup.exe"
if (-not (Test-Path $setup)) { throw "installer was not produced: $setup" }

# --------------------------------------------------------- 3. portable zip
Write-Host '==> packing portable edition'
$stage = Join-Path $dist "portable-$Version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item (Join-Path $root 'tdes.exe')     $stage
Copy-Item (Join-Path $root 'tdes_gui.exe') $stage
Copy-Item (Join-Path $root 'README.md')    $stage
Copy-Item (Join-Path $PSScriptRoot 'PORTABLE-README.txt') $stage

$zip = Join-Path $dist "$name-portable.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

# ------------------------------------------------------- 4. checksum manifest
Write-Host '==> writing SHA256SUMS.txt'
$lines = Get-ChildItem $dist -File |
    Where-Object { $_.Name -match '\.(exe|zip)$' } |
    Sort-Object Name |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
$lines | Set-Content (Join-Path $dist 'SHA256SUMS.txt') -Encoding ASCII

Write-Host ''
Write-Host '==> done. artifacts in dist\:'
Get-ChildItem $dist -File | Select-Object Name, @{n = 'Size(MB)'; e = { [math]::Round($_.Length / 1MB, 2) } } | Format-Table -AutoSize
