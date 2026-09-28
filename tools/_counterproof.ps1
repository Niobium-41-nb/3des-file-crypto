# Temporary helper for the "counterproof" experiments described in the report:
# deliberately break one detail, rebuild, count the failing selftest cases, then
# restore the standard implementation.  ASCII-only (PowerShell 5.1 reads .ps1 as ANSI).
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$src = Join-Path $root 'src\des.cpp'
$orig = [IO.File]::ReadAllText($src)

function Build-Run([string]$tag) {
    g++ -std=c++17 -O2 -Iinclude -o _cp.exe src/des.cpp src/tdes.cpp src/selftest.cpp src/main.cpp
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    $out = & .\_cp.exe selftest
    $fail = ($out | Select-String '^\[FAIL\]').Count
    $pass = ($out | Select-String '^\[PASS\]').Count
    ""
    "### $tag : PASS=$pass FAIL=$fail"
    if ($fail -gt 0) { $out | Select-String '^\[FAIL\]' | ForEach-Object { '    ' + $_.Line } }
}

try {
    # experiment A: do not swap L16 / R16 before the final permutation
    $t = $orig.Replace('u64 pre = ((u64)r << 32) | l;', 'u64 pre = ((u64)l << 32) | r;')
    if ($t -eq $orig) { throw 'pattern A not found' }
    [IO.File]::WriteAllText($src, $t)
    Build-Run 'A no L16/R16 swap'

    # experiment B: use the two wrong S-box values printed in the textbook
    #   S1 row 2 col 5: 14 (standard) -> 15 (textbook)
    #   S4 row 2 col 1: 13 (standard) -> 12 (textbook)
    $t2 = $orig.Replace('0, 15,  7,  4, 14,  2, 13,  1', '0, 15,  7,  4, 15,  2, 13,  1')
    if ($t2 -eq $orig) { throw 'S1 pattern not found' }
    $t3 = $t2.Replace('13,  8, 11,  5,  6, 15,  0,  3', '12,  8, 11,  5,  6, 15,  0,  3')
    if ($t3 -eq $t2) { throw 'S4 pattern not found' }
    [IO.File]::WriteAllText($src, $t3)
    Build-Run 'B textbook S-box values'

    # restore the standard implementation and verify
    [IO.File]::WriteAllText($src, $orig)
    Build-Run 'C restored'
} finally {
    [IO.File]::WriteAllText($src, $orig)
    Remove-Item (Join-Path $root '_cp.exe') -Force -ErrorAction SilentlyContinue
    Pop-Location
}
