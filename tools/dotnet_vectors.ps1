# ============================================================================
#  dotnet_vectors.ps1 -- Reference vectors computed by .NET DES / TripleDES
# ---------------------------------------------------------------------------
#  Purpose: provide an independent, certified third-party reference for the
#  hand-written DES/3DES implementation in this project.
#  Note: this file is intentionally ASCII-only, because Windows PowerShell 5.1
#        reads .ps1 files using the ANSI code page and would garble UTF-8 CJK.
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\dotnet_vectors.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'

function ConvertTo-Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('X2') }) -join '' }

function ConvertFrom-Hex([string]$s) {
    if ($s.Length % 2 -ne 0) { throw "hex string has odd length: $s" }
    $r = New-Object 'byte[]' ($s.Length / 2)
    for ($i = 0; $i -lt $s.Length; $i += 2) { $r[$i / 2] = [Convert]::ToByte($s.Substring($i, 2), 16) }
    return , $r
}

# Vector table: a = algorithm, k = key (hex), p = plaintext block (hex)
# K1 = 0123456789ABCDEF, K2 = 23456789ABCDEF01, K3 = 3456789ABCDEF012
$vec = @(
    @{ a = 'DES';   k = '133457799BBCDFF1'; p = '0123456789ABCDEF' },
    @{ a = 'DES';   k = '0123456789ABCDEF'; p = '0000000000000000' },
    @{ a = 'DES';   k = 'FEDCBA9876543210'; p = '0123456789ABCDEF' },
    @{ a = '3DES2'; k = '0123456789ABCDEF23456789ABCDEF01'; p = '0123456789ABCDEF' },
    @{ a = '3DES3'; k = '0123456789ABCDEF23456789ABCDEF013456789ABCDEF012'; p = '5468652071756663' },
    @{ a = '3DES3'; k = '0123456789ABCDEF23456789ABCDEF013456789ABCDEF012'; p = '0000000000000000' }
)

foreach ($v in $vec) {
    if ($v.a -eq 'DES') { $c = [System.Security.Cryptography.DES]::Create() }
    else { $c = [System.Security.Cryptography.TripleDES]::Create() }
    $c.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $c.Padding = [System.Security.Cryptography.PaddingMode]::None
    $c.Key = (ConvertFrom-Hex $v.k)
    $c.IV = (New-Object 'byte[]' 8)

    $pt = (ConvertFrom-Hex $v.p)
    $ct = $c.CreateEncryptor().TransformFinalBlock($pt, 0, 8)
    $back = $c.CreateDecryptor().TransformFinalBlock($ct, 0, 8)

    $rt = if ((ConvertTo-Hex $back) -eq $v.p) { 'OK' } else { 'FAIL' }
    "{0,-6} KEYLEN={1,2} K={2} P={3} -> C={4}  roundtrip={5}" -f `
        $v.a, ($v.k.Length / 2), $v.k, $v.p, (ConvertTo-Hex $ct), $rt
}
