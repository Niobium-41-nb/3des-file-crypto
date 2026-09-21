# ============================================================================
#  crosscheck.ps1 -- Cross-validate tdes.exe against .NET DES / TripleDES
# ---------------------------------------------------------------------------
#  Two levels of checking:
#    A) Block level : tdes.exe block -q  vs  .NET TransformFinalBlock
#    B) File  level : ciphertext produced by one side is decrypted by the other
#                     (raw mode: no self-describing header, CBC + PKCS#7)
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\crosscheck.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot          # project root
$exe = Join-Path $root 'tdes.exe'
if (-not (Test-Path $exe)) { throw "tdes.exe not found: $exe  (build it first)" }

$pass = 0
$fail = 0
function Check([bool]$ok, [string]$name, [string]$detail) {
    if ($ok) { $script:pass++ } else { $script:fail++ }
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    "[{0}] {1,-46} {2}" -f $tag, $name, $detail
}

function ConvertTo-Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('X2') }) -join '' }
function ConvertFrom-Hex([string]$s) {
    if ($s.Length % 2 -ne 0) { throw "hex string has odd length: $s" }
    $r = New-Object 'byte[]' ($s.Length / 2)
    for ($i = 0; $i -lt $s.Length; $i += 2) { $r[$i / 2] = [Convert]::ToByte($s.Substring($i, 2), 16) }
    return , $r
}

# ---------------------------------------------------------------------------
#  A) Block level
# ---------------------------------------------------------------------------
$K3DES3 = '0123456789ABCDEF23456789ABCDEF013456789ABCDEF012'
$K3DES2 = '0123456789ABCDEF23456789ABCDEF01'
$vectors = @(
    @{ a = 'DES';   k = '133457799BBCDFF1'; p = '0123456789ABCDEF' },
    @{ a = 'DES';   k = '0123456789ABCDEF'; p = '0000000000000000' },
    @{ a = 'DES';   k = 'FEDCBA9876543210'; p = '0123456789ABCDEF' },
    @{ a = '3DES2'; k = $K3DES2;            p = '0123456789ABCDEF' },
    @{ a = '3DES3'; k = $K3DES3;            p = '5468652071756663' },
    @{ a = '3DES3'; k = $K3DES3;            p = '0000000000000000' }
)

"--- A. Block level: tdes.exe vs .NET ---"
foreach ($v in $vectors) {
    # our implementation
    $mine = (& $exe block -q -e -k $v.k -p $v.p --alg $v.a).Trim()

    # .NET reference
    if ($v.a -eq 'DES') { $c = [System.Security.Cryptography.DES]::Create() }
    else { $c = [System.Security.Cryptography.TripleDES]::Create() }
    $c.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $c.Padding = [System.Security.Cryptography.PaddingMode]::None
    $c.Key = (ConvertFrom-Hex $v.k)
    $c.IV = (New-Object 'byte[]' 8)
    $pt = (ConvertFrom-Hex $v.p)
    $ref = ConvertTo-Hex ($c.CreateEncryptor().TransformFinalBlock($pt, 0, 8))

    # reverse direction: give .NET ciphertext to our -d
    $back = (& $exe block -q -d -k $v.k -p $ref --alg $v.a).Trim()

    Check ($mine -eq $ref) "$($v.a) K=$($v.k.Substring(0,4))... P=$($v.p)" "ours=$mine .net=$ref"
    Check ($back -eq $v.p) "$($v.a) decrypt .net ciphertext" "ours=$back expect=$($v.p)"
}

# ---------------------------------------------------------------------------
#  B) File level: raw CBC + PKCS#7, cross-decrypted by the other side
# ---------------------------------------------------------------------------
""
"--- B. File level: raw CBC + PKCS#7 interop ---"

$work = Join-Path $env:TEMP 'tdes_crosscheck'
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $work | Out-Null

$plainPath = Join-Path $work 'plain.bin'
$ivHex = 'A1B2C3D4E5F60718'
$iv = (ConvertFrom-Hex $ivHex)

# a 10001-byte payload (not a multiple of 8 on purpose)
$rnd = New-Object System.Random 20260921
$plain = New-Object 'byte[]' 10001
$rnd.NextBytes($plain)
[System.IO.File]::WriteAllBytes($plainPath, $plain)

$keyHex = $K3DES2
$key = (ConvertFrom-Hex $keyHex)

# B1: our tool encrypts (raw) -> .NET decrypts
$oursEnc = Join-Path $work 'ours.raw'
& $exe enc $plainPath $oursEnc -k $keyHex --alg 3des2 -m cbc -iv $ivHex --raw -f -q | Out-Null
$ct = [System.IO.File]::ReadAllBytes($oursEnc)
$td = [System.Security.Cryptography.TripleDES]::Create()
$td.Mode = [System.Security.Cryptography.CipherMode]::CBC
$td.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$td.Key = $key
$td.IV = $iv
$dec = $td.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
$same = ($dec.Length -eq $plain.Length)
if ($same) { for ($i = 0; $i -lt $plain.Length; $i++) { if ($dec[$i] -ne $plain[$i]) { $same = $false; break } } }
Check $same "tdes.exe enc -> .NET dec" "cipher $($ct.Length) bytes, plain $($dec.Length) / $($plain.Length) bytes"

# B2: .NET encrypts -> our tool decrypts (raw)
$refEnc = Join-Path $work 'ref.raw'
$td2 = [System.Security.Cryptography.TripleDES]::Create()
$td2.Mode = [System.Security.Cryptography.CipherMode]::CBC
$td2.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$td2.Key = $key
$td2.IV = $iv
$refCt = $td2.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
[System.IO.File]::WriteAllBytes($refEnc, $refCt)

$oursDec = Join-Path $work 'ours.dec'
& $exe dec $refEnc $oursDec -k $keyHex --alg 3des2 -m cbc -iv $ivHex --raw -f -q | Out-Null
$got = [System.IO.File]::ReadAllBytes($oursDec)
$same2 = ($got.Length -eq $plain.Length)
if ($same2) { for ($i = 0; $i -lt $plain.Length; $i++) { if ($got[$i] -ne $plain[$i]) { $same2 = $false; break } } }
Check $same2 ".NET enc -> tdes.exe dec" "plain $($got.Length) / $($plain.Length) bytes"

# B3: both sides produce identical raw-ciphertext bytes
Check ((ConvertTo-Hex $ct) -eq (ConvertTo-Hex $refCt)) "raw ciphertext bytes identical" "len ours=$($ct.Length) net=$($refCt.Length)"

# B4: CLI round trip with the self-describing header
$hdrEnc = Join-Path $work 'hdr.3des'
$hdrDec = Join-Path $work 'hdr.out'
& $exe enc $plainPath $hdrEnc -k $K3DES3 --alg 3des3 -m cbc -f -q | Out-Null
& $exe dec $hdrEnc $hdrDec -k $K3DES3 -f -q | Out-Null
$got2 = [System.IO.File]::ReadAllBytes($hdrDec)
$same3 = ($got2.Length -eq $plain.Length)
if ($same3) { for ($i = 0; $i -lt $plain.Length; $i++) { if ($got2[$i] -ne $plain[$i]) { $same3 = $false; break } } }
Check $same3 "CLI round trip with header (3DES3/CBC)" "plain $($got2.Length) / $($plain.Length) bytes"

""
"Total: pass=$pass fail=$fail"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
exit $(if ($fail -eq 0) { 0 } else { 1 })
