# ============================================================================
#  textbook_table.ps1 -- Verify the course table (key / plaintext / ciphertext)
# ---------------------------------------------------------------------------
#  Three-way comparison for every row:
#     (1) tdes.exe block -e   -- this project's hand-written DES
#     (2) .NET System.Security.Cryptography.DES  -- certified reference
#     (3) the ciphertext printed in the course material
#
#  Row 6 of the table prints the plaintext as 546987321456045, which is only 15
#  hex digits (one digit short). The intended value was recovered by brute force
#  ("insert one hex digit at any position", exactly one hit):
#        5469875321456045   -- the 7th digit '5' was missing
#  With that value the printed ciphertext 6B866C00D337CAA8 is reproduced exactly.
#
#  Note: .NET refuses DES weak keys (e.g. 0000000000000000) with
#  "Specified key is a known weak key for 'DES' and cannot be used", so for such
#  rows the .NET column shows "(weak key rejected)" and the check falls back to
#  "our result == table value". (This project's implementation accepts them,
#  because DES itself defines encryption for every 64-bit key.)
#
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\textbook_table.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'tdes.exe'
if (-not (Test-Path $exe)) { throw "tdes.exe not found: $exe (build it first)" }

function ConvertTo-Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('X2') }) -join '' }
function ConvertFrom-Hex([string]$s) {
    if ($s.Length % 2 -ne 0) { throw "hex string has odd length: $s" }
    $r = New-Object 'byte[]' ($s.Length / 2)
    for ($i = 0; $i -lt $s.Length; $i += 2) { $r[$i / 2] = [Convert]::ToByte($s.Substring($i, 2), 16) }
    return , $r
}

# rows of the course table (row 6 plaintext restored to 16 hex digits, see header)
$rows = @(
    @{ k = '0000000000000000'; p = '0000000000000000'; c = '8CA64DE9C1B123A7' },
    @{ k = '1111111111111111'; p = '1111111111111111'; c = 'F40379AB9E0EC533' },
    @{ k = '1234123412341234'; p = '1234123412341234'; c = 'CE93C61D8D78E6FA' },
    @{ k = '4567456745674567'; p = '4567456745674567'; c = '73874878EEE078FB' },
    @{ k = '1234567891234567'; p = '9876543211472583'; c = '7CAEEC024AE1ADCB' },
    @{ k = '5987423651456987'; p = '5469875321456045'; c = '6B866C00D337CAA8' }
)

$pass = 0
$fail = 0

"row  key               plaintext         our DES          .NET DES          table             result"
"---  ----------------  ----------------  ----------------  ----------------  ----------------  ------"

for ($i = 0; $i -lt $rows.Count; $i++) {
    $r = $rows[$i]

    # (1) this project
    $mine = (& $exe block -q -e -k $r.k -p $r.p --alg des).Trim()

    # (2) .NET reference (weak keys are rejected by .NET)
    $net = '(weak key rejected)'
    try {
        $des = [System.Security.Cryptography.DES]::Create()
        $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $des.Key = (ConvertFrom-Hex $r.k)
        $des.IV = (New-Object 'byte[]' 8)
        $pt = (ConvertFrom-Hex $r.p)
        $net = ConvertTo-Hex ($des.CreateEncryptor().TransformFinalBlock($pt, 0, 8))
    } catch {
        $net = '(weak key rejected)'
    }

    $ok = ($mine -eq $r.c) -and (($net -eq $mine) -or ($net -eq '(weak key rejected)'))
    if ($ok) { $pass++ } else { $fail++ }

    "{0,3}  {1}  {2}  {3}  {4}  {5}  {6}" -f ($i + 1), $r.k, $r.p, $mine, $net, $r.c,
        $(if ($ok) { 'PASS' } else { 'FAIL' })
}

""
"all rows consistent (our DES == table, and == .NET where .NET accepts the key): pass=$pass fail=$fail"
exit $(if ($fail -eq 0) { 0 } else { 1 })
