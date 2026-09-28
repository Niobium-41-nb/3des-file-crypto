# ============================================================================
#  keytest.ps1 -- End-to-end test of the key-file import / export feature
# ---------------------------------------------------------------------------
#  Covered:
#    1) genkey --out            : generate a key and export it to a .key file
#    2) keyinfo                 : read that file back (algorithm / length / hex)
#    3) -kf <file> / -k @<file> : encrypt and decrypt using a key file
#    4) keyexport               : export an existing hex key to a .key file
#    5) tolerant parsing        : comments, CRLF, BOM, bare hex, split key= lines
#    6) error handling          : odd-length hex, alg/length mismatch, bad path
#    7) backwards compatibility : the plain -k <HEX> form still works
#
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\keytest.ps1
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

# Run tdes.exe and return both the exit code and the combined output.
# $ErrorActionPreference is relaxed locally so that a non-zero exit code with
# text on stderr (the error cases below) does not throw a NativeCommandError.
function Run([string[]]$argv) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& $exe @argv 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    return @{ code = $code; text = $out }
}

$work = Join-Path $env:TEMP 'tdes_keytest'
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $work | Out-Null

$plain = Join-Path $work 'plain.txt'
[System.IO.File]::WriteAllText($plain, ('3DES key-file test payload. ' * 40),
                               (New-Object System.Text.UTF8Encoding($false)))
$plainHash = (Get-FileHash $plain -Algorithm SHA256).Hash

$kf      = Join-Path $work 'my.key'
$kfCopy  = Join-Path $work 'copy.key'
$kfCopy2 = Join-Path $work 'copy2.key'
$loose   = Join-Path $work 'loose.key'
$bare    = Join-Path $work 'bare.key'
$twoKey  = Join-Path $work 'two.key'
$badOdd  = Join-Path $work 'bad_odd.key'
$badAlg  = Join-Path $work 'bad_alg.key'
$encFile = Join-Path $work 'plain.3des'
$decFile = Join-Path $work 'plain.back.txt'

"--- key file test: $work ---"
""

# ---------------------------------------------------------------------------
#  1) genkey --out  ->  export a freshly generated key
# ---------------------------------------------------------------------------
$r = Run @('genkey', '--alg', '3des3', '--out', $kf)
$exported = ($r.code -eq 0) -and (Test-Path $kf)
Check $exported 'genkey --out writes a key file' $(if ($exported) { 'my.key created' } else { "exit=$($r.code)" })

$kfText = if (Test-Path $kf) { [System.IO.File]::ReadAllText($kf) } else { '' }
$m = [regex]::Match($kfText, '(?m)^key=([0-9A-Fa-f]{48})\s*$')
$algLine = [regex]::Match($kfText, '(?m)^alg=(\S+)\s*$')
Check ($m.Success -and $algLine.Success -and $algLine.Groups[1].Value -eq '3des3') `
    'key file has alg=3des3 and a 48-hex key= line' `
    "len=$(if ($m.Success) { $m.Groups[1].Value.Length } else { 0 })"
$keyHex = if ($m.Success) { $m.Groups[1].Value.ToUpper() } else { '' }

$printed = [regex]::Match($r.text, '[0-9A-Fa-f]{48}')
Check ($printed.Success -and $printed.Value.ToUpper() -eq $keyHex) `
    'genkey stdout matches the exported key' $(if ($keyHex) { $keyHex.Substring(0, 16) + '...' } else { '' })

# ---------------------------------------------------------------------------
#  2) keyinfo  ->  read the file back
# ---------------------------------------------------------------------------
$r = Run @('keyinfo', $kf)
Check (($r.code -eq 0) -and ($r.text -match '3DES-3Key') -and
       [regex]::IsMatch($r.text, $keyHex)) `
    'keyinfo reads back alg + key hex' '3DES-3Key, 48 hex chars'

# ---------------------------------------------------------------------------
#  3) -kf <file> and -k @<file>
# ---------------------------------------------------------------------------
$r = Run @('enc', $plain, $encFile, '-kf', $kf, '-f')
$encOk = ($r.code -eq 0) -and (Test-Path $encFile)
Check $encOk 'encrypt with -kf <key file>' $(if (Test-Path $encFile) { "$((Get-Item $encFile).Length) bytes" } else { "exit=$($r.code)" })

$r = Run @('dec', $encFile, $decFile, '-k', ('@' + $kf), '-f')
$decOk = ($r.code -eq 0) -and (Test-Path $decFile) -and
         ((Get-FileHash $decFile -Algorithm SHA256).Hash -eq $plainHash)
Check $decOk 'decrypt with -k @<key file>' 'sha256 round trip'

# ---------------------------------------------------------------------------
#  4) keyexport  (from a hex key, and from another key file)
# ---------------------------------------------------------------------------
$r = Run @('keyexport', $kfCopy, '-k', $keyHex)
$t = if (Test-Path $kfCopy) { [System.IO.File]::ReadAllText($kfCopy) } else { '' }
Check (($r.code -eq 0) -and [regex]::IsMatch($t, '(?m)^key=' + $keyHex + '\s*$')) `
    'keyexport -k <HEX> writes the same key' 'key= line identical'

$r = Run @('keyexport', $kfCopy2, '-k', ('@' + $kf))
$t = if (Test-Path $kfCopy2) { [System.IO.File]::ReadAllText($kfCopy2) } else { '' }
Check (($r.code -eq 0) -and [regex]::IsMatch($t, '(?m)^key=' + $keyHex + '\s*$')) `
    'keyexport -k @<file> re-exports the key' 'round trip through files'

# ---------------------------------------------------------------------------
#  5) tolerant parsing: comments, CRLF, BOM, spaces, split key= lines
# ---------------------------------------------------------------------------
$looseText = "# hand written key file`r`n" +
             "; comments are ignored`r`n" +
             "`r`n" +
             "alg = 3DES3`r`n" +
             "key = " + $keyHex.Substring(0, 16) + "`r`n" +
             "      " + $keyHex.Substring(16, 16) + "`r`n" +
             "      " + $keyHex.Substring(32, 16) + "`r`n"
[System.IO.File]::WriteAllText($loose, $looseText, (New-Object System.Text.UTF8Encoding($true)))
$r = Run @('keyinfo', $loose)
Check (($r.code -eq 0) -and ($r.text -match '3DES-3Key') -and [regex]::IsMatch($r.text, $keyHex)) `
    'tolerant parse: BOM/comments/CRLF/split key=' 'same 24-byte key'

[System.IO.File]::WriteAllText($bare, "133457799BBCDFF1`n", [System.Text.Encoding]::ASCII)
$r = Run @('keyinfo', $bare)
Check (($r.code -eq 0) -and [regex]::IsMatch($r.text, '(?m):\s*DES\s*$') -and
       [regex]::IsMatch($r.text, '133457799BBCDFF1')) `
    'bare hex line is inferred as DES' '16 hex chars -> 8 bytes'

[System.IO.File]::WriteAllText($twoKey, "key=0123456789ABCDEF23456789ABCDEF01`n", [System.Text.Encoding]::ASCII)
$r = Run @('keyinfo', $twoKey)
Check (($r.code -eq 0) -and ($r.text -match '3DES-2Key')) `
    '32-hex key is inferred as 3DES-2Key' '16 bytes'

# ---------------------------------------------------------------------------
#  6) error handling
# ---------------------------------------------------------------------------
[System.IO.File]::WriteAllText($badOdd, "key=ABC`n", [System.Text.Encoding]::ASCII)
$r = Run @('keyinfo', $badOdd)
Check ($r.code -ne 0) 'odd-length hex rejected' "exit=$($r.code)"

[System.IO.File]::WriteAllText($badAlg, "alg=3des3`nkey=133457799BBCDFF1`n", [System.Text.Encoding]::ASCII)
$r = Run @('keyinfo', $badAlg)
Check ($r.code -ne 0) 'alg / key-length mismatch rejected' "exit=$($r.code)"

$r = Run @('keyinfo', (Join-Path $work 'no_such_file.key'))
Check ($r.code -ne 0) 'missing key file rejected' "exit=$($r.code)"

$r = Run @('enc', $plain, (Join-Path $work 'never.3des'), '-kf', $badOdd)
Check ($r.code -ne 0) 'encrypt with a broken key file refused' "exit=$($r.code)"
Check (-not (Test-Path (Join-Path $work 'never.3des'))) 'no output file on failure' 'nothing written'

# ---------------------------------------------------------------------------
#  7) backwards compatibility: -k <HEX> still works
# ---------------------------------------------------------------------------
$r = Run @('block', '-k', '133457799BBCDFF1', '-p', '0123456789ABCDEF', '--alg', 'des', '-q')
Check (($r.code -eq 0) -and ($r.text -match '85E813540F0AB405')) `
    '-k <HEX> still works (DES KAT)' '85E813540F0AB405'

$r = Run @('enc', $plain, $encFile, '-k', $keyHex, '--alg', '3des3', '-f')
Check ($r.code -eq 0) 'encrypt with a raw -k <HEX> key' 'exit=0'

""
"Total: pass=$pass fail=$fail"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
exit $(if ($fail -eq 0) { 0 } else { 1 })
