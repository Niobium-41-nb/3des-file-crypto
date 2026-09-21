# ============================================================================
#  gui_smoke.ps1 -- End-to-end smoke test that DRIVES the GUI (no clicking by hand)
# ---------------------------------------------------------------------------
#  How it works: launches tdes_gui.exe, then talks to its child controls with
#  GetDlgItem + WM_SETTEXT / WM_GETTEXT / BM_CLICK, i.e. it exercises exactly the
#  code path a user would trigger (key parsing, output-path derivation and
#  validation, encryptFile / decryptFile, log rendering). Any modal dialog is closed
#  automatically so the script can never hang.
#
#  ASCII-only on purpose: Windows PowerShell 5.1 reads .ps1 files using the ANSI
#  code page, so any non-ASCII byte in this file would be corrupted (and can even
#  break string parsing).
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\gui_smoke.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'tdes_gui.exe'
if (-not (Test-Path $exe)) { throw "tdes_gui.exe not found: $exe (build it first)" }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class GuiDrv {
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)]
    public static extern IntPtr SendText(IntPtr h, uint msg, IntPtr wp, string lp);
    [DllImport("user32.dll", EntryPoint="SendMessageW")]
    public static extern IntPtr Send(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)]
    public static extern IntPtr GetText(IntPtr h, uint msg, IntPtr wp, StringBuilder lp);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", EntryPoint="FindWindowW", CharSet=CharSet.Unicode)]
    public static extern IntPtr FindWindow(string cls, string title);
}
"@

$WM_SETTEXT = 0x000C
$WM_GETTEXT = 0x000D
$WM_CLOSE = 0x0010
$BM_CLICK = 0x00F5
$ID_EDIT_FILE = 1001
$ID_EDIT_KEY = 1003
$ID_BTN_ENC = 1008
$ID_BTN_DEC = 1009
$ID_EDIT_LOG = 1010
$ID_EDIT_OUT = 1012

$script:pass = 0
$script:fail = 0
function Check([bool]$ok, [string]$name, [string]$detail) {
    if ($ok) { $script:pass++ } else { $script:fail++ }
    "[{0}] {1,-34} {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail
}

# If the app shows a modal dialog (only on errors), find it by window class
# #32770 and close it, so this script can never hang.
function DismissDialogs {
    for ($i = 0; $i -lt 5; $i++) {
        $dlg = [GuiDrv]::FindWindow('#32770', $null)
        if ($dlg -eq [IntPtr]::Zero) { break }
        [GuiDrv]::PostMessage($dlg, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 200
    }
}

function ReadLog([IntPtr]$hLog) {
    $sb = New-Object System.Text.StringBuilder 8192
    [GuiDrv]::GetText($hLog, $WM_GETTEXT, [IntPtr]8192, $sb) | Out-Null
    return $sb.ToString()
}

# Poll a condition without blocking forever
function WaitUntil([scriptblock]$cond, [int]$loops = 40, [int]$ms = 150) {
    for ($i = 0; $i -lt $loops; $i++) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds $ms
    }
    return $false
}

# ---------------------------- test data ----------------------------
$dir = Join-Path $env:TEMP 'tdes_gui_smoke'
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dir | Out-Null

$plain = Join-Path $dir 'demo_plain.txt'
1..200 | ForEach-Object { "InfoSec 3DES GUI smoke test line $_" } | Set-Content -Path $plain -Encoding UTF8
$cipher = "$plain.3des"                     # auto-derived default output name
$customDir = Join-Path $dir 'custom'
New-Item -ItemType Directory -Path $customDir | Out-Null
$customOut = Join-Path $customDir 'renamed_result.bin'
$explicitOut = Join-Path $dir 'explicit_restore.txt'
$key = 'A1B2C3D4E5F607182938F7E6D5C4B3A21029384756ABCDEF'   # 24 bytes = 3DES-3Key
$plainHash = (Get-FileHash $plain -Algorithm SHA256).Hash
$n = (Get-Item $plain).Length
$expectLen = 22 + ([math]::Floor($n / 8) + 1) * 8

"--- test data ---"
"plain     : $plain  ($n bytes)"
"sha256    : $plainHash"
"key       : $key"
"expected cipher length : $expectLen bytes"
""

# ---------------------------- launch GUI ----------------------------
$p = Start-Process -FilePath $exe -PassThru
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 30 -and $h -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 200
    $p.Refresh()
    $h = $p.MainWindowHandle
}
if ($h -eq [IntPtr]::Zero) { $p.Kill(); throw "GUI window not found" }
"window title : $($p.MainWindowTitle)"
""

$hFile = [GuiDrv]::GetDlgItem($h, $ID_EDIT_FILE)
$hKey = [GuiDrv]::GetDlgItem($h, $ID_EDIT_KEY)
$hEnc = [GuiDrv]::GetDlgItem($h, $ID_BTN_ENC)
$hDec = [GuiDrv]::GetDlgItem($h, $ID_BTN_DEC)
$hLog = [GuiDrv]::GetDlgItem($h, $ID_EDIT_LOG)
$hOut = [GuiDrv]::GetDlgItem($h, $ID_EDIT_OUT)

Check (($hFile -ne [IntPtr]::Zero) -and ($hKey -ne [IntPtr]::Zero) -and
    ($hEnc -ne [IntPtr]::Zero) -and ($hDec -ne [IntPtr]::Zero) -and
    ($hLog -ne [IntPtr]::Zero) -and ($hOut -ne [IntPtr]::Zero)) `
    "child controls found" "file/out/key/encrypt/decrypt/log"

# ------------- 1) selecting a file prefills the default output name -------------
[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
Start-Sleep -Milliseconds 300
$outNow = ReadLog $hOut
Check ($outNow -eq $cipher) "auto output name on file select" $outNow

# ------------- 2) encrypt with the default output path -------------
[GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
[GuiDrv]::PostMessage($hEnc, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
$ok = WaitUntil { Test-Path $cipher }
DismissDialogs
Check $ok "click Encrypt -> default cipher file" $(if ($ok) { "$((Get-Item $cipher).Length) bytes" } else { "not created" })
if ($ok) {
    Check ((Get-Item $cipher).Length -eq $expectLen) "cipher length = header + PKCS#7" `
        "got $((Get-Item $cipher).Length) / expected $expectLen"
    Check ((Get-FileHash $cipher -Algorithm SHA256).Hash -ne $plainHash) "ciphertext differs from plaintext" "sha256 changed"
}

# ------------- 3) custom output path (other directory + other name) -------------
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, $customOut) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hEnc, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
$ok = WaitUntil { Test-Path $customOut }
DismissDialogs
Check $ok "custom output path honored" $(if ($ok) { $customOut } else { "not created" })
if ($ok) {
    Check ((Get-Item $customOut).Length -eq $expectLen) "custom output has full content" `
        "got $((Get-Item $customOut).Length) / expected $expectLen"
    Check ((Get-FileHash $customOut -Algorithm SHA256).Hash -ne (Get-FileHash $cipher -Algorithm SHA256).Hash) `
        "random IV -> different ciphertext" "CBC IV is random per run"
}

# ------------- 4) output == input must be refused (no data loss) -------------
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hEnc, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 1200
DismissDialogs
Check ((Get-FileHash $plain -Algorithm SHA256).Hash -eq $plainHash) `
    "output == input refused" "input file left intact"

# ------------- 5) decrypt back with the auto-derived output name -------------
$bak = "$plain.bak"
Move-Item $plain $bak -Force       # move the original away so no overwrite dialog appears
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, '') | Out-Null   # empty = auto again
Start-Sleep -Milliseconds 200
[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $cipher) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hDec, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
$ok2 = WaitUntil { Test-Path $plain }
DismissDialogs
Check $ok2 "click Decrypt -> auto-restored file" $(if ($ok2) { "$((Get-Item $plain).Length) bytes" } else { "not restored" })
if ($ok2) {
    Check ((Get-FileHash $plain -Algorithm SHA256).Hash -eq $plainHash) "restored SHA256 == original" $plainHash
}

# ------------- 6) decrypt to an explicitly chosen output path -------------
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, $explicitOut) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hDec, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
$ok3 = WaitUntil { Test-Path $explicitOut }
DismissDialogs
Check $ok3 "decrypt to explicit output path" $(if ($ok3) { $explicitOut } else { "not created" })
if ($ok3) {
    Check ((Get-FileHash $explicitOut -Algorithm SHA256).Hash -eq $plainHash) `
        "explicit output SHA256 == original" $plainHash
}

""
"--- GUI log after encryption / decryption (last 16 lines) ---"
((ReadLog $hLog) -split "`r`n" | Select-Object -Last 16) -join "`r`n"
""

# ------------- 7) a nonexistent output directory must be refused -------------
$badOut = Join-Path $dir 'no_such_dir\x.bin'
[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, $badOut) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hEnc, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 1200
DismissDialogs
Check (-not (Test-Path $badOut)) "missing output dir refused" "no file created"

# ------------------- 8) wrong key is rejected -------------------
$wrongDir = Join-Path $dir 'wrong'
New-Item -ItemType Directory -Path $wrongDir | Out-Null
$c2 = Join-Path $wrongDir 'demo_plain.txt.3des'
Copy-Item $cipher $c2
$out2 = Join-Path $wrongDir 'demo_plain.txt'

[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $c2) | Out-Null
[GuiDrv]::SendText($hOut, $WM_SETTEXT, [IntPtr]::Zero, '') | Out-Null
[GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, ('B' + $key.Substring(1))) | Out-Null
Start-Sleep -Milliseconds 200
[GuiDrv]::PostMessage($hDec, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 1500
DismissDialogs
Start-Sleep -Milliseconds 400

$logText = ReadLog $hLog
# the failure line contains the ASCII marker "PKCS#7"; a successful run would have produced out2
$rejected = ($logText -like '*PKCS#7*') -and (-not (Test-Path $out2))
Check $rejected "wrong key rejected" $(if ($rejected) { "log reports PKCS#7 failure, no output" } else { "not detected" })

$p.CloseMainWindow() | Out-Null
Start-Sleep -Milliseconds 500
if (-not $p.HasExited) { $p.Kill() }

""
"Total: pass=$script:pass fail=$script:fail"
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit $(if ($script:fail -eq 0) { 0 } else { 1 })
