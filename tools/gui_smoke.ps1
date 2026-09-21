# ============================================================================
#  gui_smoke.ps1 -- End-to-end smoke test that DRIVES the GUI (no clicking by hand)
# ---------------------------------------------------------------------------
#  How it works: launches tdes_gui.exe, then talks to its child controls with
#  GetDlgItem + WM_SETTEXT / WM_GETTEXT / BM_CLICK, i.e. it exercises exactly the
#  code path a user would trigger (key parsing, output-name derivation,
#  encryptFile / decryptFile, log rendering). Any modal dialog is closed
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

# ---------------------------- test data ----------------------------
$dir = Join-Path $env:TEMP 'tdes_gui_smoke'
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dir | Out-Null

$plain = Join-Path $dir 'demo_plain.txt'
1..200 | ForEach-Object { "InfoSec 3DES GUI smoke test line $_" } | Set-Content -Path $plain -Encoding UTF8
$cipher = "$plain.3des"
$key = 'A1B2C3D4E5F607182938F7E6D5C4B3A21029384756ABCDEF'   # 24 bytes = 3DES-3Key
$plainHash = (Get-FileHash $plain -Algorithm SHA256).Hash

"--- test data ---"
"plain     : $plain"
"size      : $((Get-Item $plain).Length) bytes"
"sha256    : $plainHash"
"key       : $key"
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

Check (($hFile -ne [IntPtr]::Zero) -and ($hKey -ne [IntPtr]::Zero) -and
    ($hEnc -ne [IntPtr]::Zero) -and ($hDec -ne [IntPtr]::Zero) -and ($hLog -ne [IntPtr]::Zero)) `
    "child controls found" "file/key/encrypt/decrypt/log"

# ---------------------------- 1) encrypt ----------------------------
[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
[GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
[GuiDrv]::PostMessage($hEnc, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

$ok = $false
for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 150; if (Test-Path $cipher) { $ok = $true; break } }
DismissDialogs
Check $ok "click Encrypt -> cipher file" $(if ($ok) { "$((Get-Item $cipher).Length) bytes" } else { "not created" })

if ($ok) {
    $n = (Get-Item $plain).Length
    $expect = 22 + ([math]::Floor($n / 8) + 1) * 8
    Check ((Get-Item $cipher).Length -eq $expect) "cipher length = header + PKCS#7" `
        "got $((Get-Item $cipher).Length) / expected $expect"
    Check ((Get-FileHash $cipher -Algorithm SHA256).Hash -ne $plainHash) "ciphertext differs from plaintext" "sha256 changed"
}

""
"--- GUI log after encryption ---"
ReadLog $hLog
""

# ---------------------------- 2) decrypt ----------------------------
# remove the plaintext first so that no "overwrite?" dialog appears
Remove-Item $plain -Force
[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $cipher) | Out-Null
[GuiDrv]::PostMessage($hDec, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

$ok2 = $false
for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 150; if (Test-Path $plain) { $ok2 = $true; break } }
DismissDialogs
Check $ok2 "click Decrypt -> restored file" $(if ($ok2) { "$((Get-Item $plain).Length) bytes" } else { "not restored" })

if ($ok2) {
    $restoredHash = (Get-FileHash $plain -Algorithm SHA256).Hash
    Check ($restoredHash -eq $plainHash) "restored SHA256 == original" $restoredHash
}

""
"--- GUI log after decryption (last 12 lines) ---"
((ReadLog $hLog) -split "`r`n" | Select-Object -Last 12) -join "`r`n"
""

# ---------------------------- 3) wrong key ----------------------------
$wrongDir = Join-Path $dir 'wrong'
New-Item -ItemType Directory -Path $wrongDir | Out-Null
$c2 = Join-Path $wrongDir 'demo_plain.txt.3des'
Copy-Item $cipher $c2
$out2 = Join-Path $wrongDir 'demo_plain.txt'

[GuiDrv]::SendText($hFile, $WM_SETTEXT, [IntPtr]::Zero, $c2) | Out-Null
[GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, ('B' + $key.Substring(1))) | Out-Null
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
