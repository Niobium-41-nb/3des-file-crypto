# ============================================================================
#  gui_smoke.ps1 -- End-to-end smoke test that DRIVES the 7-Zip-style GUI
# ---------------------------------------------------------------------------
#  The main window was redesigned to mimic 7-Zip, so this script talks to the
#  new control set:
#     - the address bar is an editable COMBOBOX (2003) carrying the folder/file
#       path, so a file is selected by typing its path and notifying the app;
#     - commands (encrypt / decrypt / info / ...) are dispatched by posting
#       WM_COMMAND to the main window with the same IDs the menu and the
#       self-drawn toolbar use;
#     - parameters live in two modal #32770 dialogs, located with
#       FindWindow('#32770', $null) and driven with GetDlgItem + WM_SETTEXT /
#       BM_CLICK. Any dialog is closed automatically so the script can never
#       hang, and the dialogs are captured as PNG as well.
#
#  ASCII-only on purpose: Windows PowerShell 5.1 reads .ps1 files using the ANSI
#  code page, so any non-ASCII byte in this file would be corrupted.
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\gui_smoke.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'tdes_gui.exe'
if (-not (Test-Path $exe)) { throw "tdes_gui.exe not found: $exe (build it first)" }

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
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
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll", EntryPoint="GetClassNameW", CharSet=CharSet.Unicode)]
    public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    public delegate bool EnumProc(IntPtr h, IntPtr lp);

    // Find a visible top-level dialog (#32770) that belongs to the target process.
    // Matching by class alone is not enough: other processes (IME, shell) also own
    // #32770 windows, so the owning process id is checked as well.
    public static IntPtr FindOwnDialog(uint wantPid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr h, IntPtr lp) {
            if (!IsWindowVisible(h)) return true;
            uint p; GetWindowThreadProcessId(h, out p);
            if (p != wantPid) return true;
            var cn = new StringBuilder(64);
            GetClassName(h, cn, 64);
            if (cn.ToString() != "#32770") return true;
            found = h;
            return false;
        }, IntPtr.Zero);
        return found;
    }
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    // The common file dialog is a visible #32770 owned by our process that hosts the
    // shell view (SHELLDLL_DefView). The app's own parameter dialogs use IDs in the
    // 4000 range and have no shell view, so there is no ambiguity.
    public static IntPtr FindOwnFileDialog(uint wantPid) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate(IntPtr h, IntPtr lp) {
            if (!IsWindowVisible(h)) return true;
            uint p; GetWindowThreadProcessId(h, out p);
            if (p != wantPid) return true;
            var cn = new StringBuilder(64);
            GetClassName(h, cn, 64);
            if (cn.ToString() != "#32770") return true;
            if (GetDlgItem(h, 4006) != IntPtr.Zero) return true;   // encrypt dialog
            if (GetDlgItem(h, 4103) != IntPtr.Zero) return true;   // decrypt dialog
            if (FindChildByClass(h, "SHELLDLL_DefView") == IntPtr.Zero) return true;
            found = h;
            return false;
        }, IntPtr.Zero);
        return found;
    }

    // First descendant of the given class (depth-first order as reported by the OS).
    public static IntPtr FindChildByClass(IntPtr h, string cls) {
        IntPtr found = IntPtr.Zero;
        EnumChildWindows(h, delegate(IntPtr c, IntPtr lp) {
            if (found != IntPtr.Zero) return true;
            var sb = new StringBuilder(128); GetClassName(c, sb, 128);
            if (sb.ToString().IndexOf(cls, StringComparison.OrdinalIgnoreCase) >= 0) found = c;
            return true;
        }, IntPtr.Zero);
        return found;
    }

    // The "File name" edit of the common dialog (id 1001 / edt1); fall back to the
    // first Edit control found.
    public static IntPtr FindFileNameEdit(IntPtr h) {
        IntPtr[] all = FindEdits(h);
        return all.Length > 0 ? all[0] : IntPtr.Zero;
    }

    // The "File name" edit differs between common-dialog styles (id 1148 with the
    // modern shell view, 1001 or 0 for others), so return every Edit candidate with
    // the known file-name ids first.
    public static IntPtr[] FindEdits(IntPtr h) {
        var all = new List<IntPtr>();
        EnumChildWindows(h, delegate(IntPtr c, IntPtr lp) {
            var sb = new StringBuilder(128); GetClassName(c, sb, 128);
            if (sb.ToString() == "Edit") all.Add(c);
            return true;
        }, IntPtr.Zero);
        var ordered = new List<IntPtr>();
        foreach (int id in new int[] { 1148, 1001 }) {
            foreach (IntPtr c in all) if (GetDlgCtrlID(c) == id) ordered.Add(c);
        }
        foreach (IntPtr c in all) if (!ordered.Contains(c)) ordered.Add(c);
        return ordered.ToArray();
    }

    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);

    public static bool SetDlgItemText(IntPtr h, int id, string s) {
        IntPtr c = GetDlgItem(h, id);
        if (c == IntPtr.Zero) return false;
        SendText(c, 0x000C, IntPtr.Zero, s);   // WM_SETTEXT
        return true;
    }
}
"@

# must run DPI aware ourselves, otherwise GetWindowRect returns virtualized
# coordinates and PrintWindow captures a cropped corner on scaled displays
[GuiDrv]::SetProcessDPIAware() | Out-Null

# ------------------------------ window messages ------------------------------
$WM_SETTEXT     = 0x000C
$WM_GETTEXT     = 0x000D
$WM_COMMAND     = 0x0111
$WM_CLOSE       = 0x0010
$BM_CLICK       = 0x00F5
$LVM_GETITEMCOUNT = 0x1004
$CBN_EDITCHANGE = 5

# ------------------ main window control / command IDs (see src/gui.cpp) ------------------
$IDC_TOOLBAR    = 2001
$IDC_ADDR       = 2003
$IDC_LIST       = 2004
$IDC_LOG        = 2005
$IDC_STATUS     = 2006
$IDM_FILE_ENC   = 3002
$IDM_FILE_DEC   = 3003
$IDM_TOOLS_INFO = 3012

# ------------------------------ dialog control IDs ------------------------------
$IDC_ENC_OUT = 4001
$IDC_ENC_ALG = 4003
$IDC_ENC_KEY = 4006
$IDC_ENC_HINT = 4008
$IDC_ENC_KEY_IMPORT = 4012
$IDC_ENC_KEY_EXPORT = 4013
$IDOK        = 1
$IDC_DEC_OUT = 4101
$IDC_DEC_KEY = 4103
$IDC_DEC_HINT = 4104
$IDC_DEC_KEY_IMPORT = 4108
$IDC_DEC_KEY_EXPORT = 4109
$IDC_TXT_EDIT = 4201

$shotDir = Join-Path $env:TEMP 'tdes_gui_shots'
Remove-Item $shotDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $shotDir | Out-Null

$script:pass = 0
$script:fail = 0
function Check([bool]$ok, [string]$name, [string]$detail) {
    if ($ok) { $script:pass++ } else { $script:fail++ }
    "[{0}] {1,-38} {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail
}

function FindDialog { return [GuiDrv]::FindOwnDialog($script:appPid) }

function WaitDialog([int]$loops = 40) {
    for ($i = 0; $i -lt $loops; $i++) {
        $d = FindDialog
        if ($d -ne [IntPtr]::Zero) { return $d }
        Start-Sleep -Milliseconds 120
    }
    return [IntPtr]::Zero
}

# Close any modal dialog (#32770), including error message boxes, so the script
# can never hang. Returns how many dialogs were dismissed.
function DismissDialogs {
    $n = 0
    for ($i = 0; $i -lt 6; $i++) {
        $dlg = FindDialog
        if ($dlg -eq [IntPtr]::Zero) { break }
        [GuiDrv]::PostMessage($dlg, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        $n++
        Start-Sleep -Milliseconds 250
    }
    return $n
}

function ReadText([IntPtr]$h) {
    $sb = New-Object System.Text.StringBuilder 16384
    [GuiDrv]::GetText($h, $WM_GETTEXT, [IntPtr]16384, $sb) | Out-Null
    return $sb.ToString()
}

function WaitUntil([scriptblock]$cond, [int]$loops = 40, [int]$ms = 150) {
    for ($i = 0; $i -lt $loops; $i++) {
        if (& $cond) { return $true }
        Start-Sleep -Milliseconds $ms
    }
    return $false
}

function WaitFileDialog([int]$loops = 40) {
    for ($i = 0; $i -lt $loops; $i++) {
        $d = [GuiDrv]::FindOwnFileDialog($script:appPid)
        if ($d -ne [IntPtr]::Zero) { return $d }
        Start-Sleep -Milliseconds 120
    }
    return [IntPtr]::Zero
}

# Type the target path into the file name field of the common file dialog and press
# its OK button ("Open" / "Save"), so key-file import/export can be driven headless.
# The file-name edit ID varies with the dialog style, so each candidate is tried
# until the dialog closes.
function CompleteFileDialog([IntPtr]$d, [string]$path) {
    foreach ($edit in [GuiDrv]::FindEdits($d)) {
        [GuiDrv]::SendText($edit, $WM_SETTEXT, [IntPtr]::Zero, $path) | Out-Null
        Start-Sleep -Milliseconds 250
        $btn = [GuiDrv]::GetDlgItem($d, $IDOK)
        if ($btn -eq [IntPtr]::Zero) { return $false }
        [GuiDrv]::PostMessage($btn, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        Start-Sleep -Milliseconds 700
        if (-not [GuiDrv]::IsWindow($d)) { return $true }
    }
    return $false
}

# Privacy-safe capture: PrintWindow on our own window only
function Shot([IntPtr]$h, [string]$name) {
    if ($h -eq [IntPtr]::Zero) { return '' }
    [GuiDrv]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 300
    $r = New-Object 'GuiDrv+RECT'
    [GuiDrv]::GetWindowRect($h, [ref]$r) | Out-Null
    $w = $r.Right - $r.Left
    $ht = $r.Bottom - $r.Top
    if ($w -le 0 -or $ht -le 0) { return '' }
    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $hdc = $g.GetHdc()
    [GuiDrv]::PrintWindow($h, $hdc, 2) | Out-Null   # 2 = PW_RENDERFULLCONTENT
    $g.ReleaseHdc($hdc)
    $g.Dispose()
    $path = Join-Path $shotDir ($name + '.png')
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return $path
}

# ---------------------------- test data ----------------------------
$dir = Join-Path $env:TEMP 'tdes_gui_smoke'
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dir | Out-Null

$plain = Join-Path $dir 'demo_plain.txt'
1..200 | ForEach-Object { "InfoSec 3DES GUI smoke test line $_" } | Set-Content -Path $plain -Encoding UTF8
$cipher = "$plain.3des"                      # auto-derived default output name
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
$p = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 30 -and $h -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 200
    $p.Refresh()
    $h = $p.MainWindowHandle
}
if ($h -eq [IntPtr]::Zero) { $p.Kill(); throw "GUI window not found" }
$script:appPid = [uint32]$p.Id
"window title : $($p.MainWindowTitle)"
"process id   : $($script:appPid)"
""

$hAddr = [GuiDrv]::GetDlgItem($h, $IDC_ADDR)
$hList = [GuiDrv]::GetDlgItem($h, $IDC_LIST)
$hLog  = [GuiDrv]::GetDlgItem($h, $IDC_LOG)
$hTB   = [GuiDrv]::GetDlgItem($h, $IDC_TOOLBAR)
$hStat = [GuiDrv]::GetDlgItem($h, $IDC_STATUS)

Check (($hAddr -ne [IntPtr]::Zero) -and ($hList -ne [IntPtr]::Zero) -and
       ($hLog -ne [IntPtr]::Zero) -and ($hTB -ne [IntPtr]::Zero) -and
       ($hStat -ne [IntPtr]::Zero)) `
    "7-Zip style shell controls" "toolbar/address/list/log/status"

$rows = [GuiDrv]::Send($hList, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
Check ($rows.ToInt32() -gt 0) "file list populated" "$($rows.ToInt32()) rows"

# ------------- 1) selecting a file through the address bar -------------
[GuiDrv]::SendText($hAddr, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
[GuiDrv]::Send($h, $WM_COMMAND, [IntPtr](($CBN_EDITCHANGE -shl 16) -bor $IDC_ADDR), [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 500
Check (([GuiDrv]::Send($hList, $LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)).ToInt32() -gt 0) `
    "address bar selects a file" "file list refreshed"

# ------------- 2) encrypt with the auto-derived default output name -------------
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_ENC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
Check ($dlg -ne [IntPtr]::Zero) "encrypt dialog opened" "window class #32770"
if ($dlg -ne [IntPtr]::Zero) {
    $autoOut = ReadText ([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_OUT))
    Check ($autoOut -eq $cipher) "auto output name prefilled" $autoOut
    Check (([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_ALG) -ne [IntPtr]::Zero)) `
        "encrypt dialog has format combo" "DES / 3DES-2Key / 3DES-3Key"

    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY), $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    "encrypt dialog shot : " + (Shot $dlg 'dialog_encrypt')

    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
}
$ok = WaitUntil { Test-Path $cipher }
DismissDialogs | Out-Null
Check $ok "encrypt -> default cipher file" $(if ($ok) { "$((Get-Item $cipher).Length) bytes" } else { "not created" })
if ($ok) {
    Check ((Get-Item $cipher).Length -eq $expectLen) "cipher length = header + PKCS#7" `
        "got $((Get-Item $cipher).Length) / expected $expectLen"
    Check ((Get-FileHash $cipher -Algorithm SHA256).Hash -ne $plainHash) "ciphertext differs from plaintext" "sha256 changed"
    Check ((ReadText $hLog).Contains($cipher)) "operation logged in log panel" "output path present"
}

# ------------- 3) custom output path (other directory + other name) -------------
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_ENC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_OUT), $WM_SETTEXT, [IntPtr]::Zero, $customOut) | Out-Null
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY), $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
}
$ok = WaitUntil { Test-Path $customOut }
DismissDialogs | Out-Null
Check $ok "custom output path honored" $(if ($ok) { $customOut } else { "not created" })
if ($ok) {
    Check ((Get-Item $customOut).Length -eq $expectLen) "custom output has full content" `
        "got $((Get-Item $customOut).Length) / expected $expectLen"
    Check ((Get-FileHash $customOut -Algorithm SHA256).Hash -ne (Get-FileHash $cipher -Algorithm SHA256).Hash) `
        "random IV -> different ciphertext" "CBC IV is random per run"
}

# ------------- 4) output == input must be refused (no data loss) -------------
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_ENC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_OUT), $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY), $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    Start-Sleep -Milliseconds 900
    $dn = DismissDialogs
    Check ($dn -gt 0) "output == input refused" "validation dialog shown"
} else {
    Check $false "output == input refused" "encrypt dialog not found"
}
Start-Sleep -Milliseconds 300
Check ((Get-FileHash $plain -Algorithm SHA256).Hash -eq $plainHash) `
    "input file left intact" "sha256 unchanged"

# ------------- 5) decrypt back with the auto-derived output name -------------
$bak = "$plain.bak"
Move-Item $plain $bak -Force       # move the original away so no overwrite dialog appears
[GuiDrv]::SendText($hAddr, $WM_SETTEXT, [IntPtr]::Zero, $cipher) | Out-Null
[GuiDrv]::Send($h, $WM_COMMAND, [IntPtr](($CBN_EDITCHANGE -shl 16) -bor $IDC_ADDR), [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 500
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_DEC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    $autoDec = ReadText ([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_OUT))
    Check ($autoDec -eq $plain) "auto restore name prefilled" $autoDec
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_KEY), $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    "decrypt dialog shot : " + (Shot $dlg 'dialog_decrypt')
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
} else {
    Check $false "auto restore name prefilled" "decrypt dialog not found"
}
$ok2 = WaitUntil { Test-Path $plain }
DismissDialogs | Out-Null
Check $ok2 "decrypt -> auto-restored file" $(if ($ok2) { "$((Get-Item $plain).Length) bytes" } else { "not restored" })
if ($ok2) {
    Check ((Get-FileHash $plain -Algorithm SHA256).Hash -eq $plainHash) "restored SHA256 == original" $plainHash
}

# ------------- 6) decrypt to an explicitly chosen output path -------------
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_DEC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_OUT), $WM_SETTEXT, [IntPtr]::Zero, $explicitOut) | Out-Null
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_KEY), $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
}
$ok3 = WaitUntil { Test-Path $explicitOut }
DismissDialogs | Out-Null
Check $ok3 "decrypt to explicit output path" $(if ($ok3) { $explicitOut } else { "not created" })
if ($ok3) {
    Check ((Get-FileHash $explicitOut -Algorithm SHA256).Hash -eq $plainHash) `
        "explicit output SHA256 == original" $plainHash
}

# ------------- 7) "info" dialog parses the cipher header -------------
[GuiDrv]::SendText($hAddr, $WM_SETTEXT, [IntPtr]::Zero, $cipher) | Out-Null
[GuiDrv]::Send($h, $WM_COMMAND, [IntPtr](($CBN_EDITCHANGE -shl 16) -bor $IDC_ADDR), [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 400
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_TOOLS_INFO, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    $info = ReadText ([GuiDrv]::GetDlgItem($dlg, $IDC_TXT_EDIT))
    Check ($info.Contains('TDS1') -and $info.Contains('3DES-3Key')) `
        "info dialog parses cipher header" "magic + algorithm found"
    "info dialog shot    : " + (Shot $dlg 'dialog_info')
} else {
    Check $false "info dialog parses cipher header" "dialog not found"
}
DismissDialogs | Out-Null

# ------------- 8) key file export / import driven from the encrypt dialog -------------
$keyFile = Join-Path $dir 'gui_key.key'
[GuiDrv]::SendText($hAddr, $WM_SETTEXT, [IntPtr]::Zero, $plain) | Out-Null
[GuiDrv]::Send($h, $WM_COMMAND, [IntPtr](($CBN_EDITCHANGE -shl 16) -bor $IDC_ADDR), [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 400
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_ENC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    $hKey = [GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY)
    $hImp = [GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY_IMPORT)
    $hExp = [GuiDrv]::GetDlgItem($dlg, $IDC_ENC_KEY_EXPORT)
    Check (($hImp -ne [IntPtr]::Zero) -and ($hExp -ne [IntPtr]::Zero)) `
        "encrypt dialog has key import/export buttons" "IDs 4012 / 4013"

    # --- export the typed key to a .key file ---
    [GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, $key) | Out-Null
    Start-Sleep -Milliseconds 200
    [GuiDrv]::PostMessage($hExp, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $fd = WaitFileDialog
    Check ($fd -ne [IntPtr]::Zero) "export button opens a save dialog" "common file dialog"
    if ($fd -ne [IntPtr]::Zero) { CompleteFileDialog $fd $keyFile | Out-Null }
    $saved = WaitUntil { Test-Path $keyFile }
    Check $saved "key exported to file" $(if ($saved) { Split-Path -Leaf $keyFile } else { "not created" })
    if ($saved) {
        $txt = [System.IO.File]::ReadAllText($keyFile)
        Check ([regex]::IsMatch($txt, '(?m)^key=' + $key + '\s*$')) `
            "exported key file holds the key" "key= line matches"
    }

    # --- clear the field, then import the same file back ---
    # NOTE: the key field is a password edit, so another process cannot read its
    # text back (GetWindowText returns "").  The import is therefore verified by
    # the hint label plus a real encryption with the imported key below.
    $importOut = Join-Path $dir 'imported_key_check.3des'
    [GuiDrv]::SendText($hKey, $WM_SETTEXT, [IntPtr]::Zero, '') | Out-Null
    Start-Sleep -Milliseconds 150
    [GuiDrv]::PostMessage($hImp, $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $fd = WaitFileDialog
    Check ($fd -ne [IntPtr]::Zero) "import button opens an open dialog" "common file dialog"
    if ($fd -ne [IntPtr]::Zero) { CompleteFileDialog $fd $keyFile | Out-Null }
    $hint = [GuiDrv]::GetDlgItem($dlg, $IDC_ENC_HINT)
    $hinted = WaitUntil { (ReadText $hint) -match 'gui_key' }
    Check $hinted "import reports the imported key file" $(if ($hinted) { (ReadText $hint) } else { "hint: $(ReadText $hint)" })

    # --- the imported key must be accepted by the dialog: OK closes it and encrypts ---
    "encrypt+key dialog shot : " + (Shot $dlg 'dialog_encrypt_keyfile')
    [GuiDrv]::SendText([GuiDrv]::GetDlgItem($dlg, $IDC_ENC_OUT), $WM_SETTEXT, [IntPtr]::Zero, $importOut) | Out-Null
    Start-Sleep -Milliseconds 200
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDOK), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $okImp = WaitUntil { Test-Path $importOut }
    DismissDialogs | Out-Null
    Check ($okImp -and ((Get-Item $importOut).Length -eq $expectLen)) `
        "imported key really encrypts the file" `
        $(if ($okImp) { "$((Get-Item $importOut).Length) bytes" } else { "no output (key was rejected?)" })
} else {
    Check $false "encrypt dialog has key import/export buttons" "encrypt dialog not found"
}
DismissDialogs | Out-Null

# the decrypt dialog carries the same two buttons
[GuiDrv]::PostMessage($h, $WM_COMMAND, [IntPtr]$IDM_FILE_DEC, [IntPtr]::Zero) | Out-Null
$dlg = WaitDialog
if ($dlg -ne [IntPtr]::Zero) {
    Check (([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_KEY_IMPORT) -ne [IntPtr]::Zero) -and
           ([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_KEY_EXPORT) -ne [IntPtr]::Zero)) `
        "decrypt dialog has key import/export buttons" "IDs 4108 / 4109"
    # import a key file into the decrypt dialog as well (hint proves it was read)
    [GuiDrv]::PostMessage([GuiDrv]::GetDlgItem($dlg, $IDC_DEC_KEY_IMPORT), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $fd = WaitFileDialog
    if ($fd -ne [IntPtr]::Zero) { CompleteFileDialog $fd $keyFile | Out-Null }
    $hint = [GuiDrv]::GetDlgItem($dlg, $IDC_DEC_HINT)
    $hinted = WaitUntil { (ReadText $hint) -match 'gui_key' }
    Check $hinted "decrypt dialog imports a key file" $(if ($hinted) { (ReadText $hint) } else { "hint: $(ReadText $hint)" })
    "decrypt+key dialog shot : " + (Shot $dlg 'dialog_decrypt_keyfile')
} else {
    Check $false "decrypt dialog has key import/export buttons" "decrypt dialog not found"
}
DismissDialogs | Out-Null

# ------------- 9) main window capture -------------
Start-Sleep -Milliseconds 400
"main window shot    : " + (Shot $h 'window_main')

# ---------------------------- shutdown ----------------------------
[GuiDrv]::PostMessage($h, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 500
$p.Refresh()
if (-not $p.HasExited) { $p.Kill() }

""
"== $($script:pass) passed, $($script:fail) failed =="
"shots: $shotDir"
if ($script:fail -gt 0) { exit 1 }
