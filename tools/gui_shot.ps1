# ============================================================================
#  gui_shot.ps1 -- Launch tdes_gui.exe and capture ONLY its own window
# ---------------------------------------------------------------------------
#  Privacy-safe: uses PrintWindow(hwnd) so nothing outside the app window is
#  captured (no full-desktop grab).
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\gui_shot.ps1
#  Output: %TEMP%\tdes_gui.png
# ============================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'tdes_gui.exe'
if (-not (Test-Path $exe)) { throw "tdes_gui.exe not found: $exe (build it first)" }
$out = Join-Path $env:TEMP 'tdes_gui.png'

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class GuiShot {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@

# 让本脚本自身也 DPI 感知，否则在高分屏上 GetWindowRect 返回的是虚拟化尺寸，
# 会导致截出的图被裁切。
[GuiShot]::SetProcessDPIAware() | Out-Null

$p = Start-Process -FilePath $exe -PassThru
Start-Sleep -Milliseconds 1500
$p.Refresh()
$h = $p.MainWindowHandle
if ($h -eq [IntPtr]::Zero) { $p.Kill(); throw "no main window found" }

"window title: " + $p.MainWindowTitle

[GuiShot]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 600

$r = New-Object 'GuiShot+RECT'
[GuiShot]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left
$hh = $r.Bottom - $r.Top
"window size : ${w} x ${hh}"

$bmp = New-Object System.Drawing.Bitmap $w, $hh
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [GuiShot]::PrintWindow($h, $hdc, 2)   # 2 = PW_RENDERFULLCONTENT
$g.ReleaseHdc($hdc)
$g.Dispose()
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

"PrintWindow : $ok"
"saved       : $out"

Start-Sleep -Milliseconds 300
$p.CloseMainWindow() | Out-Null
Start-Sleep -Milliseconds 300
if (-not $p.HasExited) { $p.Kill() }
"closed      : ok"
