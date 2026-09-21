# ============================================================================
#  shot_installer.ps1 -- capture ONLY the Inno Setup installer window
# ---------------------------------------------------------------------------
#  Privacy-safe: uses PrintWindow(hwnd) on the setup process' own window, so
#  nothing outside that window is captured (no full-desktop grab).
#  Useful to verify that the Chinese wizard text renders correctly.
#  ASCII-only on purpose (Windows PowerShell 5.1 reads .ps1 as ANSI).
#
#  Run: powershell -NoProfile -ExecutionPolicy Bypass -File tools\shot_installer.ps1
#  Output: %TEMP%\tdes_setup.png
# ============================================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$ver = if ($args.Count -ge 1) { $args[0] } else { '1.0.0' }
$exe = Join-Path $root "dist\3DES-FileCrypto-$ver-win64-setup.exe"
if (-not (Test-Path $exe)) { throw "installer not found: $exe (run installer\build-installer.ps1 first)" }
$out = Join-Path $env:TEMP 'tdes_setup.png'

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SetupShot {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@

[SetupShot]::SetProcessDPIAware() | Out-Null

$p = Start-Process -FilePath $exe -ArgumentList '/LANG=chinese' -PassThru

# Inno Setup extracts itself to %TEMP%\is-*.tmp\Setup.tmp and runs THAT copy,
# so the process we started has no window of its own -> poll for the real one.
$proc = $null
$deadline = (Get-Date).AddSeconds(20)
while ((-not $proc) -and ((Get-Date) -lt $deadline)) {
    Start-Sleep -Milliseconds 400
    $proc = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 -and $_.ProcessName -like '*setup*' } |
        Select-Object -First 1
}
if (-not $proc) {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like '*setup*' } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    throw 'no installer window found'
}

$h = $proc.MainWindowHandle
"window title: " + $proc.MainWindowTitle

[SetupShot]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 800

$r = New-Object 'SetupShot+RECT'
[SetupShot]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left
$hh = $r.Bottom - $r.Top
"window size : ${w} x ${hh}"

$bmp = New-Object System.Drawing.Bitmap $w, $hh
$g = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok = [SetupShot]::PrintWindow($h, $hdc, 2)   # 2 = PW_RENDERFULLCONTENT
$g.ReleaseHdc($hdc)
$g.Dispose()
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()

"PrintWindow : $ok"
"saved       : $out"

Start-Sleep -Milliseconds 300
$proc.CloseMainWindow() | Out-Null
Start-Sleep -Milliseconds 1000
# 向导收到 WM_CLOSE 会再弹一个“确认取消”对话框，直接结束进程即可一并关闭
foreach ($q in @($proc, $p)) {
    if ($q) {
        try { $q.Refresh() } catch { }
        if (-not $q.HasExited) { Stop-Process -Id $q.Id -Force -ErrorAction SilentlyContinue }
    }
}
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ProcessName -like '*setup*' } |
    Stop-Process -Force -ErrorAction SilentlyContinue
"closed      : ok"
