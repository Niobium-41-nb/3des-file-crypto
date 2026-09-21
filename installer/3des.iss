; ============================================================================
;  3des.iss —— 3DES 文件加解密工具的 Inno Setup 安装脚本
;  ---------------------------------------------------------------------------
;  编译（任选其一）：
;    1) 直接调用编译器：
;       "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\3des.iss
;    2) 用一键构建脚本（同时产出便携版 zip 与 SHA256 清单）：
;       powershell -NoProfile -ExecutionPolicy Bypass -File installer\build-installer.ps1
;
;  要点：
;    * 默认按“当前用户”安装（PrivilegesRequired=lowest，免管理员），
;      安装向导里仍可切换为“为所有用户安装”；
;    * 安装内容 = tdes.exe（命令行）+ tdes_gui.exe（图形界面）+ README.md；
;    * 可选任务：桌面图标、把安装目录加入 PATH（便于任意位置直接用 tdes）；
;    * 卸载时自动把安装目录从 PATH 中移除，不留残留（见文件末尾 [Code]）。
;    * 本文件必须以 UTF-8 **带 BOM** 保存，否则 Inno Setup 会按 ANSI 读取而显示乱码。
; ============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.1.0"
#endif

#define MyAppName      "3DES 文件加解密"
#define MyAppPublisher "张可凡 (Niobium-41-nb)"
#define MyAppURL       "https://github.com/Niobium-41-nb/3des-file-crypto"
#define MyAppExeName   "tdes_gui.exe"
#define MyCliExeName   "tdes.exe"
#define ProjectRoot    ".."

[Setup]
; AppId 是这个软件在系统中的唯一标识，升级/卸载都靠它，一旦发布就不要再改
AppId={{8F3D5A21-4C7B-4E6A-9D18-2B7C5E9A3F64}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
AppCopyright=Copyright (C) 2026 张可凡
DefaultDirName={autopf}\3DES-FileCrypto
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
MinVersion=6.1sp1
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#ProjectRoot}\dist
OutputBaseFilename=3DES-FileCrypto-{#MyAppVersion}-win64-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; 本软件面向中文用户：直接使用 [Languages] 中定义的第一种语言（简体中文），
; 不弹语言选择框；需要英文界面时可用 setup.exe /LANG=english
ShowLanguageDialog=no
ChangesEnvironment=yes
CloseApplications=yes
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} 安装程序

[Languages]
; ChineseSimplified.isl 取自 Inno Setup 官方源码仓库（与 ISCC 同目录，随本脚本一起提交）
Name: "chinese"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "把安装目录加入 PATH（之后可在任意位置直接执行 tdes 命令）"; GroupDescription: "环境设置："; Flags: checkedonce

[Files]
Source: "{#ProjectRoot}\tdes.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#ProjectRoot}\tdes_gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ProjectRoot}\README.md";    DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
Name: "{group}\{#MyAppName}（图形界面）"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\{#MyAppName}（命令行）";   Filename: "{cmd}"; Parameters: "/k ""{app}\{#MyCliExeName} help"""; WorkingDir: "{app}"; Comment: "打开命令行并显示用法"
Name: "{group}\卸载 {#MyAppName}";        Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";       Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; 把安装目录追加到“当前用户”的 PATH（{olddata} 表示原有内容）
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "立即启动 {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
// 判断安装目录是否已经在 PATH 中（不区分大小写），避免重复添加
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

// 从 PATH 字符串中删除一个条目（按“;条目;”整体匹配，不区分大小写）
function RemovePathEntry(const PathValue, Entry: string): string;
var
  Hay, Needle: string;
  P: Integer;
begin
  Hay := ';' + PathValue + ';';
  Needle := ';' + Entry + ';';
  P := Pos(Uppercase(Needle), Uppercase(Hay));
  if P = 0 then
  begin
    Result := PathValue;
    exit;
  end;
  Result := Copy(Hay, 1, P - 1) + Copy(Hay, P + Length(Needle), Length(Hay) - P - Length(Needle) + 1);
  while (Length(Result) > 0) and (Result[1] = ';') do
    Delete(Result, 1, 1);
  while (Length(Result) > 0) and (Result[Length(Result)] = ';') do
    Delete(Result, Length(Result), 1);
end;

// 卸载时清理 PATH，保持系统环境变量干净
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OrigPath, NewPath: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    if RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
    begin
      NewPath := RemovePathEntry(OrigPath, ExpandConstant('{app}'));
      if NewPath <> OrigPath then
        RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', NewPath);
    end;
  end;
end;
