; UTF-8
#define AppVersion "0.9.0"

[Setup]
AppId={{B7E4A1C6-2D58-4F0A-9C31-6A8E5D4B71F2}
AppName=stopRKN
AppVersion={#AppVersion}
AppPublisher=stopRKN
DefaultDirName={autopf}\stopRKN
DefaultGroupName=stopRKN
DisableProgramGroupPage=yes
UsePreviousAppDir=no
OutputDir=..\dist
OutputBaseFilename=stopRKN-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\stopRKN.exe
SetupIconFile=..\resources\shield.ico
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Ярлык на рабочем столе"; GroupDescription: "Ярлыки:"

[Files]
Source: "..\dist\stage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\stopRKN"; Filename: "{app}\stopRKN.exe"
Name: "{autodesktop}\stopRKN"; Filename: "{app}\stopRKN.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\stopRKN.exe"; Parameters: "--install-service"; StatusMsg: "Регистрация службы..."; Flags: runhidden waituntilterminated
Filename: "{app}\stopRKN.exe"; Description: "Запустить stopRKN"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\stopRKN.exe"; Parameters: "--uninstall-service"; Flags: runhidden waituntilterminated

[Messages]
russian.WelcomeLabel2=Программа будет установлена вместе со службой перехвата. Окно после этого открывается без прав администратора. Настройки и правила сохраняются в C:\ProgramData\stopRKN и при удалении не стираются.

[Code]
function CreateFileW(lpFileName: String; dwDesiredAccess, dwShareMode: Cardinal;
  lpSecurityAttributes: Cardinal; dwCreationDisposition, dwFlagsAndAttributes: Cardinal;
  hTemplateFile: Cardinal): Cardinal;
  external 'CreateFileW@kernel32.dll stdcall';
function CloseHandle(hObject: Cardinal): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

function FileLocked(const Path: String): Boolean;
var
  Handle: Cardinal;
begin
  if not FileExists(Path) then begin
    Result := False;
    Exit;
  end;
  Handle := CreateFileW(Path, $40000000, 0, 0, 3, $80, 0);
  if Handle = $FFFFFFFF then
    Result := True
  else begin
    CloseHandle(Handle);
    Result := False;
  end;
end;

procedure ReleaseDivert;
var
  ResultCode, I: Integer;
  SysPath: String;
begin
  SysPath := ExpandConstant('{app}\WinDivert64.sys');
  Exec(ExpandConstant('{sys}\sc.exe'), 'failure stopRKN reset= 0 actions= /', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'config stopRKN start= disabled', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop stopRKN', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  for I := 1 to 40 do begin
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM stopRKN.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy-rules.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy-new.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop WinDivert14', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(500);
    if not FileLocked(SysPath) then
      Exit;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  ReleaseDivert;
  if FileLocked(ExpandConstant('{app}\WinDivert64.sys')) then begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'config stopRKN start= auto', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'failure stopRKN reset= 86400 actions= restart/5000/restart/5000/restart/5000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\sc.exe'), 'start stopRKN', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Result := 'WinDivert64.sys всё ещё занят. Закройте stopRKN и повторите установку.';
  end else
    Result := '';
end;
