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
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy-rules.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM myIPproxy-new.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM stopRKN.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(400);
end;
