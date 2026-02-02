; OpenLabels Installer Script
; Requires Inno Setup 6.0+
; https://jrsoftware.org/isinfo.php

#define MyAppName "OpenLabels"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Chillbot.io"
#define MyAppURL "https://github.com/chillbot-io/openlabels"
#define MyAppExeName "OpenLabelsTray.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=dist
OutputBaseFilename=OpenLabels-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Start with Windows"; GroupDescription: "Startup:"
Name: "installservice"; Description: "Install as Windows Service"; GroupDescription: "Service:"

[Files]
; Main application files (PyInstaller output)
Source: "dist\OpenLabels\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Docker Compose file
Source: "..\docker-compose.yml"; DestDir: "{commonappdata}\OpenLabels"; Flags: ignoreversion

; Sample configuration
Source: "config.sample.yaml"; DestDir: "{commonappdata}\OpenLabels"; DestName: "config.yaml"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Add to startup if selected
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OpenLabels"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: startupicon

; Store installation path
Root: HKLM; Subkey: "Software\OpenLabels"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\OpenLabels"; ValueType: string; ValueName: "DataPath"; ValueData: "{commonappdata}\OpenLabels"

[Run]
; Check for Docker Desktop
Filename: "{cmd}"; Parameters: "/c docker --version"; Flags: runhidden; Check: not IsDockerInstalled; BeforeInstall: CheckDockerRequirement

; Pull Docker images after install
Filename: "{cmd}"; Parameters: "/c docker compose -f ""{commonappdata}\OpenLabels\docker-compose.yml"" pull"; Description: "Download container images"; Flags: postinstall runhidden; StatusMsg: "Downloading container images..."

; Start the tray application
Filename: "{app}\{#MyAppExeName}"; Description: "Launch OpenLabels"; Flags: postinstall nowait skipifsilent

; Install Windows service if selected
Filename: "{app}\OpenLabelsService.exe"; Parameters: "install"; Flags: runhidden; Tasks: installservice
Filename: "{app}\OpenLabelsService.exe"; Parameters: "start"; Flags: runhidden; Tasks: installservice

[UninstallRun]
; Stop and remove service
Filename: "{app}\OpenLabelsService.exe"; Parameters: "stop"; Flags: runhidden
Filename: "{app}\OpenLabelsService.exe"; Parameters: "remove"; Flags: runhidden

; Stop Docker containers
Filename: "{cmd}"; Parameters: "/c docker compose -p openlabels down"; Flags: runhidden

[Code]
function IsDockerInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('docker', '--version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure CheckDockerRequirement();
begin
  if not IsDockerInstalled() then
  begin
    if MsgBox('Docker Desktop is required but not installed.' + #13#10 + #13#10 +
              'Would you like to download Docker Desktop now?' + #13#10 + #13#10 +
              'Click Yes to open the download page, or No to continue anyway.',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://www.docker.com/products/docker-desktop/', '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;

  // Check Windows version (requires Windows 10+)
  if not IsWin64 then
  begin
    MsgBox('OpenLabels requires 64-bit Windows 10 or later.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create data directories
    ForceDirectories(ExpandConstant('{commonappdata}\OpenLabels\data'));
    ForceDirectories(ExpandConstant('{commonappdata}\OpenLabels\logs'));
  end;
end;
