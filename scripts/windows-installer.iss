#define AppVersion GetEnv("NVPN_RELEASE_VERSION")
#define SourceDir GetEnv("NVPN_WINDOWS_PUBLISH_DIR")
#define OutputDir GetEnv("NVPN_WINDOWS_INSTALLER_OUTPUT_DIR")
#define OutputBaseName GetEnv("NVPN_WINDOWS_INSTALLER_BASENAME")
#define ProjectRoot GetEnv("NVPN_PROJECT_ROOT")

[Setup]
AppId={{DA4FA554-4718-4E6D-8CE8-E43A05B4B723}
AppName=Nostr VPN
AppVersion={#AppVersion}
AppPublisher=Nostr VPN
DefaultDirName={localappdata}\Programs\Nostr VPN
DefaultGroupName=Nostr VPN
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
PrivilegesRequired=lowest
CloseApplications=yes
CloseApplicationsFilter=NostrVpn.Windows.exe,nostr-vpn-gui.exe
SetupIconFile={#ProjectRoot}\windows\NostrVpn.Windows\Assets\nostr-vpn.ico
UninstallDisplayIcon={app}\NostrVpn.Windows.exe

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectRoot}\windows\installer\windows-installer-migrate.ps1"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\Nostr VPN"; Filename: "{app}\NostrVpn.Windows.exe"; IconFilename: "{app}\Assets\nostr-vpn.ico"
Name: "{autodesktop}\Nostr VPN"; Filename: "{app}\NostrVpn.Windows.exe"; IconFilename: "{app}\Assets\nostr-vpn.ico"; Tasks: desktopicon

Name: "{userappdata}\Microsoft\Windows\SendTo\Nostr VPN"; Filename: "{app}\NostrVpn.Windows.exe"; Parameters: "--send-files"; IconFilename: "{app}\Assets\nostr-vpn.ico"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\NostrVpn.Windows.exe"; Description: "Launch Nostr VPN"; Flags: nowait postinstall skipifsilent

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  MigrationScript: String;
  ResultCode: Integer;
begin
  ExtractTemporaryFile('windows-installer-migrate.ps1');
  MigrationScript := ExpandConstant('{tmp}\windows-installer-migrate.ps1');
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + MigrationScript + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
  then
  begin
    Result := 'Nostr VPN could not inspect the existing Windows installation. Setup stopped before copying files.';
    exit;
  end;
  if ResultCode <> 0 then
  begin
    Result := 'Nostr VPN could not safely replace an existing installation. Setup stopped to avoid installing a second copy.';
    exit;
  end;
  Result := '';
end;
