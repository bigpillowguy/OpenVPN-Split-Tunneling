; Inno Setup script for VpnClient
;
; Use installer/build.ps1 to build, validate dependencies and compile this script.
;
; Output:  installer\Output\VpnClientSetup-1.0.0.exe

#if VER < EncodeVer(6, 7, 0)
  #error "Inno Setup 6.7 or newer is required"
#endif

#define MyAppName      "OpenVPN Split Tunneling Client"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "ena"
#define MyAppExeName   "VpnClient.Ui.exe"
#define MyAppId        "{{A6A4F2D2-6E1E-4D6F-A2D6-9E1F7B3B8FCC}"

#define UiPublishDir   "..\dotnet\VpnClient.Ui\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish"
#define RedirectorDir  "..\target\release"
#define OpenVpnVersion "2.7.4-I001"
#define OpenVpnMsi     "OpenVPN-" + OpenVpnVersion + "-amd64.msi"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\VpnClient
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
OutputDir=Output
OutputBaseFilename=VpnClientSetup-{#MyAppVersion}
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
CloseApplicationsFilter=VpnClient.Ui.exe,redirector.exe
RestartApplications=no
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
; UI (single self-contained exe — bundles .NET runtime + WPF + Wpf.Ui)
Source: "{#UiPublishDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Redirector + WinDivert. The two WinDivert files MUST live next to
; redirector.exe — WinDivert resolves its driver path relative to its DLL.
Source: "{#RedirectorDir}\redirector.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#RedirectorDir}\WinDivert.dll";    DestDir: "{app}"; Flags: ignoreversion
Source: "{#RedirectorDir}\WinDivert64.sys";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "..\vendor\windivert\LICENSE"; DestDir: "{app}\licenses"; DestName: "WinDivert-LICENSE.txt"; Flags: ignoreversion

; Bundled prerequisite is extracted by PrepareToInstall only when the native
; OpenVPN binary/version or a compatible registered driver is missing.
Source: "deps\{#OpenVpnMsi}"; Flags: dontcopy

[Icons]
Name: "{group}\{#MyAppName}";          Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";    Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; shellexec is required because the UI exe is marked requireAdministrator in
; its manifest. CreateProcess from the installer fails with ERROR_ELEVATION_
; REQUIRED (740); ShellExecute triggers the UAC prompt the way Explorer would.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: shellexec postinstall skipifsilent; Check: CanLaunch

[Code]
var
  PrerequisiteNeedsRestart: Boolean;

function OpenVpnInstalled: Boolean;
var
  VersionMS, VersionLS: Cardinal;
begin
  // Only the native x64 installation is suitable for this package.
  Result := GetVersionNumbers(ExpandConstant('{commonpf64}\OpenVPN\bin\openvpn.exe'), VersionMS, VersionLS);
  if Result then
    Result := VersionMS >= ((2 shl 16) or 7);
  if Result then
    Result := RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\ovpn-dco')
           or RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\tap0901');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  MsiPath: String;
begin
  Result := '';
  if OpenVpnInstalled then exit;
  ExtractTemporaryFile('{#OpenVpnMsi}');
  MsiPath := ExpandConstant('{tmp}\{#OpenVpnMsi}');
  if not Exec(ExpandConstant('{sys}\msiexec.exe'),
      '/i "' + MsiPath + '" /quiet /norestart ADDLOCAL=OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6 /L*v "' + ExpandConstant('{tmp}\OpenVPN-install.log') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    Result := 'Could not start the OpenVPN installer. Windows error: ' + IntToStr(ResultCode);
    exit;
  end;
  if (ResultCode = 3010) or (ResultCode = 1641) then
    PrerequisiteNeedsRestart := True
  else if ResultCode <> 0 then begin
    Result := 'OpenVPN installation failed (MSI code ' + IntToStr(ResultCode) + '). See ' + ExpandConstant('{tmp}\OpenVPN-install.log');
    exit;
  end;
  if not OpenVpnInstalled then begin
    NeedsRestart := PrerequisiteNeedsRestart;
    Result := 'OpenVPN 2.7 or newer is not available after installation. Check the MSI log; restart Windows if requested, then retry setup.';
  end;
end;

function NeedRestart: Boolean;
begin
  Result := PrerequisiteNeedsRestart;
end;

function CanLaunch: Boolean;
begin
  Result := not PrerequisiteNeedsRestart;
end;
