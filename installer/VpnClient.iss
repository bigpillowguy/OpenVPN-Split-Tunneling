; Inno Setup script for VpnClient
;
; Use installer/build.ps1 to build, validate dependencies and compile this script.
;
; Output:  installer\Output\VpnClientSetup-1.3.1.exe

#if VER < EncodeVer(6, 7, 0)
  #error "Inno Setup 6.7 or newer is required"
#endif

#define MyAppName      "OpenVPN Split Tunneling Client"
#define MyAppVersion   "1.3.1"
#define MyAppPublisher "ena"
#define MyAppExeName   "VpnClient.Ui.exe"
#define MyAppId        "{{A6A4F2D2-6E1E-4D6F-A2D6-9E1F7B3B8FCC}"

#define UiPublishDir   "..\dotnet\VpnClient.Ui\bin\Release\net8.0-windows10.0.19041.0\win-x64\publish"
#define RedirectorDir  "..\target\release"
#define DnsGuardDir    "..\dotnet\VpnClient.DnsGuard\bin\Release\net8.0-windows\win-x64\publish"
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
; The LocalSystem recovery service uses a normal self-contained directory. Its
; runtime libraries must not be extracted to a user-writable temporary folder.
Source: "{#DnsGuardDir}\*"; DestDir: "{app}\DnsGuard"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "..\vendor\windivert\LICENSE"; DestDir: "{app}\licenses"; DestName: "WinDivert-LICENSE.txt"; Flags: ignoreversion
Source: "..\vendor\windivert-rs\LICENSE"; DestDir: "{app}\licenses"; DestName: "windivert-rs-LICENSE.txt"; Flags: ignoreversion

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
  DnsMaintenanceStarted: Boolean;

function InstallerProcessId: DWORD;
  external 'GetCurrentProcessId@kernel32.dll stdcall';

function PrepareDnsGuardForMaintenance: String;
var
  GuardPath: String;
  ResultCode: Integer;
begin
  Result := '';
  GuardPath := ExpandConstant('{app}\DnsGuard\VpnClient.DnsGuard.exe');
  if not FileExists(GuardPath) then begin
    if RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\VpnClientDnsGuard') then
      Result := 'The DNS recovery service is registered, but its installed helper is missing. ' +
        'Repair the existing installation and restore DNS before replacing or removing the client.';
    exit;
  end;
  DnsMaintenanceStarted := True;
  if not Exec(GuardPath, 'uninstall --maintenance-owner ' + IntToStr(InstallerProcessId),
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    Result := 'The DNS recovery helper could not start (Windows error ' + IntToStr(ResultCode) + ').';
    exit;
  end;
  if ResultCode <> 0 then
    Result := 'The DNS recovery helper refused maintenance (code ' + IntToStr(ResultCode) + '). ' +
      'Close the VPN client and let DNS restoration finish, then retry. ' +
      'If recovery is required, keep this installation in place and run DnsGuard\VpnClient.DnsGuard.exe inspect as administrator.';
end;

procedure CompleteDnsMaintenance;
var
  GuardPath: String;
  ResultCode: Integer;
begin
  if not DnsMaintenanceStarted then exit;
  GuardPath := ExpandConstant('{app}\DnsGuard\VpnClient.DnsGuard.exe');
  if FileExists(GuardPath) then begin
    if not Exec(GuardPath, 'maintenance-complete --maintenance-owner ' + IntToStr(InstallerProcessId),
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Log('Could not clear the DNS maintenance marker; it will expire with this installer process.')
    else if ResultCode <> 0 then
      Log('DNS maintenance marker cleanup returned ' + IntToStr(ResultCode) + '; it will expire with this installer process.');
  end;
  DnsMaintenanceStarted := False;
end;

function ProbeOpenExistingFile(const FileName: String; DesiredAccess, ShareMode: DWORD;
  SecurityAttributes: THandle; CreationDisposition, FlagsAndAttributes: DWORD;
  TemplateFile: THandle): THandle;
  external 'CreateFileW@kernel32.dll stdcall setuponly';
function ProbeCloseHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall setuponly';
function RemoveLegacyFile(const FileName: String): BOOL;
  external 'DeleteFileW@kernel32.dll stdcall setuponly';

function LegacyCleanupError(const FileName: String; ErrorCode: Integer): String;
begin
  Result := 'Setup must remove a retired component (' + FileName + ') before upgrading. ' +
    'Close applications previously launched through the VPN client, then retry Setup. ' +
    'Closing the VPN client alone may not release these files. ' +
    'If those applications are closed, check access to the installation folder. ' +
    '(Windows error ' + IntToStr(ErrorCode) + '.)';
end;

function OpenLegacyFileForRemoval(const FileName: String; var Probe: THandle): String;
var
  ErrorCode: Integer;
begin
  Result := '';
  // GENERIC_READ|GENERIC_WRITE, FILE_SHARE_DELETE, OPEN_EXISTING. No bytes are
  // changed or code loaded. A mapped image cannot be opened for writing.
  // Keep this handle through deletion to prevent a new reader/loader racing us.
  Probe := ProbeOpenExistingFile(ExpandConstant('{app}\') + FileName,
    $C0000000, 4, 0, 3, $80, 0);
  if Probe <> THandle(-1) then exit;
  ErrorCode := DLLGetLastError;
  if (ErrorCode = 2) or (ErrorCode = 3) then exit;
  Result := LegacyCleanupError(FileName, ErrorCode);
end;

function CheckLegacyFilesForRemoval: String;
var
  Launcher, Module: THandle;
begin
  Launcher := THandle(-1);
  Module := THandle(-1);
  try
    Result := OpenLegacyFileForRemoval('dns-launcher.exe', Launcher);
    if Result = '' then
      Result := OpenLegacyFileForRemoval('dns-hook.dll', Module);
  finally
    if Module <> THandle(-1) then ProbeCloseHandle(Module);
    if Launcher <> THandle(-1) then ProbeCloseHandle(Launcher);
  end;
end;

procedure DeleteRetiredFile(const FileName: String);
var
  ErrorCode: Integer;
begin
  if RemoveLegacyFile(ExpandConstant('{app}\') + FileName) then exit;
  ErrorCode := DLLGetLastError;
  if (ErrorCode = 2) or (ErrorCode = 3) then exit;
  RaiseException(LegacyCleanupError(FileName, ErrorCode));
end;

procedure RetireLegacyFiles;
var
  Launcher, Module: THandle;
  ErrorMessage: String;
begin
  Launcher := THandle(-1);
  Module := THandle(-1);
  try
    ErrorMessage := OpenLegacyFileForRemoval('dns-launcher.exe', Launcher);
    if ErrorMessage = '' then
      ErrorMessage := OpenLegacyFileForRemoval('dns-hook.dll', Module);
    if ErrorMessage <> '' then RaiseException(ErrorMessage);
    // Exact migration targets only; never enumerate or terminate user processes.
    // Both binary guards remain held until all removal attempts finish.
    if Launcher <> THandle(-1) then DeleteRetiredFile('dns-launcher.exe');
    if Module <> THandle(-1) then DeleteRetiredFile('dns-hook.dll');
    DeleteRetiredFile('licenses\Detours-LICENSE.txt');
  finally
    if Module <> THandle(-1) then ProbeCloseHandle(Module);
    if Launcher <> THandle(-1) then ProbeCloseHandle(Launcher);
  end;
end;

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
  // Runs before prerequisite MSI execution and before the normal file-copy phase.
  // Keep CloseApplicationsFilter narrow: never silently close arbitrary user apps.
  Result := CheckLegacyFilesForRemoval;
  if Result <> '' then exit;
  Result := PrepareDnsGuardForMaintenance;
  if Result <> '' then exit;
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

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then begin
    // Recheck after prerequisite work, before copying any client files. Locked
    // legacy components cause an actionable refusal, including silent installs.
    RetireLegacyFiles;
  end;
  if CurStep = ssPostInstall then CompleteDnsMaintenance;
end;

procedure DeinitializeSetup;
begin
  CompleteDnsMaintenance;
end;

function InitializeUninstall: Boolean;
var
  ErrorMessage: String;
begin
  ErrorMessage := PrepareDnsGuardForMaintenance;
  Result := ErrorMessage = '';
  if not Result then begin
    if not UninstallSilent then MsgBox(ErrorMessage, mbError, MB_OK);
    CompleteDnsMaintenance;
  end;
end;

procedure DeinitializeUninstall;
begin
  // On successful removal the helper is gone; its protected marker becomes
  // stale when this exact installer process exits. No service refers to it.
  CompleteDnsMaintenance;
end;

function NeedRestart: Boolean;
begin
  Result := PrerequisiteNeedsRestart;
end;

function CanLaunch: Boolean;
begin
  Result := not PrerequisiteNeedsRestart;
end;
