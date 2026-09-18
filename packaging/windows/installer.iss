#ifndef BundleRoot
  #error BundleRoot must identify the timestamped packaged application directory
#endif
#ifndef OutputRoot
  #error OutputRoot must identify a new installer output directory
#endif

[Setup]
AppId={{F4211EE6-C288-40C5-9ABD-2B636F647E30}
AppName=NetSec
AppVersion=0.2.0
AppPublisher=Matheus
DefaultDirName={autopf}\NetSec
DefaultGroupName=NetSec
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableDirPage=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputRoot}
OutputBaseFilename=NetSec-0.2.0-Windows-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NetSec-Desktop.exe

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#BundleRoot}\NetSec-Desktop\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#BundleRoot}\NetSec\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetSec"; Filename: "{app}\NetSec-Desktop.exe"
Name: "{group}\Desinstalar NetSec"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\NetSec-Desktop.exe"; Description: "Abrir NetSec"; Flags: nowait postinstall skipifsilent runasoriginaluser
