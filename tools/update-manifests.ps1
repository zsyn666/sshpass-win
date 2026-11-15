param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ExeHash,
    [Parameter(Mandatory = $true)][string]$SetupHash,
    [Parameter(Mandatory = $true)][string]$SetupName,
    [string]$Repo = "https://github.com/zsyn666/sshpass-win"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# --- Scoop bucket manifest -------------------------------------------------
$scoop = [ordered]@{
    version     = $Version
    description = "A drop-in sshpass for Windows: native password authentication for ssh, scp and sftp"
    homepage    = $Repo
    license     = "MIT"
    architecture = [ordered]@{
        "64bit" = [ordered]@{
            url  = "$Repo/releases/download/v$Version/sshpass.exe"
            hash = $ExeHash
        }
    }
    bin        = "sshpass.exe"
    checkver   = [ordered]@{ github = $Repo }
    autoupdate = [ordered]@{
        architecture = [ordered]@{
            "64bit" = [ordered]@{
                url = "$Repo/releases/download/v`$version/sshpass.exe"
            }
        }
    }
}
$scoop | ConvertTo-Json -Depth 10 | Set-Content "bucket\sshpass-win.json" -Encoding utf8

# --- WinGet manifests ------------------------------------------------------
$dir = "winget\manifests\z\zsyn666\sshpass-win\$Version"
New-Item -ItemType Directory -Force $dir | Out-Null

@"
PackageIdentifier: zsyn666.sshpass-win
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@ | Set-Content "$dir\zsyn666.sshpass-win.yaml" -Encoding utf8

@"
PackageIdentifier: zsyn666.sshpass-win
PackageVersion: $Version
InstallerType: inno
Scope: user
InstallModes:
  - interactive
  - silent
  - silentWithProgress
UpgradeBehavior: install
Commands:
  - sshpass
ReleaseDate: $(Get-Date -Format yyyy-MM-dd)
Installers:
  - Architecture: x64
    InstallerUrl: $Repo/releases/download/v$Version/$SetupName
    InstallerSha256: $SetupHash
    InstallerSwitches:
      Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
      SilentWithProgress: /SILENT /SUPPRESSMSGBOXES /NORESTART
    AppsAndFeaturesEntries:
      - DisplayName: sshpass-win
        Publisher: zsyn666
        DisplayVersion: $Version
ManifestType: installer
ManifestVersion: 1.6.0
"@ | Set-Content "$dir\zsyn666.sshpass-win.installer.yaml" -Encoding utf8

@"
PackageIdentifier: zsyn666.sshpass-win
PackageVersion: $Version
PackageLocale: en-US
Publisher: zsyn666
PublisherUrl: $Repo
PublisherSupportUrl: $Repo/issues
PackageName: sshpass-win
PackageUrl: $Repo
License: MIT
LicenseUrl: $Repo/blob/main/LICENSE
ShortDescription: A drop-in sshpass for Windows
Description: Native password authentication for ssh, scp and sftp on Windows. No MSYS, no Cygwin, no pty required.
Tags:
  - sshpass
  - ssh
  - scp
  - sftp
  - password
  - windows
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"@ | Set-Content "$dir\zsyn666.sshpass-win.locale.en-US.yaml" -Encoding utf8

Write-Host "Updated manifests for $Version"
