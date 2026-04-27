# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
#Requires -Version 7.4

[CmdletBinding()]
param (
  [Parameter(Mandatory, HelpMessage = 'The installer parser action to invoke')]
  [ValidateSet('NSIS.GetInfo', 'Inno.GetInfo', 'Inno.Expand', 'AdvancedInstaller.GetInfo', 'AdvancedInstaller.Expand')]
  [string]$Action,

  [Parameter(HelpMessage = 'The path to the installer')]
  [string]$Path,

  [Parameter(HelpMessage = 'The destination directory for extracted files')]
  [string]$DestinationPath,

  [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
  [string]$Name,

  [Parameter(HelpMessage = 'The Inno Setup language selector')]
  [string]$Language
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
  $LibraryPath = Join-Path $PSScriptRoot 'Libraries'
  $Result = switch ($Action) {
    'NSIS.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'NSIS.psm1') -Force
      Get-NSISInfo -Path $Path
    }
    'Inno.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'Inno.psm1') -Force
      Get-InnoInfo -Path $Path
    }
    'Inno.Expand' {
      Import-Module (Join-Path $LibraryPath 'Inno.psm1') -Force
      $ExpandArguments = @{
        Path = $Path
        Name = $Name
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if (-not [string]::IsNullOrWhiteSpace($Language)) { $ExpandArguments.Language = $Language }

      @(Expand-InnoInstaller @ExpandArguments).ForEach({ $_.FullName })
    }
    'AdvancedInstaller.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'AdvancedInstaller.psm1') -Force
      Get-AdvancedInstallerInfo -Path $Path
    }
    'AdvancedInstaller.Expand' {
      Import-Module (Join-Path $LibraryPath 'AdvancedInstaller.psm1') -Force
      $ExpandArguments = @{
        Path = $Path
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }

      Expand-AdvancedInstaller @ExpandArguments
    }
    default { throw "Unsupported installer parser action: $Action" }
  }

  [Console]::Out.Write(($Result | ConvertTo-Json -Depth 100 -Compress))
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
