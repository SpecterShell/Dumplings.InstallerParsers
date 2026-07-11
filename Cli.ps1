# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
#Requires -Version 7.4

[CmdletBinding()]
param (
  [Parameter(Mandatory, HelpMessage = 'The installer parser action to invoke')]
  [ValidateSet('NSIS.GetInfo', 'NSIS.GetInstallerSwitchInfo', 'NSIS.TestElectronBuilder', 'NSIS.GetElectronBuilderInfo', 'Inno.GetInfo', 'Inno.Expand', 'AdvancedInstaller.GetInfo', 'AdvancedInstaller.Expand', 'QtInstallerFramework.GetInfo', 'QtInstallerFramework.Expand', 'SetupFactory.GetInfo', 'SetupFactory.Expand')]
  [string]$Action,

  [Parameter(HelpMessage = 'The path to the installer')]
  [string]$Path,

  [Parameter(HelpMessage = 'The destination directory for extracted files')]
  [string]$DestinationPath,

  [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
  [string]$Name,

  [Parameter(HelpMessage = 'The Inno Setup language selector')]
  [string]$Language,

  [Parameter(HelpMessage = 'The maximum number of bytes written while expanding an installer')]
  [long]$MaximumExpandedBytes
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
  $LibraryPath = Join-Path $PSScriptRoot 'Libraries'
  # Parser modules share these independently consumable MIT-licensed primitives.
  Import-Module (Join-Path $LibraryPath 'Runtime.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'Binary.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'Compression.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'Archive.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'PE.psm1') -Force
  Import-Module (Join-Path $LibraryPath 'RegistryAssociations.psm1') -Force
  $Result = switch ($Action) {
    'NSIS.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'NSIS.psm1') -Force
      Get-NSISInfo -Path $Path
    }
    'NSIS.GetElectronBuilderInfo' {
      Import-Module (Join-Path $LibraryPath 'NSIS.psm1') -Force
      Get-ElectronBuilderNSISInfo -Path $Path
    }
    'NSIS.GetInstallerSwitchInfo' {
      Import-Module (Join-Path $LibraryPath 'NSIS.psm1') -Force
      Get-NSISInstallerSwitchInfo -Path $Path
    }
    'NSIS.TestElectronBuilder' {
      Import-Module (Join-Path $LibraryPath 'NSIS.psm1') -Force
      Test-ElectronBuilder -Path $Path
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
    'QtInstallerFramework.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'QtInstallerFramework.psm1') -Force
      Get-QtInstallerFrameworkInfo -Path $Path
    }
    'SetupFactory.GetInfo' {
      Import-Module (Join-Path $LibraryPath 'SetupFactory.psm1') -Force
      Get-SetupFactoryInfo -Path $Path
    }
    'SetupFactory.Expand' {
      Import-Module (Join-Path $LibraryPath 'SetupFactory.psm1') -Force
      $ExpandArguments = @{
        Path = $Path
        Name = $Name
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }
      @(Expand-SetupFactoryInstaller @ExpandArguments).ForEach({ $_.FullName })
    }
    'QtInstallerFramework.Expand' {
      Import-Module (Join-Path $LibraryPath 'QtInstallerFramework.psm1') -Force
      $ExpandArguments = @{
        Path = $Path
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if (-not [string]::IsNullOrWhiteSpace($Name)) { $ExpandArguments.Name = $Name }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }

      Expand-QtInstallerFramework @ExpandArguments
    }
    default { throw "Unsupported installer parser action: $Action" }
  }

  [Console]::Out.Write(($Result | ConvertTo-Json -Depth 100 -Compress))
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
