# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
#Requires -Version 7.4

[CmdletBinding()]
param (
  [Parameter(Mandatory, HelpMessage = 'The installer parser action to invoke')]
  [ValidateSet('NSIS.GetFormatInfo', 'NSIS.GetInfo', 'NSIS.Expand', 'NSIS.GetInstallerSwitchInfo', 'NSIS.TestElectronBuilder', 'NSIS.GetElectronBuilderInfo', 'Inno.GetFormatInfo', 'Inno.GetInfo', 'Inno.GetPascalScriptInfo', 'Inno.Expand', 'AdvancedInstaller.GetFormatInfo', 'AdvancedInstaller.GetInfo', 'AdvancedInstaller.Expand', 'QtInstallerFramework.GetFormatInfo', 'QtInstallerFramework.GetInfo', 'QtInstallerFramework.Expand', 'SetupFactory.GetInfo', 'SetupFactory.Expand')]
  [string]$Action,

  [Parameter(HelpMessage = 'The path to the installer')]
  [string]$Path,

  [Parameter(HelpMessage = 'The destination directory for extracted files')]
  [string]$DestinationPath,

  [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
  [string]$Name,

  [Parameter(HelpMessage = 'The behavior when an extracted path already exists')]
  [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
  [string]$CollisionAction = 'Rename',

  [Parameter(HelpMessage = 'Optional file used for JSON output when host prompts must remain visible')]
  [string]$ResultPath,

  [Parameter(HelpMessage = 'The Inno Setup language selector')]
  [string]$Language,

  [Parameter(HelpMessage = 'The target Windows architecture used by architecture-selecting installers')]
  [ValidateSet('x86', 'x64', 'arm64')]
  [string]$Architecture,

  [Parameter(HelpMessage = 'The target installation scope used by scope-selecting installers')]
  [ValidateSet('user', 'machine')]
  [string]$Scope,

  [Parameter(HelpMessage = 'Directories or explicit files containing external Inno Setup disk slices')]
  [string[]]$DiskSourcePath,

  [Parameter(HelpMessage = 'Paired Qt Installer Framework DAT binary-content files')]
  [string[]]$DataPath,

  [Parameter(HelpMessage = 'Local Qt Installer Framework repository roots or Updates.xml files')]
  [string[]]$RepositoryPath,

  [Parameter(HelpMessage = 'Explicit Qt Installer Framework package archives or directories')]
  [string[]]$PackagePath,

  [Parameter(HelpMessage = 'Legacy .nsisbin or current setupN.bin NSISBI sidecar paths')]
  [string[]]$ExternalDataPath,

  [Parameter(HelpMessage = 'Virtual NSIS target environment as a JSON object')]
  [string]$EnvironmentJson,

  [Parameter(HelpMessage = 'Virtual NSIS target filesystem facts as a JSON object')]
  [string]$FileSystemJson,

  [Parameter(HelpMessage = 'Treat unlisted virtual NSIS target paths as absent')]
  [switch]$FileSystemComplete,

  [Parameter(HelpMessage = 'Virtual NSIS command line')]
  [string]$CommandLine,

  [Parameter(HelpMessage = 'Explicit code page for ANSI NSIS strings')]
  [int]$AnsiCodePage,

  [Parameter(HelpMessage = 'The maximum number of bytes written while expanding an installer')]
  [long]$MaximumExpandedBytes,

  [Parameter(HelpMessage = 'Include textual disassembly in supported bytecode-analysis actions')]
  [switch]$IncludeDisassembly,

  [Parameter(HelpMessage = 'Include detailed Pascal Script analysis in Inno metadata output')]
  [switch]$IncludePascalScriptAnalysis,

  [Parameter(HelpMessage = 'Maximum characters retained from textual bytecode disassembly')]
  [int]$MaximumDisassemblyCharacters
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
  $LibraryPath = Join-Path $PSScriptRoot 'Libraries'
  $InfrastructurePath = Join-Path $LibraryPath 'Infrastructure'
  $InstallerPath = Join-Path $LibraryPath 'Installers'
  # Parser modules share these independently consumable MIT-licensed primitives.
  Import-Module (Join-Path $InfrastructurePath 'Runtime.psm1') -Force
  Import-Module (Join-Path $InfrastructurePath 'Binary.psm1') -Force
  Import-Module (Join-Path $InfrastructurePath 'FileSystem.psm1') -Force
  Import-Module (Join-Path $InfrastructurePath 'Archive.psm1') -Force
  Import-Module (Join-Path $InfrastructurePath 'PE.psm1') -Force
  Import-Module (Join-Path $InfrastructurePath 'InstallerEvidence.psm1') -Force
  $Result = switch ($Action) {
    'NSIS.GetFormatInfo' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      Get-NSISFormatInfo -Path $Path
    }
    'NSIS.GetInfo' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      $Arguments = @{ Path = $Path }
      if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $Arguments.Architecture = $Architecture }
      if (-not [string]::IsNullOrWhiteSpace($Scope)) { $Arguments.Scope = $Scope }
      if (-not [string]::IsNullOrWhiteSpace($EnvironmentJson)) { $Arguments.Environment = ConvertFrom-Json -InputObject $EnvironmentJson -AsHashtable }
      if (-not [string]::IsNullOrWhiteSpace($FileSystemJson)) { $Arguments.FileSystem = ConvertFrom-Json -InputObject $FileSystemJson -AsHashtable }
      if ($FileSystemComplete) { $Arguments.FileSystemComplete = $true }
      if ($PSBoundParameters.ContainsKey('CommandLine')) { $Arguments.CommandLine = $CommandLine }
      if ($AnsiCodePage -gt 0) { $Arguments.AnsiCodePage = $AnsiCodePage }
      Get-NSISInfo @Arguments
    }
    'NSIS.Expand' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      $ExpandArguments = @{
        Path            = $Path
        CollisionAction = $CollisionAction
      }
      if (-not [string]::IsNullOrWhiteSpace($Name)) { $ExpandArguments.Name = $Name }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }
      if ($ExternalDataPath) { $ExpandArguments.ExternalDataPath = $ExternalDataPath }
      @(Expand-NSISInstaller @ExpandArguments).ForEach({ $_.FullName })
    }
    'NSIS.GetElectronBuilderInfo' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      Get-ElectronBuilderNSISInfo -Path $Path
    }
    'NSIS.GetInstallerSwitchInfo' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      Get-NSISInstallerSwitchInfo -Path $Path
    }
    'NSIS.TestElectronBuilder' {
      Import-Module (Join-Path $InstallerPath 'NSIS.psm1') -Force
      Test-ElectronBuilder -Path $Path
    }
    'Inno.GetInfo' {
      Import-Module (Join-Path $InstallerPath 'Inno.psm1') -Force
      $Arguments = @{
        Path                        = $Path
        IncludePascalScriptAnalysis = $IncludePascalScriptAnalysis
        IncludeDisassembly          = $IncludeDisassembly
      }
      if ($MaximumDisassemblyCharacters -gt 0) { $Arguments.MaximumDisassemblyCharacters = $MaximumDisassemblyCharacters }
      Get-InnoInfo @Arguments
    }
    'Inno.GetFormatInfo' {
      Import-Module (Join-Path $InstallerPath 'Inno.psm1') -Force
      Get-InnoFormatInfo -Path $Path
    }
    'Inno.GetPascalScriptInfo' {
      Import-Module (Join-Path $InstallerPath 'Inno.psm1') -Force
      $Arguments = @{ Path = $Path; IncludeDisassembly = $IncludeDisassembly }
      if ($MaximumDisassemblyCharacters -gt 0) { $Arguments.MaximumDisassemblyCharacters = $MaximumDisassemblyCharacters }
      Get-InnoPascalScriptInfo @Arguments
    }
    'Inno.Expand' {
      Import-Module (Join-Path $InstallerPath 'Inno.psm1') -Force
      $ExpandArguments = @{
        Path            = $Path
        Name            = [string]::IsNullOrWhiteSpace($Name) ? '*' : $Name
        CollisionAction = $CollisionAction
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if (-not [string]::IsNullOrWhiteSpace($Language)) { $ExpandArguments.Language = $Language }
      if ($DiskSourcePath) { $ExpandArguments.DiskSourcePath = $DiskSourcePath }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }

      @(Expand-InnoInstaller @ExpandArguments).ForEach({ $_.FullName })
    }
    'AdvancedInstaller.GetFormatInfo' {
      Import-Module (Join-Path $InstallerPath 'AdvancedInstaller.psm1') -Force
      Get-AdvancedInstallerFormatInfo -Path $Path
    }
    'AdvancedInstaller.GetInfo' {
      Import-Module (Join-Path $InstallerPath 'AdvancedInstaller.psm1') -Force
      Get-AdvancedInstallerInfo -Path $Path
    }
    'AdvancedInstaller.Expand' {
      Import-Module (Join-Path $InstallerPath 'AdvancedInstaller.psm1') -Force
      $ExpandArguments = @{
        Path            = $Path
        CollisionAction = $CollisionAction
      }
      if (-not [string]::IsNullOrWhiteSpace($Name)) { $ExpandArguments.Name = $Name }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }

      Expand-AdvancedInstaller @ExpandArguments
    }
    'QtInstallerFramework.GetFormatInfo' {
      Import-Module (Join-Path $InstallerPath 'QtInstallerFramework.psm1') -Force
      Get-QtInstallerFrameworkFormatInfo -Path $Path
      break
    }
    'QtInstallerFramework.GetInfo' {
      Import-Module (Join-Path $InstallerPath 'QtInstallerFramework.psm1') -Force
      Get-QtInstallerFrameworkInfo -Path $Path
    }
    'SetupFactory.GetInfo' {
      Import-Module (Join-Path $InstallerPath 'SetupFactory.psm1') -Force
      Get-SetupFactoryInfo -Path $Path
    }
    'SetupFactory.Expand' {
      Import-Module (Join-Path $InstallerPath 'SetupFactory.psm1') -Force
      $ExpandArguments = @{
        Path            = $Path
        Name            = [string]::IsNullOrWhiteSpace($Name) ? '*' : $Name
        CollisionAction = $CollisionAction
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }
      @(Expand-SetupFactoryInstaller @ExpandArguments).ForEach({ $_.FullName })
    }
    'QtInstallerFramework.Expand' {
      Import-Module (Join-Path $InstallerPath 'QtInstallerFramework.psm1') -Force
      $ExpandArguments = @{
        Path            = $Path
        CollisionAction = $CollisionAction
      }
      if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $ExpandArguments.DestinationPath = $DestinationPath }
      if (-not [string]::IsNullOrWhiteSpace($Name)) { $ExpandArguments.Name = $Name }
      if ($MaximumExpandedBytes -gt 0) { $ExpandArguments.MaximumExpandedBytes = $MaximumExpandedBytes }
      if ($DataPath) { $ExpandArguments.DataPath = $DataPath }
      if ($RepositoryPath) { $ExpandArguments.RepositoryPath = $RepositoryPath }
      if ($PackagePath) { $ExpandArguments.PackagePath = $PackagePath }

      Expand-QtInstallerFramework @ExpandArguments
    }
    default { throw "Unsupported installer parser action: $Action" }
  }

  $ResultJson = $Result | ConvertTo-Json -Depth 100 -Compress
  if ([string]::IsNullOrWhiteSpace($ResultPath)) {
    [Console]::Out.Write($ResultJson)
  } else {
    # Interactive bridge calls inherit the console for PromptForChoice. Keep
    # JSON off stdout so the parent receives an unambiguous result document.
    $ResolvedResultPath = [IO.Path]::GetFullPath($ResultPath)
    $ResultDirectory = [IO.Path]::GetDirectoryName($ResolvedResultPath)
    if (-not $ResultDirectory -or -not [IO.Directory]::Exists($ResultDirectory)) {
      throw "The installer parser result directory does not exist: $ResultDirectory"
    }
    [IO.File]::WriteAllText($ResolvedResultPath, $ResultJson, [Text.UTF8Encoding]::new($false))
  }
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
