# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Public NSIS parser facade. Format decoding and system-effect simulation are
# isolated so each layer can be tested without duplicating installer reads.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$InfrastructurePath = Join-Path $PSScriptRoot '..\Infrastructure'
foreach ($Name in 'Runtime', 'Binary', 'FileSystem', 'Archive', 'PE', 'InstallerEvidence') {
  Import-Module (Join-Path $InfrastructurePath "$Name.psm1") -Force -Global
}

# Keep implementation commands nested under the public facade. This avoids polluting the CLI
# session while preserving private helper visibility for facade functions and focused tests.
$FormatModule = Import-Module (Join-Path $PSScriptRoot 'NSISFormat.psm1') -Force -PassThru
foreach ($Entry in $FormatModule.ExportedVariables.GetEnumerator()) {
  Set-Variable -Scope Script -Name $Entry.Key -Value $Entry.Value.Value
}
$SimulationModule = Import-Module (Join-Path $PSScriptRoot 'NSISSimulation.psm1') -Force -PassThru

function Expand-NSISInstaller {
  <#
  .SYNOPSIS
    Extract selected embedded files from an NSIS installer without executing it.
  .PARAMETER Path
    Path to the NSIS installer.
  .PARAMETER DestinationPath
    Extraction directory. A unique temporary directory is created when omitted.
  .PARAMETER Name
    Wildcard matched against compiled payload paths and base filenames.
  .PARAMETER MaximumExpandedBytes
    Maximum total bytes written, including aliases that share one data record.
  .PARAMETER CollisionAction
    Behavior when a payload path already exists or multiple File commands resolve to one path.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path,
    [string]$DestinationPath,
    [ValidateNotNullOrEmpty()][string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:NSIS_DEFAULT_MAXIMUM_EXPANDED_BYTES,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt'
  )

  process {
    # Format decoding remains isolated from the command simulator. The facade supplies the one
    # semantic operation needed to map compiled File commands to deterministic output paths.
    $Arguments = @{
      Path                 = $Path
      Name                 = $Name
      MaximumExpandedBytes = $MaximumExpandedBytes
      CollisionAction      = $CollisionAction
      StateInitializer     = { param($HeaderData) Initialize-NSISState -HeaderData $HeaderData }
      PayloadSelector      = { param($State, $HeaderData, $Pattern) Get-NSISPayloadEntries -State $State -HeaderData $HeaderData -Name $Pattern }
    }
    if (-not [string]::IsNullOrWhiteSpace($DestinationPath)) { $Arguments.DestinationPath = $DestinationPath }
    return Expand-NSISPayload @Arguments
  }
}

function Get-NSISInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Nullsoft Scriptable Install System installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used when the installer selects architecture-specific ARP metadata
  .PARAMETER Scope
    The target installation scope used when the installer selects scope-specific ARP metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The target Windows architecture used to resolve architecture-specific ARP metadata')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [Parameter(HelpMessage = 'The target installation scope used to resolve scope-specific ARP metadata')]
    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $SimulationArguments = @{ Path = $Path }
    if (-not [string]::IsNullOrWhiteSpace($Architecture)) { $SimulationArguments.Architecture = $Architecture }
    if (-not [string]::IsNullOrWhiteSpace($Scope)) { $SimulationArguments.Scope = $Scope }
    $Metadata = (Invoke-NSISStaticSimulation @SimulationArguments).Metadata
    if ([string]::IsNullOrWhiteSpace($Metadata.DisplayName) -and [string]::IsNullOrWhiteSpace($Metadata.DisplayVersion)) {
      throw 'The NSIS installer does not expose deterministic uninstall metadata'
    }

    # Invoke-NSISStaticSimulation constructs the canonical aggregate result;
    # return it unchanged so bridge callers see exactly the parser's evidence.
    return [pscustomobject]$Metadata
  }
}

function Read-ProductVersionFromNSIS {
  <#
  .SYNOPSIS
    Read the product version from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The NSIS installer does not expose a DisplayVersion value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromNSIS {
  <#
  .SYNOPSIS
    Read the product name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The NSIS installer does not expose a DisplayName value' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromNSIS {
  <#
  .SYNOPSIS
    Read the publisher from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The NSIS installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromNSIS {
  <#
  .SYNOPSIS
    Read the uninstall registry key name from a Nullsoft installer
  .PARAMETER Path
    The path to the NSIS installer
  .PARAMETER Architecture
    The target Windows architecture used to resolve architecture-specific metadata
  .PARAMETER Scope
    The target installation scope used to resolve scope-specific metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the NSIS installer')]
    [string]$Path,

    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture,

    [ValidateSet('user', 'machine')]
    [string]$Scope
  )

  process {
    $Arguments = @{ Path = $Path }
    if ($Architecture) { $Arguments.Architecture = $Architecture }
    if ($Scope) { $Arguments.Scope = $Scope }
    $Info = Get-NSISInfo @Arguments
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The NSIS installer does not expose an uninstall registry key' }
    return $Info.ProductCode
  }
}

Export-ModuleMember -Function Get-NSISInfo, Expand-NSISInstaller, Get-NSISInstallerSwitchInfo, Read-AdditionalInstallerSwitchesFromNSIS, Test-ElectronBuilder, Get-ElectronBuilderNSISInfo, Read-ProductVersionFromNSIS, Read-ProductNameFromNSIS, Read-PublisherFromNSIS, Read-ProductCodeFromNSIS
