# License: GPL-2.0. See Modules\InstallerParsers\LICENSE.GPL2.
# Format sources: https://github.com/HydraDragonAntivirus/HydraDragonAntivirus and https://github.com/russellbanks/Komac
#
# Binary structure consumed by this parser (absolute file offsets, LE integers):
#
#   PE bootstrapper
#   +-- payload ranges
#   +-- catalog at Footer.InfoOffset
#   |   `-- [Type:u32][Group:u32][Xor:u32][Size:u32][Offset:u32]
#   |       [NameChars:u32][Name:UTF-16LE]
#   `-- footer: FileCount@+04, InfoOffset@+10, FileOffset@+14,
#       "ADVINSTSFX"@+3C
#
# TransformFlag 2 XORs only the first min(512, Size) payload bytes with FF.
# Catalog offsets point to absolute ranges; they do not imply payload adjacency.
# Architecture-specific MSI selection follows the parsed configuration paths.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$ADVANCED_INSTALLER_MAGIC = [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
$ADVANCED_INSTALLER_FOOTER_SIZE = 72
$ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET = 60
$ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE = $ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $ADVANCED_INSTALLER_MAGIC.Length
$ADVANCED_INSTALLER_FILE_ENTRY_SIZE = 24
$ADVANCED_INSTALLER_XOR_HEADER_SIZE = 512
$ADVANCED_INSTALLER_MAXIMUM_CONFIGURATION_SIZE = 4194304

function Get-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static Advanced Installer extraction
  .PARAMETER Name
    The assembly file name under Modules\InstallerParsers\Assets
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The assembly file name under Modules\InstallerParsers\Assets')]
    [string]$Name
  )

  $AssetsPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Assets'
  if (Test-Path -Path ($Path = Join-Path -Path $AssetsPath -ChildPath $Name)) {
    return Get-Item -Path $Path -Force
  } else {
    throw "The $Name assembly could not be found"
  }
}

function Import-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for Advanced Installer extraction
  #>

  Import-InstallerArchiveDependency
}

Import-AdvancedInstallerAssembly

function Import-AdvancedInstallerMsiModule {
  <#
  .SYNOPSIS
    Load the MIT MSI helper module required to read embedded MSI metadata
  #>

  if (-not (Get-Command -Name 'Read-ProductVersionFromMsi' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\..\PackageModule\Libraries\MSI.psm1') -Force
  }
}

function Find-AdvancedInstallerBytePattern {
  <#
  .SYNOPSIS
    Find the last occurrence of a byte pattern in a byte array
  .PARAMETER Bytes
    The bytes to search
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern,

    [Parameter(HelpMessage = 'The last byte index to consider as a pattern start')]
    [int]$StartIndex = -1
  )

  $SearchLength = if ($StartIndex -lt 0) { 0 } else { [long]$StartIndex + $Pattern.Length }
  $Match = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Length $SearchLength -Maximum 1 -Reverse)
  if ($Match.Count) { return [int]$Match[0] }
  return -1
}

function Test-AdvancedInstallerBytePattern {
  <#
  .SYNOPSIS
    Test whether two byte arrays match exactly
  .PARAMETER Left
    The first byte array
  .PARAMETER Right
    The second byte array
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The first byte array')]
    [byte[]]$Left,

    [Parameter(Mandatory, HelpMessage = 'The second byte array')]
    [byte[]]$Right
  )

  return Test-BinarySequence -Left $Left -Right $Right
}

function Read-AdvancedInstallerBytes {
  <#
  .SYNOPSIS
    Read an exact byte range from a stream
  .PARAMETER Stream
    The source stream
  .PARAMETER Offset
    The starting position inside the stream
  .PARAMETER Length
    The number of bytes to read
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The source stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The starting position inside the stream')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to read')]
    [int]$Length
  )

  return , (Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Length)
}

function Test-AdvancedInstallerFooterOffset {
  <#
  .SYNOPSIS
    Validate an Advanced Installer footer candidate found while scanning from the end of the file
  .PARAMETER Stream
    The installer stream
  .PARAMETER FooterOffset
    The candidate footer offset
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The candidate footer offset')]
    [long]$FooterOffset
  )

  if ($FooterOffset -lt 0 -or $FooterOffset + $Script:ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE -gt $Stream.Length) {
    return $false
  }

  $OriginalPosition = $Stream.Position

  try {
    # A raw ADVINSTSFX occurrence is insufficient because signed payloads and nested data may
    # contain the marker. Validate the footer's catalog pointers and bounded record count as well.
    $FooterLength = Get-AdvancedInstallerFooterLength -Stream $Stream -FooterOffset $FooterOffset
    $FooterBytes = Read-AdvancedInstallerBytes -Stream $Stream -Offset $FooterOffset -Length $FooterLength

    if (-not (Test-AdvancedInstallerBytePattern -Left $FooterBytes[$Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET..($Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $Script:ADVANCED_INSTALLER_MAGIC.Length - 1)] -Right $Script:ADVANCED_INSTALLER_MAGIC)) {
      return $false
    }

    $FileCount = [System.BitConverter]::ToUInt32($FooterBytes, 4)
    $InfoOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
    $FileOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)

    if ($FileCount -eq 0 -or $FileCount -gt 0x10000) { return $false }
    if ($InfoOffset -ge $FooterOffset) { return $false }
    if ($FileOffset -ge $FooterOffset) { return $false }

    return $true
  } catch {
    return $false
  } finally {
    $null = $Stream.Seek($OriginalPosition, 'Begin')
  }
}

function Get-AdvancedInstallerFooterLength {
  <#
  .SYNOPSIS
    Get the readable Advanced Installer footer length for a candidate offset
  .PARAMETER Stream
    The installer stream
  .PARAMETER FooterOffset
    The candidate footer offset
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The candidate footer offset')]
    [long]$FooterOffset
  )

  if ($FooterOffset -lt 0 -or $FooterOffset -ge $Stream.Length) {
    throw 'The Advanced Installer footer offset is outside the installer stream'
  }

  $AvailableLength = $Stream.Length - $FooterOffset
  if ($AvailableLength -lt $Script:ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE) {
    throw 'The Advanced Installer footer is truncated'
  }

  # Some Advanced Installer SFX builds end immediately after ADVINSTSFX, while older samples have two tail bytes.
  return [int][Math]::Min([long]$Script:ADVANCED_INSTALLER_FOOTER_SIZE, $AvailableLength)
}

function Find-AdvancedInstallerFooterOffset {
  <#
  .SYNOPSIS
    Find the final valid Advanced Installer footer even when the signed installer carries a large certificate tail
  .PARAMETER Stream
    The installer stream
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream
  )

  # Search backward so the real terminal footer wins over marker bytes in earlier payloads. Large
  # Authenticode certificate tails are tolerated because the footer need not be the final bytes.
  foreach ($MagicOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Script:ADVANCED_INSTALLER_MAGIC -Maximum 4096 -Reverse)) {
    $FooterOffset = $MagicOffset - $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET
    if (Test-AdvancedInstallerFooterOffset -Stream $Stream -FooterOffset $FooterOffset) { return $FooterOffset }
  }

  throw 'The installer does not contain an Advanced Installer footer'
}

function Resolve-AdvancedInstallerExtractionPath {
  <#
  .SYNOPSIS
    Resolve a payload-relative path under the extraction root and block path traversal
  .PARAMETER DestinationPath
    The extraction root
  .PARAMETER RelativePath
    The payload-relative path from the installer metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction root')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The payload-relative path from the installer metadata')]
    [string]$RelativePath
  )

  return Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
}

function Write-AdvancedInstallerStream {
  <#
  .SYNOPSIS
    Copy an exact byte range from a source stream to a destination stream
  .PARAMETER SourceStream
    The source stream
  .PARAMETER DestinationStream
    The destination stream
  .PARAMETER Length
    The number of bytes to copy
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The source stream')]
    [System.IO.Stream]$SourceStream,

    [Parameter(Mandatory, HelpMessage = 'The destination stream')]
    [System.IO.Stream]$DestinationStream,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to copy')]
    [long]$Length
  )

  $null = Copy-BoundedStream -Source $SourceStream -Destination $DestinationStream -MaximumBytes $Length -ExpectedBytes $Length
}

function Write-AdvancedInstallerEntry {
  <#
  .SYNOPSIS
    Extract a single embedded Advanced Installer payload to disk
  .PARAMETER Path
    The path to the installer
  .PARAMETER Entry
    The parsed Advanced Installer payload entry
  .PARAMETER DestinationPath
    The target file path
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer payload entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The target file path')]
    [string]$DestinationPath
  )

  $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($DestinationPath)) -ItemType Directory -Force

  $SourceStream = [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName)
  $DestinationStream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

  try {
    # Catalog offsets are absolute file offsets and sizes are authoritative bounded ranges.
    $null = $SourceStream.Seek($Entry.Offset, 'Begin')

    # Advanced Installer marks some payloads with an XOR-obfuscated header. Only the leading block is transformed.
    $DecodedHeaderLength = [int][Math]::Min([long]$Entry.XorLength, [long]$Entry.Size)
    if ($DecodedHeaderLength -gt 0) {
      $HeaderBytes = New-Object 'byte[]' $DecodedHeaderLength
      $Read = $SourceStream.Read($HeaderBytes, 0, $DecodedHeaderLength)
      if ($Read -ne $DecodedHeaderLength) { throw 'Unexpected end of stream while decoding an Advanced Installer payload header' }
      for ($Index = 0; $Index -lt $DecodedHeaderLength; $Index++) {
        $HeaderBytes[$Index] = $HeaderBytes[$Index] -bxor 0xFF
      }
      $DestinationStream.Write($HeaderBytes, 0, $HeaderBytes.Length)
    }

    Write-AdvancedInstallerStream -SourceStream $SourceStream -DestinationStream $DestinationStream -Length ($Entry.Size - $DecodedHeaderLength)
    return Get-Item -Path $DestinationPath -Force
  } finally {
    $DestinationStream.Close()
    $SourceStream.Close()
  }
}

function Expand-AdvancedInstallerArchive {
  <#
  .SYNOPSIS
    Expand a nested 7z payload produced by Advanced Installer
  .PARAMETER Path
    The path to the extracted archive
  .PARAMETER DestinationPath
    The directory where the archive contents should be written
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The directory where the archive contents should be written')]
    [string]$DestinationPath
  )

  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  # Delegate path, link, duplicate, and output-limit enforcement to the shared archive exporter.
  $Archive = Get-InstallerArchive -Path $Path

  try {
    $null = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -MaximumExpandedBytes 17179869184 -MaximumEntries 200000
    return (Get-Item -Path $DestinationPath -Force).FullName
  } finally {
    $Archive.Dispose()
  }
}

function Test-AdvancedInstallerArchiveHasMsi {
  <#
  .SYNOPSIS
    Test whether a nested Advanced Installer archive contains MSI payloads
  .PARAMETER Path
    The path to the extracted archive
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path
  )

  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -Path $Path -Force).FullName)
  try {
    return [bool]$Archive.Entries.Where({ -not $_.IsDirectory -and $_.Key -like '*.msi' }, 'First')
  } finally {
    $Archive.Dispose()
  }
}

function Test-AdvancedInstallerNestedArchiveCandidate {
  <#
  .SYNOPSIS
    Test whether a nested Advanced Installer archive should be inspected for MSI payloads
  .PARAMETER Entry
    The parsed Advanced Installer payload entry
  .PARAMETER Path
    The extracted archive path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer payload entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The extracted archive path')]
    [string]$Path
  )

  if ([System.IO.Path]::GetExtension($Path) -ine '.7z') { return $false }

  # Advanced Installer commonly stores application files in FILES.7z.  That archive can be very large
  # and does not contain the MSI database used for AppsAndFeatures metadata.
  if ([System.IO.Path]::GetFileName($Entry.Name) -ieq 'FILES.7z') { return $false }

  return $true
}

function Resolve-AdvancedInstallerMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic payload match from an Advanced Installer extraction
  .PARAMETER Item
    The collection to search
  .PARAMETER Pattern
    The file name or wildcard pattern
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The collection to search')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Pattern
  )

  $Match = $Item.Where({ $_.Name -like $Pattern -or $_.FullName -like "*\$Pattern" })
  if (-not $Match) { throw "No MSI files matched the Advanced Installer pattern: $Pattern" }

  $ExactMatches = $Match.Where({ $_.Name -eq $Pattern -or $_.FullName.EndsWith($Pattern, [System.StringComparison]::OrdinalIgnoreCase) })
  if ($ExactMatches.Count -eq 1) { return $ExactMatches[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple MSI files matched the Advanced Installer pattern: $Pattern"
}

function New-AdvancedInstallerTempFolder {
  <#
  .SYNOPSIS
    Create a temporary directory for transient Advanced Installer extraction work
  #>
  [OutputType([string])]
  param ()

  $Path = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
  $null = New-Item -Path $Path -ItemType Directory -Force
  return $Path
}

function Read-AdvancedInstallerEntryData {
  <#
  .SYNOPSIS
    Read and decode one bounded Advanced Installer payload entry
  .PARAMETER Stream
    The open installer stream
  .PARAMETER Entry
    The parsed payload-table entry
  .PARAMETER MaximumBytes
    The maximum accepted payload size
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The open installer stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The parsed payload-table entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The maximum accepted payload size')]
    [long]$MaximumBytes
  )

  if ($Entry.Size -lt 0 -or $Entry.Size -gt $MaximumBytes -or $Entry.Size -gt [int]::MaxValue) {
    throw "The Advanced Installer payload '$($Entry.Name)' exceeds the bounded read limit"
  }

  # Configuration entries use the same leading-block XOR transform as exported payload files.
  $Bytes = Read-AdvancedInstallerBytes -Stream $Stream -Offset $Entry.Offset -Length ([int]$Entry.Size)
  $DecodedHeaderLength = [int][Math]::Min([long]$Entry.XorLength, [long]$Bytes.Length)
  for ($Index = 0; $Index -lt $DecodedHeaderLength; $Index++) {
    $Bytes[$Index] = $Bytes[$Index] -bxor 0xFF
  }
  return , $Bytes
}

function ConvertFrom-AdvancedInstallerIniData {
  <#
  .SYNOPSIS
    Parse an embedded Advanced Installer INI payload without executing the bootstrapper
  .PARAMETER Bytes
    The decoded INI bytes
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decoded INI bytes')]
    [byte[]]$Bytes
  )

  # Prefer explicit BOMs, then recognize the NUL distribution of the builder's usual UTF-16LE
  # output before falling back to UTF-8 for older stubs.
  if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
    $Text = [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
    $Text = [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes, 2, $Bytes.Length - 2)
  } elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
    $Text = [System.Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3)
  } else {
    # Advanced Installer normally emits UTF-16LE configuration. Retain support for older ANSI/UTF-8 stubs.
    $LooksUtf16 = $Bytes.Length -ge 4 -and $Bytes[1] -eq 0 -and $Bytes[3] -eq 0
    $Text = $LooksUtf16 ? [System.Text.Encoding]::Unicode.GetString($Bytes) : [System.Text.Encoding]::UTF8.GetString($Bytes)
  }

  # Parse literal sections and assignments only. Runtime substitutions remain strings and cannot
  # redirect static payload selection.
  $Sections = [ordered]@{}
  $CurrentSection = $null
  foreach ($Line in @($Text.TrimStart([char]0xFEFF) -split '\r\n|\n|\r')) {
    $TrimmedLine = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($TrimmedLine) -or $TrimmedLine.StartsWith(';') -or $TrimmedLine.StartsWith('#')) { continue }

    if ($TrimmedLine -match '^\[(?<Name>[^\]]+)\]$') {
      $CurrentSection = $Matches.Name.Trim()
      if (-not $Sections.Contains($CurrentSection)) { $Sections[$CurrentSection] = [ordered]@{} }
      continue
    }

    if ($null -eq $CurrentSection -or $TrimmedLine -notmatch '^(?<Name>[^=]+?)=(?<Value>.*)$') { continue }
    $Sections[$CurrentSection][$Matches.Name.Trim()] = $Matches.Value.Trim()
  }

  $Result = [ordered]@{}
  foreach ($SectionName in $Sections.Keys) {
    $Result[$SectionName] = [pscustomobject]$Sections[$SectionName]
  }
  return [pscustomobject]$Result
}

function Get-AdvancedInstallerSettingValue {
  <#
  .SYNOPSIS
    Read a named value from a parsed Advanced Installer INI section
  .PARAMETER Section
    The parsed INI section
  .PARAMETER Name
    The setting name
  #>
  param (
    [AllowNull()]
    [psobject]$Section,

    [Parameter(Mandatory, HelpMessage = 'The setting name')]
    [string]$Name
  )

  if ($null -eq $Section) { return $null }
  $Property = $Section.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
  return $null -eq $Property ? $null : $Property.Value
}

function Add-AdvancedInstallerArchitectureSuffix {
  <#
  .SYNOPSIS
    Insert the architecture suffix used by mixed Advanced Installer packages
  .PARAMETER Path
    The base MSI path
  .PARAMETER Suffix
    The suffix inserted immediately before the extension
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The base MSI path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The suffix inserted immediately before the extension')]
    [string]$Suffix
  )

  $Extension = [System.IO.Path]::GetExtension($Path)
  if ([string]::IsNullOrWhiteSpace($Extension)) { return "$Path$Suffix" }
  return $Path.Substring(0, $Path.Length - $Extension.Length) + $Suffix + $Extension
}

function Add-AdvancedInstallerUrlArchitectureSuffix {
  <#
  .SYNOPSIS
    Insert an architecture suffix into a download URL while retaining its query and fragment
  .PARAMETER Url
    The configured main application URL
  .PARAMETER Suffix
    The suffix inserted immediately before the path extension
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The configured main application URL')]
    [string]$Url,

    [Parameter(Mandatory, HelpMessage = 'The suffix inserted immediately before the path extension')]
    [string]$Suffix
  )

  $SuffixStart = $Url.Length
  foreach ($Delimiter in @('?', '#')) {
    $DelimiterIndex = $Url.IndexOf($Delimiter, [System.StringComparison]::Ordinal)
    if ($DelimiterIndex -ge 0 -and $DelimiterIndex -lt $SuffixStart) { $SuffixStart = $DelimiterIndex }
  }

  $PathPart = $Url.Substring(0, $SuffixStart)
  $Tail = $Url.Substring($SuffixStart)
  return (Add-AdvancedInstallerArchitectureSuffix -Path $PathPart -Suffix $Suffix) + $Tail
}

function Get-AdvancedInstallerMsiPayloadSelection {
  <#
  .SYNOPSIS
    Reproduce the bootstrapper's main MSI path selection from payload-table and INI metadata
  .PARAMETER File
    The parsed payload-table entries
  .PARAMETER GeneralOptions
    The parsed GeneralOptions INI section
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed payload-table entries')]
    [object[]]$File,

    [AllowNull()]
    [psobject]$GeneralOptions
  )

  # Reproduce the SFX's decision order from configuration and selector tuples rather than choosing
  # an arbitrary MSI by filename or architecture metadata.
  $MainAppUrl = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'MainAppURL')
  $AllPlatformsValue = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'AllPlatforms')
  $AllPlatforms = $AllPlatformsValue -match '^(?i:true|yes|1)$'

  # MainAppURL is checked before the embedded branch by the SFX. Do not silently
  # substitute an embedded MSI when the runtime would download a different payload.
  if (-not [string]::IsNullOrWhiteSpace($MainAppUrl)) {
    $PlatformMainAppUrl = $AllPlatforms ? (Add-AdvancedInstallerUrlArchitectureSuffix -Url $MainAppUrl -Suffix '.x64') : $MainAppUrl
    return [pscustomobject]@{
      SelectionMethod           = 'MainAppUrl'
      ArchitectureSelectionMode = $AllPlatforms ? 'Wow64Suffix' : 'FixedPath'
      SourceEntryName           = $null
      SourceEntryIndex          = $null
      SourceKind                = 'Download'
      BaseMsiPath               = $null
      X86MsiPath                = $null
      X64MsiPath                = $null
      Arm64MsiPath              = $null
      AllPlatforms              = $AllPlatforms
      MainAppUrl                = $MainAppUrl
      X86MainAppUrl             = $MainAppUrl
      X64MainAppUrl             = $PlatformMainAppUrl
      Arm64MainAppUrl           = $PlatformMainAppUrl
    }
  }

  # The SFX first resolves selector (1, 0) for a direct MSI or selector (3, 7) for
  # a compressed main package. For the archive form it replaces the archive extension with .msi.
  $DirectEntry = $File | Where-Object {
    $_.SelectorType -eq 1 -and $_.SelectorGroup -eq 0 -and [System.IO.Path]::GetExtension($_.Name) -ieq '.msi'
  } | Select-Object -First 1
  $ArchiveEntry = $File | Where-Object {
    $_.SelectorType -eq 3 -and $_.SelectorGroup -eq 7
  } | Select-Object -First 1

  $SourceEntry = $DirectEntry ?? $ArchiveEntry
  $BaseMsiPath = if ($DirectEntry) {
    $DirectEntry.Name
  } elseif ($ArchiveEntry) {
    [System.IO.Path]::ChangeExtension($ArchiveEntry.Name, '.msi')
  } else {
    $null
  }

  if ([string]::IsNullOrWhiteSpace($BaseMsiPath)) { return $null }
  $PlatformMsiPath = $AllPlatforms ? (Add-AdvancedInstallerArchitectureSuffix -Path $BaseMsiPath -Suffix '.x64') : $BaseMsiPath

  return [pscustomobject]@{
    SelectionMethod           = 'PayloadTable'
    ArchitectureSelectionMode = $AllPlatforms ? 'Wow64Suffix' : 'FixedPath'
    SourceEntryName           = $SourceEntry.Name
    SourceEntryIndex          = $SourceEntry.Index
    SourceKind                = $DirectEntry ? 'EmbeddedMsi' : 'EmbeddedArchive'
    BaseMsiPath               = $BaseMsiPath
    X86MsiPath                = $BaseMsiPath
    X64MsiPath                = $PlatformMsiPath
    # AllPlatforms uses IsWow64Process, so an x86 stub under ARM64 follows the .x64 path.
    # A fixed-path bootstrapper always selects its base MSI; MSI metadata validates compatibility.
    Arm64MsiPath              = $PlatformMsiPath
    AllPlatforms              = $AllPlatforms
    MainAppUrl                = [string]::IsNullOrWhiteSpace($MainAppUrl) ? $null : $MainAppUrl
    X86MainAppUrl             = $null
    X64MainAppUrl             = $null
    Arm64MainAppUrl           = $null
  }
}

function Get-AdvancedInstallerInfo {
  <#
  .SYNOPSIS
    Get metadata from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .LINK
    https://raw.githubusercontent.com/HydraDragonAntivirus/HydraDragonAntivirus/refs/heads/development-version/hydradragon/decompilers/advancedInstallerExtractor.py
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Stream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($Stream)

    try {
      # Locate and authenticate the footer before following any absolute catalog pointer.
      $FooterOffset = Find-AdvancedInstallerFooterOffset -Stream $Stream
      $FooterLength = Get-AdvancedInstallerFooterLength -Stream $Stream -FooterOffset $FooterOffset
      $FooterBytes = Read-AdvancedInstallerBytes -Stream $Stream -Offset $FooterOffset -Length $FooterLength

      $FooterMagic = [System.Text.Encoding]::ASCII.GetString($FooterBytes, $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET, $Script:ADVANCED_INSTALLER_MAGIC.Length)
      if ($FooterMagic -ne 'ADVINSTSFX') { throw 'The Advanced Installer footer signature is invalid' }

      $FileCount = [System.BitConverter]::ToUInt32($FooterBytes, 4)
      $InfoOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
      $FileOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)

      # The catalog is a sequence of fixed 24-byte records followed by variable UTF-16LE names.
      $null = $Stream.Seek($InfoOffset, 'Begin')
      $Files = [System.Collections.Generic.List[object]]::new()

      for ($Index = 0; $Index -lt $FileCount; $Index++) {
        $EntryBytes = $Reader.ReadBytes($Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE)
        if ($EntryBytes.Length -ne $Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE) { throw 'The Advanced Installer file table is truncated' }

        # The first two fields are the selector tuple used by the SFX before it resolves a payload name.
        $SelectorType = [System.BitConverter]::ToUInt32($EntryBytes, 0)
        $SelectorGroup = [System.BitConverter]::ToUInt32($EntryBytes, 4)
        $XorFlag = [System.BitConverter]::ToUInt32($EntryBytes, 8)
        $EntrySize = [System.BitConverter]::ToUInt32($EntryBytes, 12)
        $EntryOffset = [System.BitConverter]::ToUInt32($EntryBytes, 16)
        $NameLength = [int][System.BitConverter]::ToUInt32($EntryBytes, 20)
        if ($NameLength -lt 0) { throw 'The Advanced Installer payload name length is invalid' }

        $NameBytes = $Reader.ReadBytes($NameLength * 2)
        if ($NameBytes.Length -ne ($NameLength * 2)) { throw 'The Advanced Installer payload name is truncated' }

        $Name = if ($NameLength -eq 0) { "unnamed_file_${Index}.bin" } else { [System.Text.Encoding]::Unicode.GetString($NameBytes).TrimEnd([char]0) }

        $Files.Add([pscustomobject]@{
            Index         = $Index
            Name          = $Name
            Size          = [long]$EntrySize
            Offset        = [long]$EntryOffset
            SelectorType  = [int]$SelectorType
            SelectorGroup = [int]$SelectorGroup
            EncodingFlag  = [int]$XorFlag
            XorLength     = $XorFlag -eq 2 ? $Script:ADVANCED_INSTALLER_XOR_HEADER_SIZE : 0
          })
      }

      # Selector (0,3) identifies the bootstrapper INI. It is optional, but when present it controls
      # download-vs-embedded and architecture-specific MSI selection.
      $ConfigurationEntry = $Files | Where-Object {
        $_.SelectorType -eq 0 -and $_.SelectorGroup -eq 3 -and [System.IO.Path]::GetExtension($_.Name) -ieq '.ini'
      } | Select-Object -First 1
      $Configuration = if ($ConfigurationEntry) {
        $ConfigurationBytes = Read-AdvancedInstallerEntryData -Stream $Stream -Entry $ConfigurationEntry -MaximumBytes $Script:ADVANCED_INSTALLER_MAXIMUM_CONFIGURATION_SIZE
        ConvertFrom-AdvancedInstallerIniData -Bytes $ConfigurationBytes
      } else {
        $null
      }
      $GeneralOptionsProperty = $null -eq $Configuration ? $null : $Configuration.PSObject.Properties['GeneralOptions']
      $GeneralOptions = $null -eq $GeneralOptionsProperty ? $null : $GeneralOptionsProperty.Value
      $MsiPayloadSelection = Get-AdvancedInstallerMsiPayloadSelection -File $Files.ToArray() -GeneralOptions $GeneralOptions

      return [pscustomobject]@{
        InstallerType       = 'AdvancedInstaller'
        Path                = $InstallerPath
        FooterOffset        = [long]$FooterOffset
        FileOffset          = [long]$FileOffset
        FileCount           = [int]$FileCount
        Files               = $Files
        ConfigurationEntry  = $null -eq $ConfigurationEntry ? $null : $ConfigurationEntry.Name
        Configuration       = $Configuration
        GeneralOptions      = $GeneralOptions
        MsiPayloadSelection = $MsiPayloadSelection
      }
    } finally {
      $Reader.Close()
      $Stream.Close()
    }
  }
}

function Expand-AdvancedInstaller {
  <#
  .SYNOPSIS
    Extract the embedded payloads from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER DestinationPath
    The destination directory for the extracted payloads
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath
  )

  process {
    Import-AdvancedInstallerMsiModule

    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $Installer.Path -Parent
    }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    # Export catalog entries by their declared names. Only archives that actually contain MSI
    # databases are expanded; large application-file archives remain opaque.
    foreach ($Entry in $Installer.Files) {
      $EntryPath = Resolve-AdvancedInstallerExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      $EntryFile = Write-AdvancedInstallerEntry -Path $Installer.Path -Entry $Entry -DestinationPath $EntryPath

      # Advanced Installer commonly nests the actual MSI payload inside a dedicated 7z archive.
      # Skip non-MSI archives such as FILES.7z to keep validation and task runs bounded.
      if ((Test-AdvancedInstallerNestedArchiveCandidate -Entry $Entry -Path $EntryFile.FullName) -and (Test-AdvancedInstallerArchiveHasMsi -Path $EntryFile.FullName)) {
        Expand-AdvancedInstallerArchive -Path $EntryFile.FullName -DestinationPath $EntryFile.DirectoryName | Out-Null
      }
    }

    return (Get-Item -Path $DestinationPath -Force).FullName
  }
}

function Resolve-AdvancedInstallerMsiFile {
  <#
  .SYNOPSIS
    Resolve the MSI path that the Advanced Installer bootstrapper would launch
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Item
    The extracted MSI candidates
  .PARAMETER ExtractionPath
    The extraction root used to calculate payload-relative paths
  .PARAMETER Pattern
    The optional MSI file name or wildcard constraint
  .PARAMETER Architecture
    The target host architecture whose bootstrapper path should be reproduced
  .PARAMETER NameWasSpecified
    Whether the caller explicitly supplied the pattern
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(Mandatory, HelpMessage = 'The extracted MSI candidates')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The extraction root used to calculate payload-relative paths')]
    [string]$ExtractionPath,

    [Parameter(Mandatory, HelpMessage = 'The optional MSI file name or wildcard constraint')]
    [string]$Pattern,

    [string]$Architecture,

    [bool]$NameWasSpecified
  )

  $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
  $Selection = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value
  if ($Selection -and $Selection.SourceKind -eq 'Download') {
    throw "Advanced Installer obtains its main payload from MainAppURL '$($Selection.MainAppUrl)'; no embedded MSI represents the runtime selection"
  }

  # The caller's pattern narrows the extracted set, but it never replaces the SFX-selected relative
  # path when configuration metadata is available.
  $Candidates = @($Item | Where-Object {
      $_.Name -like $Pattern -or $_.FullName -like $Pattern -or ([System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName)) -like $Pattern
    })
  if (-not $Candidates) { throw "No Advanced Installer MSI matched the pattern: $Pattern" }

  # Resolve the architecture branch exactly as the bootstrapper would. Ambiguous all-platform
  # packages require an explicit host architecture instead of guessing from MSI metadata.
  $SelectedRelativePath = if ($Selection -and $Architecture) {
    $ArchitecturePropertyName = "$($Architecture.Substring(0, 1).ToUpperInvariant())$($Architecture.Substring(1))MsiPath"
    $ArchitecturePathProperty = $Selection.PSObject.Properties[$ArchitecturePropertyName]
    if ($null -eq $ArchitecturePathProperty -or [string]::IsNullOrWhiteSpace([string]$ArchitecturePathProperty.Value)) {
      throw "The Advanced Installer payload metadata does not define an MSI path for '$Architecture'"
    }
    [string]$ArchitecturePathProperty.Value
  } elseif ($Selection -and -not $Selection.AllPlatforms) {
    [string]$Selection.BaseMsiPath
  } elseif ($Selection -and $NameWasSpecified -and $Candidates.Count -eq 1) {
    return $Candidates[0]
  } elseif ($Selection -and $Selection.AllPlatforms) {
    throw 'This Advanced Installer bootstrapper selects different MSI paths by host architecture; specify -Architecture'
  } else {
    $null
  }

  if (-not [string]::IsNullOrWhiteSpace($SelectedRelativePath)) {
    $Selected = @($Candidates | Where-Object {
        [System.IO.Path]::GetRelativePath($ExtractionPath, $_.FullName).Equals($SelectedRelativePath, [System.StringComparison]::OrdinalIgnoreCase)
      })
    if ($Selected.Count -eq 1) { return $Selected[0] }
    if ($Selected.Count -gt 1) { throw "Multiple extracted MSI files have the bootstrapper-selected path: $SelectedRelativePath" }
    throw "The bootstrapper-selected MSI path was not extracted: $SelectedRelativePath"
  }

  return Resolve-AdvancedInstallerMatch -Item $Candidates -Pattern $Pattern
}

function Get-AdvancedInstallerMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted Advanced Installer payload
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    $NameWasSpecified = $PSBoundParameters.ContainsKey('Name')
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    $ExpandedPath = New-AdvancedInstallerTempFolder

    try {
      # Expansion recovers all catalog paths, then selection metadata chooses the one runtime MSI.
      # The MSI parser is applied only after that choice to avoid reversing the bootstrapper logic.
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath | Out-Null
      $MsiFiles = @(Get-ChildItem -Path $ExpandedPath -Filter '*.msi' -Recurse -File | Sort-Object -Property FullName)
      $MsiFile = Resolve-AdvancedInstallerMsiFile -Installer $Installer -Item $MsiFiles -ExtractionPath $ExpandedPath -Pattern $Name -Architecture $Architecture -NameWasSpecified $NameWasSpecified
      $MsiInfo = Get-MsiInstallerInfo -Path $MsiFile.FullName

      # MSI metadata validates the already selected payload; it is not used as the selector.
      if ($Architecture -and $MsiInfo.PackageArchitecture -cne $Architecture) {
        throw "Advanced Installer selected '$($MsiFile.Name)' for '$Architecture', but the MSI package architecture is '$($MsiInfo.PackageArchitecture)'"
      }

      $SelectionProperty = $Installer.PSObject.Properties['MsiPayloadSelection']
      $SelectionMethod = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.SelectionMethod
      $ArchitectureSelectionMode = $null -eq $SelectionProperty ? $null : $SelectionProperty.Value.ArchitectureSelectionMode

      return [pscustomobject]@{
        Name                         = $MsiFile.Name
        Path                         = $MsiFile.FullName
        PackageArchitecture          = $MsiInfo.PackageArchitecture
        Template                     = $MsiInfo.Template
        ProductName                  = $MsiInfo.DisplayName
        ProductVersion               = $MsiInfo.DisplayVersion
        Publisher                    = $MsiInfo.Publisher
        ProductCode                  = $MsiInfo.ProductCode
        UpgradeCode                  = $MsiInfo.UpgradeCode
        InstallerBuilder             = $MsiInfo.InstallerBuilder
        InstallLocationProperty      = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch        = $MsiInfo.InstallLocationSwitch
        AppsAndFeaturesInstallerType = $MsiInfo.AppsAndFeaturesInstallerType
        AppsAndFeaturesProductCode   = $MsiInfo.AppsAndFeaturesProductCode
        Protocols                    = $MsiInfo.Protocols
        FileExtensions               = $MsiInfo.FileExtensions
        RegistryAssociationInfo      = $MsiInfo.RegistryAssociationInfo
        SelectionMethod              = $SelectionMethod
        ArchitectureSelectionMode    = $ArchitectureSelectionMode
        SelectedMsiPath              = [System.IO.Path]::GetRelativePath($ExpandedPath, $MsiFile.FullName)
      }
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
    }
  }
}

function Read-ProductVersionFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductVersion
  }
}

function Read-ProductCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductCode
  }
}

function Read-UpgradeCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  .PARAMETER Architecture
    The target host architecture used to reproduce the bootstrapper's MSI path selection
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi',

    [Parameter(HelpMessage = "The target host architecture used to reproduce the bootstrapper's MSI path selection")]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).UpgradeCode
  }
}

Export-ModuleMember -Function Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
