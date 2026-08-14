# License: GPL-2.0. See Modules\InstallerParsers\LICENSE.GPL2.
# Format sources: https://github.com/russellbanks/Komac/tree/main/src/analysis/installers/advanced,
# https://github.com/SabreTools/SabreTools.Serialization/tree/main/SabreTools.Data.Models/AdvancedInstaller,
# https://github.com/HydraDragonAntivirus/HydraDragonAntivirus, and official Caphyon release/user-guide pages.
#
# Binary structure consumed by this parser (absolute file offsets, LE integers):
#
#   PE bootstrapper
#   +-- payload ranges
#   +-- catalog at Footer.TablePointer
#   |   +-- v0: [Type:u32][Group:u32][Size:u32][Offset:u32]
#   |   |       [NameChars:u32][Name:ANSI or UTF-16LE]
#   |   `-- v1: [Type:u32][Group:u32][Transform:u32][Size:u32]
#   |           [Offset:u32][NameChars:u32][Name:UTF-16LE]
#   +-- optional external-resource table
#   |   `-- [Role:u32][NameChars:u32][SiblingName:ANSI or UTF-16LE]
#   `-- 74-byte footer: ExternalCount@+00, EmbeddedCatalogEnd@+04,
#       EmbeddedCount@+08, StructureVersion@+0C, FooterOffset@+10, TablePointer@+14,
#       FileDataStart@+18, BootstrapperId@+1C, Flags@+3C, "ADVINSTSFX"@+40
#
# TransformFlag 2 XORs only the first min(512, Size) payload bytes with FF.
# Catalog offsets point to absolute ranges; they do not imply payload adjacency.
# Architecture-specific MSI selection follows the parsed configuration paths.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Constants
$ADVANCED_INSTALLER_MAGIC = [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
$ADVANCED_INSTALLER_FOOTER_SIZE = 74
$ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET = 64
$ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE = $ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $ADVANCED_INSTALLER_MAGIC.Length
$ADVANCED_INSTALLER_XOR_HEADER_SIZE = 512
$ADVANCED_INSTALLER_MAXIMUM_CONFIGURATION_SIZE = 4194304
$Script:AdvancedInstallerCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'AdvancedInstallerFormatCatalog.psd1')

# Route maps keep serialized-layout selection separate from the format readers.
# Catalog descriptors select one handler from each map; parser code never infers
# a layout from the package application's version resources.
$Script:AdvancedInstallerFooterHandlers = @{
  'footer-v1' = 'Read-AdvancedInstallerFooterV1'
}
$Script:AdvancedInstallerCatalogHandlers = @{
  'catalog-v0-ansi'    = 'Read-AdvancedInstallerCatalog'
  'catalog-v0-unicode' = 'Read-AdvancedInstallerCatalog'
  'catalog-v1-unicode' = 'Read-AdvancedInstallerCatalog'
}
$Script:AdvancedInstallerExternalResourceHandlers = @{
  'external-v1-ansi'    = 'Read-AdvancedInstallerExternalResourceTableV1'
  'external-v1-unicode' = 'Read-AdvancedInstallerExternalResourceTableV1'
}
$Script:AdvancedInstallerConfigurationHandlers = @{
  'ini-ansi-v1'    = 'ConvertFrom-AdvancedInstallerIniData'
  'ini-unicode-v1' = 'ConvertFrom-AdvancedInstallerIniData'
  'ini-auto-v1'    = 'ConvertFrom-AdvancedInstallerIniData'
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
    # The GPL parser consumes the Apache-licensed MSI reader through this narrow bridge. Global
    # import lets its family-specific table projections resolve the generic MSI query helpers,
    # without loading PackageModule's same-named Advanced Installer facade into this process.
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\..\..\PackageModule\Libraries\Installers\MSI.psm1') -Force -Global
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

function Read-AdvancedInstallerByteRange {
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
    $FooterBytes = Read-AdvancedInstallerByteRange -Stream $Stream -Offset $FooterOffset -Length $FooterLength

    if (-not (Test-AdvancedInstallerBytePattern -Left $FooterBytes[$Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET..($Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $Script:ADVANCED_INSTALLER_MAGIC.Length - 1)] -Right $Script:ADVANCED_INSTALLER_MAGIC)) {
      return $false
    }

    $ExternalFileCount = [System.BitConverter]::ToUInt32($FooterBytes, 0)
    $EmbeddedCatalogEnd = [System.BitConverter]::ToUInt32($FooterBytes, 4)
    $EmbeddedFileCount = [System.BitConverter]::ToUInt32($FooterBytes, 8)
    $PhysicalFooterOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
    $CatalogOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)
    $PayloadOffset = [System.BitConverter]::ToUInt32($FooterBytes, 24)

    if ($EmbeddedFileCount -gt 0x10000 -or $ExternalFileCount -gt 0x10000 -or ([long]$EmbeddedFileCount + $ExternalFileCount) -eq 0) { return $false }
    if ($PhysicalFooterOffset -ne $FooterOffset) { return $false }
    if ($CatalogOffset -gt $EmbeddedCatalogEnd -or $EmbeddedCatalogEnd -gt $FooterOffset) { return $false }
    if ($EmbeddedFileCount -gt 0 -and $CatalogOffset -eq $EmbeddedCatalogEnd) { return $false }
    if ($ExternalFileCount -eq 0 -and $EmbeddedCatalogEnd -ne $FooterOffset) { return $false }
    if ($ExternalFileCount -gt 0 -and $EmbeddedCatalogEnd -ge $FooterOffset) { return $false }
    if ($PayloadOffset -ge $CatalogOffset) { return $false }

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

  return $Script:ADVANCED_INSTALLER_FOOTER_SIZE
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

  $ExternalProperty = $Entry.PSObject.Properties['IsExternal']
  $IsExternal = $null -ne $ExternalProperty -and [bool]$ExternalProperty.Value
  $SourcePath = if ($IsExternal) {
    if ($Entry.MissingExternal -or -not (Test-Path -LiteralPath $Entry.SourcePath -PathType Leaf)) {
      throw "The Advanced Installer external resource is missing: $($Entry.Name)"
    }
    (Get-Item -LiteralPath $Entry.SourcePath -Force).FullName
  } else {
    (Get-Item -LiteralPath $Path -Force).FullName
  }

  # Expanding an external media set beside setup.exe may select the sibling itself as the target.
  # In that case the desired bytes are already present and opening with Create would destroy them.
  if ($IsExternal -and $SourcePath -eq [IO.Path]::GetFullPath($DestinationPath)) {
    return Get-Item -LiteralPath $SourcePath -Force
  }

  $SourceStream = [System.IO.File]::OpenRead($SourcePath)
  $DestinationStream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

  try {
    # Embedded catalog offsets are absolute file offsets. External records name a complete sibling
    # file and therefore start at offset zero in their own bounded source stream.
    $null = $SourceStream.Seek($IsExternal ? 0 : $Entry.Offset, 'Begin')

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
  .PARAMETER Name
    Optional wildcard selecting nested archive paths or file names.
  .PARAMETER CollisionAction
    Behavior when a nested output path already exists.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The directory where the archive contents should be written')]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename'
  )

  $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  # Delegate path, link, duplicate, and output-limit enforcement to the shared archive exporter.
  $Archive = Get-InstallerArchive -Path $Path

  try {
    $null = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -Name $Name `
      -CollisionAction $CollisionAction -MaximumExpandedBytes 17179869184 -MaximumEntries 200000
    return (Get-Item -Path $DestinationPath -Force).FullName
  } finally {
    $Archive.Dispose()
  }
}

function Get-AdvancedInstallerArchiveInfo {
  <#
  .SYNOPSIS
    Inspect a nested Advanced Installer archive for MSI and AES evidence without extracting entries
  .PARAMETER Path
    The path to the extracted archive
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path
  )

  $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $SourceStream = $null
  $Archive = $null
  $Entry = $null
  try {
    # Own the source stream explicitly and allow deletion of transient archive
    # files. SharpCompress can retain an encrypted 7z decoder until its archive
    # graph is collected even after Dispose(), so a path-opened archive would
    # otherwise prevent the caller from cleaning its temporary extraction tree.
    $Share = [IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    $SourceStream = [IO.FileStream]::new($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, $Share)
    $Archive = Get-InstallerArchive -Stream $SourceStream
    $EntryCount = 0
    $EncryptedEntryCount = 0
    $HasMsi = $false
    # Inspect native entries directly instead of retaining normalized entries
    # that reference the archive. Some SharpCompress 7z implementations keep
    # the source handle alive while those wrappers remain reachable.
    foreach ($Entry in $Archive.Entries) {
      if ($Entry.IsDirectory) { continue }
      $EntryCount++
      if ($Entry.PSObject.Properties.Name -contains 'IsEncrypted' -and $Entry.IsEncrypted) {
        $EncryptedEntryCount++
      }
      if ([string]$Entry.Key -like '*.msi') { $HasMsi = $true }
    }
    $Entry = $null
    return [pscustomobject][ordered]@{
      IsEncrypted         = $EncryptedEntryCount -gt 0
      Encryption          = $EncryptedEntryCount -gt 0 ? 'AES-256' : $null
      HeaderEncrypted     = $false
      HasMsi              = $HasMsi
      EntryCount          = $EntryCount
      EncryptedEntryCount = $EncryptedEntryCount
      Warnings            = [string[]]@()
    }
  } catch {
    # SharpCompress reaches its 7z AES decoder while reading an encrypted header and emits this
    # exact diagnostic before any entry can be enumerated. Treat only that source-backed path as
    # encrypted-header evidence; all other malformed archive failures remain ordinary errors.
    if ($_.Exception.ToString() -match 'Encrypted 7Zip archive has no password specified') {
      return [pscustomobject][ordered]@{
        IsEncrypted         = $true
        Encryption          = 'AES-256'
        HeaderEncrypted     = $true
        HasMsi              = $null
        EntryCount          = $null
        EncryptedEntryCount = $null
        Warnings            = [string[]]@('The Advanced Installer 7z header is encrypted, so nested paths cannot be enumerated without the authoring password.')
      }
    }
    throw
  } finally {
    $Entry = $null
    try {
      if ($Archive) { $Archive.Dispose() }
    } finally {
      if ($SourceStream) { $SourceStream.Dispose() }
    }
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

  # Advanced Installer commonly stores application files in FILES.7z.  That archive can be very large
  # and does not contain the MSI database used for AppsAndFeatures metadata.
  if ([System.IO.Path]::GetFileName($Entry.Name) -ieq 'FILES.7z') { return $false }

  # Selector (3, 7) is the compressed main package. Historical builders can give that physical 7z
  # stream the eventual MSI name, so filename extension alone is not authoritative.
  if ($Entry.SelectorType -eq 3 -and $Entry.SelectorGroup -eq 7) { return $true }
  return [System.IO.Path]::GetExtension($Path) -ieq '.7z'
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

  # External configuration is a complete sibling file; embedded configuration uses an absolute
  # range in setup.exe. Both paths retain the same bounded size and transform handling.
  $ExternalProperty = $Entry.PSObject.Properties['IsExternal']
  $IsExternal = $null -ne $ExternalProperty -and [bool]$ExternalProperty.Value
  if ($IsExternal) {
    if ($Entry.MissingExternal -or -not (Test-Path -LiteralPath $Entry.SourcePath -PathType Leaf)) {
      throw "The Advanced Installer external resource is missing: $($Entry.Name)"
    }
    $ExternalStream = [IO.File]::OpenRead($Entry.SourcePath)
    try {
      $Bytes = Read-AdvancedInstallerByteRange -Stream $ExternalStream -Offset 0 -Length ([int]$Entry.Size)
    } finally {
      $ExternalStream.Dispose()
    }
  } else {
    $Bytes = Read-AdvancedInstallerByteRange -Stream $Stream -Offset $Entry.Offset -Length ([int]$Entry.Size)
  }
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

function Test-AdvancedInstallerPayloadSelector {
  <#
  .SYNOPSIS
    Test one catalog entry against a declarative payload selector.
  .PARAMETER Entry
    Parsed Advanced Installer catalog entry.
  .PARAMETER Selector
    Two-element selector tuple containing the type and group values.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][psobject]$Entry,
    [Parameter(Mandatory)][object[]]$Selector
  )

  return $Selector.Count -eq 2 -and [int]$Entry.SelectorType -eq [int]$Selector[0] -and [int]$Entry.SelectorGroup -eq [int]$Selector[1]
}

function Get-AdvancedInstallerMsiPayloadSelection {
  <#
  .SYNOPSIS
    Reproduce the bootstrapper's main MSI path selection from payload-table and INI metadata
  .PARAMETER File
    The parsed payload-table entries
  .PARAMETER GeneralOptions
    The parsed GeneralOptions INI section
  .PARAMETER PayloadRoute
    Catalog-selected payload route descriptor.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed payload-table entries')]
    [object[]]$File,

    [AllowNull()]
    [psobject]$GeneralOptions,

    [System.Collections.IDictionary]$PayloadRoute = $Script:AdvancedInstallerCatalog.PayloadRoutes['selector-v1']
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
  $DirectSelector = [object[]]$PayloadRoute.DirectMsiSelector
  $ArchiveSelector = [object[]]$PayloadRoute.ArchiveMsiSelector
  $DirectEntry = $File | Where-Object {
    (Test-AdvancedInstallerPayloadSelector -Entry $_ -Selector $DirectSelector) -and [System.IO.Path]::GetExtension($_.Name) -ieq '.msi'
  } | Select-Object -First 1
  $ArchiveEntry = $File | Where-Object {
    Test-AdvancedInstallerPayloadSelector -Entry $_ -Selector $ArchiveSelector
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
  $IsExternal = $SourceEntry.PSObject.Properties['IsExternal'] -and [bool]$SourceEntry.IsExternal

  return [pscustomobject]@{
    SelectionMethod           = 'PayloadTable'
    ArchitectureSelectionMode = $AllPlatforms ? 'Wow64Suffix' : 'FixedPath'
    SourceEntryName           = $SourceEntry.Name
    SourceEntryIndex          = $SourceEntry.Index
    SourceKind                = if ($DirectEntry) { $IsExternal ? 'ExternalMsi' : 'EmbeddedMsi' } else { $IsExternal ? 'ExternalArchive' : 'EmbeddedArchive' }
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

function Get-AdvancedInstallerPlatformPayloadSelection {
  <#
  .SYNOPSIS
    Project the MSI/MSIX operating-system selection encoded by a modern bootstrapper.
  .PARAMETER File
    Parsed payload-table entries.
  .PARAMETER GeneralOptions
    Parsed GeneralOptions INI section.
  .PARAMETER PayloadRoute
    Catalog-selected payload route descriptor.
  .PARAMETER MsiPayloadSelection
    Previously resolved legacy MSI selection evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object[]]$File,
    [AllowNull()][psobject]$GeneralOptions,
    [Parameter(Mandatory)][System.Collections.IDictionary]$PayloadRoute,
    [AllowNull()][psobject]$MsiPayloadSelection
  )

  $MsixSelector = [object[]]$PayloadRoute.MsixPackageSelector
  if ($MsixSelector.Count -ne 2) { return $null }

  # Selector (1, 18) is emitted by Advanced Installer for each embedded APPX/MSIX branch.
  # Keep all records because bundles can contain architecture-specific package files.
  $ModernEntries = @($File | Where-Object {
      Test-AdvancedInstallerPayloadSelector -Entry $_ -Selector $MsixSelector
    })
  if ($ModernEntries.Count -eq 0) { return $null }

  $PackageFullName = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'AppxPkId')
  $MinimumWindowsVersion = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'AppxVersion')
  $PackageFamilyName = $null
  $PackageArchitecture = $null
  if ($PackageFullName -match '^(?<Name>.+)_(?<Version>\d+(?:\.\d+){3})_(?<Architecture>[^_]+)_[^_]*_(?<PublisherId>[^_]+)$') {
    $PackageFamilyName = "$($Matches.Name)_$($Matches.PublisherId)"
    $PackageArchitecture = $Matches.Architecture
  }

  $ModernPayloads = @($ModernEntries | ForEach-Object {
      [pscustomobject][ordered]@{
        Name          = [string]$_.Name
        Index         = [int]$_.Index
        PackageType   = [IO.Path]::GetExtension([string]$_.Name).TrimStart('.').ToLowerInvariant()
        SelectorType  = [int]$_.SelectorType
        SelectorGroup = [int]$_.SelectorGroup
        Size          = [long]$_.Size
        CanExtract    = [bool]$_.CanExtract
      }
    })

  return [pscustomobject][ordered]@{
    SelectionMethod       = 'OperatingSystemVersion'
    RuntimeRule           = 'UseMsixAtOrAboveMinimumWindowsVersion'
    MinimumWindowsVersion = [string]::IsNullOrWhiteSpace($MinimumWindowsVersion) ? $null : $MinimumWindowsVersion
    PackageFullName       = [string]::IsNullOrWhiteSpace($PackageFullName) ? $null : $PackageFullName
    PackageFamilyName     = $PackageFamilyName
    PackageArchitecture   = $PackageArchitecture
    LegacyMsiSelection    = $MsiPayloadSelection
    ModernPayloads        = [object[]]$ModernPayloads
  }
}

function Read-AdvancedInstallerFooterV1 {
  <#
  .SYNOPSIS
    Read and validate the versioned ADVINSTSFX footer layout.
  .PARAMETER Stream
    Seekable installer stream. The caller owns the stream and its position is restored.
  .PARAMETER FooterOffset
    Absolute offset of the footer whose magic starts at footer-relative offset 0x40.
  .PARAMETER Route
    Catalog footer-route descriptor containing field offsets and parser limits.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][long]$FooterOffset,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Route
  )

  $OriginalPosition = $Stream.Position
  try {
    if ($FooterOffset -lt 0 -or $FooterOffset + [int]$Route.MinimumSize -gt $Stream.Length) {
      throw 'The Advanced Installer footer is outside the installer stream'
    }

    $Footer = Read-BinaryBytes -Stream $Stream -Offset $FooterOffset -Count ([int]$Route.MinimumSize)
    $MagicBytes = [Text.Encoding]::ASCII.GetBytes([string]$Route.Magic)
    $ObservedMagic = $Footer[[int]$Route.MagicOffset..([int]$Route.MagicOffset + $MagicBytes.Length - 1)]
    if (-not (Test-BinarySequence -Left $ObservedMagic -Right $MagicBytes)) {
      throw 'The Advanced Installer footer signature is invalid'
    }

    $ExternalFileCount = [BitConverter]::ToUInt32($Footer, [int]$Route.ExternalFileCountOffset)
    $EmbeddedCatalogEnd = [BitConverter]::ToUInt32($Footer, [int]$Route.EmbeddedCatalogEndOffset)
    $EmbeddedFileCount = [BitConverter]::ToUInt32($Footer, [int]$Route.EmbeddedFileCountOffset)
    $StructureVersion = [BitConverter]::ToUInt32($Footer, [int]$Route.StructureVersionOffset)
    $PhysicalFooterOffset = [BitConverter]::ToUInt32($Footer, [int]$Route.PhysicalFooterOffset)
    $CatalogOffset = [BitConverter]::ToUInt32($Footer, [int]$Route.CatalogOffsetOffset)
    $PayloadOffset = [BitConverter]::ToUInt32($Footer, [int]$Route.PayloadOffsetOffset)
    $Flags = [BitConverter]::ToUInt32($Footer, [int]$Route.FlagsOffset)
    $BootstrapperIdRaw = [Text.Encoding]::ASCII.GetString($Footer, [int]$Route.BootstrapperIdOffset, [int]$Route.BootstrapperIdLength)

    if ($PhysicalFooterOffset -ne $FooterOffset) {
      throw 'The Advanced Installer footer self-offset does not identify the footer start'
    }
    if ($EmbeddedFileCount -gt [uint32]$Route.MaximumFileCount -or $ExternalFileCount -gt [uint32]$Route.MaximumFileCount -or ([long]$EmbeddedFileCount + $ExternalFileCount) -eq 0) {
      throw 'The Advanced Installer footer declares invalid embedded or external file counts'
    }
    if ($CatalogOffset -gt $EmbeddedCatalogEnd -or $EmbeddedCatalogEnd -gt $FooterOffset) {
      throw 'The Advanced Installer footer embedded-catalog range is invalid'
    }
    if ($EmbeddedFileCount -gt 0 -and $CatalogOffset -eq $EmbeddedCatalogEnd) {
      throw 'The Advanced Installer embedded catalog is empty despite a non-zero file count'
    }
    if ($ExternalFileCount -eq 0 -and $EmbeddedCatalogEnd -ne $FooterOffset) {
      throw 'The Advanced Installer footer has unclaimed bytes after the embedded catalog'
    }
    if ($ExternalFileCount -gt 0 -and $EmbeddedCatalogEnd -ge $FooterOffset) {
      throw 'The Advanced Installer external-resource table is empty or outside the footer boundary'
    }
    if ($PayloadOffset -ge $CatalogOffset) {
      throw 'The Advanced Installer payload area does not precede the file catalog'
    }
    # Controlled rebuilds produce a fresh RFC 4122 version-4 identifier in N format. Validate both
    # its textual grammar and variant/version bits instead of treating the field as an unverified digest.
    if ($BootstrapperIdRaw -notmatch '^[0-9A-Fa-f]{12}4[0-9A-Fa-f]{3}[89ABab][0-9A-Fa-f]{15}$') {
      throw 'The Advanced Installer footer bootstrapper identifier is not a version-4 GUID in N format'
    }
    $BootstrapperId = [guid]::ParseExact($BootstrapperIdRaw, 'N')

    [pscustomobject][ordered]@{
      Offset                 = [long]$FooterOffset
      Route                  = 'footer-v1'
      StructureVersion       = [uint32]$StructureVersion
      FileCount              = [uint32]$EmbeddedFileCount
      EmbeddedFileCount      = [uint32]$EmbeddedFileCount
      ExternalFileCount      = [uint32]$ExternalFileCount
      CatalogOffset          = [long]$CatalogOffset
      CatalogEndOffset       = [long]$EmbeddedCatalogEnd
      ExternalTableOffset    = [long]$EmbeddedCatalogEnd
      ExternalTableEndOffset = [long]$FooterOffset
      PayloadOffset          = [long]$PayloadOffset
      BootstrapperId         = $BootstrapperId.ToString('B').ToUpperInvariant()
      BootstrapperIdRaw      = $BootstrapperId.ToString('N').ToUpperInvariant()
      Flags                  = [uint32]$Flags
    }
  } finally {
    $null = $Stream.Seek($OriginalPosition, 'Begin')
  }
}

function Get-AdvancedInstallerCatalogEncoding {
  <#
  .SYNOPSIS
    Create the strict text decoder selected by a catalog record route.
  .PARAMETER Name
    Catalog encoding identifier.
  #>
  [OutputType([Text.Encoding])]
  param ([Parameter(Mandatory)][string]$Name)

  switch ($Name) {
    'UTF-16LE' { return [Text.UnicodeEncoding]::new($false, $true, $true) }
    'Windows-1252' {
      [Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance)
      return [Text.Encoding]::GetEncoding(1252, [Text.EncoderFallback]::ExceptionFallback, [Text.DecoderFallback]::ExceptionFallback)
    }
    default { throw "Unsupported Advanced Installer catalog encoding route: $Name" }
  }
}

function Read-AdvancedInstallerCatalog {
  <#
  .SYNOPSIS
    Parse one fixed-record Advanced Installer payload catalog.
  .PARAMETER Stream
    Seekable installer stream. The caller owns the stream and its position is restored.
  .PARAMETER Footer
    Validated footer projection defining the absolute catalog range.
  .PARAMETER RouteId
    Catalog route identifier from AdvancedInstallerFormatCatalog.psd1.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Footer,
    [Parameter(Mandatory)][string]$RouteId
  )

  $Route = $Script:AdvancedInstallerCatalog.CatalogRoutes[$RouteId]
  if (-not $Route) { throw "Unknown Advanced Installer catalog route: $RouteId" }
  $Encoding = Get-AdvancedInstallerCatalogEncoding -Name ([string]$Route.NameEncoding)
  $OriginalPosition = $Stream.Position

  try {
    $null = $Stream.Seek($Footer.CatalogOffset, 'Begin')
    $Reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::UTF8, $true)
    $Files = [Collections.Generic.List[object]]::new([int]$Footer.FileCount)

    try {
      for ($Index = 0; $Index -lt $Footer.FileCount; $Index++) {
        if ($Stream.Position + [int]$Route.FixedRecordSize -gt $Footer.CatalogEndOffset) {
          throw 'The Advanced Installer file table is truncated'
        }
        $Record = $Reader.ReadBytes([int]$Route.FixedRecordSize)
        if ($Record.Length -ne [int]$Route.FixedRecordSize) { throw 'The Advanced Installer file table is truncated' }

        $NameLength = [BitConverter]::ToUInt32($Record, [int]$Route.NameLengthOffset)
        if ($NameLength -gt 32768) { throw 'The Advanced Installer payload name exceeds the parser limit' }
        $NameByteLength = [long]$NameLength * [int]$Route.NameLengthUnit
        if ($NameByteLength -gt [int]::MaxValue -or $Stream.Position + $NameByteLength -gt $Footer.CatalogEndOffset) {
          throw 'The Advanced Installer payload name is truncated'
        }

        $NameBytes = $Reader.ReadBytes([int]$NameByteLength)
        if ($NameBytes.Length -ne $NameByteLength) { throw 'The Advanced Installer payload name is truncated' }
        $Name = if ($NameLength -eq 0) {
          "unnamed_file_${Index}.bin"
        } else {
          $Encoding.GetString($NameBytes).TrimEnd([char]0)
        }
        if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0) {
          throw 'The Advanced Installer payload name is malformed'
        }

        $EntryOffset = [BitConverter]::ToUInt32($Record, [int]$Route.PayloadOffsetOffset)
        $EntrySize = [BitConverter]::ToUInt32($Record, [int]$Route.PayloadSizeOffset)
        if ([long]$EntryOffset + [long]$EntrySize -gt $Footer.CatalogOffset) {
          throw "The Advanced Installer payload '$Name' overlaps the file catalog"
        }

        $EncodingFlag = [int]$Route.TransformFlagOffset -lt 0 ? 0 : [BitConverter]::ToUInt32($Record, [int]$Route.TransformFlagOffset)
        $Files.Add([pscustomobject][ordered]@{
            Index           = [int]$Index
            Name            = $Name
            Size            = [long]$EntrySize
            Offset          = [long]$EntryOffset
            SelectorType    = [int][BitConverter]::ToUInt32($Record, [int]$Route.SelectorTypeOffset)
            SelectorGroup   = [int][BitConverter]::ToUInt32($Record, [int]$Route.SelectorGroupOffset)
            EncodingFlag    = [int]$EncodingFlag
            XorLength       = $EncodingFlag -eq 2 ? $Script:ADVANCED_INSTALLER_XOR_HEADER_SIZE : 0
            TransformRoute  = $EncodingFlag -eq 0 ? 'Plain' : ($EncodingFlag -eq 2 ? 'XorHeader512' : 'Opaque')
            CanExtract      = $EncodingFlag -in @(0, 2)
            IsExternal      = $false
            SourcePath      = $null
            ExternalRole    = $null
            MissingExternal = $false
          })
      }
    } finally {
      $Reader.Dispose()
    }

    if ($Stream.Position -ne $Footer.CatalogEndOffset) {
      throw "The Advanced Installer '$RouteId' catalog did not consume its declared range"
    }

    [pscustomobject][ordered]@{
      RouteId       = $RouteId
      CharacterMode = $Route.NameEncoding -eq 'UTF-16LE' ? 'Unicode' : 'Ansi'
      Files         = [object[]]$Files.ToArray()
    }
  } finally {
    $null = $Stream.Seek($OriginalPosition, 'Begin')
  }
}

function Read-AdvancedInstallerExternalResourceTableV1 {
  <#
  .SYNOPSIS
    Parse the sibling-resource declarations between the embedded catalog and physical footer.
  .PARAMETER Stream
    Seekable installer stream. The caller owns the stream and its position is restored.
  .PARAMETER Footer
    Validated footer projection defining the external table range and count.
  .PARAMETER RouteId
    External-resource route identifier selected from the catalog character mode.
  .PARAMETER InstallerPath
    Resolved installer path whose parent directory contains the declared siblings.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Footer,
    [Parameter(Mandatory)][string]$RouteId,
    [Parameter(Mandatory)][string]$InstallerPath
  )

  $Route = $Script:AdvancedInstallerCatalog.ExternalResourceRoutes[$RouteId]
  if (-not $Route) { throw "Unknown Advanced Installer external-resource route: $RouteId" }
  $Encoding = Get-AdvancedInstallerCatalogEncoding -Name ([string]$Route.NameEncoding)
  $PayloadRoute = $Script:AdvancedInstallerCatalog.PayloadRoutes['selector-v1']
  $InstallerDirectory = [IO.Path]::GetDirectoryName($InstallerPath)
  $OriginalPosition = $Stream.Position

  try {
    $null = $Stream.Seek($Footer.ExternalTableOffset, 'Begin')
    $Reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::UTF8, $true)
    $Files = [Collections.Generic.List[object]]::new([int]$Footer.ExternalFileCount)

    try {
      for ($Index = 0; $Index -lt $Footer.ExternalFileCount; $Index++) {
        if ($Stream.Position + [int]$Route.FixedRecordSize -gt $Footer.ExternalTableEndOffset) {
          throw 'The Advanced Installer external-resource table is truncated'
        }
        $Record = $Reader.ReadBytes([int]$Route.FixedRecordSize)
        if ($Record.Length -ne [int]$Route.FixedRecordSize) { throw 'The Advanced Installer external-resource table is truncated' }

        $Role = [BitConverter]::ToUInt32($Record, [int]$Route.RoleOffset)
        $NameLength = [BitConverter]::ToUInt32($Record, [int]$Route.NameLengthOffset)
        if ($NameLength -eq 0 -or $NameLength -gt 32768) { throw 'The Advanced Installer external-resource name length is invalid' }
        $NameByteLength = [long]$NameLength * [int]$Route.NameLengthUnit
        if ($NameByteLength -gt [int]::MaxValue -or $Stream.Position + $NameByteLength -gt $Footer.ExternalTableEndOffset) {
          throw 'The Advanced Installer external-resource name is truncated'
        }

        $NameBytes = $Reader.ReadBytes([int]$NameByteLength)
        if ($NameBytes.Length -ne $NameByteLength) { throw 'The Advanced Installer external-resource name is truncated' }
        $Name = $Encoding.GetString($NameBytes).TrimEnd([char]0)
        if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOf([char]0) -ge 0) {
          throw 'The Advanced Installer external-resource name is malformed'
        }

        # External names are relative to setup.exe. Resolve them with the same traversal guard used
        # for extraction destinations before checking whether the complete media set is present.
        $SourcePath = Resolve-SafeExtractionPath -DestinationPath $InstallerDirectory -RelativePath $Name
        $SourceItem = Get-Item -LiteralPath $SourcePath -Force -ErrorAction SilentlyContinue
        $Selector = $PayloadRoute.ExternalRoleSelectors[[string]$Role]
        $Files.Add([pscustomobject][ordered]@{
            Index           = [int]($Footer.EmbeddedFileCount + $Index)
            Name            = $Name
            Size            = $null -eq $SourceItem ? 0L : [long]$SourceItem.Length
            Offset          = $null
            SelectorType    = $null -eq $Selector ? -1 : [int]$Selector[0]
            SelectorGroup   = $null -eq $Selector ? [int]$Role : [int]$Selector[1]
            EncodingFlag    = 0
            XorLength       = 0
            TransformRoute  = 'PlainExternal'
            CanExtract      = $null -ne $SourceItem
            IsExternal      = $true
            SourcePath      = $SourcePath
            ExternalRole    = [int]$Role
            MissingExternal = $null -eq $SourceItem
          })
      }
    } finally {
      $Reader.Dispose()
    }

    if ($Stream.Position -ne $Footer.ExternalTableEndOffset) {
      throw "The Advanced Installer '$RouteId' external-resource table did not consume its declared range"
    }

    [pscustomobject][ordered]@{
      RouteId = $RouteId
      Files   = [object[]]$Files.ToArray()
    }
  } finally {
    $null = $Stream.Seek($OriginalPosition, 'Begin')
  }
}

function Get-AdvancedInstallerConfigurationCharacterMode {
  <#
  .SYNOPSIS
    Identify an embedded bootstrapper INI encoding without interpreting its values.
  .PARAMETER Bytes
    Decoded or plain configuration payload bytes.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  if ($Bytes.Length -ge 2 -and (($Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) -or ($Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF))) {
    return 'Unicode'
  }
  if ($Bytes.Length -ge 4 -and (($Bytes[1] -eq 0 -and $Bytes[3] -eq 0) -or ($Bytes[0] -eq 0 -and $Bytes[2] -eq 0))) {
    return 'Unicode'
  }
  return 'Ansi'
}

function Get-AdvancedInstallerExplicitVersionInfo {
  <#
  .SYNOPSIS
    Read only explicitly named builder and project-schema values from bootstrapper configuration.
  .PARAMETER GeneralOptions
    Parsed GeneralOptions section. ProductVersion is deliberately excluded because it identifies the packaged application.
  #>
  [OutputType([pscustomobject])]
  param ([AllowNull()][psobject]$GeneralOptions)

  $BuilderVersion = $null
  $BuilderVersionSource = $null
  foreach ($Name in 'AdvancedInstallerVersion', 'BuilderVersion', 'AIVersion') {
    $Value = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name $Name)
    if ($Value -match '^\d+(?:\.\d+){1,3}$') {
      $BuilderVersion = $Value
      $BuilderVersionSource = "GeneralOptions.$Name"
      break
    }
  }

  $ProjectSchemaVersion = $null
  foreach ($Name in 'ProjectSchemaVersion', 'AipSchemaVersion') {
    $Value = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name $Name)
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
      $ProjectSchemaVersion = $Value
      break
    }
  }

  [pscustomobject]@{
    BuilderVersion       = $BuilderVersion
    BuilderVersionSource = $BuilderVersionSource
    ProjectSchemaVersion = $ProjectSchemaVersion
  }
}

function Resolve-AdvancedInstallerFormatProfile {
  <#
  .SYNOPSIS
    Select one immutable format profile from validated structure and character-mode evidence.
  .PARAMETER StructureVersion
    Internal uint32 structure version stored at footer offset 0x08.
  .PARAMETER CharacterMode
    ANSI or Unicode configuration/catalog evidence.
  .PARAMETER CatalogRoute
    Fully consumed catalog layout route selected from physical record framing.
  .PARAMETER BuilderVersion
    Optional explicit builder version preserved in compiled configuration. Application versions are not accepted here.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][uint32]$StructureVersion,
    [Parameter(Mandatory)][ValidateSet('Ansi', 'Unicode', 'Unknown')][string]$CharacterMode,
    [Parameter(Mandatory)][string]$CatalogRoute,
    [AllowNull()][string]$BuilderVersion
  )

  $ParsedBuilderVersion = $null
  if (-not [string]::IsNullOrWhiteSpace($BuilderVersion)) {
    $VersionValue = [version]::new()
    if ([version]::TryParse($BuilderVersion, [ref]$VersionValue)) {
      $ParsedBuilderVersion = $VersionValue
    }
  }

  $SelectedFormatProfile = $Script:AdvancedInstallerCatalog.Profiles | Where-Object {
    if ($StructureVersion -notin @($_.StructureVersions) -or $_.CatalogRoute -ne $CatalogRoute -or ($CharacterMode -ne 'Unknown' -and $_.CharacterMode -ne $CharacterMode)) {
      return $false
    }
    if ($null -eq $ParsedBuilderVersion) { return $true }

    $MinimumVersion = [version]$_.MinimumBuilderVersion
    $MaximumVersion = [version]$_.MaximumBuilderVersion
    return $ParsedBuilderVersion -ge $MinimumVersion -and $ParsedBuilderVersion -le $MaximumVersion
  } | Select-Object -First 1
  if ($SelectedFormatProfile) { return [pscustomobject]$SelectedFormatProfile }

  $Fallback = [ordered]@{}
  foreach ($Key in $Script:AdvancedInstallerCatalog.CompatibilityProfile.Keys) {
    $Fallback[$Key] = $Script:AdvancedInstallerCatalog.CompatibilityProfile[$Key]
  }
  $Fallback.CharacterMode = $CharacterMode
  $Fallback.CatalogRoute = $CatalogRoute
  $Fallback.TransformRoute = $Script:AdvancedInstallerCatalog.CatalogRoutes[$CatalogRoute].TransformRoute
  $Fallback.ExternalResourceRoute = $CharacterMode -eq 'Ansi' ? 'external-v1-ansi' : 'external-v1-unicode'
  $Fallback.ConfigurationRoute = $CharacterMode -eq 'Ansi' ? 'ini-ansi-v1' : 'ini-unicode-v1'
  return [pscustomobject]$Fallback
}

function Get-AdvancedInstallerMediaInfo {
  <#
  .SYNOPSIS
    Classify physical payload placement without confusing it with the nested package type.
  .PARAMETER File
    Validated catalog entries.
  .PARAMETER GeneralOptions
    Parsed bootstrapper configuration.
  .PARAMETER PayloadRoute
    Catalog-selected payload route descriptor.
  .PARAMETER PlatformPayloadSelection
    Parsed MSI/MSIX operating-system selection evidence, when present.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object[]]$File,
    [AllowNull()][psobject]$GeneralOptions,
    [Parameter(Mandatory)][System.Collections.IDictionary]$PayloadRoute,
    [AllowNull()][psobject]$PlatformPayloadSelection
  )

  $MainAppUrl = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'MainAppURL')
  $AllPlatforms = [string](Get-AdvancedInstallerSettingValue -Section $GeneralOptions -Name 'AllPlatforms') -match '^(?i:true|yes|1)$'
  $HasDirectMsi = [bool]($File | Where-Object { (Test-AdvancedInstallerPayloadSelector -Entry $_ -Selector ([object[]]$PayloadRoute.DirectMsiSelector)) -and $_.Name -like '*.msi' })
  $HasCompressedMain = [bool]($File | Where-Object { Test-AdvancedInstallerPayloadSelector -Entry $_ -Selector ([object[]]$PayloadRoute.ArchiveMsiSelector) })
  $HasMsix = $null -ne $PlatformPayloadSelection
  $ExternalResources = @($File | Where-Object { $_.PSObject.Properties['IsExternal'] -and $_.IsExternal })
  $MissingExternalResources = @($ExternalResources | Where-Object MissingExternal)
  $OpaqueEntries = @($File | Where-Object { -not $_.CanExtract -and -not ($_.PSObject.Properties['MissingExternal'] -and $_.MissingExternal) })
  $PrerequisitePayloads = @($File | Where-Object { $_.SelectorType -ge 100 } | ForEach-Object {
      [pscustomobject][ordered]@{
        Name          = $_.Name
        SelectorType  = [int]$_.SelectorType
        SelectorGroup = [int]$_.SelectorGroup
        Compression   = switch ([int]$_.SelectorGroup) {
          4 { 'None' }
          9 { 'Lzma' }
          default { 'Unknown' }
        }
        Size          = [long]$_.Size
        IsExternal    = [bool]($_.PSObject.Properties['IsExternal'] -and $_.IsExternal)
        CanExtract    = [bool]$_.CanExtract
      }
    })

  $MediaType = if (-not [string]::IsNullOrWhiteSpace($MainAppUrl)) {
    'WebInstaller'
  } elseif ($ExternalResources.Count -gt 0) {
    'ExternalResources'
  } elseif ($PlatformPayloadSelection -and $PlatformPayloadSelection.LegacyMsiSelection) {
    'MsiMsixPlatformSelection'
  } elseif ($HasCompressedMain) {
    'CompressedSingleExe'
  } elseif ($HasDirectMsi -or $HasMsix) {
    'SingleExe'
  } else {
    'BootstrapperOrExternalResources'
  }

  [pscustomobject][ordered]@{
    MediaType                   = $MediaType
    AllPlatforms                = $AllPlatforms
    HasDirectMsi                = $HasDirectMsi
    HasCompressedMainPackage    = $HasCompressedMain
    HasMsixPayload              = $HasMsix
    HasPlatformPayloadSelection = $null -ne $PlatformPayloadSelection
    PlatformPayloadSelection    = $PlatformPayloadSelection
    HasExternalResources        = $ExternalResources.Count -gt 0
    ExternalResources           = [object[]]$ExternalResources
    MissingExternalResources    = [object[]]$MissingExternalResources
    HasOpaquePayloadTransform   = $OpaqueEntries.Count -gt 0
    OpaquePayloads              = [object[]]$OpaqueEntries
    HasPrerequisitePayloads     = $PrerequisitePayloads.Count -gt 0
    PrerequisitePayloads        = [object[]]$PrerequisitePayloads
  }
}

function Get-AdvancedInstallerAnalysisContext {
  <#
  .SYNOPSIS
    Parse the outer bootstrapper once and retain all immutable format evidence.
  .PARAMETER Path
    Path to an Advanced Installer bootstrapper executable.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $InstallerPath = (Get-Item -LiteralPath $Path -Force).FullName
  $Stream = [IO.File]::OpenRead($InstallerPath)
  try {
    $FooterOffset = Find-AdvancedInstallerFooterOffset -Stream $Stream
    $FooterRouteId = 'footer-v1'
    $FooterRoute = $Script:AdvancedInstallerCatalog.FooterRoutes[$FooterRouteId]
    $FooterHandler = $Script:AdvancedInstallerFooterHandlers[$FooterRouteId]
    if (-not $FooterRoute -or -not $FooterHandler) { throw "Unknown Advanced Installer footer route: $FooterRouteId" }
    $Footer = & $FooterHandler -Stream $Stream -FooterOffset $FooterOffset -Route $FooterRoute

    # A catalog candidate is accepted only when all records consume the exact declared range.
    # This lets old ANSI and current Unicode media share the footer without version branching.
    $CatalogResult = $null
    $CatalogErrors = [Collections.Generic.List[string]]::new()
    foreach ($RouteId in 'catalog-v1-unicode', 'catalog-v0-unicode', 'catalog-v0-ansi') {
      try {
        $CatalogHandler = $Script:AdvancedInstallerCatalogHandlers[$RouteId]
        if (-not $CatalogHandler) { throw "Unknown Advanced Installer catalog route: $RouteId" }
        $CatalogResult = & $CatalogHandler -Stream $Stream -Footer $Footer -RouteId $RouteId
        break
      } catch {
        $CatalogErrors.Add("${RouteId}: $($_.Exception.Message)")
      }
    }
    if (-not $CatalogResult) {
      throw "No Advanced Installer catalog route validated: $($CatalogErrors -join '; ')"
    }

    $ExternalRouteId = $CatalogResult.CharacterMode -eq 'Unicode' ? 'external-v1-unicode' : 'external-v1-ansi'
    $ExternalResult = [pscustomobject]@{ RouteId = $ExternalRouteId; Files = [object[]]@() }
    if ($Footer.ExternalFileCount -gt 0) {
      $ExternalHandler = $Script:AdvancedInstallerExternalResourceHandlers[$ExternalRouteId]
      if (-not $ExternalHandler) { throw "Unknown Advanced Installer external-resource route: $ExternalRouteId" }
      $ExternalResult = & $ExternalHandler -Stream $Stream -Footer $Footer -RouteId $ExternalRouteId -InstallerPath $InstallerPath
    }

    # External declarations participate in the same selector model as embedded entries, but retain
    # their sibling source paths so later reads and extraction never seek them inside setup.exe.
    $Files = [object[]]@($CatalogResult.Files) + [object[]]@($ExternalResult.Files)
    $ConfigurationEntry = $Files | Where-Object {
      $_.SelectorType -eq 0 -and $_.SelectorGroup -eq 3 -and [IO.Path]::GetExtension($_.Name) -ieq '.ini'
    } | Select-Object -First 1
    $Configuration = $null
    $ConfigurationCharacterMode = 'Unknown'
    $ConfigurationRouteId = 'ini-auto-v1'
    if ($ConfigurationEntry) {
      if ($ConfigurationEntry.MissingExternal) {
        # A bootstrapper can be analyzed without the rest of an external media set. Selection and
        # configuration evidence stay partial until the declared INI is supplied beside setup.exe.
      } elseif (-not $ConfigurationEntry.CanExtract) {
        throw 'The Advanced Installer configuration uses an unsupported payload transform'
      } else {
        $ConfigurationBytes = Read-AdvancedInstallerEntryData -Stream $Stream -Entry $ConfigurationEntry -MaximumBytes $Script:ADVANCED_INSTALLER_MAXIMUM_CONFIGURATION_SIZE
        $ConfigurationCharacterMode = Get-AdvancedInstallerConfigurationCharacterMode -Bytes $ConfigurationBytes
        $ConfigurationRouteId = $ConfigurationCharacterMode -eq 'Unicode' ? 'ini-unicode-v1' : 'ini-ansi-v1'
        $ConfigurationHandler = $Script:AdvancedInstallerConfigurationHandlers[$ConfigurationRouteId]
        if (-not $ConfigurationHandler) { throw "Unknown Advanced Installer configuration route: $ConfigurationRouteId" }
        $Configuration = & $ConfigurationHandler -Bytes $ConfigurationBytes
      }
    }

    $GeneralOptionsProperty = $null -eq $Configuration ? $null : $Configuration.PSObject.Properties['GeneralOptions']
    $GeneralOptions = $null -eq $GeneralOptionsProperty ? $null : $GeneralOptionsProperty.Value
    $VersionInfo = Get-AdvancedInstallerExplicitVersionInfo -GeneralOptions $GeneralOptions
    $CharacterMode = $CatalogResult.CharacterMode
    $SelectedFormatProfile = Resolve-AdvancedInstallerFormatProfile -StructureVersion $Footer.StructureVersion -CharacterMode $CharacterMode -CatalogRoute $CatalogResult.RouteId -BuilderVersion $VersionInfo.BuilderVersion
    $PayloadRoute = $Script:AdvancedInstallerCatalog.PayloadRoutes[$SelectedFormatProfile.PayloadRoute]
    if (-not $PayloadRoute) { throw "Unknown Advanced Installer payload route: $($SelectedFormatProfile.PayloadRoute)" }
    $MsiPayloadSelection = Get-AdvancedInstallerMsiPayloadSelection -File $Files -GeneralOptions $GeneralOptions -PayloadRoute $PayloadRoute
    $PlatformPayloadSelection = Get-AdvancedInstallerPlatformPayloadSelection -File $Files -GeneralOptions $GeneralOptions -PayloadRoute $PayloadRoute -MsiPayloadSelection $MsiPayloadSelection
    $MediaInfo = Get-AdvancedInstallerMediaInfo -File $Files -GeneralOptions $GeneralOptions -PayloadRoute $PayloadRoute -PlatformPayloadSelection $PlatformPayloadSelection
    $Warnings = [Collections.Generic.List[string]]::new()
    if ($SelectedFormatProfile.IsFallback) {
      $Warnings.Add("Advanced Installer structure version '$($Footer.StructureVersion)' used the strictly validated compatibility profile.")
    }
    if ($MediaInfo.HasOpaquePayloadTransform) {
      $Warnings.Add('One or more Advanced Installer payloads use an unsupported transform; format metadata is available but full extraction is not.')
    }
    foreach ($MissingExternalResource in $MediaInfo.MissingExternalResources) {
      $Warnings.Add("Advanced Installer external resource '$($MissingExternalResource.Name)' is not present beside the bootstrapper; format evidence is retained but extraction is incomplete.")
    }
    if ($PlatformPayloadSelection -and $PlatformPayloadSelection.LegacyMsiSelection) {
      $Warnings.Add('Advanced Installer selects an MSIX/AppX package on supported Windows versions and an MSI on older systems; analyze both nested packages before updating installed-state metadata.')
    }

    [pscustomobject][ordered]@{
      Path                     = $InstallerPath
      Footer                   = $Footer
      Files                    = $Files
      CatalogRoute             = $CatalogResult.RouteId
      ExternalResourceRoute    = $ExternalResult.RouteId
      ConfigurationRoute       = $ConfigurationRouteId
      ConfigurationEntry       = $ConfigurationEntry
      Configuration            = $Configuration
      GeneralOptions           = $GeneralOptions
      CharacterMode            = $CharacterMode
      Profile                  = $SelectedFormatProfile
      VersionInfo              = $VersionInfo
      MediaInfo                = $MediaInfo
      MsiPayloadSelection      = $MsiPayloadSelection
      PlatformPayloadSelection = $PlatformPayloadSelection
      Warnings                 = [string[]]$Warnings.ToArray()
      Evidence                 = [string[]]@(@(
          "Footer magic ADVINSTSFX at 0x$('{0:X}' -f ($Footer.Offset + 64))"
          "Structure version $($Footer.StructureVersion)"
          "Catalog route $($CatalogResult.RouteId) consumed $($Footer.EmbeddedFileCount) embedded record(s)"
          $(if ($Footer.ExternalFileCount) { "External route $($ExternalResult.RouteId) consumed $($Footer.ExternalFileCount) sibling record(s)" })
          $(if ($ConfigurationEntry) { "Configuration entry $($ConfigurationEntry.Name) uses $CharacterMode text" })
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    }
  } finally {
    $Stream.Dispose()
  }
}

function ConvertTo-AdvancedInstallerFormatInfo {
  <#
  .SYNOPSIS
    Project an analysis context into the public format-information contract.
  .PARAMETER Context
    Parsed Advanced Installer analysis context.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][psobject]$Context)

  # A future structure may reuse the physical footer and catalog, but fallback is actionable only
  # when every payload transform remains understood. Known profiles can still expose metadata for
  # opaque optional entries while refusing those entries during extraction.
  $IsSupported = [bool]$Context.Profile.Supported
  if ($Context.Profile.IsFallback -and $Context.MediaInfo.HasOpaquePayloadTransform) {
    $IsSupported = $false
  }
  $Selection = $Context.MsiPayloadSelection

  [pscustomobject][ordered]@{
    IsAdvancedInstaller           = $true
    IsSupported                   = $IsSupported
    FormatGeneration              = $Context.Profile.FormatGeneration
    FormatProfileId               = $Context.Profile.Id
    StructureVersion              = $Context.Footer.StructureVersion
    BuilderVersion                = $Context.VersionInfo.BuilderVersion
    BuilderVersionSource          = $Context.VersionInfo.BuilderVersionSource
    BuilderVersionRange           = $Context.Profile.BuilderVersionRange
    ProjectSchemaVersion          = $Context.VersionInfo.ProjectSchemaVersion
    MediaType                     = $Context.MediaInfo.MediaType
    CharacterMode                 = $Context.CharacterMode
    ArchitectureSelection         = $null -eq $Selection ? $null : $Selection.ArchitectureSelectionMode
    ArchitectureSelectionEvidence = $null -eq $Selection ? $null : [pscustomobject][ordered]@{
      AllPlatforms = $Selection.AllPlatforms
      BaseMsiPath  = $Selection.BaseMsiPath
      X86MsiPath   = $Selection.X86MsiPath
      X64MsiPath   = $Selection.X64MsiPath
      Arm64MsiPath = $Selection.Arm64MsiPath
      MainAppUrl   = $Selection.MainAppUrl
    }
    PlatformPayloadSelection      = $Context.PlatformPayloadSelection
    FooterRoute                   = $Context.Profile.FooterRoute
    CatalogRoute                  = $Context.CatalogRoute
    ExternalResourceRoute         = $Context.ExternalResourceRoute
    ExternalResourceCount         = [int]$Context.Footer.ExternalFileCount
    ConfigurationRoute            = $Context.ConfigurationRoute
    PayloadRoute                  = $Context.Profile.PayloadRoute
    TransformRoute                = $Context.Profile.TransformRoute
    BootstrapperIdRoute           = $Context.Profile.BootstrapperIdRoute
    BootstrapperId                = $Context.Footer.BootstrapperId
    SupportedMediaModes           = [string[]]@($Context.Profile.SupportedMediaModes)
    Capabilities                  = [string[]]@($Context.Profile.Capabilities)
    ValidationStatus              = $Context.Profile.ValidationStatus
    ValidatedBuilderVersions      = [string[]]@($Context.Profile.ValidatedBuilderVersions)
    ValidationNotes               = $Context.Profile.ValidationNotes
    IsFallback                    = [bool]$Context.Profile.IsFallback
    Evidence                      = [string[]]$Context.Evidence
    Warnings                      = [string[]]$Context.Warnings
  }
}

function Get-AdvancedInstallerFormatInfo {
  <#
  .SYNOPSIS
    Identify the Advanced Installer bootstrapper format generation and selected parser routes.
  .PARAMETER Path
    Path to the candidate installer executable.
  .OUTPUTS
    A structured result. IsAdvancedInstaller is false when no complete footer/catalog route validates.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)

  process {
    try {
      return ConvertTo-AdvancedInstallerFormatInfo -Context (Get-AdvancedInstallerAnalysisContext -Path $Path)
    } catch {
      return [pscustomobject][ordered]@{
        IsAdvancedInstaller           = $false
        IsSupported                   = $false
        FormatGeneration              = $null
        FormatProfileId               = $null
        StructureVersion              = $null
        BuilderVersion                = $null
        BuilderVersionSource          = $null
        BuilderVersionRange           = $null
        ProjectSchemaVersion          = $null
        MediaType                     = $null
        CharacterMode                 = $null
        ArchitectureSelection         = $null
        ArchitectureSelectionEvidence = $null
        PlatformPayloadSelection      = $null
        FooterRoute                   = $null
        CatalogRoute                  = $null
        ExternalResourceRoute         = $null
        ExternalResourceCount         = 0
        ConfigurationRoute            = $null
        PayloadRoute                  = $null
        TransformRoute                = $null
        BootstrapperIdRoute           = $null
        BootstrapperId                = $null
        SupportedMediaModes           = [string[]]@()
        Capabilities                  = [string[]]@()
        IsFallback                    = $false
        Evidence                      = [string[]]@()
        Warnings                      = [string[]]@($_.Exception.Message)
      }
    }
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
    $Context = Get-AdvancedInstallerAnalysisContext -Path $Path
    $FormatInfo = ConvertTo-AdvancedInstallerFormatInfo -Context $Context

    # The outer SFX catalog selects payloads but does not itself prove the
    # nested package's identity or visible ARP registration.
    return [pscustomobject][ordered]@{
      Path                          = $Context.Path
      InstallerType                 = 'AdvancedInstaller'
      ProductCode                   = $null
      UpgradeCode                   = $null
      DisplayName                   = $null
      DisplayVersion                = $null
      Publisher                     = $null
      Scope                         = $null
      DefaultInstallLocation        = $null
      WritesAppsAndFeaturesEntry    = $null
      AppsAndFeaturesProductCode    = $null
      AppsAndFeaturesInstallerType  = $null
      Warnings                      = [string[]]$Context.Warnings
      UnresolvedFields              = [string[]]@()
      FooterOffset                  = [long]$Context.Footer.Offset
      InfoOffset                    = [long]$Context.Footer.CatalogOffset
      CatalogEndOffset              = [long]$Context.Footer.CatalogEndOffset
      FileOffset                    = [long]$Context.Footer.PayloadOffset
      FileCount                     = [int]$Context.Footer.FileCount
      ExternalResourceCount         = [int]$Context.Footer.ExternalFileCount
      Files                         = [object[]]$Context.Files
      ExternalResources             = [object[]]$Context.MediaInfo.ExternalResources
      HasPrerequisitePayloads       = [bool]$Context.MediaInfo.HasPrerequisitePayloads
      PrerequisitePayloads          = [object[]]$Context.MediaInfo.PrerequisitePayloads
      ConfigurationEntry            = $null -eq $Context.ConfigurationEntry ? $null : $Context.ConfigurationEntry.Name
      Configuration                 = $Context.Configuration
      GeneralOptions                = $Context.GeneralOptions
      MsiPayloadSelection           = $Context.MsiPayloadSelection
      PlatformPayloadSelection      = $Context.PlatformPayloadSelection
      IsSupported                   = $FormatInfo.IsSupported
      FormatGeneration              = $FormatInfo.FormatGeneration
      FormatProfileId               = $FormatInfo.FormatProfileId
      StructureVersion              = $FormatInfo.StructureVersion
      BuilderVersion                = $FormatInfo.BuilderVersion
      BuilderVersionSource          = $FormatInfo.BuilderVersionSource
      BuilderVersionRange           = $FormatInfo.BuilderVersionRange
      ProjectSchemaVersion          = $FormatInfo.ProjectSchemaVersion
      MediaType                     = $FormatInfo.MediaType
      CharacterMode                 = $FormatInfo.CharacterMode
      ArchitectureSelection         = $FormatInfo.ArchitectureSelection
      ArchitectureSelectionEvidence = $FormatInfo.ArchitectureSelectionEvidence
      PlatformSelectionMethod       = $null -eq $Context.PlatformPayloadSelection ? $null : $Context.PlatformPayloadSelection.SelectionMethod
      FooterRoute                   = $FormatInfo.FooterRoute
      CatalogRoute                  = $FormatInfo.CatalogRoute
      ExternalResourceRoute         = $FormatInfo.ExternalResourceRoute
      ConfigurationRoute            = $FormatInfo.ConfigurationRoute
      PayloadRoute                  = $FormatInfo.PayloadRoute
      TransformRoute                = $FormatInfo.TransformRoute
      BootstrapperIdRoute           = $FormatInfo.BootstrapperIdRoute
      BootstrapperId                = $FormatInfo.BootstrapperId
      SupportedMediaModes           = [string[]]$FormatInfo.SupportedMediaModes
      Capabilities                  = [string[]]$FormatInfo.Capabilities
      ValidationStatus              = $FormatInfo.ValidationStatus
      ValidatedBuilderVersions      = [string[]]$FormatInfo.ValidatedBuilderVersions
      ValidationNotes               = $FormatInfo.ValidationNotes
      IsFallback                    = $FormatInfo.IsFallback
      FormatEvidence                = [string[]]$FormatInfo.Evidence
      MediaInfo                     = $Context.MediaInfo
      ParserVersionInfo             = [pscustomobject][ordered]@{
        CatalogVersion           = $Script:AdvancedInstallerCatalog.CatalogVersion
        FormatGeneration         = $FormatInfo.FormatGeneration
        FormatProfileId          = $FormatInfo.FormatProfileId
        StructureVersion         = $FormatInfo.StructureVersion
        BuilderVersion           = $FormatInfo.BuilderVersion
        BuilderVersionSource     = $FormatInfo.BuilderVersionSource
        BuilderVersionRange      = $FormatInfo.BuilderVersionRange
        ProjectSchemaVersion     = $FormatInfo.ProjectSchemaVersion
        MediaType                = $FormatInfo.MediaType
        CharacterMode            = $FormatInfo.CharacterMode
        FooterRoute              = $FormatInfo.FooterRoute
        CatalogRoute             = $FormatInfo.CatalogRoute
        ExternalResourceRoute    = $FormatInfo.ExternalResourceRoute
        ConfigurationRoute       = $FormatInfo.ConfigurationRoute
        PayloadRoute             = $FormatInfo.PayloadRoute
        TransformRoute           = $FormatInfo.TransformRoute
        BootstrapperIdRoute      = $FormatInfo.BootstrapperIdRoute
        BootstrapperId           = $FormatInfo.BootstrapperId
        ValidationStatus         = $FormatInfo.ValidationStatus
        ValidatedBuilderVersions = [string[]]$FormatInfo.ValidatedBuilderVersions
        ValidationNotes          = $FormatInfo.ValidationNotes
        PlatformSelectionMethod  = $null -eq $Context.PlatformPayloadSelection ? $null : $Context.PlatformPayloadSelection.SelectionMethod
        IsFallback               = $FormatInfo.IsFallback
      }
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
  .PARAMETER Name
    Optional wildcard selecting catalog payload paths or file names. All payloads are extracted when omitted.
  .PARAMETER CollisionAction
    Behavior when a destination path already exists or catalog names collide.
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath,

    [string]$Name = '*',

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt'
  )

  process {
    Import-AdvancedInstallerMsiModule

    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $Installer.Path -Parent
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Export catalog entries by their declared names. Only archives that actually contain MSI
    # databases are expanded; large application-file archives remain opaque.
    foreach ($Entry in $Installer.Files) {
      if (-not (Test-ExtractionPattern -Path $Entry.Name -Pattern $Name)) { continue }
      $CanExtractProperty = $Entry.PSObject.Properties['CanExtract']
      if ($CanExtractProperty -and -not [bool]$CanExtractProperty.Value) {
        if ($Entry.PSObject.Properties['MissingExternal'] -and $Entry.MissingExternal) {
          throw "The Advanced Installer external resource is missing: $($Entry.Name)"
        }
        throw "The Advanced Installer payload '$($Entry.Name)' uses unsupported transform flag '$($Entry.EncodingFlag)'"
      }
      $DeclaredTargetPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      $ExternalSourceIsTarget = $Entry.PSObject.Properties['IsExternal'] -and $Entry.IsExternal -and $Entry.SourcePath -eq $DeclaredTargetPath
      $Target = if ($ExternalSourceIsTarget) {
        [pscustomobject]@{ Path = $DeclaredTargetPath; ShouldWrite = $true }
      } else {
        Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      }
      if (-not $Target.ShouldWrite) { continue }
      $CompressedMainWithPackageName = $Entry.SelectorType -eq 3 -and $Entry.SelectorGroup -eq 7 -and [IO.Path]::GetExtension($Target.Path) -ine '.7z'
      $EntryWritePath = $CompressedMainWithPackageName ? "$($Target.Path).$([guid]::NewGuid().ToString('N')).7z" : $Target.Path
      $EntryFile = Write-AdvancedInstallerEntry -Path $Installer.Path -Entry $Entry -DestinationPath $EntryWritePath

      # Advanced Installer commonly nests the actual MSI payload inside a dedicated 7z archive.
      # Skip non-MSI archives such as FILES.7z to keep validation and task runs bounded.
      try {
        if (Test-AdvancedInstallerNestedArchiveCandidate -Entry $Entry -Path $EntryFile.FullName) {
          $ArchiveInfo = Get-AdvancedInstallerArchiveInfo -Path $EntryFile.FullName
          if ($ArchiveInfo.IsEncrypted) {
            throw "The Advanced Installer payload '$($Entry.Name)' is AES-256 encrypted and cannot be expanded without its authoring password"
          }
          if ($ArchiveInfo.HasMsi) {
            Expand-AdvancedInstallerArchive -Path $EntryFile.FullName -DestinationPath ([IO.Path]::GetDirectoryName($Target.Path)) `
              -CollisionAction $CollisionAction | Out-Null
          } elseif ($CompressedMainWithPackageName) {
            Move-Item -LiteralPath $EntryFile.FullName -Destination $Target.Path -Force
          }
        }
      } finally {
        if ($CompressedMainWithPackageName -and (Test-Path -LiteralPath $EntryWritePath -PathType Leaf)) {
          Remove-Item -LiteralPath $EntryWritePath -Force -ErrorAction SilentlyContinue
        }
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
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath -CollisionAction Rename | Out-Null
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

      return [pscustomobject][ordered]@{
        Path                          = $MsiFile.FullName
        InstallerType                 = $MsiInfo.InstallerType
        ProductCode                   = $MsiInfo.ProductCode
        UpgradeCode                   = $MsiInfo.UpgradeCode
        DisplayName                   = $MsiInfo.DisplayName
        DisplayVersion                = $MsiInfo.DisplayVersion
        Publisher                     = $MsiInfo.Publisher
        Scope                         = $MsiInfo.Scope
        DefaultInstallLocation        = $MsiInfo.DefaultInstallLocation
        WritesAppsAndFeaturesEntry    = $MsiInfo.WritesAppsAndFeaturesEntry
        AppsAndFeaturesProductCode    = $MsiInfo.AppsAndFeaturesProductCode
        AppsAndFeaturesInstallerType  = $MsiInfo.AppsAndFeaturesInstallerType
        Warnings                      = [string[]]@($MsiInfo.Warnings)
        UnresolvedFields              = [string[]]@($MsiInfo.UnresolvedFields)
        Name                          = $MsiFile.Name
        PackageArchitecture           = $MsiInfo.PackageArchitecture
        Template                      = $MsiInfo.Template
        InstallerBuilder              = $MsiInfo.InstallerBuilder
        InstallerBuilderVersion       = $MsiInfo.InstallerBuilderVersion
        InstallerBuilderVersionSource = $MsiInfo.InstallerBuilderVersionSource
        InstallLocationProperty       = $MsiInfo.InstallLocationProperty
        InstallLocationSwitch         = $MsiInfo.InstallLocationSwitch
        Protocols                     = $MsiInfo.Protocols
        FileExtensions                = $MsiInfo.FileExtensions
        RegistryAssociationInfo       = $MsiInfo.RegistryAssociationInfo
        SelectionMethod               = $SelectionMethod
        ArchitectureSelectionMode     = $ArchitectureSelectionMode
        SelectedMsiPath               = [System.IO.Path]::GetRelativePath($ExpandedPath, $MsiFile.FullName)
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
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).DisplayVersion
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

Export-ModuleMember -Function Get-AdvancedInstallerFormatInfo, Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
