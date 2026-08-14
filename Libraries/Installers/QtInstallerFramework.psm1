# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/qtproject/installer-framework
#
# Binary structures consumed by this parser (trailer fields are int64 LE):
#
#   Qt IFW 1.x
#   PE installerbase -> metadata RCCs -> operations -> component data
#     -> component index -> trailer -> cookie
#
#   Qt IFW 2.0+
#   PE installerbase -> metadata RCCs -> operations -> resource collections
#     -> collection index -> trailer -> cookie
#
#   [PrimaryIndex:offset,length][MetaRange:offset,length]*
#   [Operations:offset,length][ResourceCount][BinaryContentSize]
#   [MagicMarker][Cookie:8]
#
# PrimaryIndex is a ComponentIndex in 1.x and a ResourceCollection index in
# 2.0+. Segment offsets are relative to the binary-content base until adjusted
# by EndOfExecutable. Count, range, RCC-node, archive, and output limits apply.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$QTIFW_MAGIC_COOKIE = [byte[]](0xF8, 0x68, 0xD6, 0x99, 0x1C, 0x0A, 0x63, 0xC2)
$QTIFW_MAGIC_COOKIE_DAT = [byte[]](0xF9, 0x68, 0xD6, 0x99, 0x1C, 0x0A, 0x63, 0xC2)
$QTIFW_MAGIC_MARKER_INSTALLER = 0x12023233L
$QTIFW_MAGIC_MARKER_UNINSTALLER = 0x12023234L
$QTIFW_MAGIC_MARKER_UPDATER = 0x12023235L
$QTIFW_MAGIC_MARKER_PACKAGE_MANAGER = 0x12023236L
$QTIFW_MAX_COOKIE_SEARCH_BYTES = 1048576
$QTIFW_MAX_META_RESOURCE_COUNT = 512
$QTIFW_MAX_RESOURCE_COLLECTION_COUNT = 512
$QTIFW_MAX_RESOURCE_COUNT = 4096
$QTIFW_MAX_COMPONENT_COUNT = 4096
$QTIFW_MAX_OPERATION_COUNT = 16384
$QTIFW_MAX_OPERATION_BYTES = 67108864
$QTIFW_MAX_BYTE_ARRAY_LENGTH = 134217728
$QTIFW_MAX_XML_SCAN_BYTES = 67108864
$QTIFW_MAX_TEXT_EVIDENCE_BYTES = 1048576
$QTIFW_MAX_EXECUTABLE_SCAN_BYTES = 134217728
$QTIFW_RCC_NODE_SIZE = 14
$QTIFW_RCC_FLAG_COMPRESSED = 0x01
$QTIFW_RCC_FLAG_DIRECTORY = 0x02
$QTIFW_MAX_EXPANDED_BYTES = 17179869184
$QTIFW_MAX_EXPANDED_FILES = 200000
$QTIFW_PACKAGE_ARCHIVE_PATTERN = '(?i)\.(7z|qbsp|zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz)$'

$Script:QtInstallerFrameworkCatalog = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'QtInstallerFrameworkFormatCatalog.psd1')
$Script:QtInstallerFrameworkRouteHandlers = @{
  Trailer      = @{
    'legacy-component-index-v1' = 'Get-QtInstallerFrameworkBinaryLayout'
    'resource-collections-v1'   = 'Get-QtInstallerFrameworkBinaryLayout'
  }
  Metadata     = @{
    'rcc-meta-resources-v1'           = 'Get-QtInstallerFrameworkMetadataResource'
    'rcc-and-resource-collections-v1' = 'Get-QtInstallerFrameworkMetadataResource'
  }
  PackageIndex = @{
    'component-index-v1'     = 'Get-QtInstallerFrameworkLegacyComponentCollection'
    'resource-collection-v1' = 'Get-QtInstallerFrameworkResourceCollection'
  }
  Payload      = @{
    'legacy-7z-v1'  = 'Expand-QtInstallerFrameworkPackageArchive'
    'libarchive-v1' = 'Expand-QtInstallerFrameworkPackageArchive'
  }
  Config       = @{
    'legacy-config-v1'     = 'ConvertFrom-QtInstallerFrameworkInstallerXml'
    'modern-config-v1'     = 'ConvertFrom-QtInstallerFrameworkInstallerXml'
    'modern-config-cli-v1' = 'ConvertFrom-QtInstallerFrameworkInstallerXml'
  }
  Interface    = @{
    'gui-launcher-v1'         = 'Get-QtInstallerFrameworkInterfaceInfo'
    'cli-capable-launcher-v1' = 'Get-QtInstallerFrameworkInterfaceInfo'
  }
}

function Get-QtInstallerFrameworkRouteHandler {
  <#
  .SYNOPSIS
    Resolve a catalog route to its implementation function.
  .PARAMETER Category
    Route category such as Trailer, Metadata, PackageIndex, Payload, Config, or Interface.
  .PARAMETER Route
    Catalog route identifier within the selected category.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)]
    [ValidateSet('Trailer', 'Metadata', 'PackageIndex', 'Payload', 'Config', 'Interface')]
    [string]$Category,

    [Parameter(Mandatory)]
    [string]$Route
  )

  $CategoryHandlers = $Script:QtInstallerFrameworkRouteHandlers[$Category]
  $Handler = if ($CategoryHandlers) { $CategoryHandlers[$Route] } else { $null }
  if ([string]::IsNullOrWhiteSpace([string]$Handler)) {
    throw "Qt Installer Framework route '$Category/$Route' has no implementation handler"
  }
  return [string]$Handler
}

function Import-QtInstallerFrameworkSharpCompress {
  <#
  .SYNOPSIS
    Load SharpCompress for expanding Qt Installer Framework package archives
  #>
  Import-InstallerArchiveDependency
}

function Read-QtInstallerFrameworkBytes {
  <#
  .SYNOPSIS
    Read a bounded byte range from a Qt Installer Framework binary
  .PARAMETER Stream
    The file stream to read from
  .PARAMETER Offset
    The byte offset to read from
  .PARAMETER Count
    The number of bytes to read
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The byte offset to read from')]
    [int64]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to read')]
    [int64]$Count
  )

  if ($Count -gt $QTIFW_MAX_BYTE_ARRAY_LENGTH) {
    throw "Qt Installer Framework read range is too large: $Count bytes"
  }
  return , (Read-BinaryBytes -Stream $Stream -Offset $Offset -Count ([int]$Count))
}

function Read-QtInstallerFrameworkInt64 {
  <#
  .SYNOPSIS
    Read a little-endian qint64 value used by Qt Installer Framework trailer records
  .PARAMETER Stream
    The file stream to read from
  .PARAMETER Offset
    The byte offset to read from
  #>
  [OutputType([int64])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The byte offset to read from')]
    [int64]$Offset
  )

  $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Offset -Count 8
  return [System.BitConverter]::ToInt64($Bytes, 0)
}

function Read-QtInstallerFrameworkUInt16BE {
  <#
  .SYNOPSIS
    Read a big-endian UInt16 value from a Qt RCC resource
  .PARAMETER Bytes
    The RCC byte buffer
  .PARAMETER Offset
    The byte offset to read from
  #>
  [OutputType([uint16])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The RCC byte buffer')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte offset to read from')]
    [int]$Offset
  )

  if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) { throw 'The Qt RCC UInt16 read is outside the buffer' }
  return [uint16]((([uint16]$Bytes[$Offset]) -shl 8) -bor ([uint16]$Bytes[$Offset + 1]))
}

function Read-QtInstallerFrameworkUInt32BE {
  <#
  .SYNOPSIS
    Read a big-endian UInt32 value from a Qt RCC resource
  .PARAMETER Bytes
    The RCC byte buffer
  .PARAMETER Offset
    The byte offset to read from
  #>
  [OutputType([uint32])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The RCC byte buffer')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte offset to read from')]
    [int]$Offset
  )

  if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) { throw 'The Qt RCC UInt32 read is outside the buffer' }
  return [uint32]((([uint32]$Bytes[$Offset]) -shl 24) -bor (([uint32]$Bytes[$Offset + 1]) -shl 16) -bor (([uint32]$Bytes[$Offset + 2]) -shl 8) -bor ([uint32]$Bytes[$Offset + 3]))
}

function Find-QtInstallerFrameworkBytePattern {
  <#
  .SYNOPSIS
    Find a byte pattern in a bounded byte buffer
  .PARAMETER Bytes
    The byte buffer to scan
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The byte buffer to scan')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern
  )

  return [int[]]@(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Maximum 4096)
}

function Find-QtInstallerFrameworkMagicCookie {
  <#
  .SYNOPSIS
    Locate the Qt Installer Framework magic cookie near the end of a file
  .PARAMETER Stream
    The file stream to scan
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to scan')]
    [System.IO.Stream]$Stream
  )

  $SearchLength = [Math]::Min([int64]$QTIFW_MAX_COOKIE_SEARCH_BYTES, $Stream.Length)
  $SearchStart = $Stream.Length - $SearchLength
  $InstallerCookieOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern $QTIFW_MAGIC_COOKIE -StartOffset $SearchStart -Length $SearchLength -Maximum 512 -Reverse)
  $DatCookieOffsets = @(Find-BinaryPattern -Stream $Stream -Pattern $QTIFW_MAGIC_COOKIE_DAT -StartOffset $SearchStart -Length $SearchLength -Maximum 512 -Reverse)
  $Candidates = @(
    foreach ($Offset in $InstallerCookieOffsets) {
      [pscustomobject]@{ Offset = $Offset; Kind = 'Executable' }
    }
    foreach ($Offset in $DatCookieOffsets) {
      [pscustomobject]@{ Offset = $Offset; Kind = 'Data' }
    }
  ) | Sort-Object -Property Offset -Descending

  if (-not $Candidates) { throw 'No Qt Installer Framework magic cookie was found near the end of the file' }
  return $Candidates[0]
}

function ConvertTo-QtInstallerFrameworkRange {
  <#
  .SYNOPSIS
    Convert a Qt Installer Framework start and length pair to an object
  .PARAMETER Start
    The range start offset
  .PARAMETER Length
    The range length
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The range start offset')]
    [int64]$Start,

    [Parameter(Mandatory, HelpMessage = 'The range length')]
    [int64]$Length
  )

  [pscustomobject]@{
    Start  = $Start
    Length = $Length
    End    = $Start + $Length
  }
}

function Read-QtInstallerFrameworkRange {
  <#
  .SYNOPSIS
    Read a Qt Installer Framework qint64 start and length pair
  .PARAMETER Stream
    The file stream to read from
  .PARAMETER Offset
    The byte offset to read from
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The byte offset to read from')]
    [int64]$Offset
  )

  ConvertTo-QtInstallerFrameworkRange -Start (Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Offset) -Length (Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset ($Offset + 8))
}

function Move-QtInstallerFrameworkRange {
  <#
  .SYNOPSIS
    Move a Qt Installer Framework range by a fixed offset
  .PARAMETER Range
    The range object to move
  .PARAMETER Offset
    The offset to add to the range start
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The range object to move')]
    [pscustomobject]$Range,

    [Parameter(Mandatory, HelpMessage = 'The offset to add to the range start')]
    [int64]$Offset
  )

  ConvertTo-QtInstallerFrameworkRange -Start ($Range.Start + $Offset) -Length $Range.Length
}

function Assert-QtInstallerFrameworkRange {
  <#
  .SYNOPSIS
    Validate that a Qt Installer Framework range stays inside the current file
  .PARAMETER Range
    The range object to validate
  .PARAMETER FileLength
    The total file length
  .PARAMETER Name
    A label used in error messages
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The range object to validate')]
    [pscustomobject]$Range,

    [Parameter(Mandatory, HelpMessage = 'The total file length')]
    [int64]$FileLength,

    [Parameter(Mandatory, HelpMessage = 'A label used in error messages')]
    [string]$Name
  )

  if ($Range.Start -lt 0 -or $Range.Length -lt 0 -or $Range.End -gt $FileLength) {
    throw "Invalid Qt Installer Framework $Name range: start=$($Range.Start) length=$($Range.Length)"
  }
}

function Get-QtInstallerFrameworkMarkerName {
  <#
  .SYNOPSIS
    Convert a Qt Installer Framework magic marker to a readable name
  .PARAMETER Marker
    The magic marker value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The magic marker value')]
    [int64]$Marker
  )

  switch ($Marker) {
    $QTIFW_MAGIC_MARKER_INSTALLER { 'Installer' }
    $QTIFW_MAGIC_MARKER_UNINSTALLER { 'Uninstaller' }
    $QTIFW_MAGIC_MARKER_UPDATER { 'Updater' }
    $QTIFW_MAGIC_MARKER_PACKAGE_MANAGER { 'PackageManager' }
    default { 'Unknown' }
  }
}

function Get-QtInstallerFrameworkBinaryLayout {
  <#
  .SYNOPSIS
    Read the source-compatible Qt Installer Framework binary-content trailer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $File = Get-Item -Path $Path -Force
    $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      # IFW writes the segment table immediately before the terminal cookie. Work backward from
      # that cookie instead of searching payload data for individual metadata signatures.
      $Cookie = Find-QtInstallerFrameworkMagicCookie -Stream $Stream
      $EndOfBinaryContent = $Cookie.Offset + 8
      $MetaDataCountOffset = $EndOfBinaryContent - 32
      if ($MetaDataCountOffset -lt 0) { throw 'Qt Installer Framework trailer is truncated' }

      $MetaResourceCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $MetaDataCountOffset
      if ($MetaResourceCount -lt 0 -or $MetaResourceCount -gt $QTIFW_MAX_META_RESOURCE_COUNT) {
        throw "Invalid Qt Installer Framework meta resource count: $MetaResourceCount"
      }

      $ResourceCollectionsSegmentOffset = $EndOfBinaryContent - (($MetaResourceCount * 16) + 64)
      if ($ResourceCollectionsSegmentOffset -lt 0) { throw 'Qt Installer Framework segment table is truncated' }

      # Trailer ranges are relative to the binary-content area, not absolute file offsets.
      $ResourceCollectionsSegment = Read-QtInstallerFrameworkRange -Stream $Stream -Offset $ResourceCollectionsSegmentOffset
      $Cursor = $ResourceCollectionsSegmentOffset + 16
      $MetaResourceSegments = [System.Collections.Generic.List[object]]::new()
      for ($Index = 0; $Index -lt $MetaResourceCount; $Index++) {
        $MetaResourceSegments.Add((Read-QtInstallerFrameworkRange -Stream $Stream -Offset $Cursor))
        $Cursor += 16
      }

      $OperationsSegment = Read-QtInstallerFrameworkRange -Stream $Stream -Offset $Cursor
      $ResourceCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset ($Cursor + 16)
      $BinaryContentSize = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset ($Cursor + 24)
      $MagicMarker = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset ($Cursor + 32)
      $MagicCookieBytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset ($Cursor + 40) -Count 8
      $MagicCookieHex = '0x' + (($MagicCookieBytes[7..0] | ForEach-Object { $_.ToString('x2') }) -join '')
      $EndOfExecutable = $EndOfBinaryContent - $BinaryContentSize
      if ($EndOfExecutable -lt 0 -or $EndOfExecutable -gt $File.Length) {
        throw "Invalid Qt Installer Framework executable/content split offset: $EndOfExecutable"
      }

      # Rebase every relative segment only after the executable/content split has passed its
      # range checks. This prevents a corrupt size from redirecting reads into the PE stub.
      $AdjustedMetaSegments = @(
        foreach ($Segment in $MetaResourceSegments) {
          $Moved = Move-QtInstallerFrameworkRange -Range $Segment -Offset $EndOfExecutable
          Assert-QtInstallerFrameworkRange -Range $Moved -FileLength $File.Length -Name 'meta resource'
          $Moved
        }
      )
      $AdjustedResourceCollectionSegment = Move-QtInstallerFrameworkRange -Range $ResourceCollectionsSegment -Offset $EndOfExecutable
      $AdjustedOperationsSegment = Move-QtInstallerFrameworkRange -Range $OperationsSegment -Offset $EndOfExecutable
      Assert-QtInstallerFrameworkRange -Range $AdjustedResourceCollectionSegment -FileLength $File.Length -Name 'resource collection'
      Assert-QtInstallerFrameworkRange -Range $AdjustedOperationsSegment -FileLength $File.Length -Name 'operation'

      [pscustomobject]@{
        Path                       = $File.FullName
        InstallerType              = 'Qt Installer Framework'
        CookieKind                 = $Cookie.Kind
        EndOfExecutable            = $EndOfExecutable
        EndOfBinaryContent         = $EndOfBinaryContent
        BinaryContentSize          = $BinaryContentSize
        MagicMarker                = $MagicMarker
        MagicMarkerName            = Get-QtInstallerFrameworkMarkerName -Marker $MagicMarker
        MagicCookie                = $MagicCookieHex
        MetaResourceCount          = $MetaResourceCount
        ResourceCount              = $ResourceCount
        MetaResourceSegments       = @($AdjustedMetaSegments)
        PrimaryIndexSegment        = $AdjustedResourceCollectionSegment
        ResourceCollectionsSegment = $AdjustedResourceCollectionSegment
        ComponentIndexSegment      = $AdjustedResourceCollectionSegment
        OperationsSegment          = $AdjustedOperationsSegment
      }
    } finally {
      $Stream.Dispose()
    }
  }
}

function Read-QtInstallerFrameworkByteArray {
  <#
  .SYNOPSIS
    Read a Qt Installer Framework length-prefixed byte array from a file stream
  .PARAMETER Stream
    The file stream to read from
  .PARAMETER Cursor
    The current read cursor, updated after the read
  .PARAMETER MaximumOffset
    Exclusive end offset of the enclosing trailer, index, or record segment. The
    reader validates the complete length-prefixed value before allocating it.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The current read cursor, updated after the read')]
    [ref]$Cursor,

    [Parameter(Mandatory, HelpMessage = 'The exclusive end offset of the enclosing segment')]
    [long]$MaximumOffset
  )

  if ($Cursor.Value -lt 0 -or $Cursor.Value + 8 -gt $MaximumOffset) {
    throw 'The Qt Installer Framework byte-array length is outside its enclosing segment'
  }
  $Length = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
  if ($Length -lt 0 -or $Length -gt $QTIFW_MAX_BYTE_ARRAY_LENGTH) {
    throw "Invalid Qt Installer Framework byte-array length: $Length"
  }
  if ($Length -gt $MaximumOffset - $Cursor.Value - 8) {
    throw 'The Qt Installer Framework byte array extends beyond its enclosing segment'
  }
  $Cursor.Value += 8
  $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Cursor.Value -Count $Length
  $Cursor.Value += $Length
  return , $Bytes
}

function Get-QtInstallerFrameworkResourceCollection {
  <#
  .SYNOPSIS
    Read IFW resource collection records from the binary-content resource index
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER Layout
    The parsed IFW binary-content layout
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed IFW binary-content layout')]
    [pscustomobject]$Layout
  )

  $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    # The collection index and each collection's resource index use the same qint64
    # length/range framing, but their ranges are independently relative to BinaryContent.
    $Cursor = [ref][int64]$Layout.ResourceCollectionsSegment.Start
    if ($Layout.ResourceCollectionsSegment.Length -lt 8) { return @() }
    $CollectionCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    $Cursor.Value += 8
    if ($CollectionCount -lt 0 -or $CollectionCount -gt $QTIFW_MAX_RESOURCE_COLLECTION_COUNT) {
      throw "Invalid Qt Installer Framework resource collection count: $CollectionCount"
    }

    $Collections = [System.Collections.Generic.List[object]]::new()
    for ($CollectionIndex = 0; $CollectionIndex -lt $CollectionCount; $CollectionIndex++) {
      $NameBytes = Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $Cursor -MaximumOffset $Layout.ResourceCollectionsSegment.End
      $Name = [System.Text.Encoding]::UTF8.GetString($NameBytes)
      $CollectionDataSegment = Read-QtInstallerFrameworkRange -Stream $Stream -Offset $Cursor.Value
      $Cursor.Value += 16
      $CollectionDataSegment = Move-QtInstallerFrameworkRange -Range $CollectionDataSegment -Offset $Layout.EndOfExecutable
      Assert-QtInstallerFrameworkRange -Range $CollectionDataSegment -FileLength $Stream.Length -Name 'resource collection data'

      # Enter the collection-specific catalog only after validating its rebased file range.
      $DataCursor = [ref][int64]$CollectionDataSegment.Start
      $ResourceCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $DataCursor.Value
      $DataCursor.Value += 8
      if ($ResourceCount -lt 0 -or $ResourceCount -gt $QTIFW_MAX_RESOURCE_COUNT) {
        throw "Invalid Qt Installer Framework resource count: $ResourceCount"
      }

      $Resources = [System.Collections.Generic.List[object]]::new()
      for ($ResourceIndex = 0; $ResourceIndex -lt $ResourceCount; $ResourceIndex++) {
        $ResourceNameBytes = Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $DataCursor -MaximumOffset $CollectionDataSegment.End
        $ResourceSegment = Read-QtInstallerFrameworkRange -Stream $Stream -Offset $DataCursor.Value
        $DataCursor.Value += 16
        $ResourceSegment = Move-QtInstallerFrameworkRange -Range $ResourceSegment -Offset $Layout.EndOfExecutable
        Assert-QtInstallerFrameworkRange -Range $ResourceSegment -FileLength $Stream.Length -Name 'resource data'
        $Resources.Add([pscustomobject]@{
            Name    = [System.Text.Encoding]::UTF8.GetString($ResourceNameBytes)
            Segment = $ResourceSegment
          })
      }

      $Collections.Add([pscustomobject]@{
          Name      = $Name
          Segment   = $CollectionDataSegment
          Resources = $Resources.ToArray()
        })
    }

    if ($Cursor.Value + 8 -ne $Layout.ResourceCollectionsSegment.End) {
      throw "The Qt Installer Framework resource-collection index was not consumed exactly: cursor=$($Cursor.Value) end=$($Layout.ResourceCollectionsSegment.End)"
    }
    $TrailingCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    if ($TrailingCount -ne $CollectionCount) { throw 'The Qt Installer Framework resource-collection count footer does not match its header' }

    return $Collections.ToArray()
  } finally {
    $Stream.Dispose()
  }
}

function Get-QtInstallerFrameworkLegacyComponentCollection {
  <#
  .SYNOPSIS
    Read the component and archive index emitted by Qt IFW 1.x.
  .PARAMETER Path
    Path to the Qt IFW binary.
  .PARAMETER Layout
    Validated common trailer layout whose primary segment is a ComponentIndex.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $IndexSegment = $Layout.ComponentIndexSegment
    if ($IndexSegment.Length -lt 16) { throw 'The Qt IFW 1.x component index is truncated' }
    $Cursor = [ref][int64]$IndexSegment.Start
    $ComponentCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    $Cursor.Value += 8
    if ($ComponentCount -lt 0 -or $ComponentCount -gt $QTIFW_MAX_COMPONENT_COUNT) {
      throw "Invalid Qt Installer Framework component count: $ComponentCount"
    }

    $Components = [System.Collections.Generic.List[object]]::new()
    for ($ComponentIndex = 0; $ComponentIndex -lt $ComponentCount; $ComponentIndex++) {
      $Name = [Text.Encoding]::UTF8.GetString((Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $Cursor -MaximumOffset $IndexSegment.End))
      if ($Cursor.Value + 16 -gt $IndexSegment.End) { throw 'The Qt IFW 1.x component index entry is truncated' }
      $ComponentSegment = Move-QtInstallerFrameworkRange -Range (Read-QtInstallerFrameworkRange -Stream $Stream -Offset $Cursor.Value) -Offset $Layout.EndOfExecutable
      $Cursor.Value += 16
      Assert-QtInstallerFrameworkRange -Range $ComponentSegment -FileLength $Stream.Length -Name 'legacy component data'

      $DataCursor = [ref][int64]$ComponentSegment.Start
      $ArchiveCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $DataCursor.Value
      $DataCursor.Value += 8
      if ($ArchiveCount -lt 0 -or $ArchiveCount -gt $QTIFW_MAX_RESOURCE_COUNT) {
        throw "Invalid Qt Installer Framework archive count: $ArchiveCount"
      }

      $Archives = [System.Collections.Generic.List[object]]::new()
      for ($ArchiveIndex = 0; $ArchiveIndex -lt $ArchiveCount; $ArchiveIndex++) {
        $ArchiveName = [Text.Encoding]::UTF8.GetString((Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $DataCursor -MaximumOffset $ComponentSegment.End))
        if ($DataCursor.Value + 16 -gt $ComponentSegment.End) { throw 'The Qt IFW 1.x archive descriptor is truncated' }
        $ArchiveSegment = Move-QtInstallerFrameworkRange -Range (Read-QtInstallerFrameworkRange -Stream $Stream -Offset $DataCursor.Value) -Offset $Layout.EndOfExecutable
        $DataCursor.Value += 16
        Assert-QtInstallerFrameworkRange -Range $ArchiveSegment -FileLength $Stream.Length -Name 'legacy component archive'
        if ($ArchiveSegment.Start -lt $ComponentSegment.Start -or $ArchiveSegment.End -gt $ComponentSegment.End) {
          throw "The Qt IFW 1.x archive '$ArchiveName' is outside its component data range"
        }
        $Archives.Add([pscustomobject]@{ Name = $ArchiveName; Segment = $ArchiveSegment })
      }

      $Components.Add([pscustomobject]@{
          Name      = $Name
          Kind      = 'LegacyComponent'
          Segment   = $ComponentSegment
          Resources = $Archives.ToArray()
        })
    }

    if ($Cursor.Value + 8 -ne $IndexSegment.End) { throw 'The Qt IFW 1.x component index was not consumed exactly' }
    $TrailingCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    if ($TrailingCount -ne $ComponentCount) { throw 'The Qt IFW 1.x component index count footer does not match its header' }
    return $Components.ToArray()
  } finally {
    $Stream.Dispose()
  }
}

function Get-QtInstallerFrameworkOperation {
  <#
  .SYNOPSIS
    Read the performed-operation records stored in a Qt IFW maintenance content block.
  .PARAMETER Path
    Path to the Qt IFW executable or DAT binary.
  .PARAMETER Layout
    Validated binary-content layout containing the absolute operations segment.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $Segment = $Layout.OperationsSegment
  if ($Segment.Length -eq 0) { return @() }
  if ($Segment.Length -lt 16 -or $Segment.Length -gt $QTIFW_MAX_OPERATION_BYTES) {
    throw "Invalid Qt Installer Framework operations segment length: $($Segment.Length)"
  }

  $Stream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Cursor = [ref][int64]$Segment.Start
    $Count = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    $Cursor.Value += 8
    if ($Count -lt 0 -or $Count -gt $QTIFW_MAX_OPERATION_COUNT) {
      throw "Invalid Qt Installer Framework performed-operation count: $Count"
    }

    $Operations = [Collections.Generic.List[object]]::new()
    for ($Index = 0; $Index -lt $Count; $Index++) {
      $Name = [Text.Encoding]::UTF8.GetString((Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $Cursor -MaximumOffset $Segment.End))
      $Data = [Text.Encoding]::UTF8.GetString((Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $Cursor -MaximumOffset $Segment.End))
      $Operations.Add([pscustomobject]@{ Index = $Index; Name = $Name; Data = $Data })
    }
    if ($Cursor.Value + 8 -ne $Segment.End) {
      throw "The Qt Installer Framework operations segment was not consumed exactly: cursor=$($Cursor.Value) end=$($Segment.End)"
    }
    $TrailingCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    if ($TrailingCount -ne $Count) { throw 'The Qt Installer Framework performed-operation count footer does not match its header' }
    return $Operations.ToArray()
  } finally {
    $Stream.Dispose()
  }
}

function Expand-QtInstallerFrameworkCompressedRccData {
  <#
  .SYNOPSIS
    Expand qCompress payloads used by compressed Qt RCC resources
  .PARAMETER Data
    The qCompress byte payload
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The qCompress byte payload')]
    [byte[]]$Data
  )

  if ($Data.Length -lt 4) { throw 'The compressed Qt RCC payload is truncated' }
  # qCompress prefixes its Zlib stream with the expected size in network byte order.
  $ExpectedLength = Read-QtInstallerFrameworkUInt32BE -Bytes $Data -Offset 0
  if ($ExpectedLength -gt $QTIFW_MAX_BYTE_ARRAY_LENGTH) {
    throw "The compressed Qt RCC payload expands too large: $ExpectedLength bytes"
  }

  $InputStream = [System.IO.MemoryStream]::new($Data, 4, $Data.Length - 4)
  $OutputStream = [System.IO.MemoryStream]::new()
  try {
    $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $OutputStream -MaximumBytes $QTIFW_MAX_BYTE_ARRAY_LENGTH -UncompressedSize $ExpectedLength
    $Expanded = $OutputStream.ToArray()
    if ($ExpectedLength -ne 0 -and $Expanded.Length -ne $ExpectedLength) {
      throw "The compressed Qt RCC payload expanded to $($Expanded.Length) bytes, expected $ExpectedLength"
    }
    return , $Expanded
  } finally {
    $OutputStream.Dispose()
    $InputStream.Dispose()
  }
}

function Read-QtInstallerFrameworkRccName {
  <#
  .SYNOPSIS
    Read a Qt RCC UTF-16BE resource name by offset
  .PARAMETER Bytes
    The RCC byte buffer
  .PARAMETER NamesOffset
    The RCC names section offset
  .PARAMETER NameOffset
    The resource name offset inside the names section
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The RCC byte buffer')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The RCC names section offset')]
    [int]$NamesOffset,

    [Parameter(Mandatory, HelpMessage = 'The resource name offset inside the names section')]
    [uint32]$NameOffset
  )

  $Offset = $NamesOffset + [int]$NameOffset
  $Length = Read-QtInstallerFrameworkUInt16BE -Bytes $Bytes -Offset $Offset
  $StringOffset = $Offset + 6
  $ByteLength = [int]$Length * 2
  if ($StringOffset + $ByteLength -gt $Bytes.Length) { throw 'The Qt RCC name is truncated' }
  return [System.Text.Encoding]::BigEndianUnicode.GetString($Bytes, $StringOffset, $ByteLength)
}

function Get-QtInstallerFrameworkRccResource {
  <#
  .SYNOPSIS
    Extract file resources from a Qt RCC binary buffer
  .PARAMETER Bytes
    The RCC byte buffer
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The RCC byte buffer')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 20) { throw 'The Qt RCC resource is too short' }
  if ([System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -ne 'qres') {
    throw 'The Qt RCC resource does not start with qres'
  }

  # RCC stores three absolute offsets from the start of the qres buffer. Validate the complete
  # section map before following any tree node or data pointer.
  $Version = Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset 4
  $TreeOffset = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset 8)
  $DataOffset = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset 12)
  $NamesOffset = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset 16)
  if ($Version -ne 1) { throw "Unsupported Qt RCC version: $Version" }
  if ($TreeOffset -lt 0 -or $DataOffset -lt 0 -or $NamesOffset -lt 0 -or $TreeOffset -ge $Bytes.Length -or $DataOffset -ge $Bytes.Length -or $NamesOffset -ge $Bytes.Length) {
    throw 'The Qt RCC section offsets are invalid'
  }

  # Traverse the indexed tree iteratively so maliciously deep directory nesting cannot exhaust
  # the PowerShell call stack.
  $Resources = [System.Collections.Generic.List[object]]::new()
  $Queue = [System.Collections.Queue]::new()
  $Queue.Enqueue([pscustomobject]@{ Index = 0; Path = ':' })

  while ($Queue.Count -gt 0) {
    $Current = $Queue.Dequeue()
    $NodeOffset = $TreeOffset + ([int]$Current.Index * $QTIFW_RCC_NODE_SIZE)
    if ($NodeOffset + $QTIFW_RCC_NODE_SIZE -gt $Bytes.Length) { throw 'The Qt RCC node table is truncated' }

    $NameOffset = Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset $NodeOffset
    $Flags = Read-QtInstallerFrameworkUInt16BE -Bytes $Bytes -Offset ($NodeOffset + 4)
    $IsRootNode = [int]$Current.Index -eq 0 -and [string]$Current.Path -eq ':'
    $Name = if ($IsRootNode) { '' } else { Read-QtInstallerFrameworkRccName -Bytes $Bytes -NamesOffset $NamesOffset -NameOffset $NameOffset }
    $Path = if ($IsRootNode) { ':' } elseif ($Current.Path -eq ':') { ":/$Name" } else { "$($Current.Path)/$Name" }

    if (($Flags -band $QTIFW_RCC_FLAG_DIRECTORY) -ne 0) {
      # Directory records point to a contiguous run of child nodes in the tree table.
      $ChildCount = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset ($NodeOffset + 6))
      $ChildOffset = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset ($NodeOffset + 10))
      if ($ChildCount -lt 0 -or $ChildCount -gt $QTIFW_MAX_RESOURCE_COUNT) {
        throw "Invalid Qt RCC child count: $ChildCount"
      }
      for ($ChildIndex = 0; $ChildIndex -lt $ChildCount; $ChildIndex++) {
        $Queue.Enqueue([pscustomobject]@{ Index = $ChildOffset + $ChildIndex; Path = $Path })
      }
    } else {
      # File records point into the data section, where a BE length precedes the payload.
      $DataBlobOffset = $DataOffset + [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset ($NodeOffset + 10))
      $DataLength = [int](Read-QtInstallerFrameworkUInt32BE -Bytes $Bytes -Offset $DataBlobOffset)
      $PayloadOffset = $DataBlobOffset + 4
      if ($DataLength -lt 0 -or $PayloadOffset + $DataLength -gt $Bytes.Length) { throw 'The Qt RCC payload is truncated' }
      $Payload = [byte[]]::new($DataLength)
      [System.Array]::Copy($Bytes, $PayloadOffset, $Payload, 0, $DataLength)
      if (($Flags -band $QTIFW_RCC_FLAG_COMPRESSED) -ne 0) {
        $Payload = Expand-QtInstallerFrameworkCompressedRccData -Data $Payload
      }
      $Resources.Add([pscustomobject]@{
          Name       = $Name
          Path       = $Path
          Compressed = (($Flags -band $QTIFW_RCC_FLAG_COMPRESSED) -ne 0)
          Data       = $Payload
        })
    }
  }

  return $Resources.ToArray()
}

function ConvertFrom-QtInstallerFrameworkXmlBytes {
  <#
  .SYNOPSIS
    Extract XML documents from Qt Installer Framework metadata bytes
  .PARAMETER Bytes
    The metadata bytes to inspect
  .PARAMETER Source
    The source label for the bytes
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The metadata bytes to inspect')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The source label for the bytes')]
    [string]$Source
  )

  if ($Bytes.Length -gt $QTIFW_MAX_XML_SCAN_BYTES) { return @() }
  $Resources = [System.Collections.Generic.List[object]]::new()

  try {
    # Metadata may itself be an RCC container. Recursively inspect those named resources before
    # using the conservative raw-text fallback for older IFW variants.
    foreach ($RccResource in Get-QtInstallerFrameworkRccResource -Bytes $Bytes) {
      foreach ($Item in ConvertFrom-QtInstallerFrameworkXmlBytes -Bytes $RccResource.Data -Source $RccResource.Path) {
        $Resources.Add($Item)
      }
    }
  } catch {
    # Some metadata resources are not RCC containers. Fall through to bounded XML text scanning.
  }

  # Only complete, known IFW XML roots are accepted; arbitrary XML-looking strings do not become
  # installer metadata.
  $Text = [System.Text.Encoding]::UTF8.GetString($Bytes)
  foreach ($Pattern in @('<Installer\b[\s\S]*?</Installer>', '<Updates\b[\s\S]*?</Updates>', '<PackageUpdate\b[\s\S]*?</PackageUpdate>')) {
    foreach ($Match in [regex]::Matches($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
      try {
        $Xml = [xml]$Match.Value
        $Resources.Add([pscustomobject]@{
            Source = $Source
            Root   = $Xml.DocumentElement.LocalName
            Xml    = $Xml
          })
      } catch {
        # Ignore XML-looking byte sequences that are not complete XML documents.
      }
    }
  }

  return $Resources.ToArray()
}

function ConvertFrom-QtInstallerFrameworkTextData {
  <#
  .SYNOPSIS
    Extract bounded text evidence from Qt Installer Framework metadata bytes
  .PARAMETER Bytes
    The metadata bytes to inspect
  .PARAMETER Source
    The source label for the bytes
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The metadata bytes to inspect')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The source label for the bytes')]
    [string]$Source
  )

  if ($Bytes.Length -gt $QTIFW_MAX_TEXT_EVIDENCE_BYTES) { return @() }
  $Resources = [System.Collections.Generic.List[object]]::new()

  try {
    foreach ($RccResource in Get-QtInstallerFrameworkRccResource -Bytes $Bytes) {
      foreach ($Item in ConvertFrom-QtInstallerFrameworkTextData -Bytes $RccResource.Data -Source $RccResource.Path) {
        $Resources.Add($Item)
      }
    }
  } catch {
    # Some metadata resources are not RCC containers. Fall through to bounded text scanning.
  }

  $Text = [System.Text.Encoding]::UTF8.GetString($Bytes)
  if ($Text -match '(?i)\b(AllUsers|DisableCommandLineInterface|RequiresAdminRights|AdminTargetDir|TargetDir|ProductUUID)\b') {
    $Resources.Add([pscustomobject]@{
        Source = $Source
        Text   = $Text
      })
  }

  return $Resources.ToArray()
}

function Get-QtInstallerFrameworkMetadataResource {
  <#
  .SYNOPSIS
    Extract Qt Installer Framework metadata resources from the IFW binary-content area
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER Layout
    The parsed IFW binary-content layout
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed IFW binary-content layout')]
    [pscustomobject]$Layout,

    [object[]]$Collection,

    [string]$PackageIndexRoute = 'resource-collection-v1'
  )

  $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $Results = [System.Collections.Generic.List[object]]::new()
    $Index = 0
    # Dedicated meta-resource segments are the authoritative location for config.xml and package
    # metadata in current IFW layouts.
    foreach ($Segment in @($Layout.MetaResourceSegments)) {
      $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Segment.Start -Count $Segment.Length
      foreach ($Resource in ConvertFrom-QtInstallerFrameworkXmlBytes -Bytes $Bytes -Source "MetaResource[$Index]") {
        $Results.Add($Resource)
      }
      $Index++
    }

    # Some older builders place metadata beside package archives. Ignore 7z payloads here to keep
    # metadata discovery bounded and leave archive traversal to Expand-*.
    $Collections = if ($PSBoundParameters.ContainsKey('Collection')) { @($Collection) } elseif ($PackageIndexRoute -eq 'resource-collection-v1') { @(Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout) } else { @() }
    foreach ($CollectionItem in $Collections) {
      foreach ($Resource in @($CollectionItem.Resources)) {
        if ([string]$Resource.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN) { continue }
        if ($Resource.Segment.Length -gt $QTIFW_MAX_XML_SCAN_BYTES) { continue }
        $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Resource.Segment.Start -Count $Resource.Segment.Length
        foreach ($XmlResource in ConvertFrom-QtInstallerFrameworkXmlBytes -Bytes $Bytes -Source "$($CollectionItem.Name)/$($Resource.Name)") {
          $Results.Add($XmlResource)
        }
      }
    }

    return $Results.ToArray()
  } finally {
    $Stream.Dispose()
  }
}

function Get-QtInstallerFrameworkMetadataTextResource {
  <#
  .SYNOPSIS
    Extract text evidence resources from the IFW binary-content metadata area
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER Layout
    The parsed IFW binary-content layout
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed IFW binary-content layout')]
    [pscustomobject]$Layout,

    [object[]]$Collection,

    [string]$PackageIndexRoute = 'resource-collection-v1'
  )

  $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $Results = [System.Collections.Generic.List[object]]::new()
    $Index = 0
    foreach ($Segment in @($Layout.MetaResourceSegments)) {
      $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Segment.Start -Count $Segment.Length
      foreach ($Resource in ConvertFrom-QtInstallerFrameworkTextData -Bytes $Bytes -Source "MetaResource[$Index]") {
        $Results.Add($Resource)
      }
      $Index++
    }

    $Collections = if ($PSBoundParameters.ContainsKey('Collection')) { @($Collection) } elseif ($PackageIndexRoute -eq 'resource-collection-v1') { @(Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout) } else { @() }
    foreach ($CollectionItem in $Collections) {
      foreach ($Resource in @($CollectionItem.Resources)) {
        if ([string]$Resource.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN) { continue }
        if ($Resource.Segment.Length -gt $QTIFW_MAX_TEXT_EVIDENCE_BYTES) { continue }
        $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Resource.Segment.Start -Count $Resource.Segment.Length
        foreach ($TextResource in ConvertFrom-QtInstallerFrameworkTextData -Bytes $Bytes -Source "$($CollectionItem.Name)/$($Resource.Name)") {
          $Results.Add($TextResource)
        }
      }
    }

    return $Results.ToArray()
  } finally {
    $Stream.Dispose()
  }
}

function Resolve-QtInstallerFrameworkExtractionPath {
  <#
  .SYNOPSIS
    Resolve an IFW resource path while preventing extraction outside the destination
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The relative resource path')]
    [string]$RelativePath
  )

  return Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
}

function Test-QtInstallerFrameworkExtractionMatch {
  <#
  .SYNOPSIS
    Test an IFW resource path against an extraction selector
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The resource path')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Name
  )

  return Test-ExtractionPattern -Path $Path -Pattern $Name
}

function Write-QtInstallerFrameworkBuffer {
  <#
  .SYNOPSIS
    Write a bounded IFW resource buffer to a validated output path
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The resource bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The relative output path')]
    [string]$RelativePath
  )

  $OutputPath = Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
  $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
  [System.IO.File]::WriteAllBytes($OutputPath, $Bytes)
  return Get-Item -Path $OutputPath -Force
}

function Copy-QtInstallerFrameworkSegment {
  <#
  .SYNOPSIS
    Copy an IFW file segment to another stream without loading it into memory
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file stream')]
    [System.IO.Stream]$SourceStream,

    [Parameter(Mandatory, HelpMessage = 'The source segment')]
    [pscustomobject]$Segment,

    [Parameter(Mandatory, HelpMessage = 'The destination stream')]
    [System.IO.Stream]$DestinationStream
  )

  $Range = New-BoundedReadStream -Stream $SourceStream -Offset $Segment.Start -Length $Segment.Length -LeaveOpen
  try { return Copy-BoundedStream -Source $Range -Destination $DestinationStream -MaximumBytes $Segment.Length -ExpectedBytes $Segment.Length }
  finally { $Range.Dispose() }
}

function Expand-QtInstallerFrameworkPackageArchive {
  <#
  .SYNOPSIS
    Extract selected files from an IFW package archive using validated output paths
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the package archive')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The destination directory')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The relative directory for expanded files')]
    [string]$RelativeRoot,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Name,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Rename',

    [System.Collections.Generic.ISet[string]]$ReservedPath,

    [Parameter(Mandatory, HelpMessage = 'The maximum number of expanded bytes')]
    [long]$MaximumExpandedBytes
  )

  Import-QtInstallerFrameworkSharpCompress
  $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  if (-not $ReservedPath) { $ReservedPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open($Path)
  try {
    $Entries = @($Archive.Entries)
    if ($Entries.Count -gt $QTIFW_MAX_EXPANDED_FILES) {
      throw "The Qt Installer Framework package archive contains too many entries: $($Entries.Count)"
    }

    $Files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ExpandedBytes = [long]0
    # Export only selected regular entries. Links, duplicate paths, and inaccurate expanded sizes
    # are rejected before they can alter the destination tree.
    foreach ($ArchiveEntry in $Entries) {
      if ($ArchiveEntry.IsDirectory -or [string]::IsNullOrWhiteSpace($ArchiveEntry.Key)) { continue }
      $RelativePath = Join-Path $RelativeRoot ([string]$ArchiveEntry.Key)
      if (-not (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name)) { continue }

      $EncryptedProperty = $ArchiveEntry.PSObject.Properties['IsEncrypted']
      if ($EncryptedProperty -and [bool]$EncryptedProperty.Value) {
        throw "The Qt Installer Framework package archive entry '$($ArchiveEntry.Key)' is password-protected; encrypted package extraction is unsupported"
      }

      $LinkTargetProperty = $ArchiveEntry.PSObject.Properties['LinkTarget']
      if ($LinkTargetProperty -and -not [string]::IsNullOrWhiteSpace([string]$LinkTargetProperty.Value)) {
        throw "The Qt Installer Framework package archive contains an unsupported link: $($ArchiveEntry.Key)"
      }

      $EntrySize = [long]$ArchiveEntry.Size
      if ($EntrySize -lt 0) { throw "The Qt Installer Framework package entry has an unknown size: $($ArchiveEntry.Key)" }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPath
      if (-not $Target.ShouldWrite) { continue }
      $ExpandedBytes += $EntrySize
      if ($ExpandedBytes -gt $MaximumExpandedBytes) {
        throw "The selected Qt Installer Framework package files exceed the $MaximumExpandedBytes-byte limit"
      }

      $OutputPath = $Target.Path
      $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force

      try {
        # SharpCompress represents some valid zero-byte entries without an entry stream; create
        # only that exact case and propagate all other archive failures.
        $EntryStream = $ArchiveEntry.OpenEntryStream()
      } catch {
        if ([long]$ArchiveEntry.Size -eq 0 -and $_.Exception.Message -match 'does not have a stream') {
          [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read).Dispose()
          $Files.Add((Get-Item -Path $OutputPath -Force))
          continue
        }
        throw
      }

      $OutputStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
      try {
        $Buffer = [byte[]]::new(1048576)
        $ActualSize = [long]0
        while (($Read = $EntryStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
          $ActualSize += $Read
          if (($ExpandedBytes - $EntrySize + $ActualSize) -gt $MaximumExpandedBytes) {
            throw "The selected Qt Installer Framework package files exceed the $MaximumExpandedBytes-byte limit"
          }
          $OutputStream.Write($Buffer, 0, $Read)
        }
        if ($ActualSize -ne $EntrySize) {
          throw "The Qt Installer Framework package entry '$($ArchiveEntry.Key)' expanded to $ActualSize bytes, expected $($ArchiveEntry.Size)"
        }
      } finally {
        $OutputStream.Dispose()
        $EntryStream.Dispose()
      }
      $Files.Add((Get-Item -Path $OutputPath -Force))
    }

    return [pscustomobject]@{
      Bytes = $ExpandedBytes
      Files = $Files.ToArray()
    }
  } finally {
    $Archive.Dispose()
  }
}

function Expand-QtInstallerFramework {
  <#
  .SYNOPSIS
    Extract metadata, package archives, and package payloads from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER DestinationPath
    The destination directory for extracted files
  .PARAMETER Name
    The file name or wildcard pattern to extract
  .PARAMETER MaximumExpandedBytes
    The maximum total number of bytes written to the destination
  .PARAMETER CollisionAction
    Behavior when a resource path already exists or multiple resources resolve to the same path.
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The destination directory for extracted files')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'The maximum total number of expanded bytes')]
    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = $QTIFW_MAX_EXPANDED_BYTES,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt'
  )

  process {
    # Parse and validate the trailer once, then keep one installer stream open for all segment
    # copies. Nested archive readers receive isolated temporary files because they require seeking.
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath
    if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }
    $FormatInfo = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout
    if (-not $FormatInfo.IsSupported) { throw ($FormatInfo.Warnings -join ' ') }
    $PayloadHandler = Get-QtInstallerFrameworkRouteHandler -Category Payload -Route $FormatInfo.PayloadRoute

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path ([System.IO.Path]::GetTempPath()) "Dumplings-QtIFW-$([System.Guid]::NewGuid())"
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $DestinationPath = (New-Item -Path $DestinationPath -ItemType Directory -Force).FullName

    $WrittenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $WrittenFileCount = 0
    $WrittenBytes = [long]0
    $InstallerStream = [System.IO.File]::Open($InstallerPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $MetaIndex = 0
      # Expand embedded RCC resources when possible; preserve an unrecognized metadata segment as
      # a raw .rcc file so callers can inspect newer layouts without losing evidence.
      foreach ($Segment in @($Layout.MetaResourceSegments)) {
        $Bytes = Read-QtInstallerFrameworkBytes -Stream $InstallerStream -Offset $Segment.Start -Count $Segment.Length
        try {
          $RccResources = @(Get-QtInstallerFrameworkRccResource -Bytes $Bytes)
        } catch {
          $RccResources = @()
        }

        if ($RccResources) {
          foreach ($Resource in $RccResources) {
            $RelativePath = ([string]$Resource.Path).TrimStart(':', '/', '\')
            if (-not (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name)) { continue }
            $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
              -CollisionAction $CollisionAction -ReservedPath $WrittenPaths
            if (-not $Target.ShouldWrite) { continue }

            $WrittenBytes += $Resource.Data.Length
            if ($WrittenBytes -gt $MaximumExpandedBytes) {
              throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
            }
            $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
            [IO.File]::WriteAllBytes($Target.Path, $Resource.Data)
            $WrittenFileCount++
            if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
              throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
            }
          }
        } else {
          $RelativePath = "metadata/QResources/$MetaIndex.rcc"
          if (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name) {
            $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
              -CollisionAction $CollisionAction -ReservedPath $WrittenPaths
            if ($Target.ShouldWrite) {
              $WrittenBytes += $Bytes.Length
              if ($WrittenBytes -gt $MaximumExpandedBytes) {
                throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
              }
              $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
              [IO.File]::WriteAllBytes($Target.Path, $Bytes)
              $WrittenFileCount++
              if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
                throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
              }
            }
          }
        }
        $MetaIndex++
      }

      # Resource catalog entries are copied through bounded streams. A raw resource and its
      # expanded package contents are accounted independently against the global output limit.
      foreach ($Collection in @($FormatInfo.PackageCollections)) {
        foreach ($Resource in @($Collection.Resources)) {
          if ($Resource.Segment.Length -gt $MaximumExpandedBytes) {
            throw "The Qt Installer Framework resource '$($Resource.Name)' exceeds the $MaximumExpandedBytes-byte limit"
          }

          # Materialize only the current bounded segment, never the complete installer overlay.
          $TemporaryArchivePath = [System.IO.Path]::GetTempFileName()
          try {
            $TemporaryStream = [System.IO.File]::Open($TemporaryArchivePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
            try {
              $null = Copy-QtInstallerFrameworkSegment -SourceStream $InstallerStream -Segment $Resource.Segment -DestinationStream $TemporaryStream
            } finally {
              $TemporaryStream.Dispose()
            }

            $RawRelativePath = if ($FormatInfo.PackageIndexRoute -eq 'component-index-v1') { "packages/$($Collection.Name)/$($Resource.Name)" } else { "metadata/$($Collection.Name)/$($Resource.Name)" }
            if (Test-QtInstallerFrameworkExtractionMatch -Path $RawRelativePath -Name $Name) {
              $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RawRelativePath `
                -CollisionAction $CollisionAction -ReservedPath $WrittenPaths
              if ($Target.ShouldWrite) {
                $WrittenBytes += $Resource.Segment.Length
                if ($WrittenBytes -gt $MaximumExpandedBytes) {
                  throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
                }
                $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
                [System.IO.File]::Copy($TemporaryArchivePath, $Target.Path, $true)
                $WrittenFileCount++
                if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
                  throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
                }
              }
            }

            if ([string]$Resource.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN) {
              # IFW package payloads retain their collection name as a logical package root.
              $ArchiveRoot = "packages/$($Collection.Name)/$([System.IO.Path]::GetFileNameWithoutExtension([string]$Resource.Name))"
              $RemainingExpandedBytes = $MaximumExpandedBytes - $WrittenBytes
              if ($RemainingExpandedBytes -le 0) {
                throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
              }
              $ArchiveResult = & $PayloadHandler -Path $TemporaryArchivePath -DestinationPath $DestinationPath `
                -RelativeRoot $ArchiveRoot -Name $Name -CollisionAction $CollisionAction -ReservedPath $WrittenPaths `
                -MaximumExpandedBytes $RemainingExpandedBytes
              $WrittenBytes += $ArchiveResult.Bytes
              foreach ($ExtractedFile in @($ArchiveResult.Files)) {
                $WrittenFileCount++
                if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
                  throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
                }
              }
            }
          } finally {
            Remove-Item -Path $TemporaryArchivePath -Force -ErrorAction SilentlyContinue
          }
        }
      }
    } finally {
      $InstallerStream.Dispose()
    }

    if ($WrittenFileCount -eq 0) { throw "No Qt Installer Framework resources matched the extraction selector: $Name" }
    return $DestinationPath
  }
}

function ConvertFrom-QtInstallerFrameworkInstallerXml {
  <#
  .SYNOPSIS
    Convert IFW installer config XML into static manifest-authoring metadata
  .PARAMETER Xml
    The parsed IFW installer XML document
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed IFW installer XML document')]
    [xml]$Xml
  )

  # Read direct config children only. Script-generated values remain unresolved rather than being
  # inferred from unrelated XML text.
  $Values = [ordered]@{}
  foreach ($Child in @($Xml.Installer.ChildNodes)) {
    if ($Child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
    if (-not $Values.Contains($Child.LocalName)) { $Values[$Child.LocalName] = $Child.InnerText.Trim() }
  }

  # Qt IFW 2.0 renamed the public configuration keys while continuing to accept the 1.x names.
  # Normalize both spellings here so downstream ARP and upgrade logic is generation-independent.
  $MaintenanceToolNameValue = if (-not [string]::IsNullOrWhiteSpace($Values['MaintenanceToolName'])) { $Values['MaintenanceToolName'] } else { $Values['UninstallerName'] }
  $MaintenanceToolName = if ([string]::IsNullOrWhiteSpace($MaintenanceToolNameValue)) { 'maintenancetool' } else { $MaintenanceToolNameValue }
  $MaintenanceToolIniValue = if (-not [string]::IsNullOrWhiteSpace($Values['MaintenanceToolIniFile'])) { $Values['MaintenanceToolIniFile'] } else { $Values['UninstallerIniFile'] }
  $ProductCode = $null
  foreach ($Name in @('ProductUUID', 'ProductCode')) {
    if (-not [string]::IsNullOrWhiteSpace($Values[$Name])) {
      $ProductCode = $Values[$Name]
      break
    }
  }

  [pscustomobject]@{
    Name                        = $Values['Name']
    PackageName                 = $Values['Name']
    DisplayName                 = $Values['Name']
    DisplayVersion              = $Values['Version']
    ProductVersion              = $Values['Version']
    Publisher                   = $Values['Publisher']
    ProductUrl                  = $Values['ProductUrl']
    Title                       = $Values['Title']
    ProductCode                 = $ProductCode
    TargetDir                   = $Values['TargetDir']
    AdminTargetDir              = $Values['AdminTargetDir']
    DisableCommandLineInterface = $Values['DisableCommandLineInterface']
    StartMenuDir                = $Values['StartMenuDir']
    MaintenanceToolName         = $MaintenanceToolName
    MaintenanceToolIniFile      = if ([string]::IsNullOrWhiteSpace($MaintenanceToolIniValue)) { "$MaintenanceToolName.ini" } else { $MaintenanceToolIniValue }
    SupportsModify              = $Values['SupportsModify']
    RawValues                   = $Values
  }
}

function ConvertTo-QtInstallerFrameworkBoolean {
  <#
  .SYNOPSIS
    Convert common Qt Installer Framework string boolean values
  .PARAMETER Value
    The string value to convert
  #>
  [OutputType([bool])]
  param (
    [Parameter(HelpMessage = 'The string value to convert')]
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  return $Value.Trim() -match '^(?i:true|1|yes)$'
}

function Find-QtInstallerFrameworkAsciiMarker {
  <#
  .SYNOPSIS
    Find source-backed ASCII markers in a bounded IFW executable prefix
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer file stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The maximum prefix length to scan')]
    [long]$Length,

    [Parameter(Mandatory, HelpMessage = 'The ASCII markers to find')]
    [string[]]$Marker
  )

  # Scan in chunks with an overlap long enough to preserve markers crossing buffer boundaries.
  $Found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $MaximumMarkerLength = ($Marker | Measure-Object -Property Length -Maximum).Maximum
  $Carry = ''
  $Buffer = [byte[]]::new(1048576)
  $Remaining = $Length
  $Stream.Position = 0

  while ($Remaining -gt 0 -and $Found.Count -lt $Marker.Count) {
    $Read = $Stream.Read($Buffer, 0, [int][Math]::Min($Buffer.Length, $Remaining))
    if ($Read -le 0) { throw 'The Qt IFW executable prefix is truncated' }
    $Text = $Carry + [System.Text.Encoding]::Latin1.GetString($Buffer, 0, $Read)
    foreach ($Value in $Marker) {
      if (-not $Found.Contains($Value) -and $Text.IndexOf($Value, [System.StringComparison]::Ordinal) -ge 0) {
        $null = $Found.Add($Value)
      }
    }

    $CarryLength = [Math]::Min([Math]::Max(0, $MaximumMarkerLength - 1), $Text.Length)
    $Carry = if ($CarryLength -gt 0) { $Text.Substring($Text.Length - $CarryLength) } else { '' }
    $Remaining -= $Read
  }

  return @($Found)
}

function Get-QtInstallerFrameworkVersionEvidence {
  <#
  .SYNOPSIS
    Read source-defined Qt IFW and Qt runtime version markers from the launcher.
  .PARAMETER Path
    Path to the Qt IFW binary.
  .PARAMETER Layout
    Validated binary-content layout used to bound the launcher scan.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $FrameworkVersion = $null
  $QtRuntimeVersion = $null
  $MatchedText = $null
  $ScanLength = [Math]::Min([int64]$Layout.EndOfExecutable, [int64]$QTIFW_MAX_EXECUTABLE_SCAN_BYTES)
  $Stream = [IO.File]::Open((Get-Item -Path $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Buffer = [byte[]]::new(1048576)
    $Carry = ''
    $Remaining = $ScanLength
    while ($Remaining -gt 0 -and -not $FrameworkVersion) {
      $Read = $Stream.Read($Buffer, 0, [int][Math]::Min($Buffer.Length, $Remaining))
      if ($Read -le 0) { break }
      $Text = $Carry + [Text.Encoding]::Latin1.GetString($Buffer, 0, $Read)
      $Match = [regex]::Match($Text, 'IFW Version:\s*"?(?<ifw>[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)"?(?:,\s*built with Qt\s+(?<qt>[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?))?', 'IgnoreCase')
      if (-not $Match.Success) {
        $Match = [regex]::Match($Text, 'Built with Qt Installer Framework\s+(?<ifw>[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)', 'IgnoreCase')
      }
      if ($Match.Success) {
        $FrameworkVersion = $Match.Groups['ifw'].Value
        if ($Match.Groups['qt'].Success) { $QtRuntimeVersion = $Match.Groups['qt'].Value }
        $MatchedText = $Match.Value
        break
      }
      $Carry = if ($Text.Length -gt 512) { $Text.Substring($Text.Length - 512) } else { $Text }
      $Remaining -= $Read
    }

    $PEVersion = $null
    try {
      $PELayout = Get-PELayout -Stream $Stream
      $VersionTable = Get-PEVersionStringTable -Stream $Stream -Layout $PELayout
      if ($VersionTable.PSObject.Properties['FileVersion']) { $PEVersion = [string]$VersionTable.FileVersion }
    } catch {
      # PE version resources were added after the binary format and remain optional evidence.
    }

    [pscustomobject]@{
      FrameworkVersion       = $FrameworkVersion
      FrameworkVersionSource = if ($FrameworkVersion) { 'EmbeddedSourceMarker' } else { $null }
      QtRuntimeVersion       = $QtRuntimeVersion
      MatchedText            = $MatchedText
      PEFileVersion          = $PEVersion
      ScanLength             = $ScanLength
      ScanWasLimited         = $Layout.EndOfExecutable -gt $ScanLength
    }
  } finally {
    $Stream.Dispose()
  }
}

function ConvertTo-QtInstallerFrameworkComparableVersion {
  <#
  .SYNOPSIS
    Convert the numeric prefix of an embedded Qt IFW version into System.Version.
  .PARAMETER Version
    Embedded framework or PE version text. Prerelease suffixes are ignored for catalog routing.
  #>
  [OutputType([version])]
  param ([AllowNull()][string]$Version)
  if ($Version -match '^(?<value>[0-9]+(?:\.[0-9]+){1,3})') { return [version]$Matches.value }
  return $null
}

function Resolve-QtInstallerFrameworkFormatProfile {
  <#
  .SYNOPSIS
    Select a catalog profile from explicit version and validated index structure.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][pscustomobject]$VersionEvidence
  )

  $ComparableVersion = ConvertTo-QtInstallerFrameworkComparableVersion -Version $VersionEvidence.FrameworkVersion
  $SelectedProfile = $null
  if ($ComparableVersion) {
    if ($ComparableVersion -lt [version]'1.2.0') {
      throw "Qt Installer Framework version '$($VersionEvidence.FrameworkVersion)' predates the supported 1.2 binary format"
    }
    foreach ($Candidate in @($Script:QtInstallerFrameworkCatalog.Profiles)) {
      $Minimum = [version]$Candidate.MinimumVersion
      $Maximum = if ($Candidate.MaximumVersionExclusive) { [version]$Candidate.MaximumVersionExclusive } else { $null }
      if ($ComparableVersion -ge $Minimum -and (-not $Maximum -or $ComparableVersion -lt $Maximum)) {
        $SelectedProfile = [pscustomobject]$Candidate
        break
      }
    }
  }

  $Candidates = if ($SelectedProfile) {
    @($SelectedProfile)
  } elseif ($ComparableVersion -and $ComparableVersion -ge [version]'4.12.0') {
    @([pscustomobject]$Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Modern)
  } else {
    @(
      [pscustomobject]$Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Modern
      [pscustomobject]$Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Legacy
    )
  }

  $Validated = [System.Collections.Generic.List[object]]::new()
  foreach ($Candidate in $Candidates) {
    $HandlerName = Get-QtInstallerFrameworkRouteHandler -Category PackageIndex -Route $Candidate.PackageIndexRoute
    try {
      $Collections = @(& $HandlerName -Path $Path -Layout $Layout)
      $Validated.Add([pscustomobject]@{ Profile = $Candidate; Collections = $Collections; SelectionEvidence = 'Catalog version and complete package-index validation' })
    } catch {
      if ($SelectedProfile) { throw }
    }
  }

  if ($Validated.Count -eq 0) { throw 'No Qt Installer Framework catalog profile validated the package index' }
  if ($Validated.Count -gt 1) {
    # The 2.0 overhaul retained the count/name/range index framing. For the unversioned 1.2
    # launcher, use source-defined configuration key generations to disambiguate the meaning of
    # the otherwise byte-compatible primary index.
    $ConfigText = [Text.StringBuilder]::new()
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      foreach ($Segment in @($Layout.MetaResourceSegments)) {
        if ($Segment.Length -gt $QTIFW_MAX_TEXT_EVIDENCE_BYTES) { continue }
        $null = $ConfigText.Append([Text.Encoding]::Latin1.GetString((Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Segment.Start -Count $Segment.Length)))
      }
    } finally { $Stream.Dispose() }
    $HasLegacyKeys = $ConfigText.ToString() -match 'Uninstaller(Name|IniFile)'
    $HasModernKeys = $ConfigText.ToString() -match 'MaintenanceTool(Name|IniFile)|ProductUUID|DisableCommandLineInterface'
    $SelectedGeneration = if ($HasLegacyKeys -and -not $HasModernKeys) {
      'LegacyComponentIndex'
    } elseif ($HasModernKeys -and -not $HasLegacyKeys) {
      'BinaryContent'
    } else {
      throw 'The unversioned Qt Installer Framework package index is structurally ambiguous between legacy and modern routes'
    }
    $Selected = @($Validated | Where-Object { $_.Profile.FormatGeneration -eq $SelectedGeneration } | Select-Object -First 1)
    if (-not $Selected) { throw 'The Qt Installer Framework package index is ambiguous between legacy and modern routes' }
    if ($SelectedGeneration -eq 'LegacyComponentIndex') {
      # Qt IFW 1.2 predates the embedded IFW version string. A complete ComponentIndex plus the
      # source-defined legacy config names is enough to select the normal known 1.x profile.
      $Selected[0].Profile = [pscustomobject](@($Script:QtInstallerFrameworkCatalog.Profiles | Where-Object Id -EQ 'ifw-1.x-legacy')[0])
    }
    $Selected[0].SelectionEvidence = if ($HasLegacyKeys -and -not $HasModernKeys) { 'Legacy configuration keys disambiguate the byte-compatible 1.x component index.' } else { 'Modern configuration keys disambiguate the byte-compatible 2.0+ resource-collection index.' }
    return $Selected[0]
  }
  return $Validated[0]
}

function Get-QtInstallerFrameworkFormatInfoInternal {
  <#
  .SYNOPSIS
    Resolve one validated Qt IFW layout to its catalog profile and internal parse context.
  .PARAMETER Path
    Resolved path to the installer or separate binary-content file.
  .PARAMETER Layout
    Validated common binary-content trailer and rebased segment ranges.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $VersionEvidence = Get-QtInstallerFrameworkVersionEvidence -Path $Path -Layout $Layout
  $ResolutionError = $null
  try {
    $Resolution = Resolve-QtInstallerFrameworkFormatProfile -Path $Path -Layout $Layout -VersionEvidence $VersionEvidence
  } catch {
    $ResolutionError = $_.Exception.Message
    $ComparableVersion = ConvertTo-QtInstallerFrameworkComparableVersion -Version $VersionEvidence.FrameworkVersion
    $Compatibility = if ($ComparableVersion -and $ComparableVersion -lt [version]'2.0.0') { $Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Legacy } else { $Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Modern }
    $Resolution = [pscustomobject]@{ Profile = [pscustomobject]$Compatibility; Collections = @(); SelectionEvidence = 'No package-index route validated completely.' }
  }
  $Operations = @()
  if (-not $ResolutionError) {
    try {
      $Operations = @(Get-QtInstallerFrameworkOperation -Path $Path -Layout $Layout)
    } catch {
      $ResolutionError = "The performed-operation route is malformed: $($_.Exception.Message)"
    }
  }
  $SelectedProfile = $Resolution.Profile
  # Validate every selected route before exposing a supported profile. Most generations share
  # physical readers, but the route IDs preserve source-level semantics and capability boundaries.
  foreach ($RouteCategory in @(
      @{ Category = 'Trailer'; Route = $SelectedProfile.TrailerRoute },
      @{ Category = 'Metadata'; Route = $SelectedProfile.MetadataRoute },
      @{ Category = 'PackageIndex'; Route = $SelectedProfile.PackageIndexRoute },
      @{ Category = 'Payload'; Route = $SelectedProfile.PayloadRoute },
      @{ Category = 'Config'; Route = $SelectedProfile.ConfigRoute },
      @{ Category = 'Interface'; Route = $SelectedProfile.InterfaceRoute }
    )) {
    $null = Get-QtInstallerFrameworkRouteHandler -Category $RouteCategory.Category -Route $RouteCategory.Route
  }
  $Warnings = [System.Collections.Generic.List[string]]::new()
  if (-not $VersionEvidence.FrameworkVersion) {
    $Warnings.Add('No source-defined Qt IFW version marker was found; the framework version is reported as a structurally validated range.')
  }
  if ($VersionEvidence.ScanWasLimited) { $Warnings.Add('The launcher version scan reached its bounded limit before the complete executable prefix was inspected.') }
  if ($SelectedProfile.IsFallback) { $Warnings.Add('The Qt IFW media uses a structurally compatible fallback profile; release-specific capabilities require review.') }
  if ($ResolutionError) { $Warnings.Add("The Qt IFW format route is unsupported or malformed: $ResolutionError") }
  if ($Layout.MagicMarkerName -ne 'Installer') { $Warnings.Add("The Qt IFW media role is '$($Layout.MagicMarkerName)', not Installer; manifest metadata projection is diagnostic only.") }

  $EmbeddedPackageArchiveCount = 0
  foreach ($Collection in @($Resolution.Collections)) {
    foreach ($Resource in @($Collection.Resources)) {
      if ([string]$Resource.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN) { $EmbeddedPackageArchiveCount++ }
    }
  }
  $PayloadAvailability = if ($EmbeddedPackageArchiveCount -gt 0) { 'Embedded' } else { 'ExternalOrUnavailable' }
  if (-not $ResolutionError -and $PayloadAvailability -eq 'ExternalOrUnavailable') {
    $Warnings.Add('No embedded package archive was indexed; package data is external, downloadable, or unavailable in this media.')
  }

  if ($VersionEvidence.FrameworkVersion -and $VersionEvidence.PEFileVersion) {
    $Embedded = ConvertTo-QtInstallerFrameworkComparableVersion $VersionEvidence.FrameworkVersion
    $PE = ConvertTo-QtInstallerFrameworkComparableVersion $VersionEvidence.PEFileVersion
    if ($Embedded -and $PE -and ($Embedded.Major -ne $PE.Major -or $Embedded.Minor -ne $PE.Minor)) {
      $Warnings.Add("The embedded IFW version '$($VersionEvidence.FrameworkVersion)' conflicts with PE FileVersion '$($VersionEvidence.PEFileVersion)'; the embedded source marker takes precedence.")
    }
  }
  $PESubsystem = try { Get-QtInstallerFrameworkPESubsystemInfo -Path $Path } catch { $null }

  [pscustomobject][ordered]@{
    Path                         = $Path
    IsQtInstallerFramework       = $true
    IsSupported                  = -not [bool]$ResolutionError
    FormatGeneration             = $SelectedProfile.FormatGeneration
    FormatProfileId              = $SelectedProfile.Id
    FrameworkVersion             = $VersionEvidence.FrameworkVersion
    FrameworkVersionSource       = $VersionEvidence.FrameworkVersionSource
    FrameworkVersionRange        = $SelectedProfile.FrameworkVersionRange
    QtRuntimeVersion             = $VersionEvidence.QtRuntimeVersion
    MediaRole                    = $Layout.MagicMarkerName
    CookieKind                   = $Layout.CookieKind
    PESubsystem                  = $PESubsystem
    TrailerRoute                 = $SelectedProfile.TrailerRoute
    MetadataRoute                = $SelectedProfile.MetadataRoute
    PackageIndexRoute            = $SelectedProfile.PackageIndexRoute
    PayloadRoute                 = $SelectedProfile.PayloadRoute
    ConfigRoute                  = $SelectedProfile.ConfigRoute
    InterfaceRoute               = $SelectedProfile.InterfaceRoute
    VersionEvidenceRoute         = $SelectedProfile.VersionEvidenceRoute
    CatalogVersion               = [int]$Script:QtInstallerFrameworkCatalog.CatalogVersion
    SupportsProductUuid          = [bool]$SelectedProfile.SupportsProductUuid
    SupportsCommandLineInterface = [bool]$SelectedProfile.SupportsCommandLineInterface
    SupportsLibArchive           = [bool]$SelectedProfile.SupportsLibArchive
    PayloadAvailability          = $PayloadAvailability
    Capabilities                 = [pscustomobject]@{
      ProductUuid          = [bool]$SelectedProfile.SupportsProductUuid
      CommandLineInterface = [bool]$SelectedProfile.SupportsCommandLineInterface
      LibArchive           = [bool]$SelectedProfile.SupportsLibArchive
    }
    IsFallback                   = [bool]$SelectedProfile.IsFallback
    Evidence                     = [pscustomobject]@{
      EmbeddedVersionText         = $VersionEvidence.MatchedText
      PEFileVersion               = $VersionEvidence.PEFileVersion
      VersionScanLength           = $VersionEvidence.ScanLength
      MagicMarker                 = $Layout.MagicMarker
      MagicCookie                 = $Layout.MagicCookie
      PrimaryIndexSegment         = $Layout.PrimaryIndexSegment
      CollectionCount             = @($Resolution.Collections).Count
      EmbeddedPackageArchiveCount = $EmbeddedPackageArchiveCount
      OperationCount              = $Operations.Count
      ProfileSelection            = $Resolution.SelectionEvidence
    }
    Warnings                     = [string[]]$Warnings.ToArray()
    Layout                       = $Layout
    PackageCollections           = @($Resolution.Collections)
    Operations                   = @($Operations)
  }
}

function Get-QtInstallerFrameworkFormatInfo {
  <#
  .SYNOPSIS
    Identify the Qt IFW binary generation, framework version, media role, and parser routes.
  .PARAMETER Path
    Path to a Qt IFW executable or DAT binary.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath
    if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }
    $Result = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout
    # Internal parse objects are deliberately omitted from the public diagnostic contract.
    $Result.PSObject.Properties.Remove('Layout')
    $Result.PSObject.Properties.Remove('PackageCollections')
    $Result.PSObject.Properties.Remove('Operations')
    return $Result
  }
}

function Get-QtInstallerFrameworkAnalysisContext {
  <#
  .SYNOPSIS
    Parse each Qt IFW structural layer once for one top-level metadata operation.
  .PARAMETER Path
    Path to an installer-role Qt IFW executable.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath
  $FormatInfo = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout
  if (-not $FormatInfo.IsSupported) { throw ($FormatInfo.Warnings -join ' ') }
  $Collections = @($FormatInfo.PackageCollections)
  $MetadataHandler = Get-QtInstallerFrameworkRouteHandler -Category Metadata -Route $FormatInfo.MetadataRoute
  $MetadataResources = @(& $MetadataHandler -Path $InstallerPath -Layout $Layout -Collection $Collections -PackageIndexRoute $FormatInfo.PackageIndexRoute)
  $TextResources = @(Get-QtInstallerFrameworkMetadataTextResource -Path $InstallerPath -Layout $Layout -Collection $Collections -PackageIndexRoute $FormatInfo.PackageIndexRoute)
  [pscustomobject]@{
    Path               = $InstallerPath
    Layout             = $Layout
    FormatInfo         = $FormatInfo
    PackageCollections = $Collections
    Operations         = @($FormatInfo.Operations)
    MetadataResources  = $MetadataResources
    TextResources      = $TextResources
  }
}

function Get-QtInstallerFrameworkPESubsystemInfo {
  <#
  .SYNOPSIS
    Read the PE subsystem used by a Qt Installer Framework launcher
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  Get-PESubsystemInfo -Path $Path
}

function Get-QtInstallerFrameworkInterfaceInfo {
  <#
  .SYNOPSIS
    Detect whether a Qt Installer Framework binary contains the modern command-line interface
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .PARAMETER Layout
    The parsed IFW binary-content layout
  .PARAMETER InstallerConfig
    The parsed installer config metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The parsed IFW binary-content layout')]
    [pscustomobject]$Layout,

    [Parameter(HelpMessage = 'The parsed installer config metadata')]
    [AllowNull()]
    [pscustomobject]$InstallerConfig,

    [AllowNull()]
    [pscustomobject]$FormatInfo
  )

  if (-not $Layout) { $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $Path }
  $RequiredOptionMarkers = @('accept-licenses', 'default-answer', 'confirm-command')
  $CommandMarkers = @('check-updates', 'create-offline', 'clear-cache')
  $FoundMarkers = [System.Collections.Generic.List[string]]::new()
  $Warnings = [System.Collections.Generic.List[string]]::new()
  $PESubsystemInfo = try {
    Get-QtInstallerFrameworkPESubsystemInfo -Path $Path
  } catch {
    $null
  }

  if ($FormatInfo -and $FormatInfo.InterfaceRoute -eq 'gui-launcher-v1') {
    # Releases before 4.0 do not implement commandlineinterface.cpp. Do not interpret unrelated
    # option literals in bundled Qt code as partial CLI evidence.
    $MarkerVariant = 'GUI'
  } elseif ($Layout.EndOfExecutable -le 0 -or $Layout.EndOfExecutable -gt $QTIFW_MAX_EXECUTABLE_SCAN_BYTES) {
    $MarkerVariant = 'Unknown'
    $Warnings.Add("The Qt IFW executable prefix is outside the $QTIFW_MAX_EXECUTABLE_SCAN_BYTES-byte static scan limit.")
  } else {
    $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      # CLI literals are compiled into the launcher. Stop at EndOfExecutable so packaged files cannot create false positives.
      $MarkerMatches = @(Find-QtInstallerFrameworkAsciiMarker -Stream $Stream -Length $Layout.EndOfExecutable -Marker @($RequiredOptionMarkers + $CommandMarkers))
      if ($MarkerMatches) { $FoundMarkers.AddRange([string[]]$MarkerMatches) }
    } finally {
      $Stream.Dispose()
    }

    $HasRequiredOptions = @($RequiredOptionMarkers | Where-Object { $FoundMarkers -contains $_ }).Count -eq $RequiredOptionMarkers.Count
    $FoundCommandCount = @($CommandMarkers | Where-Object { $FoundMarkers -contains $_ }).Count
    if ($HasRequiredOptions -and $FoundCommandCount -ge 2) {
      $MarkerVariant = 'CLI'
    } elseif ($FoundMarkers.Count -eq 0) {
      $MarkerVariant = 'GUI'
    } else {
      $MarkerVariant = 'Unknown'
      $Warnings.Add('The Qt IFW executable contains only partial command-line interface markers; validate silent support manually.')
    }
  }

  # The PE subsystem is the builder-selected launcher mode and therefore outranks string markers;
  # markers remain useful when the PE header cannot be parsed.
  $InterfaceVariant = if ($FormatInfo -and $FormatInfo.InterfaceRoute -eq 'gui-launcher-v1') {
    'GUI'
  } else {
    switch ($PESubsystemInfo.Name) {
      'WindowsCui' { 'CLI'; break }
      'WindowsGui' { 'GUI'; break }
      default { $MarkerVariant }
    }
  }
  if ($PESubsystemInfo -and $MarkerVariant -ne 'Unknown' -and $InterfaceVariant -ne $MarkerVariant) {
    $Warnings.Add("The PE subsystem identifies this as $InterfaceVariant, but embedded command markers suggest $MarkerVariant. The PE subsystem result takes precedence.")
  }

  $DisabledByConfig = if ($InstallerConfig) {
    ConvertTo-QtInstallerFrameworkBoolean -Value $InstallerConfig.DisableCommandLineInterface
  } else {
    $false
  }
  $CommandLineInterface = switch ($InterfaceVariant) {
    'CLI' { if ($DisabledByConfig) { 'Disabled' } else { 'Enabled' } }
    'GUI' { 'Unavailable' }
    default { 'Unknown' }
  }
  $SupportsSilentInstallation = $CommandLineInterface -eq 'Enabled'

  if ($InterfaceVariant -eq 'GUI') {
    $Warnings.Add('The Qt IFW launcher does not contain the modern command-line interface; GUI-only installers do not support WinGet-compatible silent installation.')
  } elseif ($DisabledByConfig) {
    $Warnings.Add('The embedded IFW config disables the command-line interface, so silent installation and AllUsers scope overrides are unavailable.')
  }

  [pscustomobject]@{
    InterfaceVariant            = $InterfaceVariant
    CommandLineInterface        = $CommandLineInterface
    HasCommandLineInterface     = $InterfaceVariant -eq 'CLI'
    CommandLineInterfaceEnabled = $CommandLineInterface -eq 'Enabled'
    SupportsSilentInstallation  = $SupportsSilentInstallation
    DisabledByConfig            = $DisabledByConfig
    Confidence                  = if ($InterfaceVariant -eq 'Unknown') { 'low' } else { 'high' }
    Evidence                    = [pscustomobject]@{
      ScanRange             = [pscustomobject]@{ Start = 0; Length = $Layout.EndOfExecutable }
      PESubsystem           = $PESubsystemInfo
      MarkerVariant         = $MarkerVariant
      RequiredOptionMarkers = $RequiredOptionMarkers
      CommandMarkers        = $CommandMarkers
      FoundMarkers          = $FoundMarkers.ToArray()
      SourceRule            = 'Qt IFW 4.0+ may include the command-line interface; within that generation the Windows CUI subsystem identifies the headless launcher and DisableCommandLineInterface can disable it.'
      InterfaceRoute        = if ($FormatInfo) { $FormatInfo.InterfaceRoute } else { $null }
    }
    Warnings                    = $Warnings.ToArray()
  }
}

function Get-QtInstallerFrameworkInstallLocationInfo {
  <#
  .SYNOPSIS
    Determine whether a Qt Installer Framework CLI requires an explicit installation root
  .PARAMETER InstallerConfig
    The parsed installer config metadata
  .PARAMETER InterfaceInfo
    Static Qt IFW CLI/GUI interface evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The parsed installer config metadata')]
    [AllowNull()]
    [pscustomobject]$InstallerConfig,

    [Parameter(HelpMessage = 'Static Qt IFW CLI/GUI interface evidence')]
    [AllowNull()]
    [pscustomobject]$InterfaceInfo
  )

  # IFW's CLI fails an empty targetDir check unless --root supplies a concrete path.
  $DefaultTargetDir = if ($InstallerConfig) { [string]$InstallerConfig.TargetDir } else { $null }
  $HasDefaultTargetDir = -not [string]::IsNullOrWhiteSpace($DefaultTargetDir)
  $SupportsSilentInstallation = [bool]$InterfaceInfo.SupportsSilentInstallation
  $RequiresExplicitInstallLocation = if ($SupportsSilentInstallation) { -not $HasDefaultTargetDir } else { $null }

  [pscustomobject]@{
    DefaultTargetDir                = $DefaultTargetDir
    HasDefaultTargetDir             = $HasDefaultTargetDir
    RequiresExplicitInstallLocation = $RequiresExplicitInstallLocation
    InstallLocationSwitch           = '--root "<INSTALLPATH>"'
    Evidence                        = [pscustomobject]@{
      SourceRule  = 'CommandLineInterface::setTargetDir uses --root when supplied and otherwise uses the embedded TargetDir; an empty target fails targetDirWarning.'
      ConfigKey   = 'TargetDir'
      ConfigValue = $DefaultTargetDir
    }
  }
}

function Get-QtInstallerFrameworkUpgradeInfo {
  <#
  .SYNOPSIS
    Determine whether a Qt Installer Framework installer can overwrite an existing IFW installation
  .PARAMETER InstallerConfig
    The parsed installer config metadata
  .PARAMETER InstallLocationInfo
    Static Qt IFW install-location evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The parsed installer config metadata')]
    [AllowNull()]
    [pscustomobject]$InstallerConfig,

    [Parameter(HelpMessage = 'Static Qt IFW install-location evidence')]
    [AllowNull()]
    [pscustomobject]$InstallLocationInfo
  )

  $MaintenanceToolName = if ($InstallerConfig -and -not [string]::IsNullOrWhiteSpace($InstallerConfig.MaintenanceToolName)) {
    [string]$InstallerConfig.MaintenanceToolName
  } else {
    'maintenancetool'
  }
  $TargetDir = if ($InstallLocationInfo) { [string]$InstallLocationInfo.DefaultTargetDir } else { $null }
  # PackageManagerCore refuses a target containing its maintenance tool; it does not overwrite an
  # existing installation as an in-place upgrade.
  $ExistingInstallationMarker = if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    "<TARGETDIR>\$MaintenanceToolName.exe"
  } else {
    "$($TargetDir.TrimEnd('/', '\'))\$MaintenanceToolName.exe"
  }

  [pscustomobject]@{
    SupportsExistingInstallationOverride = $false
    ExistingInstallationMarker           = $ExistingInstallationMarker
    RecommendedUpgradeBehavior           = 'uninstallPrevious'
    Evidence                             = [pscustomobject]@{
      SourceRule          = 'PackageManagerCore::installationAllowedToDirectory returns false when the configured maintenance-tool executable exists in the target directory.'
      MaintenanceToolName = $MaintenanceToolName
    }
  }
}

function Get-QtInstallerFrameworkScopeInfo {
  <#
  .SYNOPSIS
    Determine IFW Apps and Features scope from source-compatible AllUsers behavior
  .PARAMETER InstallerConfig
    The parsed installer config metadata
  .PARAMETER TextResource
    Bounded text resources used as additional static evidence
  .PARAMETER InterfaceInfo
    Static Qt IFW CLI/GUI interface evidence
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(HelpMessage = 'The parsed installer config metadata')]
    [AllowNull()]
    [pscustomobject]$InstallerConfig,

    [Parameter(HelpMessage = 'Bounded text resources used as additional static evidence')]
    [object[]]$TextResource = @(),

    [Parameter(HelpMessage = 'Static Qt IFW CLI/GUI interface evidence')]
    [AllowNull()]
    [pscustomobject]$InterfaceInfo
  )

  if (-not $InstallerConfig) {
    return [pscustomobject]@{
      Scope                            = $null
      DefaultScope                     = $null
      SupportedScopes                  = @()
      SupportsUserScope                = $false
      SupportsMachineScope             = $false
      SupportsDualScope                = $false
      SupportsCommandLineScopeOverride = $false
      UserScopeSwitch                  = $null
      MachineScopeSwitch               = $null
      DisableCommandLineInterface      = $null
      Evidence                         = [pscustomobject]@{
        RegisterPathRule               = 'IFW registerPath writes HKLM only when AllUsers == true; otherwise it writes HKCU.'
        DefaultScopeReason             = 'No installer-config metadata was available.'
        AllUsersMentionSources         = @()
        AllUsersTrueAssignmentSources  = @()
        AllUsersFalseAssignmentSources = @()
        RequiresAdminRightsSources     = @()
      }
    }
  }

  $DisableCommandLineInterface = ConvertTo-QtInstallerFrameworkBoolean -Value $InstallerConfig.DisableCommandLineInterface
  # AllUsers determines whether IFW writes its registration under HKLM or HKCU. A functioning CLI
  # can override this value; resource mentions alone do not prove unconditional script behavior.
  $AllUsersRaw = if ($InstallerConfig.RawValues.Contains('AllUsers')) { $InstallerConfig.RawValues['AllUsers'] } else { $null }
  $AllUsersDefault = $AllUsersRaw -ceq 'true'
  $DefaultScope = if ($AllUsersDefault) { 'machine' } else { 'user' }
  $SupportsCommandLineScopeOverride = [bool]$InterfaceInfo.SupportsSilentInstallation -and -not $DisableCommandLineInterface
  $SupportedScopes = if ($SupportsCommandLineScopeOverride) { @('user', 'machine') } else { @($DefaultScope) }

  $AllUsersMentionSources = [System.Collections.Generic.List[string]]::new()
  $AllUsersTrueAssignmentSources = [System.Collections.Generic.List[string]]::new()
  $AllUsersFalseAssignmentSources = [System.Collections.Generic.List[string]]::new()
  $RequiresAdminRightsSources = [System.Collections.Generic.List[string]]::new()
  # Preserve script/config mentions as evidence for manual control-flow review without allowing
  # those strings to replace the explicit default from installer config.
  foreach ($Resource in @($TextResource)) {
    $Text = [string]$Resource.Text
    if ($Text -match '(?i)\bAllUsers\b') { $AllUsersMentionSources.Add([string]$Resource.Source) }
    if ($Text -match '(?i)\bAllUsers\s*=\s*["'']?true\b|setValue\s*\(\s*["'']AllUsers["'']\s*,\s*["'']true["'']\s*\)') {
      $AllUsersTrueAssignmentSources.Add([string]$Resource.Source)
    }
    if ($Text -match '(?i)\bAllUsers\s*=\s*["'']?false\b|setValue\s*\(\s*["'']AllUsers["'']\s*,\s*["'']false["'']\s*\)') {
      $AllUsersFalseAssignmentSources.Add([string]$Resource.Source)
    }
    if ($Text -match '(?i)<RequiresAdminRights>\s*true\s*</RequiresAdminRights>') {
      $RequiresAdminRightsSources.Add([string]$Resource.Source)
    }
  }

  [pscustomobject]@{
    Scope                            = $DefaultScope
    DefaultScope                     = $DefaultScope
    SupportedScopes                  = $SupportedScopes
    SupportsUserScope                = $SupportedScopes -contains 'user'
    SupportsMachineScope             = $SupportedScopes -contains 'machine'
    SupportsDualScope                = $SupportedScopes.Count -gt 1
    SupportsCommandLineScopeOverride = $SupportsCommandLineScopeOverride
    UserScopeSwitch                  = if ($SupportsCommandLineScopeOverride) { 'AllUsers=false' } else { $null }
    MachineScopeSwitch               = if ($SupportsCommandLineScopeOverride) { 'AllUsers=true' } else { $null }
    DisableCommandLineInterface      = $DisableCommandLineInterface
    Evidence                         = [pscustomobject]@{
      RegisterPathRule               = 'IFW registerPath writes HKLM only when AllUsers == true; otherwise it writes HKCU.'
      DefaultScopeReason             = if ($AllUsersDefault) { 'Embedded/user-defined AllUsers value is true.' } else { 'No embedded/user-defined AllUsers=true value was found; IFW defaults to HKCU ARP.' }
      AllUsersRawValue               = $AllUsersRaw
      AllUsersMentionSources         = @($AllUsersMentionSources | Select-Object -Unique)
      AllUsersTrueAssignmentSources  = @($AllUsersTrueAssignmentSources | Select-Object -Unique)
      AllUsersFalseAssignmentSources = @($AllUsersFalseAssignmentSources | Select-Object -Unique)
      RequiresAdminRightsSources     = @($RequiresAdminRightsSources | Select-Object -Unique)
      InterfaceVariant               = $InterfaceInfo.InterfaceVariant
      CommandLineInterface           = $InterfaceInfo.CommandLineInterface
    }
  }
}

function Get-QtInstallerFrameworkInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Context = Get-QtInstallerFrameworkAnalysisContext -Path $Path
    $File = Get-Item -LiteralPath $Context.Path -Force
    $Layout = $Context.Layout
    $FormatInfo = $Context.FormatInfo
    if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }
    if ($FormatInfo.MediaRole -ne 'Installer') { throw "Qt Installer Framework media role '$($FormatInfo.MediaRole)' is not an installer; use Get-QtInstallerFrameworkFormatInfo for diagnostics" }

    # Recover structured metadata first, then derive interface, install-root, upgrade, and scope
    # evidence from one shared config object.
    $MetadataResources = @($Context.MetadataResources)
    $TextResources = @($Context.TextResources)
    $InstallerXmlResource = @($MetadataResources | Where-Object { $_.Root -eq 'Installer' } | Select-Object -First 1)
    $InstallerConfig = if ($InstallerXmlResource) {
      $ConfigHandler = Get-QtInstallerFrameworkRouteHandler -Category Config -Route $FormatInfo.ConfigRoute
      & $ConfigHandler -Xml $InstallerXmlResource[0].Xml
    } else {
      $null
    }
    if ($InstallerConfig -and $FormatInfo.PackageIndexRoute -eq 'component-index-v1' -and [string]::IsNullOrWhiteSpace($InstallerConfig.ProductCode)) {
      # Qt IFW 1.x uses ProductName verbatim as the uninstall registry subkey. ProductUUID was
      # introduced with the 2.0 configuration generation.
      $InstallerConfig.ProductCode = $InstallerConfig.PackageName
    }
    $InterfaceHandler = Get-QtInstallerFrameworkRouteHandler -Category Interface -Route $FormatInfo.InterfaceRoute
    $InterfaceInfo = & $InterfaceHandler -Path $File.FullName -Layout $Layout -InstallerConfig $InstallerConfig -FormatInfo $FormatInfo
    $InstallLocationInfo = Get-QtInstallerFrameworkInstallLocationInfo -InstallerConfig $InstallerConfig -InterfaceInfo $InterfaceInfo
    $UpgradeInfo = Get-QtInstallerFrameworkUpgradeInfo -InstallerConfig $InstallerConfig -InstallLocationInfo $InstallLocationInfo
    $ScopeInfo = Get-QtInstallerFrameworkScopeInfo -InstallerConfig $InstallerConfig -TextResource $TextResources -InterfaceInfo $InterfaceInfo

    $Warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($Warning in @($FormatInfo.Warnings)) { $Warnings.Add([string]$Warning) }
    if (-not $InstallerConfig) {
      $Warnings.Add('No IFW installer-config/config.xml metadata was recovered from the embedded resources.')
    } elseif ($FormatInfo.PackageIndexRoute -ne 'component-index-v1' -and [string]::IsNullOrWhiteSpace($InstallerConfig.ProductCode)) {
      $Warnings.Add('No embedded ProductUUID was found. Qt IFW generates the Windows uninstall key at install time unless a script/config sets ProductUUID.')
    }
    foreach ($Warning in @($InterfaceInfo.Warnings)) { $Warnings.Add($Warning) }
    if ($InstallLocationInfo.RequiresExplicitInstallLocation -eq $true) {
      $Warnings.Add('The embedded TargetDir is empty, so command-line installation requires --root with an absolute installation path.')
    }
    if ($ScopeInfo.Evidence.AllUsersTrueAssignmentSources -or $ScopeInfo.Evidence.AllUsersFalseAssignmentSources) {
      $Warnings.Add('Static resources mention AllUsers assignments. Confirm conditional script control flow before relying on the default scope.')
    }

    # Qt IFW's installer configuration is the authoritative source for the
    # maintenance-tool uninstall identity. Emit that evidence explicitly.
    [pscustomobject][ordered]@{
      Path                                 = $File.FullName
      InstallerType                        = 'Qt Installer Framework'
      ProductCode                          = $InstallerConfig.ProductCode
      UpgradeCode                          = $null
      DisplayName                          = $InstallerConfig.DisplayName
      DisplayVersion                       = $InstallerConfig.DisplayVersion
      Publisher                            = $InstallerConfig.Publisher
      Scope                                = $ScopeInfo.Scope
      DefaultInstallLocation               = $InstallerConfig.TargetDir
      WritesAppsAndFeaturesEntry           = $true
      AppsAndFeaturesProductCode           = $InstallerConfig.ProductCode
      AppsAndFeaturesInstallerType         = 'exe'
      Warnings                             = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields                     = [string[]]@()
      BinaryMarker                         = $Layout.MagicMarkerName
      IsQtInstallerFramework               = $FormatInfo.IsQtInstallerFramework
      IsSupported                          = $FormatInfo.IsSupported
      FormatGeneration                     = $FormatInfo.FormatGeneration
      FormatProfileId                      = $FormatInfo.FormatProfileId
      FrameworkVersion                     = $FormatInfo.FrameworkVersion
      FrameworkVersionSource               = $FormatInfo.FrameworkVersionSource
      FrameworkVersionRange                = $FormatInfo.FrameworkVersionRange
      QtRuntimeVersion                     = $FormatInfo.QtRuntimeVersion
      MediaRole                            = $FormatInfo.MediaRole
      CookieKind                           = $FormatInfo.CookieKind
      TrailerRoute                         = $FormatInfo.TrailerRoute
      MetadataRoute                        = $FormatInfo.MetadataRoute
      PackageIndexRoute                    = $FormatInfo.PackageIndexRoute
      PayloadRoute                         = $FormatInfo.PayloadRoute
      ConfigRoute                          = $FormatInfo.ConfigRoute
      InterfaceRoute                       = $FormatInfo.InterfaceRoute
      VersionEvidenceRoute                 = $FormatInfo.VersionEvidenceRoute
      CatalogVersion                       = $FormatInfo.CatalogVersion
      SupportsProductUuid                  = $FormatInfo.SupportsProductUuid
      SupportsCommandLineInterface         = $FormatInfo.SupportsCommandLineInterface
      SupportsLibArchive                   = $FormatInfo.SupportsLibArchive
      PayloadAvailability                  = $FormatInfo.PayloadAvailability
      FormatCapabilities                   = $FormatInfo.Capabilities
      IsFallback                           = $FormatInfo.IsFallback
      FormatEvidence                       = $FormatInfo.Evidence
      InterfaceVariant                     = $InterfaceInfo.InterfaceVariant
      CommandLineInterface                 = $InterfaceInfo.CommandLineInterface
      HasCommandLineInterface              = $InterfaceInfo.HasCommandLineInterface
      CommandLineInterfaceEnabled          = $InterfaceInfo.CommandLineInterfaceEnabled
      SupportsSilentInstallation           = $InterfaceInfo.SupportsSilentInstallation
      DisableCommandLineInterface          = $InterfaceInfo.DisabledByConfig
      CommandLineInterfaceEvidence         = $InterfaceInfo.Evidence
      PESubsystem                          = $InterfaceInfo.Evidence.PESubsystem
      PackageName                          = $InstallerConfig.PackageName
      ProductUrl                           = $InstallerConfig.ProductUrl
      Title                                = $InstallerConfig.Title
      AdminTargetDir                       = $InstallerConfig.AdminTargetDir
      HasDefaultTargetDir                  = $InstallLocationInfo.HasDefaultTargetDir
      RequiresExplicitInstallLocation      = $InstallLocationInfo.RequiresExplicitInstallLocation
      InstallLocationSwitch                = $InstallLocationInfo.InstallLocationSwitch
      InstallLocationEvidence              = $InstallLocationInfo.Evidence
      SupportsExistingInstallationOverride = $UpgradeInfo.SupportsExistingInstallationOverride
      ExistingInstallationMarker           = $UpgradeInfo.ExistingInstallationMarker
      RecommendedUpgradeBehavior           = $UpgradeInfo.RecommendedUpgradeBehavior
      UpgradeEvidence                      = $UpgradeInfo.Evidence
      DefaultScope                         = $ScopeInfo.DefaultScope
      SupportedScopes                      = $ScopeInfo.SupportedScopes
      SupportsUserScope                    = $ScopeInfo.SupportsUserScope
      SupportsMachineScope                 = $ScopeInfo.SupportsMachineScope
      SupportsDualScope                    = $ScopeInfo.SupportsDualScope
      SupportsCommandLineScopeOverride     = $ScopeInfo.SupportsCommandLineScopeOverride
      UserScopeSwitch                      = $ScopeInfo.UserScopeSwitch
      MachineScopeSwitch                   = $ScopeInfo.MachineScopeSwitch
      ScopeEvidence                        = $ScopeInfo.Evidence
      StartMenuDir                         = $InstallerConfig.StartMenuDir
      MaintenanceToolName                  = $InstallerConfig.MaintenanceToolName
      MaintenanceToolIniFile               = $InstallerConfig.MaintenanceToolIniFile
      SupportsModify                       = $InstallerConfig.SupportsModify
      InstallerConfigSource                = if ($InstallerXmlResource) { $InstallerXmlResource[0].Source } else { $null }
      MetadataResourceCount                = $Layout.MetaResourceCount
      ResourceCollectionCount              = @($Context.PackageCollections).Count
      OperationCount                       = @($Context.Operations).Count
      Operations                           = @($Context.Operations)
      MetadataRoots                        = @($MetadataResources | Select-Object -ExpandProperty Root -Unique)
      RawInstallerConfig                   = $InstallerConfig.RawValues
      ParserVersionInfo                    = [pscustomobject]@{
        Parser                = 'Dumplings.QtInstallerFramework'
        BinaryLayout          = $FormatInfo.FormatGeneration
        FormatProfileId       = $FormatInfo.FormatProfileId
        FrameworkVersion      = $FormatInfo.FrameworkVersion
        FrameworkVersionRange = $FormatInfo.FrameworkVersionRange
        TrailerRoute          = $FormatInfo.TrailerRoute
        MetadataRoute         = $FormatInfo.MetadataRoute
        PackageIndexRoute     = $FormatInfo.PackageIndexRoute
        PayloadRoute          = $FormatInfo.PayloadRoute
        ConfigRoute           = $FormatInfo.ConfigRoute
        InterfaceRoute        = $FormatInfo.InterfaceRoute
        VersionEvidenceRoute  = $FormatInfo.VersionEvidenceRoute
        CatalogVersion        = $FormatInfo.CatalogVersion
        CookieSearch          = 'Last 1 MiB'
        ScopeRule             = 'PackageManagerCorePrivate::registerPath'
        InterfaceRule         = 'PE subsystem plus DisableCommandLineInterface; executable-prefix markers are corroborating evidence'
        SourceReference       = 'Qt Installer Framework binarycontent.cpp, binaryformat.cpp, rcc.cpp, main.cpp, commandlineinterface.cpp, packagemanagercore.cpp, packagemanagercore_p.cpp'
      }
    }
  }
}

function Test-QtInstallerFrameworkCLI {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer contains the modern command-line interface
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).InterfaceVariant -eq 'CLI'
  }
}

function Test-QtInstallerFrameworkSilentInstallation {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer supports its command-line silent installation path
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsSilentInstallation
  }
}

function Test-QtInstallerFrameworkRequiresInstallLocation {
  <#
  .SYNOPSIS
    Test whether Qt IFW silent installation requires an explicit --root path
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).RequiresExplicitInstallLocation -eq $true
  }
}

function Test-QtInstallerFrameworkSupportsExistingInstallationOverride {
  <#
  .SYNOPSIS
    Test whether Qt IFW can install over an existing IFW installation in the target directory
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsExistingInstallationOverride
  }
}

function Read-UpgradeBehaviorFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the recommended WinGet upgrade behavior for a Qt IFW installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).RecommendedUpgradeBehavior
  }
}

function Read-ProductVersionFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the product version from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayVersion)) { throw 'The Qt Installer Framework installer does not expose a Version value' }
    return $Info.DisplayVersion
  }
}

function Read-ProductNameFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the package name from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.PackageName)) { throw 'The Qt Installer Framework installer does not expose a Name value' }
    return $Info.PackageName
  }
}

function Read-PublisherFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the publisher from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Qt Installer Framework installer does not expose a Publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the ProductUUID/uninstall key from a Qt Installer Framework installer when statically embedded
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    $Info = Get-QtInstallerFrameworkInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Qt Installer Framework installer does not expose a deterministic ProductUUID value' }
    return $Info.ProductCode
  }
}

function Read-ScopeFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the default Apps and Features scope from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).DefaultScope
  }
}

function Read-SupportedScopesFromQtInstallerFramework {
  <#
  .SYNOPSIS
    Read the statically supported Apps and Features scopes from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportedScopes
  }
}

function Test-QtInstallerFrameworkDualScope {
  <#
  .SYNOPSIS
    Test whether a Qt Installer Framework installer exposes both user and machine ARP scope paths
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path
  )

  process {
    (Get-QtInstallerFrameworkInfo -Path $Path).SupportsDualScope
  }
}

Export-ModuleMember -Function Get-QtInstallerFrameworkBinaryLayout, Get-QtInstallerFrameworkFormatInfo, Get-QtInstallerFrameworkInfo, Expand-QtInstallerFramework, Test-QtInstallerFrameworkCLI, Test-QtInstallerFrameworkSilentInstallation, Test-QtInstallerFrameworkRequiresInstallLocation, Test-QtInstallerFrameworkSupportsExistingInstallationOverride, Read-UpgradeBehaviorFromQtInstallerFramework, Read-ProductVersionFromQtInstallerFramework, Read-ProductNameFromQtInstallerFramework, Read-PublisherFromQtInstallerFramework, Read-ProductCodeFromQtInstallerFramework, Read-ScopeFromQtInstallerFramework, Read-SupportedScopesFromQtInstallerFramework, Test-QtInstallerFrameworkDualScope
