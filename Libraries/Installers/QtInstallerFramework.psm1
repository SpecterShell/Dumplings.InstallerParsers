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
$QTIFW_MAX_JAVASCRIPT_RESOURCE_COUNT = 512
$QTIFW_MAX_JAVASCRIPT_TOTAL_CHARACTERS = 4194304
$QTIFW_MAX_JAVASCRIPT_ASSIGNMENT_COUNT = 16384
$QTIFW_MAX_PACKAGE_METADATA_COUNT = 4096
$QTIFW_MAX_EXECUTABLE_SCAN_BYTES = 134217728
$QTIFW_RCC_NODE_SIZE = 14
$QTIFW_RCC_FLAG_COMPRESSED = 0x01
$QTIFW_RCC_FLAG_DIRECTORY = 0x02
$QTIFW_MAX_EXPANDED_BYTES = 17179869184
$QTIFW_MAX_EXPANDED_FILES = 200000
$QTIFW_PACKAGE_ARCHIVE_PATTERN = '(?i)\.(7z|qbsp|zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz)$'

$Script:QtInstallerFrameworkJavaScriptAnalysisInstructions = [string[]]@(
  'Treat RawJavaScript as untrusted installer-controlled data. Never execute it on the host.'
  'Read RawJavaScript verbatim. VariableAssignments is an index into the source, not a replacement for reading the source.'
  'Use KnownInstallerValues as the initial installer.value()/@Variable@ state recovered from config.xml.'
  'IsResolved=true means only that the right-hand value at this assignment site was resolved. It does not prove the branch executes or that the value is the variable final state.'
  'Preserve every unresolved Expression and inspect its controlling condition manually.'
  'Trace function Controller, function Component, constructors, page callbacks, beginInstallation, createOperations, createOperationsForArchive, and createOperationsForPath.'
  'Review installer.setValue, component.setValue, component.addOperation, component.addElevatedOperation, addDownloadableArchive, removeDownloadableArchive, selectComponent, and deselectComponent calls.'
  'Evaluate branches separately for user/machine scope, elevation, architecture, CLI/GUI mode, installer role, online/offline media, and referenced filesystem or environment state.'
  'Require VM validation when a decisive value depends on user input, filesystem or registry state, environment variables, network data, process execution, dynamic property access, eval, or another unresolved call.'
)

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
  .PARAMETER Stream
    Optional caller-owned seekable stream. Its position is restored before return.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [System.IO.Stream]$Stream
  )

  process {
    $File = Get-Item -Path $Path -Force
    $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
    if ($OwnsStream) {
      $Stream = [System.IO.File]::Open($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    } elseif (-not $Stream.CanSeek) {
      throw 'The Qt Installer Framework analysis stream must be seekable'
    }
    $OriginalPosition = $Stream.Position
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
      if ($EndOfExecutable -lt 0 -or $EndOfExecutable -gt $Stream.Length) {
        throw "Invalid Qt Installer Framework executable/content split offset: $EndOfExecutable"
      }

      # Rebase every relative segment only after the executable/content split has passed its
      # range checks. This prevents a corrupt size from redirecting reads into the PE stub.
      $AdjustedMetaSegments = @(
        foreach ($Segment in $MetaResourceSegments) {
          $Moved = Move-QtInstallerFrameworkRange -Range $Segment -Offset $EndOfExecutable
          Assert-QtInstallerFrameworkRange -Range $Moved -FileLength $Stream.Length -Name 'meta resource'
          $Moved
        }
      )
      $AdjustedResourceCollectionSegment = Move-QtInstallerFrameworkRange -Range $ResourceCollectionsSegment -Offset $EndOfExecutable
      $AdjustedOperationsSegment = Move-QtInstallerFrameworkRange -Range $OperationsSegment -Offset $EndOfExecutable
      Assert-QtInstallerFrameworkRange -Range $AdjustedResourceCollectionSegment -FileLength $Stream.Length -Name 'resource collection'
      Assert-QtInstallerFrameworkRange -Range $AdjustedOperationsSegment -FileLength $Stream.Length -Name 'operation'

      [pscustomobject]@{
        Path                       = $File.FullName
        InstallerType              = 'exe'
        Family                     = 'Qt Installer Framework'
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
      if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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
  .PARAMETER Stream
    Optional caller-owned seekable stream. Its position is restored before return.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the Qt Installer Framework installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed IFW binary-content layout')]
    [pscustomobject]$Layout,

    [System.IO.Stream]$Stream
  )

  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [System.IO.Stream]$Stream
  )

  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function ConvertFrom-QtInstallerFrameworkOperationXml {
  <#
  .SYNOPSIS
    Decode the XML envelope serialized by KDUpdater::UpdateOperation::toXml.
  .PARAMETER Xml
    Bounded UTF-8 operation XML read from the performed-operations segment.
  .OUTPUTS
    Arguments used for the operation, arguments before the optional UNDOOPERATION marker, and typed value evidence. Complex QVariant values remain encoded because decoding Qt's QDataStream representation is unnecessary for effect projection.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyString()][string]$Xml)

  $ReaderSettings = [Xml.XmlReaderSettings]::new()
  $ReaderSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $ReaderSettings.XmlResolver = $null
  $ReaderSettings.MaxCharactersInDocument = $QTIFW_MAX_OPERATION_BYTES
  $StringReader = [IO.StringReader]::new($Xml)
  $Reader = [Xml.XmlReader]::Create($StringReader, $ReaderSettings)
  try {
    $Document = [Xml.XmlDocument]::new()
    $Document.XmlResolver = $null
    $Document.Load($Reader)
  } finally {
    $Reader.Dispose()
    $StringReader.Dispose()
  }

  if ($Document.DocumentElement.LocalName -cne 'operation') {
    throw "The Qt Installer Framework performed-operation XML root is '$($Document.DocumentElement.LocalName)', expected 'operation'"
  }

  $Arguments = [Collections.Generic.List[string]]::new()
  foreach ($Node in @($Document.SelectNodes('/operation/arguments/argument'))) {
    $Arguments.Add([string]$Node.InnerText)
  }
  $UndoIndex = $Arguments.IndexOf('UNDOOPERATION')
  $PerformArguments = if ($UndoIndex -ge 0) { @($Arguments.GetRange(0, $UndoIndex)) } else { @($Arguments) }

  $Values = [ordered]@{}
  $ValueRecords = [Collections.Generic.List[object]]::new()
  foreach ($Node in @($Document.SelectNodes('/operation/values/value'))) {
    $Name = [string]$Node.GetAttribute('name')
    $Type = [string]$Node.GetAttribute('type')
    $Text = [string]$Node.InnerText
    $IsEncoded = $Type -in @('QByteArray', 'QStringList', 'QVariant', 'QVariantHash', 'QVariantList', 'QVariantMap')
    $Value = if ($IsEncoded) {
      $Text
    } else {
      switch -Regex ($Type) {
        '^(bool|Boolean)$' { $Text -ceq 'true'; break }
        '^(char|short|int|long|long long|qlonglong|qint\d+|uchar|ushort|uint|ulong|ulong long|qulonglong|quint\d+)$' {
          $ParsedInteger = [long]0
          if ([long]::TryParse($Text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$ParsedInteger)) { $ParsedInteger } else { $Text }
          break
        }
        '^(double|float)$' {
          $ParsedNumber = [double]0
          if ([double]::TryParse($Text, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ParsedNumber)) { $ParsedNumber } else { $Text }
          break
        }
        default { $Text }
      }
    }
    if (-not [string]::IsNullOrWhiteSpace($Name)) { $Values[$Name] = $Value }
    $ValueRecords.Add([pscustomobject][ordered]@{
        Name      = $Name
        Type      = $Type
        Value     = $Value
        IsEncoded = $IsEncoded
        RawText   = $Text
      })
  }

  [pscustomobject][ordered]@{
    Arguments        = [string[]]$Arguments.ToArray()
    PerformArguments = [string[]]$PerformArguments
    IsUndoOperation  = $UndoIndex -ge 0
    Values           = $Values
    ValueRecords     = [object[]]$ValueRecords.ToArray()
  }
}

function Resolve-QtInstallerFrameworkRegistryTarget {
  <#
  .SYNOPSIS
    Normalize a QSettings native-format path and key into a Windows registry value target.
  .PARAMETER Path
    Registry hive plus key path used to construct QSettingsWrapper.
  .PARAMETER Key
    QSettings key. Slash-delimited groups become registry subkeys and the final segment becomes the value name.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Key
  )

  if ($Path -notmatch '^(?<Root>HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)[\\/]*(?<Key>.*)$') { return $null }
  $MatchedRoot = [string]$Matches.Root
  $MatchedKey = [string]$Matches.Key
  $Root = switch -Regex ($MatchedRoot) {
    '^(HKEY_LOCAL_MACHINE|HKLM)$' { 'HKLM'; break }
    '^(HKEY_CURRENT_USER|HKCU)$' { 'HKCU'; break }
    '^(HKEY_CLASSES_ROOT|HKCR)$' { 'HKCR'; break }
  }
  $RegistryKey = $MatchedKey.Replace('/', '\').Trim('\')
  $KeyParts = @($Key -split '[\\/]' | Where-Object { $_ -cne '' })
  if ($KeyParts.Count -eq 0) { return $null }
  if ($KeyParts.Count -gt 1) {
    $RegistryKey = @($RegistryKey, ($KeyParts[0..($KeyParts.Count - 2)] -join '\')) | Where-Object { $_ } | Join-String -Separator '\'
  }
  [pscustomobject][ordered]@{
    Root = $Root
    Key  = $RegistryKey
    Name = if ($KeyParts[-1] -ceq 'Default') { '' } else { $KeyParts[-1] }
  }
}

function New-QtInstallerFrameworkRegistryEffect {
  <#
  .SYNOPSIS
    Create normalized static registry-write evidence for a performed Qt IFW operation.
  .PARAMETER Operation
    Decoded operation that produced the write.
  .PARAMETER Root
    Normalized registry root.
  .PARAMETER Key
    Registry key relative to the root.
  .PARAMETER Name
    Registry value name; an empty string denotes the default value.
  .PARAMETER Value
    Literal value written by the operation.
  .PARAMETER Type
    Best available registry value type.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Operation,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Key,
    [AllowEmptyString()][string]$Name = '',
    [AllowNull()][object]$Value,
    [string]$Type = 'String'
  )

  [pscustomobject][ordered]@{
    Category       = 'Registry'
    Action         = 'SetValue'
    Root           = $Root
    Key            = $Key.Replace('/', '\').Trim('\')
    Name           = $Name
    Value          = $Value
    Type           = $Type
    OperationIndex = $Operation.Index
    OperationName  = $Operation.Name
  }
}

function ConvertTo-QtInstallerFrameworkOperationEffect {
  <#
  .SYNOPSIS
    Project one decoded performed operation into source-defined system effects.
  .PARAMETER Operation
    Operation returned by Get-QtInstallerFrameworkOperation.
  .PARAMETER Scope
    Installed scope used by Qt IFW when selecting HKCU or HKLM for scope-sensitive operations.
  .OUTPUTS
    Effect objects and warnings. Unknown operations remain available in Operations and are reported rather than guessed.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][psobject]$Operation,
    [ValidateSet('user', 'machine')][string]$Scope = 'user'
  )

  $Arguments = [string[]]@($Operation.PerformArguments)
  $Effects = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  $ScopedRoot = if ($Scope -eq 'machine') { 'HKLM' } else { 'HKCU' }
  $AddFileEffect = {
    param([string]$Action, [hashtable]$Properties)
    $Effect = [ordered]@{
      Category       = 'FileSystem'
      Action         = $Action
      OperationIndex = $Operation.Index
      OperationName  = $Operation.Name
    }
    foreach ($Pair in $Properties.GetEnumerator()) { $Effect[$Pair.Key] = $Pair.Value }
    $Effects.Add([pscustomobject]$Effect)
  }

  switch -CaseSensitive ($Operation.Name) {
    'Copy' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'CopyFile' @{ SourcePath = $Arguments[0]; DestinationPath = $Arguments[1] } } }
    'Move' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'MoveFile' @{ SourcePath = $Arguments[0]; DestinationPath = $Arguments[1] } } }
    'SimpleMoveFile' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'MoveFile' @{ SourcePath = $Arguments[0]; DestinationPath = $Arguments[1] } } }
    'Delete' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'DeleteFile' @{ Path = $Arguments[0] } } }
    'Mkdir' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'CreateDirectory' @{ Path = $Arguments[0] } } }
    'Rmdir' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'RemoveDirectory' @{ Path = $Arguments[0] } } }
    'CopyDirectory' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'CopyDirectory' @{ SourcePath = $Arguments[0]; DestinationPath = $Arguments[1]; ForceOverwrite = $Arguments.Count -gt 2 -and $Arguments[2] -ceq 'forceOverwrite' } } }
    'CreateLink' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'CreateLink' @{ Path = $Arguments[0]; TargetPath = $Arguments[1] } } }
    'Extract' { if ($Arguments.Count -ge 2) { & $AddFileEffect 'ExtractArchive' @{ ArchivePath = $Arguments[0]; DestinationPath = $Arguments[1] } } }
    'AppendFile' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'AppendFile' @{ Path = $Arguments[0] } } }
    'PrependFile' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'PrependFile' @{ Path = $Arguments[0] } } }
    'Replace' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'ReplaceText' @{ Path = $Arguments[0] } } }
    'LineReplace' { if ($Arguments.Count -ge 1) { & $AddFileEffect 'ReplaceLine' @{ Path = $Arguments[0] } } }
    'Settings' {
      $SettingsArguments = [ordered]@{}
      foreach ($Argument in $Arguments) {
        $Separator = $Argument.IndexOf('=')
        if ($Separator -gt 0) { $SettingsArguments[$Argument.Substring(0, $Separator)] = $Argument.Substring($Separator + 1) }
      }
      if ($SettingsArguments.path) {
        & $AddFileEffect 'ModifySettingsFile' @{
          Path       = $SettingsArguments.path
          Method     = $SettingsArguments.method
          SettingKey = $SettingsArguments.key
          Value      = $SettingsArguments.value
        }
      }
    }
    'CreateShortcut' {
      if ($Arguments.Count -ge 2) {
        $Shortcut = [pscustomobject][ordered]@{
          Category        = 'Shortcut'
          Action          = 'CreateShortcut'
          TargetPath      = $Arguments[0]
          ShortcutPath    = $Arguments[1]
          TargetArguments = if ($Arguments.Count -gt 2) { $Arguments[2] } else { $null }
          OperationIndex  = $Operation.Index
          OperationName   = $Operation.Name
        }
        $Effects.Add($Shortcut)
        & $AddFileEffect 'CreateShortcut' @{ Path = $Arguments[1]; TargetPath = $Arguments[0] }
      }
    }
    'RegisterFileType' {
      $MutableArguments = [Collections.Generic.List[string]]::new()
      foreach ($Argument in $Arguments) { $MutableArguments.Add($Argument) }
      $ProgId = $null
      for ($Index = $MutableArguments.Count - 1; $Index -ge 0; $Index--) {
        if ($MutableArguments[$Index].StartsWith('ProgId=', [StringComparison]::Ordinal)) {
          $ProgId = $MutableArguments[$Index].Substring(7)
          $MutableArguments.RemoveAt($Index)
        }
      }
      if ($MutableArguments.Count -ge 2) {
        $Extension = $MutableArguments[0].TrimStart('.')
        if ([string]::IsNullOrWhiteSpace($ProgId)) { $ProgId = "${Extension}_auto_file" }
        $ClassesRoot = 'Software\Classes'
        $ExtensionKey = "$ClassesRoot\.$Extension"
        $ProgIdKey = "$ClassesRoot\$ProgId"
        $ApplicationKey = "$ClassesRoot\Applications\$ProgId"
        $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key $ExtensionKey -Value $ProgId))
        $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key "$ExtensionKey\OpenWithProgIds" -Name $ProgId -Value ''))
        $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key "$ProgIdKey\shell\Open\Command" -Value $MutableArguments[1]))
        $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key "$ApplicationKey\shell\Open\Command" -Value $MutableArguments[1]))
        if ($MutableArguments.Count -gt 2 -and $MutableArguments[2]) { $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key $ProgIdKey -Value $MutableArguments[2])) }
        if ($MutableArguments.Count -gt 3 -and $MutableArguments[3]) { $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key $ExtensionKey -Name 'Content Type' -Value $MutableArguments[3])) }
        if ($MutableArguments.Count -gt 4 -and $MutableArguments[4]) { $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $ScopedRoot -Key "$ProgIdKey\DefaultIcon" -Value $MutableArguments[4])) }
      }
    }
    'EnvironmentVariable' {
      if ($Arguments.Count -ge 2) {
        $Persistent = $Arguments.Count -lt 3 -or $Arguments[2] -ceq 'true'
        $SystemWide = $Arguments.Count -gt 3 -and $Arguments[3] -ceq 'true'
        if ($Persistent) {
          $Root = if ($SystemWide) { 'HKLM' } else { 'HKCU' }
          $Key = if ($SystemWide) { 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' } else { 'Environment' }
          $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $Root -Key $Key -Name $Arguments[0] -Value $Arguments[1] -Type 'StringOrExpandString'))
        } else {
          $Effects.Add([pscustomobject][ordered]@{ Category = 'Environment'; Action = 'SetProcessVariable'; Name = $Arguments[0]; Value = $Arguments[1]; OperationIndex = $Operation.Index; OperationName = $Operation.Name })
        }
      }
    }
    'GlobalConfig' {
      $Target = $null
      $Value = $null
      if ($Arguments.Count -eq 3) {
        $Target = Resolve-QtInstallerFrameworkRegistryTarget -Path $Arguments[0] -Key $Arguments[1]
        $Value = $Arguments[2]
        if (-not $Target) { & $AddFileEffect 'ModifyNativeSettings' @{ Path = $Arguments[0]; SettingKey = $Arguments[1]; Value = $Value } }
      } elseif ($Arguments.Count -eq 4 -or $Arguments.Count -eq 5) {
        $Offset = if ($Arguments.Count -eq 5) { 1 } else { 0 }
        $Root = if ($Arguments.Count -eq 5 -and $Arguments[0] -ceq 'SystemScope') { 'HKLM' } else { 'HKCU' }
        $BasePath = "$Root\Software\$($Arguments[$Offset])\$($Arguments[$Offset + 1])"
        $Target = Resolve-QtInstallerFrameworkRegistryTarget -Path $BasePath -Key $Arguments[$Offset + 2]
        $Value = $Arguments[$Offset + 3]
      }
      if ($Target) { $Effects.Add((New-QtInstallerFrameworkRegistryEffect -Operation $Operation -Root $Target.Root -Key $Target.Key -Name $Target.Name -Value $Value)) }
    }
    'Execute' {
      if ($Arguments.Count -ge 1) {
        $Effects.Add([pscustomobject][ordered]@{ Category = 'Process'; Action = 'Execute'; Path = $Arguments[0]; Arguments = [string[]]@($Arguments | Select-Object -Skip 1); OperationIndex = $Operation.Index; OperationName = $Operation.Name })
        $Warnings.Add("Qt IFW operation $($Operation.Index) executes '$($Arguments[0])'; its side effects require payload inspection or VM validation.")
      }
    }
    default {
      $Warnings.Add("Qt IFW performed operation '$($Operation.Name)' is preserved but has no static effect projection.")
    }
  }

  if ($Effects.Count -eq 0 -and $Arguments.Count -eq 0) {
    $Warnings.Add("Qt IFW performed operation '$($Operation.Name)' has no usable arguments.")
  }
  [pscustomobject][ordered]@{
    Effects     = [object[]]$Effects.ToArray()
    Diagnostics = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata)
  }
}

function Get-QtInstallerFrameworkOperationEffectInfo {
  <#
  .SYNOPSIS
    Aggregate decoded Qt IFW operations into system-effect collections.
  .PARAMETER Operation
    Decoded performed operations.
  .PARAMETER Scope
    Installed scope used for scope-sensitive registry operations.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][object[]]$Operation,
    [ValidateSet('user', 'machine')][string]$Scope = 'user'
  )

  $Effects = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  foreach ($Item in @($Operation)) {
    $Projection = ConvertTo-QtInstallerFrameworkOperationEffect -Operation $Item -Scope $Scope
    foreach ($Effect in @($Projection.Effects)) { $Effects.Add($Effect) }
    foreach ($Warning in @($Projection.Diagnostics)) { $Warnings.Add($Warning) }
    $Item | Add-Member -NotePropertyName Effects -NotePropertyValue ([object[]]@($Projection.Effects)) -Force
    $Item | Add-Member -NotePropertyName Diagnostics -NotePropertyValue ([object[]]@($Projection.Diagnostics)) -Force
  }

  [pscustomobject][ordered]@{
    Effects            = [object[]]$Effects.ToArray()
    FileSystemEffects  = [object[]]@($Effects | Where-Object Category -CEQ 'FileSystem')
    RegistryWrites     = [object[]]@($Effects | Where-Object Category -CEQ 'Registry')
    ShortcutEffects    = [object[]]@($Effects | Where-Object Category -CEQ 'Shortcut')
    EnvironmentEffects = [object[]]@($Effects | Where-Object Category -CEQ 'Environment')
    ExecutionEffects   = [object[]]@($Effects | Where-Object Category -CEQ 'Process')
    Diagnostics        = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata))
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
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [System.IO.Stream]$Stream
  )

  $Segment = $Layout.OperationsSegment
  if ($Segment.Length -eq 0) { return @() }
  if ($Segment.Length -lt 16 -or $Segment.Length -gt $QTIFW_MAX_OPERATION_BYTES) {
    throw "Invalid Qt Installer Framework operations segment length: $($Segment.Length)"
  }

  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [IO.File]::Open((Get-Item -LiteralPath $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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
      $Decoded = ConvertFrom-QtInstallerFrameworkOperationXml -Xml $Data
      $Operations.Add([pscustomobject][ordered]@{
          Index            = $Index
          Name             = $Name
          Arguments        = [string[]]$Decoded.Arguments
          PerformArguments = [string[]]$Decoded.PerformArguments
          IsUndoOperation  = $Decoded.IsUndoOperation
          Values           = $Decoded.Values
          ValueRecords     = [object[]]$Decoded.ValueRecords
          RawXml           = $Data
          Data             = $Data
        })
    }
    if ($Cursor.Value + 8 -ne $Segment.End) {
      throw "The Qt Installer Framework operations segment was not consumed exactly: cursor=$($Cursor.Value) end=$($Segment.End)"
    }
    $TrailingCount = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
    if ($TrailingCount -ne $Count) { throw 'The Qt Installer Framework performed-operation count footer does not match its header' }
    return $Operations.ToArray()
  } finally {
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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
  foreach ($Pattern in @('<Installer\b[\s\S]*?</Installer>', '<Updates\b[\s\S]*?</Updates>', '<Package\b[\s\S]*?</Package>', '<PackageUpdate\b[\s\S]*?</PackageUpdate>')) {
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
    $RccResources = @(Get-QtInstallerFrameworkRccResource -Bytes $Bytes)
    foreach ($RccResource in $RccResources) {
      foreach ($Item in ConvertFrom-QtInstallerFrameworkTextData -Bytes $RccResource.Data -Source $RccResource.Path) {
        $Resources.Add($Item)
      }
    }
    # Once an RCC tree has been decoded, its named leaf resources are the evidence. Scanning the
    # parent container as UTF-8 would expose the complete binary RCC blob as a duplicate script.
    if ($RccResources.Count -gt 0) { return $Resources.ToArray() }
  } catch {
    # Some metadata resources are not RCC containers. Fall through to bounded text scanning.
  }

  $Text = [System.Text.Encoding]::UTF8.GetString($Bytes)
  $IsJavaScript = Test-QtInstallerFrameworkJavaScriptText -Text $Text -Source $Source
  if ($IsJavaScript -or $Text -match '(?i)\b(AllUsers|DisableCommandLineInterface|RequiresAdminRights|AdminTargetDir|TargetDir|ProductUUID)\b') {
    $Resources.Add([pscustomobject]@{
        Source = $Source
        Kind   = if ($IsJavaScript) { 'JavaScript' } else { 'TextEvidence' }
        Text   = $Text
      })
  }

  return $Resources.ToArray()
}

function Test-QtInstallerFrameworkJavaScriptText {
  <#
  .SYNOPSIS
    Identify a named Qt IFW controller or component JavaScript resource.
  .PARAMETER Text
    Decoded resource text. The caller retains ownership of the source bytes.
  .PARAMETER Source
    RCC or package resource path used as filename evidence.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string]$Text,

    [Parameter(Mandatory)]
    [string]$Source
  )

  if ($Source -match '(?i)\.(?:js|qs)$') { return $true }
  return $Text -match '(?m)^\s*function\s+(?:Controller|Component)\s*\('
}

function ConvertFrom-QtInstallerFrameworkJavaScriptStringLiteral {
  <#
  .SYNOPSIS
    Decode one bounded JavaScript single- or double-quoted string literal without executing code.
  .PARAMETER Expression
    Complete quoted literal, including its opening and closing quote.
  .OUTPUTS
    An object containing Success and Value. Unsupported escapes return Success=false.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Expression
  )

  if ($Expression.Length -lt 2) { return [pscustomobject]@{ Success = $false; Value = $null } }
  $Quote = $Expression[0]
  if (($Quote -ne [char]39 -and $Quote -ne [char]34) -or $Expression[$Expression.Length - 1] -ne $Quote) {
    return [pscustomobject]@{ Success = $false; Value = $null }
  }

  $Builder = [System.Text.StringBuilder]::new($Expression.Length - 2)
  for ($Index = 1; $Index -lt ($Expression.Length - 1); $Index++) {
    $Character = $Expression[$Index]
    if ($Character -ne [char]92) {
      # An unescaped matching quote before the final delimiter means this is a compound expression,
      # not one complete string literal (for example, "a" + "b").
      if ($Character -eq $Quote) { return [pscustomobject]@{ Success = $false; Value = $null } }
      $null = $Builder.Append($Character)
      continue
    }

    $Index++
    if ($Index -ge ($Expression.Length - 1)) { return [pscustomobject]@{ Success = $false; Value = $null } }
    $Escape = $Expression[$Index]
    switch ($Escape) {
      "'" { $null = $Builder.Append([char]39) }
      '"' { $null = $Builder.Append([char]34) }
      '\' { $null = $Builder.Append([char]92) }
      'b' { $null = $Builder.Append([char]8) }
      'f' { $null = $Builder.Append([char]12) }
      'n' { $null = $Builder.Append("`n") }
      'r' { $null = $Builder.Append("`r") }
      't' { $null = $Builder.Append("`t") }
      'v' { $null = $Builder.Append([char]11) }
      '0' {
        if (($Index + 1) -lt ($Expression.Length - 1) -and [char]::IsDigit($Expression[$Index + 1])) {
          return [pscustomobject]@{ Success = $false; Value = $null }
        }
        $null = $Builder.Append([char]0)
      }
      'x' {
        if (($Index + 2) -ge $Expression.Length) { return [pscustomobject]@{ Success = $false; Value = $null } }
        $Hex = $Expression.Substring($Index + 1, 2)
        if ($Hex -notmatch '^[0-9A-Fa-f]{2}$') { return [pscustomobject]@{ Success = $false; Value = $null } }
        $null = $Builder.Append([char][Convert]::ToUInt16($Hex, 16))
        $Index += 2
      }
      'u' {
        if (($Index + 4) -ge $Expression.Length) { return [pscustomobject]@{ Success = $false; Value = $null } }
        $Hex = $Expression.Substring($Index + 1, 4)
        if ($Hex -notmatch '^[0-9A-Fa-f]{4}$') { return [pscustomobject]@{ Success = $false; Value = $null } }
        $null = $Builder.Append([char][Convert]::ToUInt16($Hex, 16))
        $Index += 4
      }
      default { return [pscustomobject]@{ Success = $false; Value = $null } }
    }
  }

  return [pscustomobject]@{ Success = $true; Value = $Builder.ToString() }
}

function Resolve-QtInstallerFrameworkJavaScriptValue {
  <#
  .SYNOPSIS
    Resolve a JavaScript expression only when it is a literal, known variable, or known IFW value.
  .PARAMETER Expression
    Verbatim right-hand-side expression from one assignment.
  .PARAMETER VariableState
    Case-sensitive map of assignments resolved earlier in source order.
  .PARAMETER InstallerValues
    Values recovered from installer config.xml and available through installer.value().
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)]
    [string]$Expression,

    [Parameter(Mandatory)]
    [System.Collections.Generic.Dictionary[string, object]]$VariableState,

    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$InstallerValues
  )

  $Candidate = $Expression.Trim()
  if ($Candidate.Length -ge 2 -and $Candidate[0] -in @([char]39, [char]34)) {
    $StringValue = ConvertFrom-QtInstallerFrameworkJavaScriptStringLiteral -Expression $Candidate
    if ($StringValue.Success) {
      return [pscustomobject]@{ IsResolved = $true; Value = $StringValue.Value; ValueType = 'String'; ResolutionSource = 'Literal' }
    }
  }
  if ($Candidate -ceq 'true' -or $Candidate -ceq 'false') {
    return [pscustomobject]@{ IsResolved = $true; Value = ($Candidate -ceq 'true'); ValueType = 'Boolean'; ResolutionSource = 'Literal' }
  }
  if ($Candidate -ceq 'null') {
    return [pscustomobject]@{ IsResolved = $true; Value = $null; ValueType = 'Null'; ResolutionSource = 'Literal' }
  }
  if ($Candidate -match '^[+-]?0[xX](?<hex>[0-9A-Fa-f]+)$') {
    try {
      $HexValue = [Convert]::ToInt64($Matches.hex, 16)
      if ($Candidate[0] -eq '-') { $HexValue = - $HexValue }
      return [pscustomobject]@{ IsResolved = $true; Value = $HexValue; ValueType = 'Number'; ResolutionSource = 'Literal' }
    } catch {
      # Oversized numeric literals remain unresolved instead of failing the complete installer parse.
    }
  }
  if ($Candidate -match '^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$') {
    $Integer = [int64]0
    if ($Candidate -match '^[+-]?\d+$' -and [int64]::TryParse($Candidate, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$Integer)) {
      return [pscustomobject]@{ IsResolved = $true; Value = $Integer; ValueType = 'Number'; ResolutionSource = 'Literal' }
    }
    $Number = [double]0
    if ([double]::TryParse($Candidate, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$Number)) {
      return [pscustomobject]@{ IsResolved = $true; Value = $Number; ValueType = 'Number'; ResolutionSource = 'Literal' }
    }
  }
  if ($Candidate -match '^(?<receiver>installer|component)\.value\(\s*(?<name>["''][^"'']*["''])\s*\)$') {
    $NameValue = ConvertFrom-QtInstallerFrameworkJavaScriptStringLiteral -Expression $Matches.name
    if ($NameValue.Success -and $InstallerValues.Contains([string]$NameValue.Value)) {
      return [pscustomobject]@{ IsResolved = $true; Value = $InstallerValues[[string]$NameValue.Value]; ValueType = 'String'; ResolutionSource = "$($Matches.receiver).value/config.xml" }
    }
  }
  if ($Candidate -match '^(?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$' -and $VariableState.ContainsKey($Candidate)) {
    $PriorValue = $VariableState[$Candidate]
    if ($PriorValue.IsResolved) {
      return [pscustomobject]@{ IsResolved = $true; Value = $PriorValue.Value; ValueType = $PriorValue.ValueType; ResolutionSource = "Variable:$Candidate" }
    }
  }

  return [pscustomobject]@{ IsResolved = $false; Value = $null; ValueType = $null; ResolutionSource = $null }
}

function Get-QtInstallerFrameworkJavaScriptVariableAssignment {
  <#
  .SYNOPSIS
    Index conservative, single-line JavaScript assignments in source order.
  .PARAMETER Text
    Verbatim JavaScript source. It is not modified or executed.
  .PARAMETER InstallerValues
    Values recovered from installer config.xml for safe installer.value() resolution.
  .OUTPUTS
    Assignment records with the raw expression and an optional statically resolved value.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)]
    [string]$Text,

    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$InstallerValues
  )

  # Replace comments and template-string bodies with spaces while retaining every original offset.
  # Regex matches against this lexical mask, then expressions are sliced from the untouched source.
  $MaskCharacters = $Text.ToCharArray()
  $State = 'Code'
  $Escaped = $false
  for ($Index = 0; $Index -lt $MaskCharacters.Length; $Index++) {
    $Character = $MaskCharacters[$Index]
    $Next = if (($Index + 1) -lt $MaskCharacters.Length) { $MaskCharacters[$Index + 1] } else { [char]0 }
    $HandledLexicalState = $false
    switch ($State) {
      'LineComment' {
        $HandledLexicalState = $true
        if ($Character -eq "`r" -or $Character -eq "`n") { $State = 'Code' } else { $MaskCharacters[$Index] = ' ' }
      }
      'BlockComment' {
        $HandledLexicalState = $true
        if ($Character -eq '*' -and $Next -eq '/') {
          $MaskCharacters[$Index] = ' '
          $MaskCharacters[$Index + 1] = ' '
          $Index++
          $State = 'Code'
        } elseif ($Character -ne "`r" -and $Character -ne "`n") {
          $MaskCharacters[$Index] = ' '
        }
      }
      'Template' {
        $HandledLexicalState = $true
        if ($Character -ne "`r" -and $Character -ne "`n") { $MaskCharacters[$Index] = 'x' }
        if ($Escaped) {
          $Escaped = $false
        } elseif ($Character -eq [char]92) {
          $Escaped = $true
        } elseif ($Character -eq [char]96) {
          $State = 'Code'
        }
      }
      'SingleQuote' {
        $HandledLexicalState = $true
        if ($Escaped) {
          $Escaped = $false
        } elseif ($Character -eq [char]92) {
          $Escaped = $true
        } elseif ($Character -eq [char]39) {
          $State = 'Code'
        }
        if ($State -ne 'Code' -and $Character -ne "`r" -and $Character -ne "`n") { $MaskCharacters[$Index] = 'x' }
      }
      'DoubleQuote' {
        $HandledLexicalState = $true
        if ($Escaped) {
          $Escaped = $false
        } elseif ($Character -eq [char]92) {
          $Escaped = $true
        } elseif ($Character -eq [char]34) {
          $State = 'Code'
        }
        if ($State -ne 'Code' -and $Character -ne "`r" -and $Character -ne "`n") { $MaskCharacters[$Index] = 'x' }
      }
    }
    if ($HandledLexicalState) { continue }

    if ($Character -eq '/' -and $Next -eq '/') {
      $MaskCharacters[$Index] = ' '
      $MaskCharacters[$Index + 1] = ' '
      $Index++
      $State = 'LineComment'
    } elseif ($Character -eq '/' -and $Next -eq '*') {
      $MaskCharacters[$Index] = ' '
      $MaskCharacters[$Index + 1] = ' '
      $Index++
      $State = 'BlockComment'
    } elseif ($Character -eq [char]39) {
      $State = 'SingleQuote'
    } elseif ($Character -eq [char]34) {
      $State = 'DoubleQuote'
    } elseif ($Character -eq [char]96) {
      $MaskCharacters[$Index] = 'x'
      $State = 'Template'
    }
  }

  $MaskedText = [string]::new($MaskCharacters)
  $Pattern = '(?m)^[\t ]*(?:(?<declaration>var|let|const)\s+)?(?<name>(?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*=(?!=|>)\s*(?<expression>[^\r\n;]+)\s*;?'
  $AssignmentMatches = [regex]::Matches($MaskedText, $Pattern)
  if ($AssignmentMatches.Count -gt $QTIFW_MAX_JAVASCRIPT_ASSIGNMENT_COUNT) {
    throw "The Qt Installer Framework JavaScript contains more than $QTIFW_MAX_JAVASCRIPT_ASSIGNMENT_COUNT indexed assignments"
  }

  $Assignments = [System.Collections.Generic.List[object]]::new($AssignmentMatches.Count)
  $VariableState = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
  $Line = 1
  $LineScanOffset = 0
  foreach ($Match in $AssignmentMatches) {
    while (($NewLineOffset = $Text.IndexOf("`n", $LineScanOffset, [System.StringComparison]::Ordinal)) -ge 0 -and $NewLineOffset -lt $Match.Index) {
      $Line++
      $LineScanOffset = $NewLineOffset + 1
    }

    $Name = $Match.Groups['name'].Value
    $ExpressionGroup = $Match.Groups['expression']
    $MaskedExpression = $ExpressionGroup.Value
    $LeadingWhitespace = $MaskedExpression.Length - $MaskedExpression.TrimStart().Length
    $ExpressionLength = $MaskedExpression.Trim().Length
    $Expression = if ($ExpressionLength -gt 0) { $Text.Substring($ExpressionGroup.Index + $LeadingWhitespace, $ExpressionLength) } else { '' }
    $Resolved = Resolve-QtInstallerFrameworkJavaScriptValue -Expression $Expression -VariableState $VariableState -InstallerValues $InstallerValues
    $Assignment = [pscustomobject][ordered]@{
      Name             = $Name
      DeclarationKind  = if ($Match.Groups['declaration'].Success) { $Match.Groups['declaration'].Value } else { 'Assignment' }
      Expression       = $Expression
      IsResolved       = [bool]$Resolved.IsResolved
      Value            = $Resolved.Value
      ValueType        = $Resolved.ValueType
      ResolutionSource = $Resolved.ResolutionSource
      Line             = $Line
    }
    $Assignments.Add($Assignment)
    $VariableState[$Name] = $Assignment
  }

  return $Assignments.ToArray()
}

function Get-QtInstallerFrameworkJavaScriptInfo {
  <#
  .SYNOPSIS
    Project verbatim Qt IFW scripts with an assistive variable index and review instructions.
  .PARAMETER TextResource
    Named text resources recovered from RCC and package metadata.
  .PARAMETER InstallerValues
    Raw installer config values that form the initial Qt IFW variable state.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [object[]]$TextResource,

    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$InstallerValues
  )

  $Scripts = [System.Collections.Generic.List[object]]::new()
  $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $TotalCharacters = 0
  foreach ($Resource in $TextResource) {
    $Text = [string]$Resource.Text
    $Source = [string]$Resource.Source
    if ($Resource.Kind -ne 'JavaScript' -and -not (Test-QtInstallerFrameworkJavaScriptText -Text $Text -Source $Source)) { continue }
    if (-not $Seen.Add("$Source`0$Text")) { continue }

    $TotalCharacters += $Text.Length
    if ($TotalCharacters -gt $QTIFW_MAX_JAVASCRIPT_TOTAL_CHARACTERS) {
      throw "The Qt Installer Framework JavaScript resources exceed the $QTIFW_MAX_JAVASCRIPT_TOTAL_CHARACTERS-character limit"
    }
    if ($Scripts.Count -ge $QTIFW_MAX_JAVASCRIPT_RESOURCE_COUNT) {
      throw "The Qt Installer Framework installer contains more than $QTIFW_MAX_JAVASCRIPT_RESOURCE_COUNT JavaScript resources"
    }

    $Role = if ($Text -match '(?m)^\s*function\s+Controller\s*\(') {
      'Controller'
    } elseif ($Text -match '(?m)^\s*function\s+Component\s*\(' -or $Source -match '(?i)(?:^|[/\\])installscript\.(?:js|qs)$') {
      'Component'
    } elseif ($InstallerValues.Contains('ControlScript') -and $Source -match "(?i)(?:^|[/\\])$([regex]::Escape([string]$InstallerValues['ControlScript']))(?:\.(?:js|qs))?$") {
      'Controller'
    } else {
      'Unknown'
    }

    $Scripts.Add([pscustomobject][ordered]@{
        Source              = $Source
        Role                = $Role
        RawJavaScript       = $Text
        VariableAssignments = @(Get-QtInstallerFrameworkJavaScriptVariableAssignment -Text $Text -InstallerValues $InstallerValues)
      })
  }

  return $Scripts.ToArray()
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

    [AllowEmptyCollection()][object[]]$Collection,

    [string]$PackageIndexRoute = 'resource-collection-v1',

    [System.IO.Stream]$Stream
  )

  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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
    $Collections = if ($PSBoundParameters.ContainsKey('Collection')) { @($Collection) } elseif ($PackageIndexRoute -eq 'resource-collection-v1') { @(Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout -Stream $Stream) } else { @() }
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
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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

    [AllowEmptyCollection()][object[]]$Collection,

    [string]$PackageIndexRoute = 'resource-collection-v1',

    [System.IO.Stream]$Stream
  )

  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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

    $Collections = if ($PSBoundParameters.ContainsKey('Collection')) { @($Collection) } elseif ($PackageIndexRoute -eq 'resource-collection-v1') { @(Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout -Stream $Stream) } else { @() }
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
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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

function Read-QtInstallerFrameworkRepositoryManifest {
  <#
  .SYNOPSIS
    Read a bounded local Qt IFW repository Updates.xml document.
  .PARAMETER Path
    Repository directory or explicit Updates.xml path. Network URLs are intentionally unsupported.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Resolved = Resolve-InstallerFileSystemPath -Path $Path
  $UpdatesPath = if (Test-Path -LiteralPath $Resolved -PathType Container) { Join-Path $Resolved 'Updates.xml' } else { $Resolved }
  $UpdatesPath = Resolve-InstallerFileSystemPath -Path $UpdatesPath -PathType Leaf
  $File = Get-Item -LiteralPath $UpdatesPath -Force
  if ($File.Length -gt $QTIFW_MAX_XML_SCAN_BYTES) { throw "Qt IFW repository metadata exceeds the $QTIFW_MAX_XML_SCAN_BYTES-byte limit: $UpdatesPath" }
  $Settings = [Xml.XmlReaderSettings]::new()
  $Settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
  $Settings.XmlResolver = $null
  $Reader = [Xml.XmlReader]::Create($UpdatesPath, $Settings)
  try {
    $Document = [Xml.XmlDocument]::new()
    $Document.XmlResolver = $null
    $Document.Load($Reader)
  } finally {
    $Reader.Dispose()
  }
  if ($Document.DocumentElement.LocalName -ne 'Updates') { throw "The Qt IFW repository metadata root is not Updates: $UpdatesPath" }
  $Resource = [pscustomobject]@{ Xml = $Document; Root = 'Updates'; Source = $UpdatesPath }
  [pscustomobject][ordered]@{
    RootPath = (Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($UpdatesPath)) -Force).FullName
    Path     = $UpdatesPath
    Packages = [object[]]@(Get-QtInstallerFrameworkPackageManifestInfo -Resource @($Resource) -SourceKind Repository)
  }
}

function Resolve-QtInstallerFrameworkExternalPackageSource {
  <#
  .SYNOPSIS
    Resolve caller-provided repository roots and package files to bounded local archives.
  .PARAMETER RepositoryPath
    Local Qt IFW repository roots or Updates.xml files.
  .PARAMETER PackagePath
    Explicit package archive files or directories containing package archives.
  .PARAMETER PackageMetadata
    Embedded package declarations used to resolve explicit package directories.
  .OUTPUTS
    Resolved archive path, package name, declared archive name, and evidence source.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [string[]]$RepositoryPath,
    [string[]]$PackagePath,
    [object[]]$PackageMetadata = @()
  )

  $Sources = [Collections.Generic.List[object]]::new()
  $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $AddSource = {
    param([string]$Candidate, [string]$PackageName, [string]$ArchiveName, [string]$SourceKind)
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) { return }
    $ResolvedCandidate = (Get-Item -LiteralPath $Candidate -Force).FullName
    if ([string]$ResolvedCandidate -notmatch $QTIFW_PACKAGE_ARCHIVE_PATTERN -or -not $Seen.Add($ResolvedCandidate)) { return }
    $Sources.Add([pscustomobject][ordered]@{
        Path        = $ResolvedCandidate
        PackageName = $PackageName
        ArchiveName = if ([string]::IsNullOrWhiteSpace($ArchiveName)) { [IO.Path]::GetFileName($ResolvedCandidate) } else { $ArchiveName }
        SourceKind  = $SourceKind
      })
  }

  foreach ($RepositoryItem in @($RepositoryPath)) {
    if ([string]::IsNullOrWhiteSpace($RepositoryItem)) { continue }
    $Repository = Read-QtInstallerFrameworkRepositoryManifest -Path $RepositoryItem
    foreach ($Package in @($Repository.Packages)) {
      foreach ($Reference in @($Package.ArchiveReferences)) {
        $RelativePath = ([string]$Reference.RelativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $Candidate = [IO.Path]::GetFullPath((Join-Path $Repository.RootPath $RelativePath))
        $RootPrefix = $Repository.RootPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $Candidate.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
          throw "Qt IFW repository archive path escapes its repository root: $($Reference.RelativePath)"
        }
        & $AddSource $Candidate $Package.Name $Reference.Name 'Repository'
      }
    }
  }

  foreach ($PackageItem in @($PackagePath)) {
    if ([string]::IsNullOrWhiteSpace($PackageItem)) { continue }
    $ResolvedPackageItem = Resolve-InstallerFileSystemPath -Path $PackageItem
    if (Test-Path -LiteralPath $ResolvedPackageItem -PathType Leaf) {
      & $AddSource $ResolvedPackageItem $null ([IO.Path]::GetFileName($ResolvedPackageItem)) 'ExplicitPackage'
      continue
    }
    $Directory = (Get-Item -LiteralPath $ResolvedPackageItem -Force).FullName
    if ($PackageMetadata.Count -gt 0) {
      foreach ($Package in @($PackageMetadata)) {
        foreach ($Reference in @($Package.ArchiveReferences)) {
          foreach ($RelativePath in @($Reference.RelativePath, $Reference.VersionedName, $Reference.Name)) {
            if ([string]::IsNullOrWhiteSpace([string]$RelativePath)) { continue }
            $Candidate = [IO.Path]::GetFullPath((Join-Path $Directory ([string]$RelativePath).Replace('/', [IO.Path]::DirectorySeparatorChar)))
            $RootPrefix = $Directory.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
            if ($Candidate.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) { & $AddSource $Candidate $Package.Name $Reference.Name 'ExplicitPackageDirectory' }
          }
        }
      }
    } else {
      $VisitedFileCount = 0
      $CandidateFileCount = 0
      foreach ($CandidatePath in [IO.Directory]::EnumerateFiles($Directory, '*', [IO.SearchOption]::AllDirectories)) {
        $VisitedFileCount++
        if ($VisitedFileCount -gt $QTIFW_MAX_EXPANDED_FILES) { throw "The Qt IFW external package directory contains more than $QTIFW_MAX_EXPANDED_FILES files" }
        $CandidateFile = [IO.FileInfo]::new($CandidatePath)
        if ($CandidateFile.Name -notmatch $QTIFW_PACKAGE_ARCHIVE_PATTERN) { continue }
        $CandidateFileCount++
        if ($CandidateFileCount -gt $QTIFW_MAX_RESOURCE_COUNT) { throw "The Qt IFW external package directory contains more than $QTIFW_MAX_RESOURCE_COUNT archives" }
        & $AddSource $CandidateFile.FullName $CandidateFile.Directory.Name $CandidateFile.Name 'ExplicitPackageDirectory'
      }
    }
  }
  return $Sources.ToArray()
}

function Open-QtInstallerFrameworkPackageArchive {
  <#
  .SYNOPSIS
    Open one Qt IFW package archive through the source-defined suffix route.
  .DESCRIPTION
    Qt IFW's libarchive backend treats gzip, bzip2, and xz as filters around a TAR archive. SharpCompress's generic factory does not consistently recurse through those filters, so this helper unwraps the filter into a bounded seekable stream before opening the TAR catalog. A .qbsp file is a 7z archive with a Qt-specific suffix.
  .PARAMETER Path
    Resolved package-archive path.
  .PARAMETER MaximumArchiveBytes
    Maximum decompressed TAR stream size before parsing archive entries.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumArchiveBytes
  )

  Import-QtInstallerFrameworkSharpCompress
  $ResolvedPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $LowerName = [IO.Path]::GetFileName($ResolvedPath).ToLowerInvariant()
  $Filter = if ($LowerName.EndsWith('.tar.gz') -or $LowerName.EndsWith('.tgz')) {
    'GZip'
  } elseif ($LowerName.EndsWith('.tar.bz2') -or $LowerName.EndsWith('.tbz2')) {
    'BZip2'
  } elseif ($LowerName.EndsWith('.tar.xz') -or $LowerName.EndsWith('.txz')) {
    'Xz'
  } else {
    $null
  }

  if (-not $Filter) {
    return [pscustomobject]@{
      Archive  = [SharpCompress.Archives.ArchiveFactory]::Open($ResolvedPath)
      Source   = $null
      Filter   = $null
      Seekable = $null
      Format   = if ($LowerName.EndsWith('.qbsp')) { 'qbsp/7z' } else { [IO.Path]::GetExtension($LowerName).TrimStart('.') }
    }
  }

  $Source = [IO.File]::Open($ResolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $FilterStream = switch ($Filter) {
      'GZip' { [IO.Compression.GZipStream]::new($Source, [IO.Compression.CompressionMode]::Decompress, $true) }
      'BZip2' { New-InstallerDecompressionStream -Algorithm BZip2 -Stream $Source -LeaveOpen }
      'Xz' { [SharpCompress.Compressors.Xz.XZStream]::new($Source) }
    }
    try {
      $Seekable = New-InstallerSeekableStream -SourceStream $FilterStream -MaximumBytes $MaximumArchiveBytes
      try {
        $ReaderOptions = [SharpCompress.Readers.ReaderOptions]::new()
        $Archive = [SharpCompress.Archives.Tar.TarArchive]::Open($Seekable.Stream, $ReaderOptions)
        return [pscustomobject]@{
          Archive  = $Archive
          Source   = $Source
          Filter   = $FilterStream
          Seekable = $Seekable
          Format   = "tar.$($Filter.ToLowerInvariant())"
        }
      } catch {
        $Seekable.Dispose()
        throw
      }
    } catch {
      $FilterStream.Dispose()
      throw
    }
  } catch {
    $Source.Dispose()
    throw
  }
}

function Close-QtInstallerFrameworkPackageArchive {
  <#
  .SYNOPSIS
    Dispose a package archive and every owned filter or spill stream in dependency order.
  .PARAMETER Context
    Context returned by Open-QtInstallerFrameworkPackageArchive.
  #>
  param ([Parameter(Mandatory)][psobject]$Context)

  if ($Context.Archive) { $Context.Archive.Dispose() }
  if ($Context.Seekable) { $Context.Seekable.Dispose() }
  if ($Context.Filter) { $Context.Filter.Dispose() }
  if ($Context.Source) { $Context.Source.Dispose() }
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

    [AllowEmptyCollection()][System.Collections.Generic.ISet[string]]$ReservedPath,

    [Parameter(Mandatory, HelpMessage = 'The maximum number of expanded bytes')]
    [long]$MaximumExpandedBytes
  )

  $Path = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  if (-not $ReservedPath) { $ReservedPath = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
  $ArchiveContext = Open-QtInstallerFrameworkPackageArchive -Path $Path -MaximumArchiveBytes $QTIFW_MAX_EXPANDED_BYTES
  $Archive = $ArchiveContext.Archive
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
    Close-QtInstallerFrameworkPackageArchive -Context $ArchiveContext
  }
}

function Expand-QtInstallerFrameworkContent {
  <#
  .SYNOPSIS
    Expand one already-open Qt IFW executable or DAT content source.
  .PARAMETER Stream
    Caller-owned seekable stream. The helper does not dispose it.
  .PARAMETER Layout
    Validated binary layout for the stream.
  .PARAMETER FormatInfo
    Catalog result containing package collections and the payload route.
  .OUTPUTS
    Number of files and bytes written from this content source.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][pscustomobject]$FormatInfo,
    [Parameter(Mandatory)][string]$DestinationPath,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction,
    [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.ISet[string]]$ReservedPath,
    [Parameter(Mandatory)][long]$MaximumExpandedBytes
  )

  $PayloadHandler = Get-QtInstallerFrameworkRouteHandler -Category Payload -Route $FormatInfo.PayloadRoute
  $WrittenFileCount = 0
  $WrittenBytes = [long]0
  $MetaIndex = 0
  foreach ($Segment in @($Layout.MetaResourceSegments)) {
    $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Segment.Start -Count $Segment.Length
    try { $RccResources = @(Get-QtInstallerFrameworkRccResource -Bytes $Bytes) } catch { $RccResources = @() }
    if ($RccResources) {
      foreach ($Resource in $RccResources) {
        $RelativePath = ([string]$Resource.Path).TrimStart(':', '/', '\')
        if (-not (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name)) { continue }
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPath
        if (-not $Target.ShouldWrite) { continue }
        $WrittenBytes += $Resource.Data.Length
        if ($WrittenBytes -gt $MaximumExpandedBytes) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
        $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
        [IO.File]::WriteAllBytes($Target.Path, $Resource.Data)
        $WrittenFileCount++
        if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) { throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount" }
      }
    } else {
      $RelativePath = "metadata/QResources/$MetaIndex.rcc"
      if (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPath
        if ($Target.ShouldWrite) {
          $WrittenBytes += $Bytes.Length
          if ($WrittenBytes -gt $MaximumExpandedBytes) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          [IO.File]::WriteAllBytes($Target.Path, $Bytes)
          $WrittenFileCount++
        }
      }
    }
    $MetaIndex++
  }

  foreach ($Collection in @($FormatInfo.PackageCollections)) {
    foreach ($Resource in @($Collection.Resources)) {
      if ($Resource.Segment.Length -gt $MaximumExpandedBytes) { throw "The Qt Installer Framework resource '$($Resource.Name)' exceeds the $MaximumExpandedBytes-byte limit" }
      $TemporaryArchivePath = [IO.Path]::GetTempFileName()
      try {
        $TemporaryStream = [IO.File]::Open($TemporaryArchivePath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
        try { $null = Copy-QtInstallerFrameworkSegment -SourceStream $Stream -Segment $Resource.Segment -DestinationStream $TemporaryStream } finally { $TemporaryStream.Dispose() }
        $RawRelativePath = if ($FormatInfo.PackageIndexRoute -eq 'component-index-v1') { "packages/$($Collection.Name)/$($Resource.Name)" } else { "metadata/$($Collection.Name)/$($Resource.Name)" }
        if (Test-QtInstallerFrameworkExtractionMatch -Path $RawRelativePath -Name $Name) {
          $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RawRelativePath -CollisionAction $CollisionAction -ReservedPath $ReservedPath
          if ($Target.ShouldWrite) {
            $WrittenBytes += $Resource.Segment.Length
            if ($WrittenBytes -gt $MaximumExpandedBytes) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
            $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
            [IO.File]::Copy($TemporaryArchivePath, $Target.Path, $true)
            $WrittenFileCount++
          }
        }
        if ([string]$Resource.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN) {
          $ArchiveRoot = "packages/$($Collection.Name)/$([IO.Path]::GetFileNameWithoutExtension([string]$Resource.Name))"
          $RemainingExpandedBytes = $MaximumExpandedBytes - $WrittenBytes
          if ($RemainingExpandedBytes -le 0) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
          $ArchiveResult = & $PayloadHandler -Path $TemporaryArchivePath -DestinationPath $DestinationPath -RelativeRoot $ArchiveRoot -Name $Name -CollisionAction $CollisionAction -ReservedPath $ReservedPath -MaximumExpandedBytes $RemainingExpandedBytes
          $WrittenBytes += $ArchiveResult.Bytes
          $WrittenFileCount += @($ArchiveResult.Files).Count
        }
        if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) { throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount" }
      } finally {
        Remove-Item -LiteralPath $TemporaryArchivePath -Force -ErrorAction SilentlyContinue
      }
    }
  }

  [pscustomobject]@{ Bytes = $WrittenBytes; FileCount = $WrittenFileCount }
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
  .PARAMETER DataPath
    Paired Qt IFW DAT binary-content files to parse and extract with the installer.
  .PARAMETER RepositoryPath
    Local Qt IFW repository roots or Updates.xml files. The parser never downloads repositories.
  .PARAMETER PackagePath
    Explicit package archives or directories containing package archives.
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
    [string]$CollisionAction = 'Prompt',

    [string[]]$DataPath,

    [string[]]$RepositoryPath,

    [string[]]$PackagePath
  )

  process {
    # Parse and validate the trailer once, then keep one installer stream open for all segment
    # copies. Nested archive readers receive isolated temporary files because they require seeking.
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $WrittenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $WrittenFileCount = 0
    $WrittenBytes = [long]0
    $InstallerStream = [System.IO.File]::Open($InstallerPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
      $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath -Stream $InstallerStream
      if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }
      $PELayout = try { Get-PELayout -Stream $InstallerStream } catch { $null }
      $FormatInfo = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout -Stream $InstallerStream -PELayout $PELayout
      if (-not $FormatInfo.IsSupported) { throw (@($FormatInfo.Diagnostics).Message -join ' ') }

      if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
        $DestinationPath = Join-Path ([System.IO.Path]::GetTempPath()) "Dumplings-QtIFW-$([System.Guid]::NewGuid())"
      }
      $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
      $DestinationPath = (New-Item -Path $DestinationPath -ItemType Directory -Force).FullName

      $PrimaryResult = Expand-QtInstallerFrameworkContent -Stream $InstallerStream -Layout $Layout -FormatInfo $FormatInfo -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -ReservedPath $WrittenPaths -MaximumExpandedBytes $MaximumExpandedBytes
      $WrittenBytes = $PrimaryResult.Bytes
      $WrittenFileCount = $PrimaryResult.FileCount
    } finally {
      $InstallerStream.Dispose()
    }

    # A paired DAT file has the same trailer and resource catalogs as an executable, but no PE
    # launcher. Parse each caller-provided DAT once and account its output against the same limits.
    foreach ($DataItem in @($DataPath)) {
      if ([string]::IsNullOrWhiteSpace($DataItem)) { continue }
      $ResolvedDataPath = Resolve-InstallerFileSystemPath -Path $DataItem -PathType Leaf
      if ($ResolvedDataPath -eq $InstallerPath) { continue }
      $DataStream = [IO.File]::Open($ResolvedDataPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $DataLayout = Get-QtInstallerFrameworkBinaryLayout -Path $ResolvedDataPath -Stream $DataStream
        if ($DataLayout.CookieKind -ne 'Data') { throw "The external Qt IFW data path does not contain a DAT cookie: $ResolvedDataPath" }
        # Paired DAT files inherit the launcher's format profile. They usually omit the launcher's
        # version marker and configuration RCC, so resolving them as standalone media would lose
        # the exact profile evidence already validated on the executable.
        $DataPackageIndexHandler = Get-QtInstallerFrameworkRouteHandler -Category PackageIndex -Route $FormatInfo.PackageIndexRoute
        $DataCollections = @(& $DataPackageIndexHandler -Path $ResolvedDataPath -Layout $DataLayout -Stream $DataStream)
        $DataFormatInfo = $FormatInfo.PSObject.Copy()
        $DataFormatInfo.PackageCollections = $DataCollections
        $RemainingExpandedBytes = $MaximumExpandedBytes - $WrittenBytes
        if ($RemainingExpandedBytes -le 0) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
        $DataResult = Expand-QtInstallerFrameworkContent -Stream $DataStream -Layout $DataLayout -FormatInfo $DataFormatInfo -DestinationPath $DestinationPath -Name $Name -CollisionAction $CollisionAction -ReservedPath $WrittenPaths -MaximumExpandedBytes $RemainingExpandedBytes
        $WrittenBytes += $DataResult.Bytes
        $WrittenFileCount += $DataResult.FileCount
      } finally {
        $DataStream.Dispose()
      }
    }

    # Resolve Qt repository paths exactly as the runtime does: <component>/<version><archive>.
    # Explicit package files are also accepted for media whose Updates.xml is unavailable.
    $ExternalSources = @(Resolve-QtInstallerFrameworkExternalPackageSource -RepositoryPath $RepositoryPath -PackagePath $PackagePath -PackageMetadata @($FormatInfo.PackageMetadata))
    if (($RepositoryPath -or $PackagePath) -and $ExternalSources.Count -eq 0) {
      throw 'No Qt Installer Framework package archives were resolved from the caller-provided repository or package paths'
    }
    foreach ($ExternalSource in $ExternalSources) {
      $ArchiveName = [IO.Path]::GetFileName([string]$ExternalSource.Path)
      $PackageName = if ([string]::IsNullOrWhiteSpace([string]$ExternalSource.PackageName)) { 'external' } else { [string]$ExternalSource.PackageName }
      $RawRelativePath = "packages/$PackageName/$ArchiveName"
      if (Test-QtInstallerFrameworkExtractionMatch -Path $RawRelativePath -Name $Name) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RawRelativePath -CollisionAction $CollisionAction -ReservedPath $WrittenPaths
        if ($Target.ShouldWrite) {
          $Length = (Get-Item -LiteralPath $ExternalSource.Path -Force).Length
          $WrittenBytes += $Length
          if ($WrittenBytes -gt $MaximumExpandedBytes) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
          $null = New-Item -Path ([IO.Path]::GetDirectoryName($Target.Path)) -ItemType Directory -Force
          [IO.File]::Copy($ExternalSource.Path, $Target.Path, $true)
          $WrittenFileCount++
        }
      }
      $ArchiveRoot = "packages/$PackageName/$([IO.Path]::GetFileNameWithoutExtension([string]$ExternalSource.ArchiveName))"
      $RemainingExpandedBytes = $MaximumExpandedBytes - $WrittenBytes
      if ($RemainingExpandedBytes -le 0) { throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit" }
      $ArchiveResult = Expand-QtInstallerFrameworkPackageArchive -Path $ExternalSource.Path -DestinationPath $DestinationPath -RelativeRoot $ArchiveRoot -Name $Name -CollisionAction $CollisionAction -ReservedPath $WrittenPaths -MaximumExpandedBytes $RemainingExpandedBytes
      $WrittenBytes += $ArchiveResult.Bytes
      $WrittenFileCount += @($ArchiveResult.Files).Count
      if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) { throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount" }
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
  .PARAMETER Stream
    Caller-owned seekable stream shared by the analysis context.
  .PARAMETER PELayout
    Optional PE layout already parsed from Stream.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [System.IO.Stream]$Stream,
    [AllowNull()][pscustomobject]$PELayout
  )

  $FrameworkVersion = $null
  $QtRuntimeVersion = $null
  $MatchedText = $null
  $ScanLength = [Math]::Min([int64]$Layout.EndOfExecutable, [int64]$QTIFW_MAX_EXECUTABLE_SCAN_BYTES)
  $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
  if ($OwnsStream) { $Stream = [IO.File]::Open((Get-Item -Path $Path -Force).FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) }
  $OriginalPosition = $Stream.Position
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
      if (-not $PELayout) { $PELayout = Get-PELayout -Stream $Stream }
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
    if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function Get-QtInstallerFrameworkPackageManifestInfo {
  <#
  .SYNOPSIS
    Project source-defined Package and Updates XML into package payload declarations.
  .PARAMETER Resource
    Parsed XML resources recovered from the installer or a repository Updates.xml file.
  .PARAMETER SourceKind
    Evidence origin used to distinguish embedded metadata from a caller-provided repository.
  .OUTPUTS
    Package records containing component identity, version, virtual state, and version-prefixed archive paths used by Qt IFW repositories.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource,
    [ValidateSet('Embedded', 'Repository')][string]$SourceKind = 'Embedded'
  )

  $Packages = [Collections.Generic.List[object]]::new()
  $SeenPackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($Item in @($Resource)) {
    if (-not $Item -or -not $Item.Xml) { continue }
    $Root = $Item.Xml.DocumentElement
    if (-not $Root) { continue }
    $Nodes = switch ($Root.LocalName) {
      'Updates' { @($Root.ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element -and $_.LocalName -eq 'PackageUpdate' }) }
      'Package' { @($Root) }
      'PackageUpdate' { @($Root) }
      default { @() }
    }
    foreach ($Node in $Nodes) {
      if ($Packages.Count -ge $QTIFW_MAX_PACKAGE_METADATA_COUNT) {
        throw "Qt Installer Framework package metadata exceeds the $QTIFW_MAX_PACKAGE_METADATA_COUNT-record limit"
      }
      $Values = [ordered]@{}
      foreach ($Child in @($Node.ChildNodes)) {
        if ($Child.NodeType -ne [Xml.XmlNodeType]::Element) { continue }
        if (-not $Values.Contains($Child.LocalName)) { $Values[$Child.LocalName] = $Child.InnerText.Trim() }
      }
      $Name = [string]$Values['Name']
      $Version = [string]$Values['Version']
      $ArchiveNames = [Collections.Generic.List[string]]::new()
      foreach ($ArchiveName in ([string]$Values['DownloadableArchives'] -split ',')) {
        $TrimmedName = $ArchiveName.Trim()
        if (-not [string]::IsNullOrWhiteSpace($TrimmedName)) { $ArchiveNames.Add($TrimmedName) }
      }
      $ArchiveReferences = [Collections.Generic.List[object]]::new()
      foreach ($ArchiveName in $ArchiveNames) {
        $VersionedName = "$Version$ArchiveName"
        $ArchiveReferences.Add([pscustomobject][ordered]@{
            Name          = $ArchiveName
            VersionedName = $VersionedName
            RelativePath  = if ([string]::IsNullOrWhiteSpace($Name)) { $VersionedName } else { "$Name/$VersionedName" }
          })
      }
      $PackageKey = "$SourceKind`0$([string]$Item.Source)`0$Name`0$Version`0$($ArchiveNames -join ',')"
      if (-not $SeenPackages.Add($PackageKey)) { continue }
      $UpdateFile = @($Node.ChildNodes | Where-Object { $_.NodeType -eq [Xml.XmlNodeType]::Element -and $_.LocalName -eq 'UpdateFile' } | Select-Object -First 1)
      $Packages.Add([pscustomobject][ordered]@{
          Name                 = $Name
          Version              = $Version
          DisplayName          = [string]$Values['DisplayName']
          Virtual              = ConvertTo-QtInstallerFrameworkBoolean -Value ([string]$Values['Virtual'])
          DownloadableArchives = [string[]]$ArchiveNames.ToArray()
          ArchiveReferences    = [object[]]$ArchiveReferences.ToArray()
          CompressedSize       = if ($UpdateFile) { [string]$UpdateFile[0].GetAttribute('CompressedSize') } else { $null }
          UncompressedSize     = if ($UpdateFile) { [string]$UpdateFile[0].GetAttribute('UncompressedSize') } else { $null }
          Source               = [string]$Item.Source
          SourceKind           = $SourceKind
          DocumentKind         = $Node.LocalName
          RawValues            = $Values
        })
    }
  }
  return $Packages.ToArray()
}

function Get-QtInstallerFrameworkRepositoryUrl {
  <#
  .SYNOPSIS
    Read source-defined RemoteRepositories URLs from installer configuration XML.
  .PARAMETER Resource
    Parsed embedded XML resources.
  #>
  [OutputType([string[]])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resource)

  $Urls = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Item in @($Resource)) {
    if (-not $Item.Xml -or $Item.Xml.DocumentElement.LocalName -ne 'Installer') { continue }
    foreach ($Node in @($Item.Xml.SelectNodes("//*[local-name()='RemoteRepositories']/*[local-name()='Repository']/*[local-name()='Url']"))) {
      $Value = $Node.InnerText.Trim()
      if (-not [string]::IsNullOrWhiteSpace($Value)) { $null = $Urls.Add($Value) }
    }
  }
  return [string[]]@($Urls)
}

function Get-QtInstallerFrameworkPayloadAvailabilityInfo {
  <#
  .SYNOPSIS
    Classify where Qt IFW package data lives using structured package and repository evidence.
  .PARAMETER Path
    Resolved executable or DAT path.
  .PARAMETER Layout
    Parsed Qt IFW binary layout.
  .PARAMETER Collection
    Parsed embedded package collections.
  .PARAMETER PackageMetadata
    Parsed Package or PackageUpdate records.
  .PARAMETER RepositoryUrl
    Remote repository URLs declared by installer configuration.
  .PARAMETER HasDynamicDownloadableArchive
    Indicates that component JavaScript may add archives at runtime.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Collection,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$PackageMetadata,
    [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RepositoryUrl,
    [bool]$HasDynamicDownloadableArchive
  )

  $EmbeddedArchiveCount = @($Collection | ForEach-Object Resources | Where-Object { [string]$_.Name -match $QTIFW_PACKAGE_ARCHIVE_PATTERN }).Count
  $DeclaredArchives = @($PackageMetadata | ForEach-Object ArchiveReferences)
  $SidecarCandidates = [Collections.Generic.List[string]]::new()
  $File = Get-Item -LiteralPath $Path -Force
  foreach ($Candidate in @(
      [IO.Path]::ChangeExtension($File.FullName, '.dat')
    )) {
    if ($Candidate -ne $File.FullName -and (Test-Path -LiteralPath $Candidate -PathType Leaf)) { $SidecarCandidates.Add((Get-Item -LiteralPath $Candidate -Force).FullName) }
  }

  $HasOnlinePackages = $RepositoryUrl.Count -gt 0 -or $HasDynamicDownloadableArchive -or @($PackageMetadata | Where-Object DocumentKind -EQ 'PackageUpdate').Count -gt 0
  $HasSidecarData = $Layout.CookieKind -eq 'Data' -or $SidecarCandidates.Count -gt 0
  $HasPackageMetadata = $PackageMetadata.Count -gt 0
  $AllDeclaredEmpty = $HasPackageMetadata -and $DeclaredArchives.Count -eq 0 -and -not $HasDynamicDownloadableArchive
  $Availability = if ($EmbeddedArchiveCount -gt 0) {
    'Embedded'
  } elseif ($HasSidecarData) {
    'SidecarData'
  } elseif ($HasOnlinePackages) {
    'OnlinePackages'
  } elseif ($DeclaredArchives.Count -gt 0 -or -not $HasPackageMetadata) {
    'MissingFiles'
  } elseif ($AllDeclaredEmpty) {
    'IntentionallyEmpty'
  } else {
    'MissingFiles'
  }

  [pscustomobject][ordered]@{
    Availability                  = $Availability
    EmbeddedPackageArchiveCount   = $EmbeddedArchiveCount
    DeclaredPackageArchiveCount   = $DeclaredArchives.Count
    HasOnlinePackages             = $HasOnlinePackages
    HasSidecarData                = $HasSidecarData
    HasMissingFiles               = $Availability -eq 'MissingFiles'
    IsIntentionallyEmpty          = $Availability -eq 'IntentionallyEmpty'
    SidecarCandidates             = [string[]]$SidecarCandidates.ToArray()
    RepositoryUrls                = [string[]]$RepositoryUrl
    DeclaredArchiveReferences     = [object[]]$DeclaredArchives
    MissingArchiveReferences      = if ($Availability -eq 'MissingFiles') { [object[]]$DeclaredArchives } else { [object[]]@() }
    HasDynamicDownloadableArchive = $HasDynamicDownloadableArchive
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
  .PARAMETER Stream
    Caller-owned stream used by every candidate package-index route.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][pscustomobject]$VersionEvidence,
    [System.IO.Stream]$Stream
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
      $Collections = @(& $HandlerName -Path $Path -Layout $Layout -Stream $Stream)
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
    foreach ($Segment in @($Layout.MetaResourceSegments)) {
      if ($Segment.Length -gt $QTIFW_MAX_TEXT_EVIDENCE_BYTES) { continue }
      $null = $ConfigText.Append([Text.Encoding]::Latin1.GetString((Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Segment.Start -Count $Segment.Length)))
    }
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
  .PARAMETER Stream
    Caller-owned stream shared by all route readers.
  .PARAMETER PELayout
    Cached PE layout, or null for DAT content.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [AllowNull()][pscustomobject]$PELayout
  )

  $VersionEvidence = Get-QtInstallerFrameworkVersionEvidence -Path $Path -Layout $Layout -Stream $Stream -PELayout $PELayout
  $ResolutionError = $null
  try {
    $Resolution = Resolve-QtInstallerFrameworkFormatProfile -Path $Path -Layout $Layout -VersionEvidence $VersionEvidence -Stream $Stream
  } catch {
    $ResolutionError = $_.Exception.Message
    $ComparableVersion = ConvertTo-QtInstallerFrameworkComparableVersion -Version $VersionEvidence.FrameworkVersion
    $Compatibility = if ($ComparableVersion -and $ComparableVersion -lt [version]'2.0.0') { $Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Legacy } else { $Script:QtInstallerFrameworkCatalog.CompatibilityProfiles.Modern }
    $Resolution = [pscustomobject]@{ Profile = [pscustomobject]$Compatibility; Collections = @(); SelectionEvidence = 'No package-index route validated completely.' }
  }
  $Operations = @()
  if (-not $ResolutionError) {
    try {
      $Operations = @(Get-QtInstallerFrameworkOperation -Path $Path -Layout $Layout -Stream $Stream)
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
  $Warnings = [System.Collections.Generic.List[object]]::new()
  if (-not $VersionEvidence.FrameworkVersion) {
    $Warnings.Add('No source-defined Qt IFW version marker was found; the framework version is reported as a structurally validated range.')
  }
  if ($VersionEvidence.ScanWasLimited) { $Warnings.Add('The launcher version scan reached its bounded limit before the complete executable prefix was inspected.') }
  if ($SelectedProfile.IsFallback) { $Warnings.Add('The Qt IFW media uses a structurally compatible fallback profile; release-specific capabilities require review.') }
  if ($ResolutionError) { $Warnings.Add("The Qt IFW format route is unsupported or malformed: $ResolutionError") }
  if ($Layout.MagicMarkerName -ne 'Installer') { $Warnings.Add("The Qt IFW media role is '$($Layout.MagicMarkerName)', not Installer; manifest metadata projection is diagnostic only.") }

  $MetadataResources = @()
  $TextResources = @()
  if (-not $ResolutionError) {
    $MetadataHandler = Get-QtInstallerFrameworkRouteHandler -Category Metadata -Route $SelectedProfile.MetadataRoute
    $MetadataResources = @(& $MetadataHandler -Path $Path -Layout $Layout -Collection @($Resolution.Collections) -PackageIndexRoute $SelectedProfile.PackageIndexRoute -Stream $Stream)
    $TextResources = @(Get-QtInstallerFrameworkMetadataTextResource -Path $Path -Layout $Layout -Collection @($Resolution.Collections) -PackageIndexRoute $SelectedProfile.PackageIndexRoute -Stream $Stream)
  }
  $PackageMetadata = @(Get-QtInstallerFrameworkPackageManifestInfo -Resource $MetadataResources)
  $RepositoryUrls = @(Get-QtInstallerFrameworkRepositoryUrl -Resource $MetadataResources)
  $HasDynamicDownloadableArchive = @($TextResources | Where-Object { [string]$_.Text -match '\baddDownloadableArchive\s*\(' }).Count -gt 0
  $PayloadInfo = Get-QtInstallerFrameworkPayloadAvailabilityInfo -Path $Path -Layout $Layout -Collection @($Resolution.Collections) -PackageMetadata $PackageMetadata -RepositoryUrl $RepositoryUrls -HasDynamicDownloadableArchive $HasDynamicDownloadableArchive
  if (-not $ResolutionError) {
    switch ($PayloadInfo.Availability) {
      'OnlinePackages' { $Warnings.Add('Package payloads are supplied by the configured online repository and are not embedded in this media.') }
      'SidecarData' { $Warnings.Add('Package payloads are stored in a separate Qt IFW DAT sidecar; provide it to Expand-QtInstallerFramework with -DataPath.') }
      'MissingFiles' { $Warnings.Add('Package metadata declares or implies external payload files, but no embedded, sidecar, or online repository source was resolved.') }
      'IntentionallyEmpty' { $Warnings.Add('Package metadata is present but declares no package archives; this media is intentionally payload-free.') }
    }
  }

  if ($VersionEvidence.FrameworkVersion -and $VersionEvidence.PEFileVersion) {
    $Embedded = ConvertTo-QtInstallerFrameworkComparableVersion $VersionEvidence.FrameworkVersion
    $PE = ConvertTo-QtInstallerFrameworkComparableVersion $VersionEvidence.PEFileVersion
    if ($Embedded -and $PE -and ($Embedded.Major -ne $PE.Major -or $Embedded.Minor -ne $PE.Minor)) {
      $Warnings.Add("The embedded IFW version '$($VersionEvidence.FrameworkVersion)' conflicts with PE FileVersion '$($VersionEvidence.PEFileVersion)'; the embedded source marker takes precedence.")
    }
  }
  $PESubsystem = try { Get-QtInstallerFrameworkPESubsystemInfo -Path $Path -PELayout $PELayout } catch { $null }

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
    PayloadAvailability          = $PayloadInfo.Availability
    PayloadAvailabilityEvidence  = $PayloadInfo
    PackageMetadata              = [object[]]$PackageMetadata
    RepositoryUrls               = [string[]]$RepositoryUrls
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
      EmbeddedPackageArchiveCount = $PayloadInfo.EmbeddedPackageArchiveCount
      DeclaredPackageArchiveCount = $PayloadInfo.DeclaredPackageArchiveCount
      OperationCount              = $Operations.Count
      ProfileSelection            = $Resolution.SelectionEvidence
    }
    Diagnostics                  = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata)
    Layout                       = $Layout
    PackageCollections           = @($Resolution.Collections)
    Operations                   = @($Operations)
    MetadataResources            = @($MetadataResources)
    TextResources                = @($TextResources)
  }
}

function Get-QtInstallerFrameworkFormatInfo {
  <#
  .SYNOPSIS
    Identify the Qt IFW binary generation, framework version, media role, and parser routes.
  .PARAMETER Path
    Path to a Qt IFW executable or DAT binary.
  .OUTPUTS
    Format routes, version evidence, package declarations, repository URLs, and precise payload availability without internal stream-bound parse objects.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $Stream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
      $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath -Stream $Stream
      if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }
      $PELayout = try { Get-PELayout -Stream $Stream } catch { $null }
      $Result = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout -Stream $Stream -PELayout $PELayout
      # Internal parse objects are deliberately omitted from the public diagnostic contract.
      foreach ($PropertyName in @('Layout', 'PackageCollections', 'Operations', 'MetadataResources', 'TextResources')) { $Result.PSObject.Properties.Remove($PropertyName) }
      return $Result
    } finally {
      $Stream.Dispose()
    }
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
  $Stream = [IO.File]::Open($InstallerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath -Stream $Stream
    $PELayout = try { Get-PELayout -Stream $Stream } catch { $null }
    $FormatInfo = Get-QtInstallerFrameworkFormatInfoInternal -Path $InstallerPath -Layout $Layout -Stream $Stream -PELayout $PELayout
    if (-not $FormatInfo.IsSupported) { throw (@($FormatInfo.Diagnostics).Message -join ' ') }
    $MetadataResources = @($FormatInfo.MetadataResources)
    $InstallerXmlResource = @($MetadataResources | Where-Object { $_.Root -eq 'Installer' } | Select-Object -First 1)
    $InstallerConfig = if ($InstallerXmlResource) {
      $ConfigHandler = Get-QtInstallerFrameworkRouteHandler -Category Config -Route $FormatInfo.ConfigRoute
      & $ConfigHandler -Xml $InstallerXmlResource[0].Xml
    } else {
      $null
    }
    if ($InstallerConfig -and $FormatInfo.PackageIndexRoute -eq 'component-index-v1' -and [string]::IsNullOrWhiteSpace($InstallerConfig.ProductCode)) {
      $InstallerConfig.ProductCode = $InstallerConfig.PackageName
    }
    $InterfaceHandler = Get-QtInstallerFrameworkRouteHandler -Category Interface -Route $FormatInfo.InterfaceRoute
    $InterfaceInfo = & $InterfaceHandler -Path $InstallerPath -Layout $Layout -InstallerConfig $InstallerConfig -FormatInfo $FormatInfo -Stream $Stream -PELayout $PELayout
    [pscustomobject]@{
      Path                 = $InstallerPath
      Layout               = $Layout
      PELayout             = $PELayout
      FormatInfo           = $FormatInfo
      PackageCollections   = @($FormatInfo.PackageCollections)
      Operations           = @($FormatInfo.Operations)
      MetadataResources    = $MetadataResources
      TextResources        = @($FormatInfo.TextResources)
      InstallerXmlResource = if ($InstallerXmlResource) { $InstallerXmlResource[0] } else { $null }
      InstallerConfig      = $InstallerConfig
      InterfaceInfo        = $InterfaceInfo
    }
  } finally {
    $Stream.Dispose()
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
    [string]$Path,

    [AllowNull()][pscustomobject]$PELayout
  )

  if (-not $PELayout) { return Get-PESubsystemInfo -Path $Path }
  [pscustomobject]@{
    Path        = $Path
    Subsystem   = $PELayout.Subsystem
    Name        = $PELayout.SubsystemName
    IsGui       = $PELayout.Subsystem -eq 2
    IsConsole   = $PELayout.Subsystem -in 3, 5, 7
    IsWindowsPE = $PELayout.Subsystem -in 2, 3
  }
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
  .PARAMETER Stream
    Optional caller-owned stream used for bounded launcher marker scanning.
  .PARAMETER PELayout
    Optional cached PE layout used for subsystem evidence.
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
    [pscustomobject]$FormatInfo,

    [System.IO.Stream]$Stream,

    [AllowNull()]
    [pscustomobject]$PELayout
  )

  if (-not $Layout) { $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $Path }
  $RequiredOptionMarkers = @('accept-licenses', 'default-answer', 'confirm-command')
  $CommandMarkers = @('check-updates', 'create-offline', 'clear-cache')
  $FoundMarkers = [System.Collections.Generic.List[string]]::new()
  $Warnings = [System.Collections.Generic.List[object]]::new()
  $PESubsystemInfo = try {
    Get-QtInstallerFrameworkPESubsystemInfo -Path $Path -PELayout $PELayout
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
    $OwnsStream = -not $PSBoundParameters.ContainsKey('Stream')
    if ($OwnsStream) { $Stream = [System.IO.File]::Open((Get-Item -Path $Path -Force).FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite) }
    $OriginalPosition = $Stream.Position
    try {
      # CLI literals are compiled into the launcher. Stop at EndOfExecutable so packaged files cannot create false positives.
      $MarkerMatches = @(Find-QtInstallerFrameworkAsciiMarker -Stream $Stream -Length $Layout.EndOfExecutable -Marker @($RequiredOptionMarkers + $CommandMarkers))
      if ($MarkerMatches) { $FoundMarkers.AddRange([string[]]$MarkerMatches) }
    } finally {
      if ($OwnsStream) { $Stream.Dispose() } else { $Stream.Position = $OriginalPosition }
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
    $Warnings.Add((New-InstallerDiagnostic -Id 'QtIFW.Installability.GuiOnly' -Source 'QtInstallerFramework' -Message 'The Qt IFW launcher does not contain the modern command-line interface; GUI-only installers do not support WinGet-compatible silent installation.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes))
  } elseif ($DisabledByConfig) {
    $Warnings.Add((New-InstallerDiagnostic -Id 'QtIFW.Installability.CommandLineDisabled' -Source 'QtInstallerFramework' -Message 'The embedded IFW config disables the command-line interface, so silent installation and AllUsers scope overrides are unavailable.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes, Scope))
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
    Diagnostics                 = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata)
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

function Get-QtInstallerFrameworkAppsAndFeaturesEffectInfo {
  <#
  .SYNOPSIS
    Reconstruct the Windows maintenance-tool ARP registration defined by Qt IFW.
  .DESCRIPTION
    PackageManagerCorePrivate::registerMaintenanceTool writes this entry directly rather than recording it as an UpdateOperation. The result is kept separate from performed-operation effects while sharing the same normalized registry-write shape.
  .PARAMETER InstallerConfig
    Parsed installer configuration containing ProductUUID, product metadata, target directory, and maintenance-tool settings.
  .PARAMETER Scope
    Installed scope that selects HKCU or HKLM.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()][psobject]$InstallerConfig,
    [Parameter(Mandatory)][ValidateSet('user', 'machine')][string]$Scope
  )

  $Effects = [Collections.Generic.List[object]]::new()
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $Entries = [Collections.Generic.List[object]]::new()
  $Warnings = [Collections.Generic.List[object]]::new()
  if (-not $InstallerConfig) {
    return [pscustomobject][ordered]@{ Effects = @(); RegistryWrites = @(); Entries = @(); Diagnostics = @(ConvertTo-InstallerDiagnostic -InputObject @(@()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata) }
  }

  $ProductCode = [string]$InstallerConfig.ProductCode
  if ([string]::IsNullOrWhiteSpace($ProductCode)) {
    return [pscustomobject][ordered]@{ Effects = @(); RegistryWrites = @(); Entries = @(); Diagnostics = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata) }
  }

  $Root = if ($Scope -eq 'machine') { 'HKLM' } else { 'HKCU' }
  $Key = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
  $MaintenanceToolName = [string]$InstallerConfig.MaintenanceToolName
  if ([string]::IsNullOrWhiteSpace($MaintenanceToolName)) { $MaintenanceToolName = 'maintenancetool' }
  if (-not $MaintenanceToolName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { $MaintenanceToolName += '.exe' }
  $MaintenanceTool = if ([string]::IsNullOrWhiteSpace([string]$InstallerConfig.TargetDir)) { $MaintenanceToolName } else { "$($InstallerConfig.TargetDir.TrimEnd('/','\'))\$MaintenanceToolName" }
  $SyntheticOperation = [pscustomobject]@{ Index = -1; Name = 'MaintenanceRegistration' }

  $Values = [ordered]@{
    DisplayName     = $InstallerConfig.DisplayName
    DisplayVersion  = $InstallerConfig.DisplayVersion
    DisplayIcon     = $MaintenanceTool
    Publisher       = $InstallerConfig.Publisher
    UrlInfoAbout    = $InstallerConfig.ProductUrl
    Comments        = $InstallerConfig.Title
    InstallLocation = $InstallerConfig.TargetDir
    UninstallString = "`"$MaintenanceTool`" --start-uninstaller"
    NoModify        = if ((ConvertTo-QtInstallerFrameworkBoolean -Value $InstallerConfig.SupportsModify) -eq $false) { 1 } else { 0 }
    NoRepair        = 1
  }
  foreach ($Pair in $Values.GetEnumerator()) {
    if ($null -eq $Pair.Value -or ($Pair.Value -is [string] -and [string]::IsNullOrWhiteSpace($Pair.Value))) { continue }
    $Type = if ($Pair.Key -in @('NoModify', 'NoRepair')) { 'DWord' } else { 'String' }
    $Write = New-QtInstallerFrameworkRegistryEffect -Operation $SyntheticOperation -Root $Root -Key $Key -Name $Pair.Key -Value $Pair.Value -Type $Type
    $RegistryWrites.Add($Write)
  }

  $Entry = [pscustomobject][ordered]@{
    ProductCode    = $ProductCode
    DisplayName    = $InstallerConfig.DisplayName
    DisplayVersion = $InstallerConfig.DisplayVersion
    Publisher      = $InstallerConfig.Publisher
    InstallerType  = 'exe'
  }
  $Entries.Add($Entry)
  $Effects.Add([pscustomobject][ordered]@{
      Category        = 'AppsAndFeatures'
      Action          = 'RegisterMaintenanceTool'
      Root            = $Root
      Key             = $Key
      ProductCode     = $ProductCode
      DisplayName     = $InstallerConfig.DisplayName
      DisplayVersion  = $InstallerConfig.DisplayVersion
      Publisher       = $InstallerConfig.Publisher
      InstallLocation = $InstallerConfig.TargetDir
      UninstallString = $Values.UninstallString
      Source          = 'PackageManagerCorePrivate::registerMaintenanceTool'
    })

  [pscustomobject][ordered]@{
    Effects        = [object[]]$Effects.ToArray()
    RegistryWrites = [object[]]$RegistryWrites.ToArray()
    Entries        = [object[]]$Entries.ToArray()
    Diagnostics    = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings.ToArray()) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata)
  }
}

function Get-QtInstallerFrameworkInfo {
  <#
  .SYNOPSIS
    Get static metadata from a Qt Installer Framework installer
  .PARAMETER Path
    The path to the Qt Installer Framework installer
  .OUTPUTS
    Static installer metadata plus package-location evidence, decoded performed-operation effects, maintenance ARP evidence, KnownInstallerValues, verbatim JavaScriptResources with assignment-site values, and JavaScriptAnalysisInstructions. Returned JavaScript is untrusted evidence and is never executed.
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
    $InstallerXmlResource = $Context.InstallerXmlResource
    $InstallerConfig = $Context.InstallerConfig
    $InterfaceInfo = $Context.InterfaceInfo
    $InstallLocationInfo = Get-QtInstallerFrameworkInstallLocationInfo -InstallerConfig $InstallerConfig -InterfaceInfo $InterfaceInfo
    $UpgradeInfo = Get-QtInstallerFrameworkUpgradeInfo -InstallerConfig $InstallerConfig -InstallLocationInfo $InstallLocationInfo
    $ScopeInfo = Get-QtInstallerFrameworkScopeInfo -InstallerConfig $InstallerConfig -TextResource $TextResources -InterfaceInfo $InterfaceInfo
    $KnownInstallerValues = if ($InstallerConfig) { $InstallerConfig.RawValues } else { [ordered]@{} }
    $JavaScriptResources = @(Get-QtInstallerFrameworkJavaScriptInfo -TextResource $TextResources -InstallerValues $KnownInstallerValues)
    $EffectScope = if ($ScopeInfo.Scope -in @('user', 'machine')) { $ScopeInfo.Scope } else { 'user' }
    $OperationEffectInfo = Get-QtInstallerFrameworkOperationEffectInfo -Operation $Context.Operations -Scope $EffectScope
    $AppsAndFeaturesEffectInfo = Get-QtInstallerFrameworkAppsAndFeaturesEffectInfo -InstallerConfig $InstallerConfig -Scope $EffectScope
    $RegistryWrites = [object[]]@($OperationEffectInfo.RegistryWrites) + [object[]]@($AppsAndFeaturesEffectInfo.RegistryWrites)
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites

    $Warnings = [System.Collections.Generic.List[object]]::new()
    foreach ($Diagnostic in @($FormatInfo.Diagnostics)) { $Warnings.Add($Diagnostic) }
    foreach ($Diagnostic in @($OperationEffectInfo.Diagnostics)) { $Warnings.Add($Diagnostic) }
    foreach ($Diagnostic in @($AppsAndFeaturesEffectInfo.Diagnostics)) { $Warnings.Add($Diagnostic) }
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Warnings.Add($Diagnostic) }
    if (-not $InstallerConfig) {
      $Warnings.Add('No IFW installer-config/config.xml metadata was recovered from the embedded resources.')
    } elseif ($FormatInfo.PackageIndexRoute -ne 'component-index-v1' -and [string]::IsNullOrWhiteSpace($InstallerConfig.ProductCode)) {
      $Warnings.Add('No embedded ProductUUID was found. Qt IFW generates the Windows uninstall key at install time unless a script/config sets ProductUUID.')
    }
    foreach ($Warning in @($InterfaceInfo.Diagnostics)) { $Warnings.Add($Warning) }
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
      InstallerType                        = 'exe'
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
      AppsAndFeaturesEntries               = [object[]]$AppsAndFeaturesEffectInfo.Entries
      Diagnostics                          = @(Merge-InstallerDiagnostics -Diagnostic @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]$Warnings) -Source 'QtInstallerFramework' -Kind Incomplete -Areas Metadata))
      UnresolvedFields                     = [string[]]@()
      Family                               = 'Qt Installer Framework'
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
      PayloadAvailabilityEvidence          = $FormatInfo.PayloadAvailabilityEvidence
      PackageMetadata                      = [object[]]$FormatInfo.PackageMetadata
      RepositoryUrls                       = [string[]]$FormatInfo.RepositoryUrls
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
      InstallerConfigSource                = if ($InstallerXmlResource) { $InstallerXmlResource.Source } else { $null }
      MetadataResourceCount                = $Layout.MetaResourceCount
      ResourceCollectionCount              = @($Context.PackageCollections).Count
      OperationCount                       = @($Context.Operations).Count
      Operations                           = @($Context.Operations)
      OperationEffects                     = [object[]]$OperationEffectInfo.Effects
      FileSystemEffects                    = [object[]]$OperationEffectInfo.FileSystemEffects
      RegistryWrites                       = $RegistryWrites
      RegistryAssociationInfo              = $RegistryAssociationInfo
      Protocols                            = [string[]]$RegistryAssociationInfo.Protocols
      FileExtensions                       = [string[]]$RegistryAssociationInfo.FileExtensions
      ProtocolEffects                      = [object[]]$RegistryAssociationInfo.ProtocolAssociations
      FileAssociationEffects               = [object[]]$RegistryAssociationInfo.FileExtensionAssociations
      ShortcutEffects                      = [object[]]$OperationEffectInfo.ShortcutEffects
      EnvironmentEffects                   = [object[]]$OperationEffectInfo.EnvironmentEffects
      ExecutionEffects                     = [object[]]$OperationEffectInfo.ExecutionEffects
      AppsAndFeaturesEffects               = [object[]]$AppsAndFeaturesEffectInfo.Effects
      MetadataRoots                        = @($MetadataResources | Select-Object -ExpandProperty Root -Unique)
      RawInstallerConfig                   = $InstallerConfig.RawValues
      KnownInstallerValues                 = $KnownInstallerValues
      JavaScriptCount                      = $JavaScriptResources.Count
      RequiresJavaScriptReview             = $JavaScriptResources.Count -gt 0
      JavaScriptResources                  = $JavaScriptResources
      JavaScriptAnalysisInstructions       = [string[]]$Script:QtInstallerFrameworkJavaScriptAnalysisInstructions
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
