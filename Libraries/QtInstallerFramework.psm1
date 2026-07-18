# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/qtproject/installer-framework
#
# Binary structure consumed by this parser (trailer fields are int64 LE):
#
#   PE installerbase -> appended binary content
#     +-- resource collection
#     +-- metadata/resource/archive ranges
#     `-- trailer ending in F8 68 D6 99 1C 0A 63 C2 (installer cookie)
#
#   [ResourceCollection:offset,length][MetaRange:offset,length]*
#   [Operations:offset,length][ResourceCount][BinaryContentSize]
#   [MagicMarker][Cookie:8]
#
# Segment offsets are relative to the binary-content base until adjusted by
# EndOfExecutable. Metadata may contain Qt RCC trees; payloads may be 7z archives.
# Count, range, RCC-node, archive, and expanded-output limits are enforced.

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
$QTIFW_MAX_BYTE_ARRAY_LENGTH = 134217728
$QTIFW_MAX_XML_SCAN_BYTES = 67108864
$QTIFW_MAX_TEXT_EVIDENCE_BYTES = 1048576
$QTIFW_MAX_EXECUTABLE_SCAN_BYTES = 134217728
$QTIFW_RCC_NODE_SIZE = 14
$QTIFW_RCC_FLAG_COMPRESSED = 0x01
$QTIFW_RCC_FLAG_DIRECTORY = 0x02
$QTIFW_MAX_EXPANDED_BYTES = 17179869184
$QTIFW_MAX_EXPANDED_FILES = 200000

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
        ResourceCollectionsSegment = $AdjustedResourceCollectionSegment
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
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The file stream to read from')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The current read cursor, updated after the read')]
    [ref]$Cursor
  )

  $Length = Read-QtInstallerFrameworkInt64 -Stream $Stream -Offset $Cursor.Value
  $Cursor.Value += 8
  if ($Length -lt 0 -or $Length -gt $QTIFW_MAX_BYTE_ARRAY_LENGTH) {
    throw "Invalid Qt Installer Framework byte-array length: $Length"
  }
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
      $NameBytes = Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $Cursor
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
        $ResourceNameBytes = Read-QtInstallerFrameworkByteArray -Stream $Stream -Cursor $DataCursor
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

    return $Collections.ToArray()
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
    [pscustomobject]$Layout
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
    foreach ($Collection in Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout) {
      foreach ($Resource in @($Collection.Resources)) {
        if ([System.IO.Path]::GetExtension([string]$Resource.Name) -ieq '.7z') { continue }
        if ($Resource.Segment.Length -gt $QTIFW_MAX_XML_SCAN_BYTES) { continue }
        $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Resource.Segment.Start -Count $Resource.Segment.Length
        foreach ($XmlResource in ConvertFrom-QtInstallerFrameworkXmlBytes -Bytes $Bytes -Source "$($Collection.Name)/$($Resource.Name)") {
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
    [pscustomobject]$Layout
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

    foreach ($Collection in Get-QtInstallerFrameworkResourceCollection -Path $Path -Layout $Layout) {
      foreach ($Resource in @($Collection.Resources)) {
        if ([System.IO.Path]::GetExtension([string]$Resource.Name) -ieq '.7z') { continue }
        if ($Resource.Segment.Length -gt $QTIFW_MAX_TEXT_EVIDENCE_BYTES) { continue }
        $Bytes = Read-QtInstallerFrameworkBytes -Stream $Stream -Offset $Resource.Segment.Start -Count $Resource.Segment.Length
        foreach ($TextResource in ConvertFrom-QtInstallerFrameworkTextData -Bytes $Bytes -Source "$($Collection.Name)/$($Resource.Name)") {
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

    [Parameter(Mandatory, HelpMessage = 'The maximum number of expanded bytes')]
    [long]$MaximumExpandedBytes
  )

  Import-QtInstallerFrameworkSharpCompress
  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -Path $Path -Force).FullName)
  try {
    $Entries = @($Archive.Entries)
    if ($Entries.Count -gt $QTIFW_MAX_EXPANDED_FILES) {
      throw "The Qt Installer Framework package archive contains too many entries: $($Entries.Count)"
    }

    $Files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $WrittenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ExpandedBytes = [long]0
    # Export only selected regular entries. Links, duplicate paths, and inaccurate expanded sizes
    # are rejected before they can alter the destination tree.
    foreach ($ArchiveEntry in $Entries) {
      if ($ArchiveEntry.IsDirectory -or [string]::IsNullOrWhiteSpace($ArchiveEntry.Key)) { continue }
      $RelativePath = Join-Path $RelativeRoot ([string]$ArchiveEntry.Key)
      if (-not (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name)) { continue }

      $LinkTargetProperty = $ArchiveEntry.PSObject.Properties['LinkTarget']
      if ($LinkTargetProperty -and -not [string]::IsNullOrWhiteSpace([string]$LinkTargetProperty.Value)) {
        throw "The Qt Installer Framework package archive contains an unsupported link: $($ArchiveEntry.Key)"
      }

      $EntrySize = [long]$ArchiveEntry.Size
      if ($EntrySize -lt 0) { throw "The Qt Installer Framework package entry has an unknown size: $($ArchiveEntry.Key)" }
      $ExpandedBytes += $EntrySize
      if ($ExpandedBytes -gt $MaximumExpandedBytes) {
        throw "The selected Qt Installer Framework package files exceed the $MaximumExpandedBytes-byte limit"
      }

      $OutputPath = Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
      if (-not $WrittenPaths.Add($OutputPath)) {
        throw "The Qt Installer Framework package archive contains a duplicate output path: $($ArchiveEntry.Key)"
      }
      if (Test-Path -LiteralPath $OutputPath) {
        throw "The Qt Installer Framework package archive would overwrite an existing output path: $($ArchiveEntry.Key)"
      }
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
    [long]$MaximumExpandedBytes = $QTIFW_MAX_EXPANDED_BYTES
  )

  process {
    # Parse and validate the trailer once, then keep one installer stream open for all segment
    # copies. Nested 7z readers receive isolated temporary files because they require seeking.
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $InstallerPath
    if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path ([System.IO.Path]::GetTempPath()) "Dumplings-QtIFW-$([System.Guid]::NewGuid())"
    }
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
            $OutputPath = Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
            if (-not $WrittenPaths.Add($OutputPath)) {
              throw "The Qt Installer Framework metadata contains a duplicate output path: $RelativePath"
            }

            $WrittenBytes += $Resource.Data.Length
            if ($WrittenBytes -gt $MaximumExpandedBytes) {
              throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
            }
            $null = Write-QtInstallerFrameworkBuffer -Bytes $Resource.Data -DestinationPath $DestinationPath -RelativePath $RelativePath
            $WrittenFileCount++
            if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
              throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
            }
          }
        } else {
          $RelativePath = "metadata/QResources/$MetaIndex.rcc"
          if (Test-QtInstallerFrameworkExtractionMatch -Path $RelativePath -Name $Name) {
            $OutputPath = Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
            if (-not $WrittenPaths.Add($OutputPath)) {
              throw "The Qt Installer Framework metadata contains a duplicate output path: $RelativePath"
            }
            $WrittenBytes += $Bytes.Length
            if ($WrittenBytes -gt $MaximumExpandedBytes) {
              throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
            }
            $null = Write-QtInstallerFrameworkBuffer -Bytes $Bytes -DestinationPath $DestinationPath -RelativePath $RelativePath
            $WrittenFileCount++
            if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
              throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
            }
          }
        }
        $MetaIndex++
      }

      # Resource catalog entries are copied through bounded streams. A raw resource and its
      # expanded package contents are accounted independently against the global output limit.
      foreach ($Collection in Get-QtInstallerFrameworkResourceCollection -Path $InstallerPath -Layout $Layout) {
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

            $RawRelativePath = "metadata/$($Collection.Name)/$($Resource.Name)"
            if (Test-QtInstallerFrameworkExtractionMatch -Path $RawRelativePath -Name $Name) {
              $RawOutputPath = Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $DestinationPath -RelativePath $RawRelativePath
              if (-not $WrittenPaths.Add($RawOutputPath)) {
                throw "The Qt Installer Framework resources contain a duplicate output path: $RawRelativePath"
              }
              $WrittenBytes += $Resource.Segment.Length
              if ($WrittenBytes -gt $MaximumExpandedBytes) {
                throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
              }
              $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($RawOutputPath)) -ItemType Directory -Force
              [System.IO.File]::Copy($TemporaryArchivePath, $RawOutputPath, $true)
              $WrittenFileCount++
              if ($WrittenFileCount -gt $QTIFW_MAX_EXPANDED_FILES) {
                throw "The Qt Installer Framework extraction contains too many files: $WrittenFileCount"
              }
            }

            if ([System.IO.Path]::GetExtension([string]$Resource.Name) -ieq '.7z') {
              # IFW package payloads retain their collection name as a logical package root.
              $ArchiveRoot = "packages/$($Collection.Name)/$([System.IO.Path]::GetFileNameWithoutExtension([string]$Resource.Name))"
              $RemainingExpandedBytes = $MaximumExpandedBytes - $WrittenBytes
              if ($RemainingExpandedBytes -le 0) {
                throw "The Qt Installer Framework extraction exceeds the $MaximumExpandedBytes-byte limit"
              }
              $ArchiveResult = Expand-QtInstallerFrameworkPackageArchive -Path $TemporaryArchivePath -DestinationPath $DestinationPath -RelativeRoot $ArchiveRoot -Name $Name -MaximumExpandedBytes $RemainingExpandedBytes
              $WrittenBytes += $ArchiveResult.Bytes
              foreach ($ExtractedFile in @($ArchiveResult.Files)) {
                if (-not $WrittenPaths.Add($ExtractedFile.FullName)) {
                  throw "The Qt Installer Framework resources contain a duplicate output path: $($ExtractedFile.FullName)"
                }
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

  $MaintenanceToolName = if ([string]::IsNullOrWhiteSpace($Values['MaintenanceToolName'])) { 'maintenancetool' } else { $Values['MaintenanceToolName'] }
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
    MaintenanceToolIniFile      = if ([string]::IsNullOrWhiteSpace($Values['MaintenanceToolIniFile'])) { "$MaintenanceToolName.ini" } else { $Values['MaintenanceToolIniFile'] }
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
    [pscustomobject]$InstallerConfig
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

  if ($Layout.EndOfExecutable -le 0 -or $Layout.EndOfExecutable -gt $QTIFW_MAX_EXECUTABLE_SCAN_BYTES) {
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
  $InterfaceVariant = switch ($PESubsystemInfo.Name) {
    'WindowsCui' { 'CLI'; break }
    'WindowsGui' { 'GUI'; break }
    default { $MarkerVariant }
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
      SourceRule            = 'The Windows CUI subsystem identifies the headless launcher and the Windows GUI subsystem identifies the GUI launcher; commandlineinterface.cpp enforces DisableCommandLineInterface.'
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
    $File = Get-Item -Path $Path -Force
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $File.FullName
    if ($Layout.MagicMarkerName -eq 'Unknown') { throw "Unsupported Qt Installer Framework magic marker: $($Layout.MagicMarker)" }

    # Recover structured metadata first, then derive interface, install-root, upgrade, and scope
    # evidence from one shared config object.
    $MetadataResources = @(Get-QtInstallerFrameworkMetadataResource -Path $File.FullName -Layout $Layout)
    $TextResources = @(Get-QtInstallerFrameworkMetadataTextResource -Path $File.FullName -Layout $Layout)
    $InstallerXmlResource = @($MetadataResources | Where-Object { $_.Root -eq 'Installer' } | Select-Object -First 1)
    $InstallerConfig = if ($InstallerXmlResource) {
      ConvertFrom-QtInstallerFrameworkInstallerXml -Xml $InstallerXmlResource[0].Xml
    } else {
      $null
    }
    $InterfaceInfo = Get-QtInstallerFrameworkInterfaceInfo -Path $File.FullName -Layout $Layout -InstallerConfig $InstallerConfig
    $InstallLocationInfo = Get-QtInstallerFrameworkInstallLocationInfo -InstallerConfig $InstallerConfig -InterfaceInfo $InterfaceInfo
    $UpgradeInfo = Get-QtInstallerFrameworkUpgradeInfo -InstallerConfig $InstallerConfig -InstallLocationInfo $InstallLocationInfo
    $ScopeInfo = Get-QtInstallerFrameworkScopeInfo -InstallerConfig $InstallerConfig -TextResource $TextResources -InterfaceInfo $InterfaceInfo

    $Warnings = [System.Collections.Generic.List[string]]::new()
    if (-not $InstallerConfig) {
      $Warnings.Add('No IFW installer-config/config.xml metadata was recovered from the embedded resources.')
    } elseif ([string]::IsNullOrWhiteSpace($InstallerConfig.ProductCode)) {
      $Warnings.Add('No embedded ProductUUID was found. Qt IFW generates the Windows uninstall key at install time unless a script/config sets ProductUUID.')
    }
    foreach ($Warning in @($InterfaceInfo.Warnings)) { $Warnings.Add($Warning) }
    if ($InstallLocationInfo.RequiresExplicitInstallLocation -eq $true) {
      $Warnings.Add('The embedded TargetDir is empty, so command-line installation requires --root with an absolute installation path.')
    }
    if ($ScopeInfo.Evidence.AllUsersTrueAssignmentSources -or $ScopeInfo.Evidence.AllUsersFalseAssignmentSources) {
      $Warnings.Add('Static resources mention AllUsers assignments. Confirm conditional script control flow before relying on the default scope.')
    }

    [pscustomobject]@{
      Path                                 = $File.FullName
      InstallerType                        = 'Qt Installer Framework'
      BinaryMarker                         = $Layout.MagicMarkerName
      InterfaceVariant                     = $InterfaceInfo.InterfaceVariant
      CommandLineInterface                 = $InterfaceInfo.CommandLineInterface
      HasCommandLineInterface              = $InterfaceInfo.HasCommandLineInterface
      CommandLineInterfaceEnabled          = $InterfaceInfo.CommandLineInterfaceEnabled
      SupportsSilentInstallation           = $InterfaceInfo.SupportsSilentInstallation
      DisableCommandLineInterface          = $InterfaceInfo.DisabledByConfig
      CommandLineInterfaceEvidence         = $InterfaceInfo.Evidence
      PESubsystem                          = $InterfaceInfo.Evidence.PESubsystem
      PackageName                          = $InstallerConfig.PackageName
      DisplayName                          = $InstallerConfig.DisplayName
      ProductName                          = $InstallerConfig.PackageName
      DisplayVersion                       = $InstallerConfig.DisplayVersion
      ProductVersion                       = $InstallerConfig.ProductVersion
      Publisher                            = $InstallerConfig.Publisher
      ProductUrl                           = $InstallerConfig.ProductUrl
      Title                                = $InstallerConfig.Title
      ProductCode                          = $InstallerConfig.ProductCode
      TargetDir                            = $InstallerConfig.TargetDir
      AdminTargetDir                       = $InstallerConfig.AdminTargetDir
      HasDefaultTargetDir                  = $InstallLocationInfo.HasDefaultTargetDir
      RequiresExplicitInstallLocation      = $InstallLocationInfo.RequiresExplicitInstallLocation
      InstallLocationSwitch                = $InstallLocationInfo.InstallLocationSwitch
      InstallLocationEvidence              = $InstallLocationInfo.Evidence
      SupportsExistingInstallationOverride = $UpgradeInfo.SupportsExistingInstallationOverride
      ExistingInstallationMarker           = $UpgradeInfo.ExistingInstallationMarker
      RecommendedUpgradeBehavior           = $UpgradeInfo.RecommendedUpgradeBehavior
      UpgradeEvidence                      = $UpgradeInfo.Evidence
      Scope                                = $ScopeInfo.Scope
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
      WritesAppsAndFeaturesEntry           = $true
      InstallerConfigSource                = if ($InstallerXmlResource) { $InstallerXmlResource[0].Source } else { $null }
      MetadataResourceCount                = $Layout.MetaResourceCount
      ResourceCollectionCount              = @(Get-QtInstallerFrameworkResourceCollection -Path $File.FullName -Layout $Layout).Count
      MetadataRoots                        = @($MetadataResources | Select-Object -ExpandProperty Root -Unique)
      RawInstallerConfig                   = $InstallerConfig.RawValues
      Warnings                             = $Warnings.ToArray()
      ParserVersionInfo                    = [pscustomobject]@{
        Parser          = 'Dumplings.QtInstallerFramework'
        BinaryLayout    = 'Qt Installer Framework BinaryContent'
        CookieSearch    = 'Last 1 MiB'
        ScopeRule       = 'PackageManagerCorePrivate::registerPath'
        InterfaceRule   = 'PE subsystem plus DisableCommandLineInterface; executable-prefix markers are corroborating evidence'
        SourceReference = 'Qt Installer Framework binarycontent.cpp, binaryformat.cpp, rcc.cpp, main.cpp, commandlineinterface.cpp, packagemanagercore.cpp, packagemanagercore_p.cpp'
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

Export-ModuleMember -Function Get-QtInstallerFrameworkBinaryLayout, Get-QtInstallerFrameworkInfo, Expand-QtInstallerFramework, Test-QtInstallerFrameworkCLI, Test-QtInstallerFrameworkSilentInstallation, Test-QtInstallerFrameworkRequiresInstallLocation, Test-QtInstallerFrameworkSupportsExistingInstallationOverride, Read-UpgradeBehaviorFromQtInstallerFramework, Read-ProductVersionFromQtInstallerFramework, Read-ProductNameFromQtInstallerFramework, Read-PublisherFromQtInstallerFramework, Read-ProductCodeFromQtInstallerFramework, Read-ScopeFromQtInstallerFramework, Read-SupportedScopesFromQtInstallerFramework, Test-QtInstallerFrameworkDualScope
