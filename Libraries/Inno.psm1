# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/jrsoftware/issrc, https://github.com/jrathlev/InnoUnpacker-Windows-GUI, and https://github.com/russellbanks/Komac

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$INNO_SETUP_ID_SIZE = 64
$INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE = 11111
$INNO_RT_RCDATA = 10
$INNO_SIGNATURE_PATTERN = '^Inno Setup Setup Data \(([^)]+)\)(?: \(([uU])\))?$'
$INNO_OFFSET_TABLE_ID = [System.Text.Encoding]::ASCII.GetString([byte[]](0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A))
$INNO_OFFSET_TABLE_VERSION_1_SIZE = 44
$INNO_OFFSET_TABLE_VERSION_2_SIZE = 64
$INNO_ENCRYPTION_HEADER_SIZE_6500 = 49
$INNO_MAX_CHUNK_SIZE = 4096
$INNO_MAX_DECOMPRESSED_BLOCK_SIZE = 1073741824
$INNO_LEAD_BYTES_SIZE = 32
$INNO_CHUNK_MAGIC = [System.Text.Encoding]::ASCII.GetString([byte[]](0x7A, 0x6C, 0x62, 0x1A))
$INNO_VERSION_5_HEADER_COUNT_FIELDS = 16
$INNO_LANGUAGE_ENTRY_STRINGS = 6
$INNO_LANGUAGE_ENTRY_ANSI_STRINGS = 4
$INNO_LANGUAGE_ENTRY_FIXED_SIZE = 25
$INNO_CUSTOM_MESSAGE_ENTRY_STRINGS = 2
$INNO_CUSTOM_MESSAGE_ENTRY_FIXED_SIZE = 4
$INNO_PERMISSION_ENTRY_ANSI_STRINGS = 1
$INNO_TYPE_ENTRY_STRINGS = 4
$INNO_TYPE_ENTRY_FIXED_SIZE = 33
$INNO_COMPONENT_ENTRY_STRINGS = 5
$INNO_COMPONENT_ENTRY_FIXED_SIZE = 42
$INNO_TASK_ENTRY_STRINGS = 6
$INNO_TASK_ENTRY_FIXED_SIZE = 26
$INNO_DIRECTORY_ENTRY_STRINGS = 7
$INNO_DIRECTORY_ENTRY_FIXED_SIZE = 27
$INNO_FILE_ENTRY_STRINGS = 10
$INNO_FILE_ENTRY_OPTIONS_SIZE = 4
$INNO_FILE_ENTRY_FIXED_SIZE = 43
$INNO_FILE_LOCATION_ENTRY_SIZE = 74
$INNO_VERSION5_HEADER_FIXED_SIZE_5310 = 188
$INNO_VERSION5_HEADER_FIXED_SIZE_5500 = 189

function Get-Assembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static installer parsing
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

function Import-Assembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for Inno Setup parsing
  #>

  Import-InstallerArchiveDependency
}

Import-Assembly

function Get-InstallerCrc32 {
  <#
  .SYNOPSIS
    Calculate the CRC32 checksum for a byte array
  .PARAMETER Bytes
    The bytes to hash
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to hash')]
    [byte[]]$Bytes
  )

  process {
    return [BitConverter]::ToInt32([BitConverter]::GetBytes((Get-BinaryCrc32 -Bytes $Bytes)), 0)
  }
}

function Get-InnoResourceBytes {
  <#
  .SYNOPSIS
    Read a native PE resource from an Inno installer
  .PARAMETER Path
    The path to the installer
  .PARAMETER Id
    The integer resource ID
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The integer resource ID')]
    [int]$Id
  )

  $Resource = Get-PEResourceInfo -Path $Path |
    Where-Object { $_.TypeId -eq $Script:INNO_RT_RCDATA -and $_.Id -eq $Id } |
    Select-Object -First 1
  if (-not $Resource) { throw 'The requested Inno resource could not be found.' }
  return ,(Read-PEResourceData -Resource $Resource -MaximumBytes 1048576)
}

function Get-InnoOffsetTable {
  <#
  .SYNOPSIS
    Read and validate the Inno Setup loader offset table
  .PARAMETER Path
    The path to the installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  $Bytes = Get-InnoResourceBytes -Path $Path -Id $Script:INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE
  $Identifier = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 12)
  if ($Identifier -ne $Script:INNO_OFFSET_TABLE_ID) { throw 'The Inno Setup offset table identifier is invalid' }

  $Version = [System.BitConverter]::ToUInt32($Bytes, 12)

  switch ($Version) {
    1 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_1_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $TableBytes = $Bytes[0..($Script:INNO_OFFSET_TABLE_VERSION_1_SIZE - 1)]
      $StoredCrc = [System.BitConverter]::ToInt32($TableBytes, 40)
      $ExpectedCrc = Get-InstallerCrc32 -Bytes $TableBytes[0..39]
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      return [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToUInt32($TableBytes, 16)
        Offset0   = [System.BitConverter]::ToUInt32($TableBytes, 32)
        Offset1   = [System.BitConverter]::ToUInt32($TableBytes, 36)
      }
    }
    2 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_2_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $TableBytes = $Bytes[0..($Script:INNO_OFFSET_TABLE_VERSION_2_SIZE - 1)]
      $StoredCrc = [System.BitConverter]::ToInt32($TableBytes, 60)
      $ExpectedCrc = Get-InstallerCrc32 -Bytes $TableBytes[0..59]
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      return [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToInt64($TableBytes, 16)
        Offset0   = [System.BitConverter]::ToInt64($TableBytes, 40)
        Offset1   = [System.BitConverter]::ToInt64($TableBytes, 48)
      }
    }
    default { throw "Unsupported Inno Setup offset table version: $Version" }
  }
}

function Get-InnoVersionNumber {
  <#
  .SYNOPSIS
    Convert an Inno Setup signature version string to its numeric form
  .PARAMETER Version
    The version string from the setup signature
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The version string from the setup signature')]
    [string]$Version
  )

  $Match = [regex]::Match($Version, '^(\d+)\.(\d+)\.(\d+)')
  if (-not $Match.Success) { throw "Unsupported Inno Setup signature version: $Version" }

  return ([int]$Match.Groups[1].Value * 1000) + ([int]$Match.Groups[2].Value * 100) + [int]$Match.Groups[3].Value
}

function Get-InnoLayout {
  <#
  .SYNOPSIS
    Get the header layout information for a supported Inno Setup version
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  .PARAMETER UnicodeVariant
    Indicates whether the setup signature uses the Unicode Inno Setup format
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber,

    [Parameter(Mandatory, HelpMessage = 'Indicates whether the setup signature uses the Unicode Inno Setup format')]
    [bool]$UnicodeVariant
  )

  if ($VersionNumber -ge 6700) {
    return [pscustomobject]@{ HeaderStringCount = 39; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $true; StringEncoding = 'Unicode' }
  } elseif ($VersionNumber -ge 6500) {
    return [pscustomobject]@{ HeaderStringCount = 34; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false; StringEncoding = 'Unicode' }
  } elseif ($VersionNumber -ge 6300) {
    return [pscustomobject]@{ HeaderStringCount = 32; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false; StringEncoding = 'Unicode' }
  } elseif ($VersionNumber -ge 6000) {
    return [pscustomobject]@{ HeaderStringCount = 30; HeaderAnsiStringCount = 4; UsesInt64BlockHeader = $false; StringEncoding = 'Unicode' }
  } elseif ($VersionNumber -ge 5500) {
    return [pscustomobject]@{
      HeaderStringCount     = 28
      HeaderAnsiStringCount = 4
      UsesInt64BlockHeader  = $false
      StringEncoding        = $UnicodeVariant ? 'Unicode' : 'Ansi'
    }
  } elseif ($VersionNumber -ge 5310) {
    return [pscustomobject]@{
      HeaderStringCount     = 26
      HeaderAnsiStringCount = 4
      UsesInt64BlockHeader  = $false
      StringEncoding        = $UnicodeVariant ? 'Unicode' : 'Ansi'
    }
  } else {
    throw "Unsupported Inno Setup version: $VersionNumber"
  }
}

function Get-InnoVersion5HeaderFixedSize {
  <#
  .SYNOPSIS
    Get the fixed-size ANSI Inno Setup 5.x header tail size after the serialized strings
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  if ($VersionNumber -ge 5500) {
    return $Script:INNO_VERSION5_HEADER_FIXED_SIZE_5500
  } elseif ($VersionNumber -ge 5310) {
    return $Script:INNO_VERSION5_HEADER_FIXED_SIZE_5310
  } else {
    throw "Unsupported ANSI Inno Setup 5.x header layout: $VersionNumber"
  }
}

function Get-InnoAnsiEncoding {
  <#
  .SYNOPSIS
    Get the active ANSI code page used by legacy Inno Setup installers
  #>
  [OutputType([System.Text.Encoding])]
  param ()

  return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
}

function Read-InnoReaderStrings {
  <#
  .SYNOPSIS
    Read a sequence of serialized Inno Setup strings from a binary reader
  .PARAMETER Reader
    The binary reader positioned at the first serialized string
  .PARAMETER Count
    The number of strings to read
  .PARAMETER Encoding
    The encoding used by the serialized strings
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader positioned at the first serialized string')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The number of strings to read')]
    [int]$Count,

    [Parameter(Mandatory, HelpMessage = 'The encoding used by the serialized strings')]
    [System.Text.Encoding]$Encoding
  )

  $Values = [System.Collections.Generic.List[string]]::new()

  for ($i = 0; $i -lt $Count; $i++) {
    $Length = $Reader.ReadInt32()
    if ($Length -lt 0 -or $Length -gt ($Reader.BaseStream.Length - $Reader.BaseStream.Position)) { throw 'The Inno Setup header string length is invalid' }

    if ($Length -eq 0) {
      $Values.Add('')
    } else {
      $Values.Add($Encoding.GetString($Reader.ReadBytes($Length)))
    }
  }

  return $Values.ToArray()
}

function Test-InnoCompressedBlockHeader {
  <#
  .SYNOPSIS
    Validate the compressed block header that precedes the setup header stream
  .PARAMETER Reader
    The binary reader for the installer
  .PARAMETER Offset
    The candidate compressed block offset
  .PARAMETER UsesInt64BlockHeader
    Whether the block header stores the size as Int64
  .PARAMETER FileLength
    The installer file length
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader for the installer')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The candidate compressed block offset')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'Whether the block header stores the size as Int64')]
    [bool]$UsesInt64BlockHeader,

    [Parameter(Mandatory, HelpMessage = 'The installer file length')]
    [long]$FileLength
  )

  $HeaderLength = $UsesInt64BlockHeader ? 9 : 5
  if ($Offset + 4 + $HeaderLength -gt $FileLength) { return }

  $Reader.BaseStream.Seek($Offset, 'Begin') | Out-Null
  $StoredCrc = $Reader.ReadInt32()
  $HeaderBytes = $Reader.ReadBytes($HeaderLength)
  if ($HeaderBytes.Length -ne $HeaderLength) { return }
  if ($StoredCrc -ne (Get-InstallerCrc32 -Bytes $HeaderBytes)) { return }

  $StoredSize = if ($UsesInt64BlockHeader) {
    [System.BitConverter]::ToInt64($HeaderBytes, 0)
  } else {
    [System.BitConverter]::ToUInt32($HeaderBytes, 0)
  }

  if ($StoredSize -le 0 -or $Offset + 4 + $HeaderLength + $StoredSize -gt $FileLength) { return }

  return [pscustomobject]@{
    HeaderOffset = $Offset
    HeaderLength = $HeaderLength
    StoredSize   = $StoredSize
    Compressed   = [bool]$HeaderBytes[$HeaderLength - 1]
  }
}

function Expand-InnoLzmaBytes {
  <#
  .SYNOPSIS
    Expand a raw LZMA buffer stored by Inno Setup
  .PARAMETER Bytes
    The raw buffer containing the 5-byte LZMA properties prefix followed by compressed data
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw buffer containing the 5-byte LZMA properties prefix followed by compressed data')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 6) { throw 'The Inno Setup LZMA stream is too small' }

  $Properties = $Bytes[0..4]
  $CompressedStream = [System.IO.MemoryStream]::new($Bytes, 5, $Bytes.Length - 5, $false)
  $OutputStream = [System.IO.MemoryStream]::new()

  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $CompressedStream -Destination $OutputStream -MaximumBytes $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -Properties $Properties
    return ,($OutputStream.ToArray())
  } finally {
    $CompressedStream.Dispose()
    $OutputStream.Dispose()
  }
}

function Expand-InnoLzma2Bytes {
  <#
  .SYNOPSIS
    Expand a raw LZMA2 buffer stored by Inno Setup
  .PARAMETER Bytes
    The raw buffer containing the 1-byte LZMA2 properties prefix followed by compressed data
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw buffer containing the 1-byte LZMA2 properties prefix followed by compressed data')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 2) { throw 'The Inno Setup LZMA2 stream is too small' }

  $Properties = $Bytes[0..0]
  $CompressedStream = [System.IO.MemoryStream]::new($Bytes, 1, $Bytes.Length - 1, $false)
  $OutputStream = [System.IO.MemoryStream]::new()

  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma2 -Stream $CompressedStream -Destination $OutputStream -MaximumBytes $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -Properties $Properties
    return ,($OutputStream.ToArray())
  } finally {
    $CompressedStream.Dispose()
    $OutputStream.Dispose()
  }
}

function Read-InnoCompressedBlock {
  <#
  .SYNOPSIS
    Read and decompress a chunked Inno Setup block
  .PARAMETER Reader
    The binary reader for the installer
  .PARAMETER BlockHeader
    The parsed block header metadata
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader for the installer')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The parsed block header metadata')]
    [pscustomobject]$BlockHeader
  )

  $Reader.BaseStream.Seek($BlockHeader.HeaderOffset + 4 + $BlockHeader.HeaderLength, 'Begin') | Out-Null

  $CompressedBytes = [System.Collections.Generic.List[byte]]::new()
  $Remaining = [long]$BlockHeader.StoredSize

  while ($Remaining -gt 0) {
    $ChunkCrc = $Reader.ReadInt32()
    $Remaining -= 4

    $ChunkLength = [int][Math]::Min($Script:INNO_MAX_CHUNK_SIZE, $Remaining)
    $ChunkBytes = $Reader.ReadBytes($ChunkLength)
    if ($ChunkBytes.Length -ne $ChunkLength) { throw 'The Inno Setup compressed block is truncated' }
    if ($ChunkCrc -ne (Get-InstallerCrc32 -Bytes $ChunkBytes)) { throw 'The Inno Setup compressed block chunk CRC is invalid' }

    $CompressedBytes.AddRange($ChunkBytes)
    $Remaining -= $ChunkLength
  }

  $RawBytes = $CompressedBytes.ToArray()
  $BlockBytes = if ($BlockHeader.Compressed) {
    Expand-InnoLzmaBytes -Bytes $RawBytes
  } else {
    $RawBytes
  }

  return [pscustomobject]@{
    HeaderOffset = $BlockHeader.HeaderOffset
    HeaderLength = $BlockHeader.HeaderLength
    StoredSize   = $BlockHeader.StoredSize
    Compressed   = $BlockHeader.Compressed
    NextOffset   = $BlockHeader.HeaderOffset + 4 + $BlockHeader.HeaderLength + $BlockHeader.StoredSize
    Bytes        = $BlockBytes
  }
}

function Get-InnoHeaderBlockInfo {
  <#
  .SYNOPSIS
    Read and decompress the first Inno Setup metadata block
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset0
    The offset of the embedded setup data
  .PARAMETER Layout
    The supported Inno header layout
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset of the embedded setup data')]
    [long]$Offset0,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $FileStream = [System.IO.File]::OpenRead($InstallerPath)
  $Reader = [System.IO.BinaryReader]::new($FileStream)

  try {
    $Reader.BaseStream.Seek($Offset0, 'Begin') | Out-Null

    # Offset0 points to the setup signature that precedes the first compressed metadata block.
    $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
    if ($SignatureBytes.Length -ne $Script:INNO_SETUP_ID_SIZE) { throw 'The Inno Setup signature is truncated' }

    $HeaderOffset = $null
    $CandidateOffsets = if ($VersionNumber -ge 6500) {
      @(
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + $Script:INNO_ENCRYPTION_HEADER_SIZE_6500
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + 52
        $Offset0 + $Script:INNO_SETUP_ID_SIZE + 4 + 56
      )
    } else {
      @($Offset0 + $Script:INNO_SETUP_ID_SIZE)
    }

    foreach ($CandidateOffset in $CandidateOffsets) {
      $HeaderOffset = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $CandidateOffset -UsesInt64BlockHeader $Layout.UsesInt64BlockHeader -FileLength $FileStream.Length
      if ($HeaderOffset) { break }
    }

    if (-not $HeaderOffset) { throw 'The Inno Setup header block could not be located' }
    return Read-InnoCompressedBlock -Reader $Reader -BlockHeader $HeaderOffset
  } finally {
    $Reader.Close()
    $FileStream.Close()
  }
}

function Get-InnoHeaderBlock {
  <#
  .SYNOPSIS
    Read and decompress the first Inno Setup metadata block
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset0
    The offset of the embedded setup data
  .PARAMETER Layout
    The supported Inno header layout
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset of the embedded setup data')]
    [long]$Offset0,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  return ,((Get-InnoHeaderBlockInfo -Path $Path -Offset0 $Offset0 -Layout $Layout -VersionNumber $VersionNumber).Bytes)
}

function Read-InnoWideStrings {
  <#
  .SYNOPSIS
    Decode the fixed-order wide string header values from an Inno Setup header stream
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Count
    The number of wide strings to read
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed header stream bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The number of wide strings to read')]
    [int]$Count
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Values = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $Count; $i++) {
      $Length = $Reader.ReadInt32()
      if ($Length -lt 0 -or $Length -gt ($Stream.Length - $Stream.Position)) { throw 'The Inno Setup header string length is invalid' }

      if ($Length -eq 0) {
        $Values.Add('')
      } else {
        $Values.Add([System.Text.Encoding]::Unicode.GetString($Reader.ReadBytes($Length)))
      }
    }

    return $Values.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Read-InnoAnsiStrings {
  <#
  .SYNOPSIS
    Decode the fixed-order ANSI string header values from an Inno Setup header stream
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Count
    The number of ANSI strings to read
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed header stream bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The number of ANSI strings to read')]
    [int]$Count
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Values = [System.Collections.Generic.List[string]]::new()
    $Encoding = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)

    for ($i = 0; $i -lt $Count; $i++) {
      $Length = $Reader.ReadInt32()
      if ($Length -lt 0 -or $Length -gt ($Stream.Length - $Stream.Position)) { throw 'The Inno Setup header string length is invalid' }

      if ($Length -eq 0) {
        $Values.Add('')
      } else {
        $Values.Add($Encoding.GetString($Reader.ReadBytes($Length)))
      }
    }

    return $Values.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Read-InnoHeaderStrings {
  <#
  .SYNOPSIS
    Decode the fixed-order header strings from an Inno Setup header stream
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Layout
    The supported Inno header layout
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed header stream bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Values = [System.Collections.Generic.List[string]]::new()

    switch ($Layout.StringEncoding) {
      'Unicode' {
        foreach ($Value in (Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderStringCount -Encoding ([System.Text.Encoding]::Unicode))) {
          $Values.Add($Value)
        }
        foreach ($Value in (Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderAnsiStringCount -Encoding (Get-InnoAnsiEncoding))) {
          $Values.Add($Value)
        }
      }
      'Ansi' {
        $AnsiCount = $Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount
        foreach ($Value in (Read-InnoReaderStrings -Reader $Reader -Count $AnsiCount -Encoding (Get-InnoAnsiEncoding))) {
          $Values.Add($Value)
        }
      }
      default { throw "Unsupported Inno Setup header string encoding: $($Layout.StringEncoding)" }
    }

    return $Values.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Get-InnoHeaderFixedDataOffset {
  <#
  .SYNOPSIS
    Get version-specific offsets for fixed Inno Setup header fields after serialized strings
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  # Offsets are relative to the fixed header tail after all Unicode and ANSI header strings.
  # They follow the packed TSetupHeader records in innounp's Struct*.pas files.
  if ($VersionNumber -ge 6700) {
    return [pscustomobject]@{ PrivilegesRequired = 139; PrivilegesRequiredOverridesAllowed = 140 }
  } elseif ($VersionNumber -ge 6500) {
    return [pscustomobject]@{ PrivilegesRequired = 112; PrivilegesRequiredOverridesAllowed = 113 }
  } elseif ($VersionNumber -ge 6400) {
    return [pscustomobject]@{ PrivilegesRequired = 156; PrivilegesRequiredOverridesAllowed = 157 }
  } elseif ($VersionNumber -ge 6000) {
    return [pscustomobject]@{ PrivilegesRequired = 144; PrivilegesRequiredOverridesAllowed = 145 }
  }

  return $null
}

function Get-InnoPEInfo {
  <#
  .SYNOPSIS
    Read basic PE architecture information from an installer executable
  .PARAMETER Path
    The path to the installer executable
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer executable')]
    [string]$Path
  )

  $Layout = Get-PELayout -Path $Path
  if (-not $Layout) { throw 'The file does not contain a valid PE header.' }
  $Architecture = switch ($Layout.Machine) {
    0x014C { 'x86' }; 0x8664 { 'x64' }; 0xAA64 { 'arm64' }; 0x01C4 { 'arm' }
    default { "unknown:0x$($Layout.Machine.ToString('X4'))" }
  }
  [pscustomobject]@{ Architecture = $Architecture; Is64Bit = $Layout.Machine -in 0x8664, 0xAA64; Machine = $Layout.Machine }
}

function Get-InnoHeaderArchitectureData {
  <#
  .SYNOPSIS
    Read architecture directives from Inno Setup header strings when available
  .PARAMETER HeaderValues
    The parsed Inno Setup header strings
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  .PARAMETER PEInfo
    The installer PE architecture information used for default directives
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Inno Setup header strings')]
    [AllowEmptyString()]
    [string[]]$HeaderValues,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber,

    [Parameter(Mandatory, HelpMessage = 'The installer PE architecture information used for default directives')]
    [pscustomobject]$PEInfo
  )

  $ArchitecturesAllowed = $null
  $ArchitecturesInstallIn64BitMode = $null

  # Inno Setup 6.3+ stores architecture directives as header strings. Older
  # versions keep packed enum sets in the fixed header tail, which is handled
  # conservatively as unknown for now to avoid false unsupported results.
  if ($VersionNumber -ge 6300 -and $HeaderValues.Count -gt 31) {
    $ArchitecturesAllowed = $HeaderValues[30]
    $ArchitecturesInstallIn64BitMode = $HeaderValues[31]
  }

  $EffectiveArchitecturesAllowed = if ([string]::IsNullOrWhiteSpace($ArchitecturesAllowed)) {
    if ($PEInfo.Architecture -eq 'x64') { 'x64compatible' } else { 'x86compatible' }
  } else {
    $ArchitecturesAllowed
  }

  $EffectiveArchitecturesInstallIn64BitMode = if ([string]::IsNullOrWhiteSpace($ArchitecturesInstallIn64BitMode) -and $PEInfo.Architecture -eq 'x64') {
    'x64compatible'
  } else {
    $ArchitecturesInstallIn64BitMode
  }

  return [pscustomobject]@{
    ArchitecturesAllowed                     = $ArchitecturesAllowed
    ArchitecturesInstallIn64BitMode          = $ArchitecturesInstallIn64BitMode
    EffectiveArchitecturesAllowed            = $EffectiveArchitecturesAllowed
    EffectiveArchitecturesInstallIn64BitMode = $EffectiveArchitecturesInstallIn64BitMode
    IsKnown                                  = $VersionNumber -ge 6300
  }
}

function ConvertTo-InnoArchitectureExpressionToken {
  <#
  .SYNOPSIS
    Tokenize an Inno Setup architecture expression
  .PARAMETER Expression
    The ArchitecturesAllowed expression
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ArchitecturesAllowed expression')]
    [string]$Expression
  )

  $Tokens = @([regex]::Matches($Expression.ToLowerInvariant(), '\(|\)|\band\b|\bor\b|\bnot\b|[a-z0-9]+') | ForEach-Object { $_.Value })
  if (-not $Tokens) { return @() }

  $Normalized = [System.Collections.Generic.List[string]]::new()
  $PreviousIsOperand = $false

  foreach ($Token in $Tokens) {
    $CurrentIsOperand = $Token -notin @('and', 'or', 'not', '(', ')')
    if (($PreviousIsOperand -or ($Normalized.Count -gt 0 -and $Normalized[$Normalized.Count - 1] -eq ')')) -and ($CurrentIsOperand -or $Token -eq '(' -or $Token -eq 'not')) {
      # A space-separated list is equivalent to a logical OR in Inno Setup.
      $Normalized.Add('or')
    }
    $Normalized.Add($Token)
    $PreviousIsOperand = $CurrentIsOperand
  }

  return $Normalized.ToArray()
}

function Test-InnoArchitectureIdentifier {
  <#
  .SYNOPSIS
    Evaluate a single Inno Setup architecture identifier for a Windows architecture
  .PARAMETER Identifier
    The architecture identifier from the Inno expression
  .PARAMETER Architecture
    The target Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The architecture identifier from the Inno expression')]
    [string]$Identifier,

    [Parameter(Mandatory, HelpMessage = 'The target Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  switch ($Architecture) {
    'x86' {
      return $Identifier -in @('x86', 'x86os', 'x86compatible')
    }
    'x64' {
      return $Identifier -in @('x64', 'x64os', 'x64compatible', 'win64', 'x86compatible')
    }
    'arm64' {
      return $Identifier -in @('arm64', 'win64', 'x64compatible', 'x86compatible')
    }
  }
}

function Test-InnoArchitectureExpression {
  <#
  .SYNOPSIS
    Evaluate whether an Inno Setup architecture expression supports a Windows architecture
  .PARAMETER Expression
    The ArchitecturesAllowed expression
  .PARAMETER Architecture
    The target Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The ArchitecturesAllowed expression')]
    [string]$Expression,

    [Parameter(Mandatory, HelpMessage = 'The target Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  $Tokens = ConvertTo-InnoArchitectureExpressionToken -Expression $Expression
  if (-not $Tokens) { return $false }

  $Precedence = @{
    'or'  = 1
    'and' = 2
    'not' = 3
  }
  $Output = [System.Collections.Generic.List[string]]::new()
  $Operators = [System.Collections.Generic.Stack[string]]::new()

  foreach ($Token in $Tokens) {
    if ($Token -notin @('and', 'or', 'not', '(', ')')) {
      $Output.Add($Token)
      continue
    }

    switch ($Token) {
      '(' { $Operators.Push($Token) }
      ')' {
        while ($Operators.Count -gt 0 -and $Operators.Peek() -ne '(') {
          $Output.Add($Operators.Pop())
        }
        if ($Operators.Count -gt 0 -and $Operators.Peek() -eq '(') { $Operators.Pop() | Out-Null }
      }
      default {
        while (
          $Operators.Count -gt 0 -and
          $Operators.Peek() -ne '(' -and
          $Precedence[$Operators.Peek()] -ge $Precedence[$Token]
        ) {
          $Output.Add($Operators.Pop())
        }
        $Operators.Push($Token)
      }
    }
  }

  while ($Operators.Count -gt 0) {
    $Operator = $Operators.Pop()
    if ($Operator -ne '(') { $Output.Add($Operator) }
  }

  $Values = [System.Collections.Generic.Stack[bool]]::new()
  foreach ($Token in $Output) {
    switch ($Token) {
      'not' {
        if ($Values.Count -lt 1) { return $false }
        $Values.Push(-not $Values.Pop())
      }
      'and' {
        if ($Values.Count -lt 2) { return $false }
        $Right = $Values.Pop()
        $Left = $Values.Pop()
        $Values.Push($Left -and $Right)
      }
      'or' {
        if ($Values.Count -lt 2) { return $false }
        $Right = $Values.Pop()
        $Left = $Values.Pop()
        $Values.Push($Left -or $Right)
      }
      default {
        $Values.Push((Test-InnoArchitectureIdentifier -Identifier $Token -Architecture $Architecture))
      }
    }
  }

  $Values.Count -gt 0 -and $Values.Pop()
}

function Resolve-InnoBooleanDirective {
  <#
  .SYNOPSIS
    Resolve an Inno Setup yes/no directive with its implicit default
  .PARAMETER Value
    The serialized directive value from the setup header
  .PARAMETER Default
    The default value used by Inno Setup when the directive is omitted
  #>
  [OutputType([bool])]
  param (
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The default value used by Inno Setup when the directive is omitted')]
    [bool]$Default
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }

  switch -Regex ($Value.Trim()) {
    '^(?i:yes|true|1)$' { return $true }
    '^(?i:no|false|0)$' { return $false }
    default { return $Default }
  }
}

function Get-InnoAppsAndFeaturesEntryInfo {
  <#
  .SYNOPSIS
    Determine whether Inno Setup should create its own Apps & Features registry entry
  .PARAMETER HeaderValues
    The parsed Inno Setup header strings
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Inno Setup header strings')]
    [AllowEmptyString()]
    [string[]]$HeaderValues,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  $CreateUninstallRegKey = if ($HeaderValues.Count -gt 24) { $HeaderValues[24] } else { $null }
  $Uninstallable = if ($HeaderValues.Count -gt 25) { $HeaderValues[25] } else { $null }

  # Inno writes an ARP entry only when the uninstall registry key is created
  # and an uninstaller is registered. Both directives default to "yes".
  $CreatesUninstallRegistryKey = Resolve-InnoBooleanDirective -Value $CreateUninstallRegKey -Default $true
  $RegistersUninstaller = Resolve-InnoBooleanDirective -Value $Uninstallable -Default $true

  return [pscustomobject]@{
    WritesAppsAndFeaturesEntry  = $CreatesUninstallRegistryKey -and $RegistersUninstaller
    CreateUninstallRegKey       = $CreateUninstallRegKey
    Uninstallable               = $Uninstallable
    CreatesUninstallRegistryKey = $CreatesUninstallRegistryKey
    RegistersUninstaller        = $RegistersUninstaller
    IsKnown                     = $VersionNumber -ge 5310 -or $HeaderValues.Count -gt 24
  }
}

function Get-InnoUnsupportedArchitectureList {
  <#
  .SYNOPSIS
    Get Windows architectures not supported by an Inno Setup architecture expression
  .PARAMETER Expression
    The effective ArchitecturesAllowed expression
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The effective ArchitecturesAllowed expression')]
    [AllowEmptyString()]
    [string]$Expression
  )

  if ([string]::IsNullOrWhiteSpace($Expression)) { return @() }

  @('x86', 'x64', 'arm64') | Where-Object {
    -not (Test-InnoArchitectureExpression -Expression $Expression -Architecture $_)
  }
}

function Get-InnoSupportedArchitectureList {
  <#
  .SYNOPSIS
    Get Windows architectures supported by an Inno Setup architecture expression
  .PARAMETER Expression
    The effective ArchitecturesAllowed expression
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The effective ArchitecturesAllowed expression')]
    [AllowEmptyString()]
    [string]$Expression
  )

  if ([string]::IsNullOrWhiteSpace($Expression)) { return @() }

  @('x86', 'x64', 'arm64') | Where-Object {
    Test-InnoArchitectureExpression -Expression $Expression -Architecture $_
  }
}

function Read-InnoHeaderFixedData {
  <#
  .SYNOPSIS
    Read selected fixed Inno Setup header fields from the decompressed header stream
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Layout
    The supported Inno header layout
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed header stream bytes')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    switch ($Layout.StringEncoding) {
      'Unicode' {
        $null = Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderStringCount -Encoding ([System.Text.Encoding]::Unicode)
        $null = Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderAnsiStringCount -Encoding (Get-InnoAnsiEncoding)
      }
      'Ansi' {
        $AnsiCount = $Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount
        $null = Read-InnoReaderStrings -Reader $Reader -Count $AnsiCount -Encoding (Get-InnoAnsiEncoding)
      }
      default { throw "Unsupported Inno Setup header string encoding: $($Layout.StringEncoding)" }
    }

    $FixedTailOffset = $Reader.BaseStream.Position
    $FieldOffset = Get-InnoHeaderFixedDataOffset -VersionNumber $VersionNumber
    if (-not $FieldOffset) {
      return [pscustomobject]@{
        PrivilegesRequired                 = $null
        PrivilegesRequiredOverridesAllowed = @()
        SupportsPrivilegeOverride          = $false
        SupportsCommandLineScopeOverride   = $false
      }
    }

    if ($FixedTailOffset + $FieldOffset.PrivilegesRequiredOverridesAllowed -ge $Reader.BaseStream.Length) {
      throw 'The Inno Setup fixed header is truncated'
    }

    $Reader.BaseStream.Seek($FixedTailOffset + $FieldOffset.PrivilegesRequired, 'Begin') | Out-Null
    $PrivilegesRequiredValue = $Reader.ReadByte()
    $PrivilegesRequired = switch ($PrivilegesRequiredValue) {
      0 { 'none' }
      1 { 'poweruser' }
      2 { 'admin' }
      3 { 'lowest' }
      default { "unknown:$PrivilegesRequiredValue" }
    }

    $Reader.BaseStream.Seek($FixedTailOffset + $FieldOffset.PrivilegesRequiredOverridesAllowed, 'Begin') | Out-Null
    $OverridesValue = $Reader.ReadByte()
    $Overrides = @()
    if (($OverridesValue -band 0x01) -ne 0) { $Overrides += 'commandline' }
    if (($OverridesValue -band 0x02) -ne 0) { $Overrides += 'dialog' }

    return [pscustomobject]@{
      PrivilegesRequired                 = $PrivilegesRequired
      PrivilegesRequiredOverridesAllowed = $Overrides
      SupportsPrivilegeOverride          = [bool]$Overrides
      SupportsCommandLineScopeOverride   = $Overrides -contains 'commandline'
    }
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Convert-InnoPrivilegeToScope {
  <#
  .SYNOPSIS
    Convert an Inno Setup PrivilegesRequired value to its default install scope
  .PARAMETER PrivilegesRequired
    The parsed PrivilegesRequired value
  #>
  [OutputType([string])]
  param (
    [AllowNull()]
    [string]$PrivilegesRequired
  )

  switch ($PrivilegesRequired) {
    'none' { 'user' }
    'lowest' { 'user' }
    'poweruser' { 'machine' }
    'admin' { 'machine' }
    default { $null }
  }
}

function Resolve-InnoDefaultDirectory {
  <#
  .SYNOPSIS
    Resolve the common deterministic directory constants used in DefaultDirName
  .PARAMETER Value
    The raw DefaultDirName value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw DefaultDirName value')]
    [AllowEmptyString()]
    [string]$Value
  )

  $Replacements = [ordered]@{
    '{autopf}'   = $env:ProgramFiles
    '{pf}'       = $env:ProgramFiles
    '{pf32}'     = (${env:ProgramFiles(x86)} ?? $env:ProgramFiles)
    '{autopf32}' = (${env:ProgramFiles(x86)} ?? $env:ProgramFiles)
    '{pf64}'     = (${env:ProgramW6432} ?? $env:ProgramFiles)
    '{autopf64}' = (${env:ProgramW6432} ?? $env:ProgramFiles)
    '{commonpf}' = $env:ProgramFiles
  }

  $ResolvedValue = $Value
  foreach ($Name in $Replacements.Keys) {
    if ($ResolvedValue.StartsWith($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $ResolvedValue.Replace($Name, $Replacements[$Name])
    }
  }

  return $ResolvedValue
}

function Test-InnoResolvedValue {
  <#
  .SYNOPSIS
    Test whether an Inno Setup metadata string is deterministic enough to expose directly
  .PARAMETER Value
    The metadata value
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The metadata value')]
    [AllowEmptyString()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  if ($Value -match '\{code:') { return $false }
  if ($Value -match '^\{[A-Za-z]+:[^}]+\}$') { return $false }
  return $true
}

function Get-InnoInfo {
  <#
  .SYNOPSIS
    Get static metadata from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)

    try {
      $Reader.BaseStream.Seek($OffsetTable.Offset0, 'Begin') | Out-Null
      $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
      $Signature = [System.Text.Encoding]::ASCII.GetString($SignatureBytes).Trim([char]0)
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $SignatureMatch = [regex]::Match($Signature, $Script:INNO_SIGNATURE_PATTERN)
    if (-not $SignatureMatch.Success) { throw 'The file is not a supported Inno Setup installer' }

    $PEInfo = Get-InnoPEInfo -Path $InstallerPath
    $VersionNumber = Get-InnoVersionNumber -Version $SignatureMatch.Groups[1].Value
    $Layout = Get-InnoLayout -VersionNumber $VersionNumber -UnicodeVariant ([bool]$SignatureMatch.Groups[2].Success)
    $HeaderBytes = Get-InnoHeaderBlock -Path $InstallerPath -Offset0 $OffsetTable.Offset0 -Layout $Layout -VersionNumber $VersionNumber
    $HeaderValues = Read-InnoHeaderStrings -Bytes $HeaderBytes -Layout $Layout
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBytes -Layout $Layout -VersionNumber $VersionNumber
    $HeaderArchitectureData = Get-InnoHeaderArchitectureData -HeaderValues $HeaderValues -VersionNumber $VersionNumber -PEInfo $PEInfo
    $AppsAndFeaturesEntryInfo = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber $VersionNumber

    $AppName = $HeaderValues[0]
    $AppVerName = $HeaderValues[1]
    $AppId = $HeaderValues[2]
    $AppPublisher = $HeaderValues[4]
    $AppVersion = $HeaderValues[9]
    $DefaultDirName = $HeaderValues[10]
    $UninstallDisplayName = $HeaderValues[14]

    $DisplayName = if (Test-InnoResolvedValue -Value $UninstallDisplayName) {
      $UninstallDisplayName
    } elseif (Test-InnoResolvedValue -Value $AppVerName) {
      $AppVerName
    } else {
      $AppName
    }

    $ResolvedDefaultDirName = Resolve-InnoDefaultDirectory -Value $DefaultDirName
    $Scope = if (
      $ResolvedDefaultDirName.StartsWith($env:ProgramFiles, [System.StringComparison]::OrdinalIgnoreCase) -or
      (${env:ProgramFiles(x86)} -and $ResolvedDefaultDirName.StartsWith(${env:ProgramFiles(x86)}, [System.StringComparison]::OrdinalIgnoreCase))
    ) {
      'machine'
    } elseif (
      $ResolvedDefaultDirName.StartsWith($env:LOCALAPPDATA, [System.StringComparison]::OrdinalIgnoreCase) -or
      $ResolvedDefaultDirName.StartsWith($env:APPDATA, [System.StringComparison]::OrdinalIgnoreCase) -or
      $ResolvedDefaultDirName.StartsWith($env:USERPROFILE, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
      'user'
    } else {
      $null
    }
    $DefaultScope = Convert-InnoPrivilegeToScope -PrivilegesRequired $HeaderFixedData.PrivilegesRequired
    $SupportedScopes = if ($HeaderFixedData.SupportsCommandLineScopeOverride -and $DefaultScope) {
      @('user', 'machine')
    } elseif ($DefaultScope) {
      @($DefaultScope)
    } else {
      @()
    }

    return [pscustomobject]@{
      Path                   = $InstallerPath
      InstallerType          = 'Inno'
      DisplayVersion         = $AppVersion
      DisplayName            = $DisplayName
      Publisher              = $AppPublisher
      ProductCode            = $AppId
      DefaultInstallLocation = $ResolvedDefaultDirName
      Scope                  = $Scope
      DefaultScope           = $DefaultScope
      SupportedScopes        = $SupportedScopes
      SupportsDualScope      = $SupportedScopes.Count -gt 1
      PrivilegesRequired     = $HeaderFixedData.PrivilegesRequired
      PrivilegesRequiredOverridesAllowed = $HeaderFixedData.PrivilegesRequiredOverridesAllowed
      SupportsCommandLineScopeOverride = $HeaderFixedData.SupportsCommandLineScopeOverride
      WritesAppsAndFeaturesEntry = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry
      CreateUninstallRegKey = $AppsAndFeaturesEntryInfo.CreateUninstallRegKey
      Uninstallable = $AppsAndFeaturesEntryInfo.Uninstallable
      CreatesUninstallRegistryKey = $AppsAndFeaturesEntryInfo.CreatesUninstallRegistryKey
      RegistersUninstaller = $AppsAndFeaturesEntryInfo.RegistersUninstaller
      ArchitecturesAllowed = $HeaderArchitectureData.ArchitecturesAllowed
      ArchitecturesInstallIn64BitMode = $HeaderArchitectureData.ArchitecturesInstallIn64BitMode
      EffectiveArchitecturesAllowed = $HeaderArchitectureData.EffectiveArchitecturesAllowed
      EffectiveArchitecturesInstallIn64BitMode = $HeaderArchitectureData.EffectiveArchitecturesInstallIn64BitMode
      SupportedArchitectures = if ($HeaderArchitectureData.IsKnown) { Get-InnoSupportedArchitectureList -Expression $HeaderArchitectureData.EffectiveArchitecturesAllowed } else { @() }
      UnsupportedArchitectures = if ($HeaderArchitectureData.IsKnown) { Get-InnoUnsupportedArchitectureList -Expression $HeaderArchitectureData.EffectiveArchitecturesAllowed } else { @() }
      InstallerArchitecture = $PEInfo.Architecture
      AppName                = $AppName
      AppVerName             = $AppVerName
      AppVersion             = $AppVersion
      AppId                  = $AppId
      UninstallDisplayName   = $UninstallDisplayName
      Signature              = $Signature
      VersionNumber          = $VersionNumber
    }
  }
}

function Read-ProductVersionFromInno {
  <#
  .SYNOPSIS
    Read the product version from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path

    if (Test-InnoResolvedValue -Value $Info.AppVersion) { return $Info.AppVersion }

    $Match = [regex]::Match($Info.AppVerName, '(\d+(?:[.-]\d+)+)')
    if ($Match.Success) { return $Match.Groups[1].Value }

    throw 'The Inno Setup installer does not expose a deterministic version value'
  }
}

function Read-ProductNameFromInno {
  <#
  .SYNOPSIS
    Read the product name from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.DisplayName)) { throw 'The Inno Setup installer does not expose a product name' }
    return $Info.DisplayName
  }
}

function Read-PublisherFromInno {
  <#
  .SYNOPSIS
    Read the publisher from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.Publisher)) { throw 'The Inno Setup installer does not expose a publisher value' }
    return $Info.Publisher
  }
}

function Read-ProductCodeFromInno {
  <#
  .SYNOPSIS
    Read the AppId value from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    $Info = Get-InnoInfo -Path $Path
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Inno Setup installer does not expose an AppId value' }
    return $Info.ProductCode
  }
}

function Get-InnoVersion5Header {
  <#
  .SYNOPSIS
    Read the legacy ANSI Inno Setup 5.x header counts needed for static file extraction
  .PARAMETER Bytes
    The decompressed first metadata block
  .PARAMETER Layout
    The supported Inno header layout
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed first metadata block')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  if ($Layout.StringEncoding -ne 'Ansi') { throw 'Inno file extraction currently supports ANSI Inno Setup installers only' }

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $HeaderValues = Read-InnoReaderStrings -Reader $Reader -Count ($Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount) -Encoding (Get-InnoAnsiEncoding)
    $HeaderFixedSize = Get-InnoVersion5HeaderFixedSize -VersionNumber $VersionNumber
    # Old ANSI installers persist the fixed metadata immediately after the main header strings.
    $Reader.BaseStream.Seek($Script:INNO_LEAD_BYTES_SIZE, 'Current') | Out-Null

    $Counts = [ordered]@{
      NumLanguageEntries         = $Reader.ReadInt32()
      NumCustomMessageEntries    = $Reader.ReadInt32()
      NumPermissionEntries       = $Reader.ReadInt32()
      NumTypeEntries             = $Reader.ReadInt32()
      NumComponentEntries        = $Reader.ReadInt32()
      NumTaskEntries             = $Reader.ReadInt32()
      NumDirEntries              = $Reader.ReadInt32()
      NumFileEntries             = $Reader.ReadInt32()
      NumFileLocationEntries     = $Reader.ReadInt32()
      NumIconEntries             = $Reader.ReadInt32()
      NumIniEntries              = $Reader.ReadInt32()
      NumRegistryEntries         = $Reader.ReadInt32()
      NumInstallDeleteEntries    = $Reader.ReadInt32()
      NumUninstallDeleteEntries  = $Reader.ReadInt32()
      NumRunEntries              = $Reader.ReadInt32()
      NumUninstallRunEntries     = $Reader.ReadInt32()
    }

    $RemainingHeaderBytes = $HeaderFixedSize - $Script:INNO_LEAD_BYTES_SIZE - ($Script:INNO_VERSION_5_HEADER_COUNT_FIELDS * 4)
    if ($RemainingHeaderBytes -lt 0) { throw 'The ANSI Inno Setup header size is invalid' }
    $Reader.BaseStream.Seek($RemainingHeaderBytes, 'Current') | Out-Null

    return [pscustomobject]@{
      HeaderValues = $HeaderValues
      Counts       = [pscustomobject]$Counts
      StreamOffset = $Reader.BaseStream.Position
    }
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Skip-InnoVersion5Entry {
  <#
  .SYNOPSIS
    Skip an ANSI Inno Setup 5.x metadata entry in the first metadata block
  .PARAMETER Reader
    The binary reader positioned at the start of the entry
  .PARAMETER StringCount
    The number of serialized ANSI strings in the entry
  .PARAMETER FixedSize
    The number of fixed-size bytes that follow the serialized strings
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader positioned at the start of the entry')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The number of serialized ANSI strings in the entry')]
    [int]$StringCount,

    [Parameter(Mandatory, HelpMessage = 'The number of fixed-size bytes that follow the serialized strings')]
    [int]$FixedSize
  )

  $null = Read-InnoReaderStrings -Reader $Reader -Count $StringCount -Encoding (Get-InnoAnsiEncoding)
  $Reader.BaseStream.Seek($FixedSize, 'Current') | Out-Null
}

function Get-InnoVersion5FileEntries {
  <#
  .SYNOPSIS
    Parse file entries from the first metadata block of an ANSI Inno Setup 5.x installer
  .PARAMETER Bytes
    The decompressed first metadata block
  .PARAMETER Header
    The parsed ANSI Inno Setup 5.x header metadata
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed first metadata block')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The parsed ANSI Inno Setup 5.x header metadata')]
    [pscustomobject]$Header
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Reader.BaseStream.Seek($Header.StreamOffset, 'Begin') | Out-Null

    for ($i = 0; $i -lt $Header.Counts.NumLanguageEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount ($Script:INNO_LANGUAGE_ENTRY_STRINGS + $Script:INNO_LANGUAGE_ENTRY_ANSI_STRINGS) -FixedSize $Script:INNO_LANGUAGE_ENTRY_FIXED_SIZE
    }
    for ($i = 0; $i -lt $Header.Counts.NumCustomMessageEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_CUSTOM_MESSAGE_ENTRY_STRINGS -FixedSize $Script:INNO_CUSTOM_MESSAGE_ENTRY_FIXED_SIZE
    }
    for ($i = 0; $i -lt $Header.Counts.NumPermissionEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_PERMISSION_ENTRY_ANSI_STRINGS -FixedSize 0
    }
    for ($i = 0; $i -lt $Header.Counts.NumTypeEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_TYPE_ENTRY_STRINGS -FixedSize $Script:INNO_TYPE_ENTRY_FIXED_SIZE
    }
    for ($i = 0; $i -lt $Header.Counts.NumComponentEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_COMPONENT_ENTRY_STRINGS -FixedSize $Script:INNO_COMPONENT_ENTRY_FIXED_SIZE
    }
    for ($i = 0; $i -lt $Header.Counts.NumTaskEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_TASK_ENTRY_STRINGS -FixedSize $Script:INNO_TASK_ENTRY_FIXED_SIZE
    }
    for ($i = 0; $i -lt $Header.Counts.NumDirEntries; $i++) {
      Skip-InnoVersion5Entry -Reader $Reader -StringCount $Script:INNO_DIRECTORY_ENTRY_STRINGS -FixedSize $Script:INNO_DIRECTORY_ENTRY_FIXED_SIZE
    }

    $Entries = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -lt $Header.Counts.NumFileEntries; $i++) {
      $Strings = Read-InnoReaderStrings -Reader $Reader -Count $Script:INNO_FILE_ENTRY_STRINGS -Encoding (Get-InnoAnsiEncoding)
      $null = $Reader.ReadBytes(20) # MinVersion + OnlyBelowVersion
      $LocationEntry = $Reader.ReadInt32()
      $Attribs = $Reader.ReadInt32()
      $ExternalSize = $Reader.ReadInt64()
      $PermissionsEntry = $Reader.ReadInt16()
      $Options = $Reader.ReadBytes($Script:INNO_FILE_ENTRY_OPTIONS_SIZE)
      $FileType = $Reader.ReadByte()

      $Entries.Add([pscustomobject]@{
          SourceFilename   = $Strings[0]
          DestName         = $Strings[1]
          InstallFontName  = $Strings[2]
          StrongAssemblyName = $Strings[3]
          Components       = $Strings[4]
          Tasks            = $Strings[5]
          Languages        = $Strings[6]
          Check            = $Strings[7]
          AfterInstall     = $Strings[8]
          BeforeInstall    = $Strings[9]
          LocationEntry    = $LocationEntry
          Attribs          = $Attribs
          ExternalSize     = $ExternalSize
          PermissionsEntry = $PermissionsEntry
          Options          = $Options
          FileType         = $FileType
        })
    }

    return $Entries.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function ConvertFrom-InnoVersion5FileLocationFlags {
  <#
  .SYNOPSIS
    Decode the flag bitset used by ANSI Inno Setup 5.x file location entries
  .PARAMETER Value
    The raw bitset value from the file location entry
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw bitset value from the file location entry')]
    [uint16]$Value
  )

  return [pscustomobject]@{
    VersionInfoValid       = [bool]($Value -band 0x0001)
    VersionInfoNotValid    = [bool]($Value -band 0x0002)
    TimeStampInUtc         = [bool]($Value -band 0x0004)
    IsUninstallExecutable  = [bool]($Value -band 0x0008)
    CallInstructionOptimized = [bool]($Value -band 0x0010)
    TouchApplied           = [bool]($Value -band 0x0020)
    ChunkEncrypted         = [bool]($Value -band 0x0040)
    ChunkCompressed        = [bool]($Value -band 0x0080)
    SolidBreak             = [bool]($Value -band 0x0100)
  }
}

function Get-InnoVersion5FileLocations {
  <#
  .SYNOPSIS
    Parse file location entries from the second metadata block of an ANSI Inno Setup 5.x installer
  .PARAMETER Bytes
    The decompressed second metadata block
  .PARAMETER Count
    The number of file location entries to read
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed second metadata block')]
    [byte[]]$Bytes,

    [Parameter(HelpMessage = 'The number of file location entries to read')]
    [int]$Count
  )

  if ($Count -le 0) {
    if (($Bytes.Length % $Script:INNO_FILE_LOCATION_ENTRY_SIZE) -ne 0) { throw 'The Inno Setup file location block size is invalid' }
    $Count = [int]($Bytes.Length / $Script:INNO_FILE_LOCATION_ENTRY_SIZE)
  }

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Locations = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -lt $Count; $i++) {
      $FirstSlice = $Reader.ReadInt32()
      $LastSlice = $Reader.ReadInt32()
      $StartOffset = [long]$Reader.ReadInt32()
      $ChunkSuboffset = $Reader.ReadInt64()
      $OriginalSize = $Reader.ReadInt64()
      $ChunkCompressedSize = $Reader.ReadInt64()
      $Sha1 = $Reader.ReadBytes(20)
      $TimeStamp = $Reader.ReadBytes(8)
      $FileVersionMS = $Reader.ReadUInt32()
      $FileVersionLS = $Reader.ReadUInt32()
      $Flags = ConvertFrom-InnoVersion5FileLocationFlags -Value $Reader.ReadUInt16()

      $Locations.Add([pscustomobject]@{
          FirstSlice          = $FirstSlice
          LastSlice           = $LastSlice
          StartOffset         = $StartOffset
          ChunkSuboffset      = $ChunkSuboffset
          OriginalSize        = $OriginalSize
          ChunkCompressedSize = $ChunkCompressedSize
          Sha1                = $Sha1
          TimeStamp           = $TimeStamp
          FileVersionMS       = $FileVersionMS
          FileVersionLS       = $FileVersionLS
          Flags               = $Flags
        })
    }

    return $Locations.ToArray()
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Resolve-InnoExtractionPath {
  <#
  .SYNOPSIS
    Resolve an extracted Inno payload path under the destination root and block path traversal
  .PARAMETER DestinationPath
    The extraction root
  .PARAMETER RelativePath
    The payload-relative path to be extracted
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction root')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The payload-relative path to be extracted')]
    [string]$RelativePath
  )

  return Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
}

function Resolve-InnoVersion5FileMatch {
  <#
  .SYNOPSIS
    Resolve deterministic file entry matches from an ANSI Inno Setup 5.x installer
  .PARAMETER Entry
    The parsed file entries
  .PARAMETER Name
    The file name or wildcard pattern to match
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed file entries')]
    [pscustomobject[]]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern to match')]
    [string]$Name
  )

  if ($Name -eq '*') {
    return $Entry.Where({ $_.LocationEntry -ge 0 })
  }

  $Match = $Entry.Where({
      $_.LocationEntry -ge 0 -and (
        $_.DestName -like $Name -or
        $_.SourceFilename -like $Name -or
        ([System.IO.Path]::GetFileName($_.DestName)) -like $Name -or
        ([System.IO.Path]::GetFileName($_.SourceFilename)) -like $Name
      )
    })
  if (-not $Match) { throw "No files matched the Inno Setup pattern: $Name" }

  $ExactMatches = $Match.Where({
      $_.DestName -ieq $Name -or
      $_.SourceFilename -ieq $Name -or
      ([System.IO.Path]::GetFileName($_.DestName)) -ieq $Name -or
      ([System.IO.Path]::GetFileName($_.SourceFilename)) -ieq $Name
    })
  if ($ExactMatches) { return $ExactMatches }

  return $Match
}

function Find-InnoVersion5FileEntry {
  <#
  .SYNOPSIS
    Locate a targeted ANSI Inno Setup 5.x file entry directly from the first metadata block
  .PARAMETER Bytes
    The decompressed first metadata block
  .PARAMETER Name
    The exact file name to locate
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed first metadata block')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The exact file name to locate')]
    [string]$Name
  )

  $Encoding = Get-InnoAnsiEncoding
  $TargetName = $Name.ToLowerInvariant()
  $FileEntryTrailerSize = $Script:INNO_FILE_ENTRY_FIXED_SIZE

  for ($Start = 0; $Start -le $Bytes.Length - (4 + $FileEntryTrailerSize); $Start++) {
    $DeclaredLength = [System.BitConverter]::ToInt32($Bytes, $Start)
    if ($DeclaredLength -lt 0 -or $DeclaredLength -gt 4096) { continue }

    $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
    $Reader = [System.IO.BinaryReader]::new($Stream)
    try {
      $Reader.BaseStream.Seek($Start, 'Begin') | Out-Null
      $Strings = Read-InnoReaderStrings -Reader $Reader -Count $Script:INNO_FILE_ENTRY_STRINGS -Encoding $Encoding
      if ($Reader.BaseStream.Position + $FileEntryTrailerSize -gt $Reader.BaseStream.Length) { continue }

      $CandidateNames = @(
        $Strings[0],
        $Strings[1],
        [System.IO.Path]::GetFileName($Strings[0]),
        [System.IO.Path]::GetFileName($Strings[1])
      ).Where({ -not [string]::IsNullOrWhiteSpace($_) }).ForEach({ $_.ToLowerInvariant() })

      if (-not $CandidateNames.Where({ $_ -eq $TargetName -or $_.EndsWith("\$TargetName") }, 'First')) { continue }

      $null = $Reader.ReadBytes(20) # MinVersion + OnlyBelowVersion
      $LocationEntry = $Reader.ReadInt32()
      $Attribs = $Reader.ReadInt32()
      $ExternalSize = $Reader.ReadInt64()
      $PermissionsEntry = $Reader.ReadInt16()
      $Options = $Reader.ReadBytes($Script:INNO_FILE_ENTRY_OPTIONS_SIZE)
      $FileType = $Reader.ReadByte()

      if ($LocationEntry -lt 0 -or $LocationEntry -gt 500000) { continue }

      return [pscustomobject]@{
        SourceFilename   = $Strings[0]
        DestName         = $Strings[1]
        InstallFontName  = $Strings[2]
        StrongAssemblyName = $Strings[3]
        Components       = $Strings[4]
        Tasks            = $Strings[5]
        Languages        = $Strings[6]
        Check            = $Strings[7]
        AfterInstall     = $Strings[8]
        BeforeInstall    = $Strings[9]
        LocationEntry    = $LocationEntry
        Attribs          = $Attribs
        ExternalSize     = $ExternalSize
        PermissionsEntry = $PermissionsEntry
        Options          = $Options
        FileType         = $FileType
      }
    } catch {
    } finally {
      $Reader.Close()
      $Stream.Close()
    }
  }

  throw "No file entry matched the ANSI Inno Setup target: $Name"
}

function Convert-InnoCallInstructions {
  <#
  .SYNOPSIS
    Reverse the legacy Inno Setup x86 CALL/JMP optimization for extracted files
  .PARAMETER Bytes
    The extracted file bytes
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The extracted file bytes')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 5) { return }

  $Limit = $Bytes.Length - 4
  $Index = 0
  while ($Index -lt $Limit) {
    if ($Bytes[$Index] -eq 0xE8 -or $Bytes[$Index] -eq 0xE9) {
      $Index++
      if ($Bytes[$Index + 3] -eq 0x00 -or $Bytes[$Index + 3] -eq 0xFF) {
        $Address = [uint32]($Index + 4)
        $Address = [uint32]((0x100000000 - [uint64]$Address) % 0x100000000)
        for ($Offset = 0; $Offset -lt 3; $Offset++) {
          $Address = $Address + $Bytes[$Index + $Offset]
          $Bytes[$Index + $Offset] = [byte]($Address -band 0xFF)
          $Address = $Address -shr 8
        }
      }
      $Index += 4
    } else {
      $Index++
    }
  }
}

function Convert-InnoCallInstructions5309 {
  <#
  .SYNOPSIS
    Reverse the Inno Setup 5.3.9+ CALL/JMP optimization for extracted files
  .PARAMETER Bytes
    The extracted file bytes
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The extracted file bytes')]
    [byte[]]$Bytes
  )

  if ($Bytes.Length -lt 5) { return }

  $Limit = $Bytes.Length - 4
  $Index = 0
  while ($Index -lt $Limit) {
    if ($Bytes[$Index] -eq 0xE8 -or $Bytes[$Index] -eq 0xE9) {
      $Index++
      if ($Bytes[$Index + 3] -eq 0x00 -or $Bytes[$Index + 3] -eq 0xFF) {
        $Address = [uint32](($Index + 4) -band 0xFFFFFF)
        $Relative = [uint32]$Bytes[$Index] + ([uint32]$Bytes[$Index + 1] * 0x100) + ([uint32]$Bytes[$Index + 2] * 0x10000)
        if ($Relative -lt $Address) {
          $Relative = [uint32]([uint64]$Relative + 0x1000000 - [uint64]$Address)
        } else {
          $Relative = [uint32]([uint64]$Relative - [uint64]$Address)
        }

        if (($Relative -band 0x800000) -ne 0) {
          $Bytes[$Index + 3] = [byte]($Bytes[$Index + 3] -bxor 0xFF)
        }

        $Bytes[$Index] = [byte]($Relative -band 0xFF)
        $Bytes[$Index + 1] = [byte](($Relative -shr 8) -band 0xFF)
        $Bytes[$Index + 2] = [byte](($Relative -shr 16) -band 0xFF)
      }
      $Index += 4
    } else {
      $Index++
    }
  }
}

function Get-InnoVersion5FileBytes {
  <#
  .SYNOPSIS
    Extract a single file payload from an ANSI Inno Setup 5.x installer without executing it
  .PARAMETER Path
    The path to the installer
  .PARAMETER Offset1
    The setup data offset from the loader offset table
  .PARAMETER Location
    The parsed file location entry
  .PARAMETER VersionNumber
    The numeric Inno Setup version
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The setup data offset from the loader offset table')]
    [long]$Offset1,

    [Parameter(Mandatory, HelpMessage = 'The parsed file location entry')]
    [pscustomobject]$Location,

    [Parameter(Mandatory, HelpMessage = 'The numeric Inno Setup version')]
    [int]$VersionNumber
  )

  if ($Location.Flags.ChunkEncrypted) { throw 'Encrypted Inno Setup file chunks are not supported' }

  $Stream = [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    # Offset1 points at the setup data stream. StartOffset is chunk-relative within that stream.
    $Stream.Seek($Offset1 + $Location.StartOffset, 'Begin') | Out-Null
    $ChunkMagic = [System.Text.Encoding]::ASCII.GetString($Reader.ReadBytes(4))
    if ($ChunkMagic -ne $Script:INNO_CHUNK_MAGIC) { throw 'The Inno Setup chunk marker is invalid' }

    $ChunkBytes = $Reader.ReadBytes([int]$Location.ChunkCompressedSize)
    if ($ChunkBytes.Length -ne $Location.ChunkCompressedSize) { throw 'The Inno Setup file chunk is truncated' }

    $ChunkCandidates = [System.Collections.Generic.List[object]]::new()

    if ($Location.Flags.ChunkCompressed) {
      foreach ($CompressionCandidate in @(
          @{ Name = 'LZMA'; Expand = { param($Bytes) Expand-InnoLzmaBytes -Bytes $Bytes } },
          @{ Name = 'LZMA2'; Expand = { param($Bytes) Expand-InnoLzma2Bytes -Bytes $Bytes } }
        )) {
        try {
          $ChunkCandidates.Add([pscustomobject]@{
              Name  = $CompressionCandidate.Name
              Bytes = & $CompressionCandidate.Expand $ChunkBytes
            })
        } catch {
        }
      }
    } else {
      $ChunkCandidates.Add([pscustomobject]@{
          Name  = 'Stored'
          Bytes = $ChunkBytes
        })
    }

    if (-not $ChunkCandidates) {
      throw 'The Inno Setup file chunk could not be decompressed with a supported method'
    }

    $CandidateFailures = [System.Collections.Generic.List[string]]::new()

    foreach ($ChunkCandidate in $ChunkCandidates) {
      if ($Location.ChunkSuboffset -lt 0 -or $Location.ChunkSuboffset + $Location.OriginalSize -gt $ChunkCandidate.Bytes.Length) {
        $CandidateFailures.Add("$($ChunkCandidate.Name): the Inno Setup file chunk metadata is invalid")
        continue
      }

      $RawBytes = [byte[]]::new([int]$Location.OriginalSize)
      [Buffer]::BlockCopy($ChunkCandidate.Bytes, [int]$Location.ChunkSuboffset, $RawBytes, 0, $RawBytes.Length)
      $FileCandidates = [System.Collections.Generic.List[object]]::new()

      if ($Location.Flags.CallInstructionOptimized) {
        $DecodedBytes = [byte[]]$RawBytes.Clone()
        if ($VersionNumber -ge 5309) {
          Convert-InnoCallInstructions5309 -Bytes $DecodedBytes
        } else {
          Convert-InnoCallInstructions -Bytes $DecodedBytes
        }
        $FileCandidates.Add([pscustomobject]@{ Name = "$($ChunkCandidate.Name)/Decoded"; Bytes = $DecodedBytes })
      }
      $FileCandidates.Add([pscustomobject]@{ Name = "$($ChunkCandidate.Name)/Raw"; Bytes = $RawBytes })

      foreach ($FileCandidate in $FileCandidates) {
        if ($Location.Sha1.Length -eq 20) {
          $ActualSha1 = [System.Security.Cryptography.SHA1]::HashData($FileCandidate.Bytes)
          if ([System.Linq.Enumerable]::SequenceEqual($ActualSha1, $Location.Sha1)) {
            return ,$FileCandidate.Bytes
          }
          $CandidateFailures.Add("$($FileCandidate.Name): SHA1 digest mismatch")
        } else {
          return ,$FileCandidate.Bytes
        }
      }
    }

    throw "The extracted Inno Setup file does not match the stored SHA1 digest. Tried: $($CandidateFailures -join '; ')"
  } finally {
    $Reader.Close()
    $Stream.Close()
  }
}

function Read-UnsupportedArchitecturesFromInno {
  <#
  .SYNOPSIS
    Read Windows architectures that an Inno Setup installer does not support
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures
  }
}

function Test-InnoUnsupportedArchitecture {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer does not support a Windows architecture
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER Architecture
    The Windows architecture to test
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The Windows architecture to test')]
    [ValidateSet('x86', 'x64', 'arm64')]
    [string]$Architecture
  )

  process {
    (Get-InnoInfo -Path $Path).UnsupportedArchitectures -contains $Architecture
  }
}

function Test-InnoAppsAndFeaturesEntry {
  <#
  .SYNOPSIS
    Test whether an Inno Setup installer writes its own Apps & Features registry entry
  .PARAMETER Path
    The path to the Inno Setup installer
  #>
  [OutputType([bool])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path
  )

  process {
    (Get-InnoInfo -Path $Path).WritesAppsAndFeaturesEntry
  }
}

function Expand-InnoInstaller {
  <#
  .SYNOPSIS
    Extract selected files from an ANSI Inno Setup 5.x installer without executing it
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER DestinationPath
    The directory where matching files should be written
  .PARAMETER Name
    The file name or wildcard pattern to extract
  .PARAMETER Language
    An optional Inno Setup language name used to disambiguate language-specific payloads
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The file name or wildcard pattern to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'An optional Inno Setup language name used to disambiguate language-specific payloads')]
    [string]$Language
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $InstallerPath -Parent
    }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)
    try {
      $Reader.BaseStream.Seek($OffsetTable.Offset0, 'Begin') | Out-Null
      $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
      $Signature = [System.Text.Encoding]::ASCII.GetString($SignatureBytes).Trim([char]0)
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $SignatureMatch = [regex]::Match($Signature, $Script:INNO_SIGNATURE_PATTERN)
    if (-not $SignatureMatch.Success) { throw 'The file is not a supported Inno Setup installer' }

    $VersionNumber = Get-InnoVersionNumber -Version $SignatureMatch.Groups[1].Value
    $Layout = Get-InnoLayout -VersionNumber $VersionNumber -UnicodeVariant ([bool]$SignatureMatch.Groups[2].Success)
    if ($Layout.StringEncoding -ne 'Ansi' -or $VersionNumber -lt 5310 -or $VersionNumber -ge 6000) {
      throw "Static Inno file extraction is currently limited to ANSI Inno Setup 5.x installers. Found $Signature"
    }

    if ($Name -eq '*') { throw 'Static Inno file extraction currently requires an explicit file name' }

    $HeaderBlockInfo = Get-InnoHeaderBlockInfo -Path $InstallerPath -Offset0 $OffsetTable.Offset0 -Layout $Layout -VersionNumber $VersionNumber
    $Header = Get-InnoVersion5Header -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -VersionNumber $VersionNumber
    $FileEntries = Get-InnoVersion5FileEntries -Bytes $HeaderBlockInfo.Bytes -Header $Header
    $MatchedEntries = @(Resolve-InnoVersion5FileMatch -Entry $FileEntries -Name $Name)
    if ($PSBoundParameters.ContainsKey('Language')) {
      $MatchedEntries = @($MatchedEntries.Where({
            -not [string]::IsNullOrWhiteSpace($_.Languages) -and
            (@($_.Languages -split '[,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -contains $Language)
          }))
      if (-not $MatchedEntries) { throw "No files matched the Inno Setup language selector: $Language" }
    }

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)
    try {
      $LocationBlockHeader = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $HeaderBlockInfo.NextOffset -UsesInt64BlockHeader $Layout.UsesInt64BlockHeader -FileLength $FileStream.Length
      if (-not $LocationBlockHeader) { throw 'The Inno Setup file location block could not be located' }
      $LocationBlockInfo = Read-InnoCompressedBlock -Reader $Reader -BlockHeader $LocationBlockHeader
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $FileLocations = Get-InnoVersion5FileLocations -Bytes $LocationBlockInfo.Bytes -Count $Header.Counts.NumFileLocationEntries
    $ExtractedFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $ExtractionFailures = [System.Collections.Generic.List[string]]::new()
    $WrittenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($Entry in $MatchedEntries) {
      try {
        if ($Entry.LocationEntry -lt 0 -or $Entry.LocationEntry -ge $FileLocations.Count) {
          throw "The Inno Setup file entry '$($Entry.SourceFilename)' points to an invalid file location index"
        }

        $Location = $FileLocations[$Entry.LocationEntry]
        $FileBytes = Get-InnoVersion5FileBytes -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location -VersionNumber $VersionNumber
        $RelativePath = if ([string]::IsNullOrWhiteSpace($Entry.DestName)) {
          [System.IO.Path]::GetFileName($Entry.SourceFilename)
        } else {
          $Entry.DestName
        }
        if ($WrittenPaths.Contains($RelativePath)) { continue }
        $OutputPath = Resolve-InnoExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath

        $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
        [System.IO.File]::WriteAllBytes($OutputPath, $FileBytes)
        $null = $WrittenPaths.Add($RelativePath)
        $ExtractedFiles.Add((Get-Item -Path $OutputPath -Force))
      } catch {
        $ExtractionFailures.Add($_.Exception.Message)
      }
    }

    if (-not $ExtractedFiles) {
      $FailureMessage = $ExtractionFailures | Select-Object -Unique | ForEach-Object { "  - $_" }
      throw "No matching Inno Setup files could be extracted:`n$($FailureMessage -join [Environment]::NewLine)"
    }

    return $ExtractedFiles.ToArray()
  }
}

Export-ModuleMember -Function Get-InnoInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno, Read-UnsupportedArchitecturesFromInno, Test-InnoUnsupportedArchitecture, Test-InnoAppsAndFeaturesEntry, Expand-InnoInstaller
