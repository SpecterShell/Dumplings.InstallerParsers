# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/jrsoftware/issrc, https://github.com/jrathlev/InnoUnpacker-Windows-GUI, and https://github.com/russellbanks/Komac
#
# Binary structure consumed by this parser:
#
#   PE/.rsrc/RCDATA/#11111 -> offset table (44-byte v1 or 64-byte v2)
#     magic[12], version@+0C, Offset0/Offset1, CRC32 at the table tail
#   Offset0 -> setup signature[64] -> optional encryption header
#     -> [stored-size][compressed flag][CRC32 + <=4096-byte chunks]*
#     -> setup header and version-dependent tables
#   Offset1 -> file locations -> 7A 6C 62 1A ("zlb" 1A) payload blocks
#
# Offset-table values become absolute file offsets after resource decoding.
# Integer fields are little-endian; compressed metadata is stored or raw LZMA.
# Every declared range, chunk CRC, decompressed size, and table count is bounded.

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
$INNO_MAX_ENTRY_STRING_SIZE = 1048576
$INNO_MAX_FILE_ENTRY_PATH_SCAN = 16384
$INNO_PAYLOAD_BUFFER_SIZE = 1048576
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

function Import-InnoCallTransform {
  <#
  .SYNOPSIS
    Load the source-backed Inno CALL/JMP byte transform once
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.InnoCallTransform').Type) { return }

  $SourcePath = Join-Path $PSScriptRoot '..\Assets\InnoCallTransform.cs'
  if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
    throw "The Inno Setup CALL/JMP transform source is missing: $SourcePath"
  }
  Add-Type -Path $SourcePath -ErrorAction Stop
}

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

  # Require the exact RCDATA type/ID pair used by the loader. Arbitrary resource
  # bytes are not accepted as offset-table or setup metadata evidence.
  if (-not $Resource) { throw 'The requested Inno resource could not be found.' }
  return , (Read-PEResourceData -Resource $Resource -MaximumBytes 1048576)
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

  $InstallerLength = (Get-Item -Path $Path -Force).Length
  $Bytes = Get-InnoResourceBytes -Path $Path -Id $Script:INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE
  if ($Bytes.Length -lt 16) { throw 'The Inno Setup offset table is truncated' }
  $Identifier = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 12)
  if ($Identifier -ne $Script:INNO_OFFSET_TABLE_ID) { throw 'The Inno Setup offset table identifier is invalid' }

  $Version = [System.BitConverter]::ToUInt32($Bytes, 12)

  # Offset-table v1 uses 32-bit offsets and a 44-byte record; v2 widens the
  # persisted sizes/offsets to 64 bits and moves the CRC to byte 60.
  switch ($Version) {
    1 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_1_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $StoredCrc = [System.BitConverter]::ToUInt32($Bytes, 40)
      $ExpectedCrc = Get-BinaryCrc32 -Bytes $Bytes -Offset 0 -Count 40
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      $Result = [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToUInt32($Bytes, 16)
        Offset0   = [System.BitConverter]::ToUInt32($Bytes, 32)
        Offset1   = [System.BitConverter]::ToUInt32($Bytes, 36)
      }
      break
    }
    2 {
      if ($Bytes.Length -lt $Script:INNO_OFFSET_TABLE_VERSION_2_SIZE) { throw 'The Inno Setup offset table is truncated' }
      $StoredCrc = [System.BitConverter]::ToUInt32($Bytes, 60)
      $ExpectedCrc = Get-BinaryCrc32 -Bytes $Bytes -Offset 0 -Count 60
      if ($StoredCrc -ne $ExpectedCrc) { throw 'The Inno Setup offset table CRC is invalid' }

      $Result = [pscustomobject]@{
        Version   = $Version
        TotalSize = [System.BitConverter]::ToInt64($Bytes, 16)
        Offset0   = [System.BitConverter]::ToInt64($Bytes, 40)
        Offset1   = [System.BitConverter]::ToInt64($Bytes, 48)
      }
      break
    }
    default { throw "Unsupported Inno Setup offset table version: $Version" }
  }

  # TotalSize is the compiler-recorded minimum setup.exe size. Authenticode data
  # may follow it, but the embedded setup offsets must remain inside the file.
  if ($Result.TotalSize -le 0 -or $Result.TotalSize -gt $InstallerLength) {
    throw 'The Inno Setup offset table total size is invalid'
  }
  if ($Result.Offset0 -lt 0 -or $Result.Offset0 -gt $InstallerLength - $Script:INNO_SETUP_ID_SIZE) {
    throw 'The Inno Setup primary data offset is outside the installer'
  }
  if ($Result.Offset1 -lt 0 -or ($Result.Offset1 -ne 0 -and $Result.Offset1 -ge $InstallerLength)) {
    throw 'The Inno Setup secondary data offset is outside the installer'
  }

  return $Result
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

  if ($VersionNumber -lt 5310) { throw "Unsupported Inno Setup version: $VersionNumber" }

  # The setup signature is the serialization contract. These transitions match
  # SetupHeaderStrings in the corresponding official Shared.Struct.pas records.
  $HeaderStringCount = if ($VersionNumber -ge 6700) {
    39
  } elseif ($VersionNumber -ge 6500) {
    34
  } elseif ($VersionNumber -ge 6402) {
    33
  } elseif ($VersionNumber -ge 6300) {
    32
  } elseif ($VersionNumber -ge 6000) {
    30
  } elseif ($VersionNumber -ge 5506) {
    28
  } elseif ($VersionNumber -ge 5500) {
    27
  } else {
    26
  }

  # Fixed offsets are relative to the packed header tail after serialized
  # strings. They must not be inferred from the compiler executable version.
  $PrivilegesRequiredOffset = if ($VersionNumber -ge 7000) {
    143
  } elseif ($VersionNumber -ge 6700) {
    139
  } elseif ($VersionNumber -ge 6601) {
    129
  } elseif ($VersionNumber -ge 6600) {
    128
  } elseif ($VersionNumber -ge 6502) {
    120
  } elseif ($VersionNumber -ge 6500) {
    112
  } elseif ($VersionNumber -ge 6400) {
    156
  } elseif ($VersionNumber -ge 6000) {
    144
  } elseif ($VersionNumber -ge 5507) {
    # 5.5.7 replaced WizardImageBackColor (Longint) with the one-byte
    # WizardImageAlphaFormat enum, moving the remaining packed fields by 3.
    135 + ($UnicodeVariant ? 0 : $Script:INNO_LEAD_BYTES_SIZE)
  } else {
    138 + ($UnicodeVariant ? 0 : $Script:INNO_LEAD_BYTES_SIZE)
  }

  $HasPrivilegeOverrides = $VersionNumber -ge 6000
  $PackedArchitectureOffset = if ($VersionNumber -ge 6000 -and $VersionNumber -lt 6300) {
    149
  } elseif ($VersionNumber -ge 5507 -and $VersionNumber -lt 6000) {
    139 + ($UnicodeVariant ? 0 : $Script:INNO_LEAD_BYTES_SIZE)
  } elseif ($VersionNumber -lt 6000) {
    142 + ($UnicodeVariant ? 0 : $Script:INNO_LEAD_BYTES_SIZE)
  } else {
    $null
  }

  $FileLocationStartOffsetSize = $VersionNumber -ge 6502 ? 8 : 4
  $FileLocationDigestSize = $VersionNumber -ge 6400 ? 32 : 20
  $FileLocationUsesLegacyFlags = $VersionNumber -lt 6403
  $FileLocationHasSign = $VersionNumber -ge 6300 -and $VersionNumber -lt 6403
  $FileLocationEntrySize = 8 + $FileLocationStartOffsetSize + 24 + $FileLocationDigestSize + 8 + 8 +
  ($FileLocationUsesLegacyFlags ? 2 : 1) + ($FileLocationHasSign ? 1 : 0)

  return [pscustomobject]@{
    VersionNumber                            = $VersionNumber
    HeaderStringCount                        = $HeaderStringCount
    HeaderAnsiStringCount                    = 4
    UsesInt64BlockHeader                     = $VersionNumber -ge 6700
    StringEncoding                           = if ($VersionNumber -ge 6000 -or $UnicodeVariant) { 'Unicode' } else { 'Ansi' }
    HasEncryptionHeader                      = $VersionNumber -ge 6500
    EncryptionHeaderSize                     = if ($VersionNumber -ge 6500) { $Script:INNO_ENCRYPTION_HEADER_SIZE_6500 } else { 0 }
    PrivilegesRequiredOffset                 = $PrivilegesRequiredOffset
    PrivilegesRequiredOverridesAllowedOffset = if ($HasPrivilegeOverrides) { $PrivilegesRequiredOffset + 1 } else { $null }
    CompressMethodOffset                     = $PrivilegesRequiredOffset + ($HasPrivilegeOverrides ? 4 : 3)
    ArchitecturesEncoding                    = if ($VersionNumber -ge 6300) { 'Expression' } else { 'PackedSet' }
    ArchitecturesAllowedOffset               = $PackedArchitectureOffset
    ArchitecturesInstallIn64BitModeOffset    = if ($null -ne $PackedArchitectureOffset) { $PackedArchitectureOffset + 1 } else { $null }
    PackedArchitecturesIncludeArm64          = $VersionNumber -ge 6000
    FileEntryStringCount                     = $VersionNumber -ge 6500 ? 15 : 10
    FileEntryAnsiStringCount                 = $VersionNumber -ge 6500 ? 1 : 0
    FileEntryHasVerification                 = $VersionNumber -ge 6500
    FileLocationStartOffsetSize              = $FileLocationStartOffsetSize
    FileLocationDigestAlgorithm              = $VersionNumber -ge 6400 ? 'SHA256' : 'SHA1'
    FileLocationDigestSize                   = $FileLocationDigestSize
    FileLocationUsesLegacyFlags              = $FileLocationUsesLegacyFlags
    FileLocationHasSign                      = $FileLocationHasSign
    FileLocationEntrySize                    = $FileLocationEntrySize
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
    [System.Text.Encoding]$Encoding,

    [Parameter(HelpMessage = 'The maximum serialized byte length of one string')]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaximumLength = $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE
  )

  $Values = [System.Collections.Generic.List[string]]::new()

  for ($i = 0; $i -lt $Count; $i++) {
    $Length = $Reader.ReadInt32()
    if ($Length -lt 0 -or $Length -gt $MaximumLength -or $Length -gt ($Reader.BaseStream.Length - $Reader.BaseStream.Position)) {
      throw 'The Inno Setup header string length is invalid'
    }

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

  # The CRC covers only the size/compressed flag header. Payload chunks carry
  # their own CRC records and are validated separately during block reading.
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

  $AvailableStoredBytes = $FileLength - $Offset - 4 - $HeaderLength
  if (
    $StoredSize -lt 5 -or
    $StoredSize -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -or
    $StoredSize -gt $AvailableStoredBytes
  ) { return }

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

  $Properties = [byte[]]::new(5)
  [System.Buffer]::BlockCopy($Bytes, 0, $Properties, 0, $Properties.Length)
  $CompressedStream = [System.IO.MemoryStream]::new($Bytes, 5, $Bytes.Length - 5, $false)
  $OutputStream = [System.IO.MemoryStream]::new()

  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $CompressedStream -Destination $OutputStream -MaximumBytes $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -Properties $Properties
    return , ($OutputStream.ToArray())
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

  $Properties = [byte[]]::new(1)
  $Properties[0] = $Bytes[0]
  $CompressedStream = [System.IO.MemoryStream]::new($Bytes, 1, $Bytes.Length - 1, $false)
  $OutputStream = [System.IO.MemoryStream]::new()

  try {
    $null = Expand-InstallerCompressedStream -Algorithm Lzma2 -Stream $CompressedStream -Destination $OutputStream -MaximumBytes $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -Properties $Properties
    return , ($OutputStream.ToArray())
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

  $ChunkRecordSize = $Script:INNO_MAX_CHUNK_SIZE + 4
  $ChunkCount = [long][Math]::Ceiling([double]$BlockHeader.StoredSize / [double]$ChunkRecordSize)
  $RawLength = [long]$BlockHeader.StoredSize - ($ChunkCount * 4)
  if ($RawLength -le 0 -or $RawLength -gt [int]::MaxValue) {
    throw 'The Inno Setup compressed block payload size is invalid'
  }

  # StoredSize includes one CRC32 before each <=4 KiB chunk. Allocate the
  # payload once instead of growing a List[byte] and copying every chunk twice.
  $RawBytes = [byte[]]::new([int]$RawLength)
  $Remaining = [long]$BlockHeader.StoredSize
  $WriteOffset = 0

  # Reassemble each <=4 KiB data chunk only after its adjacent stored CRC
  # matches; no partial block is returned after a failed chunk.
  while ($Remaining -gt 0) {
    if ($Remaining -lt 5) { throw 'The Inno Setup compressed block contains a truncated chunk record' }
    $ChunkCrc = $Reader.ReadUInt32()
    $Remaining -= 4

    $ChunkLength = [int][Math]::Min($Script:INNO_MAX_CHUNK_SIZE, $Remaining)
    $TotalRead = 0
    while ($TotalRead -lt $ChunkLength) {
      $Read = $Reader.Read($RawBytes, $WriteOffset + $TotalRead, $ChunkLength - $TotalRead)
      if ($Read -le 0) { throw 'The Inno Setup compressed block is truncated' }
      $TotalRead += $Read
    }
    if ($ChunkCrc -ne (Get-BinaryCrc32 -Bytes $RawBytes -Offset $WriteOffset -Count $ChunkLength)) {
      throw 'The Inno Setup compressed block chunk CRC is invalid'
    }

    $WriteOffset += $ChunkLength
    $Remaining -= $ChunkLength
  }
  if ($WriteOffset -ne $RawBytes.Length) { throw 'The Inno Setup compressed block payload length is invalid' }

  $BlockBytes = if ($BlockHeader.Compressed) {
    , (Expand-InnoLzmaBytes -Bytes $RawBytes)
  } else {
    , $RawBytes
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

function Read-InnoSetupEncryptionHeader {
  <#
  .SYNOPSIS
    Read and validate the Inno Setup 6.5+ encryption header
  .PARAMETER Reader
    The binary reader positioned over the installer
  .PARAMETER Offset
    The offset of the encryption-header CRC
  .PARAMETER FileLength
    The complete installer length used for bounds checking
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader positioned over the installer')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The offset of the encryption-header CRC')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The complete installer length used for bounds checking')]
    [long]$FileLength
  )

  $RecordLength = 4 + $Script:INNO_ENCRYPTION_HEADER_SIZE_6500
  if ($Offset -lt 0 -or $Offset + $RecordLength -gt $FileLength) {
    throw 'The Inno Setup encryption header is truncated'
  }

  $Reader.BaseStream.Seek($Offset, 'Begin') | Out-Null
  $StoredCrc = $Reader.ReadInt32()
  $Bytes = $Reader.ReadBytes($Script:INNO_ENCRYPTION_HEADER_SIZE_6500)
  if ($Bytes.Length -ne $Script:INNO_ENCRYPTION_HEADER_SIZE_6500) {
    throw 'The Inno Setup encryption header is truncated'
  }
  if ($StoredCrc -ne (Get-InstallerCrc32 -Bytes $Bytes)) {
    throw 'The Inno Setup encryption header CRC is invalid'
  }

  $EncryptionUseValue = $Bytes[0]

  # EncryptionUse is a closed enum in the source record. Unknown values indicate
  # an unsupported layout rather than a future mode that can be guessed safely.
  $EncryptionUse = switch ($EncryptionUseValue) {
    0 { 'None' }
    1 { 'Files' }
    2 { 'Full' }
    default { throw "The Inno Setup encryption mode is invalid: $EncryptionUseValue" }
  }

  return [pscustomobject]@{
    EncryptionUse = $EncryptionUse
    KDFIterations = [System.BitConverter]::ToInt32($Bytes, 17)
    PasswordTest  = [System.BitConverter]::ToInt32($Bytes, 45)
    HeaderOffset  = $Offset
    NextOffset    = $Offset + $RecordLength
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
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset of the embedded setup data')]
    [long]$Offset0,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout
  )

  $InstallerPath = (Get-Item -Path $Path -Force).FullName
  $FileStream = [System.IO.File]::OpenRead($InstallerPath)
  $Reader = [System.IO.BinaryReader]::new($FileStream)

  try {
    $Reader.BaseStream.Seek($Offset0, 'Begin') | Out-Null

    # Offset0 points to the setup signature that precedes the first compressed metadata block.
    $SignatureBytes = $Reader.ReadBytes($Script:INNO_SETUP_ID_SIZE)
    if ($SignatureBytes.Length -ne $Script:INNO_SETUP_ID_SIZE) { throw 'The Inno Setup signature is truncated' }

    $EncryptionHeader = if ($Layout.HasEncryptionHeader) {
      Read-InnoSetupEncryptionHeader -Reader $Reader -Offset ($Offset0 + $Script:INNO_SETUP_ID_SIZE) -FileLength $FileStream.Length
    } else {
      [pscustomobject]@{
        EncryptionUse = 'None'
        KDFIterations = $null
        PasswordTest  = $null
        HeaderOffset  = $null
        NextOffset    = $Offset0 + $Script:INNO_SETUP_ID_SIZE
      }
    }

    if ($EncryptionHeader.EncryptionUse -eq 'Full') {
      throw 'The Inno Setup metadata is fully encrypted and requires the setup password'
    }

    $HeaderOffset = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $EncryptionHeader.NextOffset -UsesInt64BlockHeader $Layout.UsesInt64BlockHeader -FileLength $FileStream.Length
    if (-not $HeaderOffset) { throw 'The Inno Setup header block could not be located' }
    $BlockInfo = Read-InnoCompressedBlock -Reader $Reader -BlockHeader $HeaderOffset
    $BlockInfo | Add-Member -NotePropertyName EncryptionHeader -NotePropertyValue $EncryptionHeader
    return $BlockInfo
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
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The offset of the embedded setup data')]
    [long]$Offset0,

    [Parameter(Mandatory, HelpMessage = 'The supported Inno header layout')]
    [pscustomobject]$Layout
  )

  return , ((Get-InnoHeaderBlockInfo -Path $Path -Offset0 $Offset0 -Layout $Layout).Bytes)
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
  .PARAMETER PEInfo
    The installer PE architecture information used for default directives
  .PARAMETER HeaderFixedData
    The parsed fixed header fields, including legacy packed architecture sets
  .PARAMETER Layout
    The source-version-specific serialized header layout
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Inno Setup header strings')]
    [AllowEmptyString()]
    [string[]]$HeaderValues,

    [Parameter(Mandatory, HelpMessage = 'The installer PE architecture information used for default directives')]
    [pscustomobject]$PEInfo,

    [Parameter(Mandatory, HelpMessage = 'The parsed fixed header fields')]
    [pscustomobject]$HeaderFixedData,

    [Parameter(Mandatory, HelpMessage = 'The source-version-specific serialized header layout')]
    [pscustomobject]$Layout
  )

  $Warnings = [System.Collections.Generic.List[string]]::new()

  if ($Layout.ArchitecturesEncoding -eq 'PackedSet') {
    # Pre-6.3 records serialize TSetupProcessorArchitectures as a one-byte set.
    # An empty allowed set means no OS architecture restriction.
    $AllowedValue = $HeaderFixedData.ArchitecturesAllowedSet
    $Install64Value = $HeaderFixedData.ArchitecturesInstallIn64BitModeSet
    $Supported = if ($AllowedValue -eq 0) {
      @('x86', 'x64', 'arm64')
    } else {
      @(
        if (($AllowedValue -band 0x02) -ne 0) { 'x86' }
        if (($AllowedValue -band 0x04) -ne 0) { 'x64' }
        if ($Layout.PackedArchitecturesIncludeArm64 -and ($AllowedValue -band 0x10) -ne 0) { 'arm64' }
      )
    }
    if (($AllowedValue -band 0x08) -ne 0) {
      $Warnings.Add('The installer supports the legacy IA64 architecture, which WinGet no longer represents.')
    }

    $Install64Architectures = @(
      if (($Install64Value -band 0x04) -ne 0) { 'x64' }
      if ($Layout.PackedArchitecturesIncludeArm64 -and ($Install64Value -band 0x10) -ne 0) { 'arm64' }
    )
    $InstallModes = @($Supported | ForEach-Object { $Install64Architectures -contains $_ } | Sort-Object -Unique)

    return [pscustomobject]@{
      ArchitecturesAllowed                     = $null
      ArchitecturesInstallIn64BitMode          = $null
      EffectiveArchitecturesAllowed            = $Supported -join ' or '
      EffectiveArchitecturesInstallIn64BitMode = $Install64Architectures -join ' or '
      SupportedArchitectures                   = $Supported
      UnsupportedArchitectures                 = @('x86', 'x64', 'arm64') | Where-Object { $Supported -notcontains $_ }
      InstallIn64BitMode                       = if ($InstallModes.Count -eq 1) { [bool]$InstallModes[0] } else { $null }
      PackedArchitecturesAllowed               = $AllowedValue
      PackedArchitecturesInstallIn64BitMode    = $Install64Value
      IsKnown                                  = $true
      Warnings                                 = $Warnings.ToArray()
    }
  }

  $ArchitecturesAllowed = if ($HeaderValues.Count -gt 30) { $HeaderValues[30] } else { $null }
  $ArchitecturesInstallIn64BitMode = if ($HeaderValues.Count -gt 31) { $HeaderValues[31] } else { $null }
  $EffectiveArchitecturesAllowed = if ([string]::IsNullOrWhiteSpace($ArchitecturesAllowed)) {
    if ($PEInfo.Architecture -eq 'x64') { 'x64compatible' } else { 'x86compatible' }
  } else { $ArchitecturesAllowed }
  $EffectiveArchitecturesInstallIn64BitMode = if ([string]::IsNullOrWhiteSpace($ArchitecturesInstallIn64BitMode) -and $PEInfo.Architecture -eq 'x64') {
    'x64compatible'
  } else { $ArchitecturesInstallIn64BitMode }

  try {
    $Supported = @(Get-InnoSupportedArchitectureList -Expression $EffectiveArchitecturesAllowed)
    $Unsupported = @('x86', 'x64', 'arm64') | Where-Object { $Supported -notcontains $_ }
    $InstallModes = @($Supported | ForEach-Object {
        -not [string]::IsNullOrWhiteSpace($EffectiveArchitecturesInstallIn64BitMode) -and
        (Test-InnoArchitectureExpression -Expression $EffectiveArchitecturesInstallIn64BitMode -Architecture $_)
      } | Sort-Object -Unique)
    $IsKnown = $true
  } catch {
    $Warnings.Add("The architecture directives could not be evaluated statically: $($_.Exception.Message)")
    $Supported = @()
    $Unsupported = @()
    $InstallModes = @()
    $IsKnown = $false
  }

  return [pscustomobject]@{
    ArchitecturesAllowed                     = $ArchitecturesAllowed
    ArchitecturesInstallIn64BitMode          = $ArchitecturesInstallIn64BitMode
    EffectiveArchitecturesAllowed            = $EffectiveArchitecturesAllowed
    EffectiveArchitecturesInstallIn64BitMode = $EffectiveArchitecturesInstallIn64BitMode
    SupportedArchitectures                   = $Supported
    UnsupportedArchitectures                 = $Unsupported
    InstallIn64BitMode                       = if ($InstallModes.Count -eq 1) { [bool]$InstallModes[0] } else { $null }
    PackedArchitecturesAllowed               = $null
    PackedArchitecturesInstallIn64BitMode    = $null
    IsKnown                                  = $IsKnown
    Warnings                                 = $Warnings.ToArray()
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

  $Tokens = [System.Collections.Generic.List[string]]::new()
  $Text = $Expression.ToLowerInvariant()
  $Position = 0
  while ($Position -lt $Text.Length) {
    if ([char]::IsWhiteSpace($Text[$Position])) {
      $Position++
      continue
    }
    if ($Text[$Position] -in @('(', ')')) {
      $Tokens.Add([string]$Text[$Position])
      $Position++
      continue
    }

    $Match = [regex]::Match($Text.Substring($Position), '^[a-z_][a-z0-9_\\]*')
    if (-not $Match.Success) {
      throw "Invalid symbol '$($Text[$Position])' in Inno Setup architecture expression"
    }
    $Tokens.Add($Match.Value)
    $Position += $Match.Length
  }
  if ($Tokens.Count -eq 0) { return @() }

  $Normalized = [System.Collections.Generic.List[string]]::new()
  $PreviousIsOperand = $false

  foreach ($Token in $Tokens) {
    $CurrentIsOperand = $Token -notin @('and', 'or', 'not', '(', ')')
    if (($PreviousIsOperand -or ($Normalized.Count -gt 0 -and $Normalized[$Normalized.Count - 1] -eq ')')) -and $CurrentIsOperand) {
      # SilentOrAllowed inserts OR only before another identifier.
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

  $KnownIdentifiers = @('arm32compatible', 'arm64', 'win64', 'x64', 'x64os', 'x64compatible', 'x86', 'x86os', 'x86compatible')
  if ($Identifier -notin $KnownIdentifiers) {
    throw "Unknown Inno Setup architecture identifier: $Identifier"
  }

  switch ($Architecture) {
    'x86' {
      return $Identifier -in @('x86', 'x86os', 'x86compatible')
    }
    'x64' {
      return $Identifier -in @('x64', 'x64os', 'x64compatible', 'win64', 'x86compatible')
    }
    'arm64' {
      return $Identifier -in @('arm32compatible', 'arm64', 'win64', 'x64compatible', 'x86compatible')
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

  # Convert the compiler expression to reverse-polish notation with a small
  # shunting-yard evaluator. No Inno Pascal code or host architecture is run.
  $Tokens = ConvertTo-InnoArchitectureExpressionToken -Expression $Expression
  if (-not $Tokens) { throw 'The Inno Setup architecture expression is empty' }

  $Precedence = @{
    'or'  = 1
    'and' = 2
    'not' = 3
  }
  $Output = [System.Collections.Generic.List[string]]::new()
  $Operators = [System.Collections.Generic.Stack[string]]::new()

  # Build RPN using Inno's not > and > or precedence and explicit parentheses.
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
        if ($Operators.Count -eq 0 -or $Operators.Peek() -ne '(') {
          throw 'The Inno Setup architecture expression has an unmatched closing parenthesis'
        }
        $Operators.Pop() | Out-Null
      }
      default {
        while (
          $Operators.Count -gt 0 -and
          $Operators.Peek() -ne '(' -and
          ($Precedence[$Operators.Peek()] -gt $Precedence[$Token] -or
          ($Token -ne 'not' -and $Precedence[$Operators.Peek()] -eq $Precedence[$Token]))
        ) {
          $Output.Add($Operators.Pop())
        }
        $Operators.Push($Token)
      }
    }
  }

  while ($Operators.Count -gt 0) {
    $Operator = $Operators.Pop()
    if ($Operator -eq '(') { throw 'The Inno Setup architecture expression has an unmatched opening parenthesis' }
    $Output.Add($Operator)
  }

  # Evaluate identifiers against the requested Windows architecture only after
  # syntax normalization, rejecting missing operands deterministically.
  $Values = [System.Collections.Generic.Stack[bool]]::new()
  foreach ($Token in $Output) {
    switch ($Token) {
      'not' {
        if ($Values.Count -lt 1) { throw 'The Inno Setup architecture expression is missing an operand for not' }
        $Values.Push(-not $Values.Pop())
      }
      'and' {
        if ($Values.Count -lt 2) { throw 'The Inno Setup architecture expression is missing an operand for and' }
        $Right = $Values.Pop()
        $Left = $Values.Pop()
        $Values.Push($Left -and $Right)
      }
      'or' {
        if ($Values.Count -lt 2) { throw 'The Inno Setup architecture expression is missing an operand for or' }
        $Right = $Values.Pop()
        $Left = $Values.Pop()
        $Values.Push($Left -or $Right)
      }
      default {
        $Values.Push((Test-InnoArchitectureIdentifier -Identifier $Token -Architecture $Architecture))
      }
    }
  }

  if ($Values.Count -ne 1) { throw 'The Inno Setup architecture expression is invalid' }
  return $Values.Pop()
}

function Get-InnoBooleanDirectiveInfo {
  <#
  .SYNOPSIS
    Resolve a static Inno Setup yes/no directive and preserve dynamic expressions as unknown
  .PARAMETER Value
    The serialized directive value from the setup header
  .PARAMETER Default
    The default value used by Inno Setup when the directive is omitted
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The default value used by Inno Setup when the directive is omitted')]
    [bool]$Default
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return [pscustomobject]@{ Value = $Default; IsResolved = $true; IsDefault = $true; IsDynamic = $false }
  }

  switch -Regex ($Value.Trim()) {
    '^(?i:yes|true|1)$' { return [pscustomobject]@{ Value = $true; IsResolved = $true; IsDefault = $false; IsDynamic = $false } }
    '^(?i:no|false|0)$' { return [pscustomobject]@{ Value = $false; IsResolved = $true; IsDefault = $false; IsDynamic = $false } }
    default { return [pscustomobject]@{ Value = $null; IsResolved = $false; IsDefault = $false; IsDynamic = $true } }
  }
}

function Resolve-InnoBooleanDirective {
  <#
  .SYNOPSIS
    Resolve a static Inno Setup yes/no directive, returning null for a dynamic expression
  .PARAMETER Value
    The serialized directive value from the setup header
  .PARAMETER Default
    The default value used by Inno Setup when the directive is omitted
  #>
  [OutputType([Nullable[bool]])]
  param (
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The default value used by Inno Setup when the directive is omitted')]
    [bool]$Default
  )

  return (Get-InnoBooleanDirectiveInfo -Value $Value -Default $Default).Value
}

function Get-InnoAppsAndFeaturesEntryInfo {
  <#
  .SYNOPSIS
    Determine whether Inno Setup should create its own Apps & Features registry entry
  .PARAMETER HeaderValues
    The parsed Inno Setup header strings
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
  $CreateUninstallRegKeyInfo = Get-InnoBooleanDirectiveInfo -Value $CreateUninstallRegKey -Default $true
  $UninstallableInfo = Get-InnoBooleanDirectiveInfo -Value $Uninstallable -Default $true
  $WritesAppsAndFeaturesEntry = if (
    ($CreateUninstallRegKeyInfo.IsResolved -and -not $CreateUninstallRegKeyInfo.Value) -or
    ($UninstallableInfo.IsResolved -and -not $UninstallableInfo.Value)
  ) {
    $false
  } elseif ($CreateUninstallRegKeyInfo.IsResolved -and $UninstallableInfo.IsResolved) {
    $true
  } else {
    $null
  }

  return [pscustomobject]@{
    WritesAppsAndFeaturesEntry    = $WritesAppsAndFeaturesEntry
    CreateUninstallRegKey         = $CreateUninstallRegKey
    Uninstallable                 = $Uninstallable
    CreatesUninstallRegistryKey   = $CreateUninstallRegKeyInfo.Value
    RegistersUninstaller          = $UninstallableInfo.Value
    CreateUninstallRegKeyResolved = $CreateUninstallRegKeyInfo.IsResolved
    UninstallableResolved         = $UninstallableInfo.IsResolved
    IsResolved                    = $null -ne $WritesAppsAndFeaturesEntry
    IsKnown                       = $VersionNumber -ge 5310 -or $HeaderValues.Count -gt 24
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
    [pscustomobject]$Layout
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    # Serialized variable-length strings precede a generation-specific fixed
    # tail. Consume them according to the selected source-backed layout first.
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
    # These offsets are relative to the fixed-tail start, not the beginning of
    # the decompressed block. Validate the furthest field before seeking.
    $RequiredOffsets = @(
      $Layout.PrivilegesRequiredOffset
      $Layout.PrivilegesRequiredOverridesAllowedOffset
      $Layout.ArchitecturesAllowedOffset
      $Layout.ArchitecturesInstallIn64BitModeOffset
      $Layout.CompressMethodOffset
    ) | Where-Object { $null -ne $_ }
    $LastRequiredOffset = ($RequiredOffsets | Measure-Object -Maximum).Maximum
    if ($null -eq $LastRequiredOffset -or $FixedTailOffset + $LastRequiredOffset -ge $Reader.BaseStream.Length) {
      throw 'The Inno Setup fixed header is truncated'
    }

    # Decode compiler enums and bitsets without evaluating script expressions;
    # unknown enum values remain explicit rather than receiving a guessed scope.
    $Reader.BaseStream.Seek($FixedTailOffset + $Layout.PrivilegesRequiredOffset, 'Begin') | Out-Null
    $PrivilegesRequiredValue = $Reader.ReadByte()
    $PrivilegesRequired = switch ($PrivilegesRequiredValue) {
      0 { 'none' }
      1 { 'poweruser' }
      2 { 'admin' }
      3 { 'lowest' }
      default { "unknown:$PrivilegesRequiredValue" }
    }

    $Overrides = @()
    if ($null -ne $Layout.PrivilegesRequiredOverridesAllowedOffset) {
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.PrivilegesRequiredOverridesAllowedOffset, 'Begin') | Out-Null
      $OverridesValue = $Reader.ReadByte()
      if (($OverridesValue -band 0x01) -ne 0) { $Overrides += 'commandline' }
      if (($OverridesValue -band 0x02) -ne 0) { $Overrides += 'dialog' }
    }

    $ArchitecturesAllowedSet = $null
    $ArchitecturesInstallIn64BitModeSet = $null
    if ($Layout.ArchitecturesEncoding -eq 'PackedSet') {
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.ArchitecturesAllowedOffset, 'Begin') | Out-Null
      $ArchitecturesAllowedSet = $Reader.ReadByte()
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.ArchitecturesInstallIn64BitModeOffset, 'Begin') | Out-Null
      $ArchitecturesInstallIn64BitModeSet = $Reader.ReadByte()
    }

    $Reader.BaseStream.Seek($FixedTailOffset + $Layout.CompressMethodOffset, 'Begin') | Out-Null
    $CompressMethodValue = $Reader.ReadByte()
    $CompressMethod = switch ($CompressMethodValue) {
      0 { 'Stored' }
      1 { 'Zlib' }
      2 { 'BZip2' }
      3 { 'Lzma' }
      4 { 'Lzma2' }
      default { throw "The Inno Setup compression method is invalid: $CompressMethodValue" }
    }

    return [pscustomobject]@{
      PrivilegesRequired                 = $PrivilegesRequired
      PrivilegesRequiredOverridesAllowed = $Overrides
      SupportsPrivilegeOverride          = [bool]$Overrides
      SupportsCommandLineScopeOverride   = $Overrides -contains 'commandline'
      ArchitecturesAllowedSet            = $ArchitecturesAllowedSet
      ArchitecturesInstallIn64BitModeSet = $ArchitecturesInstallIn64BitModeSet
      CompressMethod                     = $CompressMethod
      CompressMethodValue                = $CompressMethodValue
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

function Find-InnoConstantEnd {
  <#
  .SYNOPSIS
    Find the closing brace of an Inno Setup constant, including nested constants
  .PARAMETER Value
    The compiled directive value
  .PARAMETER StartIndex
    The zero-based index of the opening brace
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The compiled directive value')]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The zero-based index of the opening brace')]
    [int]$StartIndex
  )

  $Depth = 1
  $Index = $StartIndex + 1
  while ($Index -lt $Value.Length) {
    if ($Value[$Index] -eq '{') {
      if ($Index + 1 -lt $Value.Length -and $Value[$Index + 1] -eq '{') {
        $Index += 2
        continue
      }
      $Depth++
    } elseif ($Value[$Index] -eq '}') {
      $Depth--
      if ($Depth -eq 0) { return $Index }
    }
    $Index++
  }

  return -1
}

function Get-InnoStaticStringInfo {
  <#
  .SYNOPSIS
    Decode literal braces and resolve only explicitly supplied static Inno constants
  .PARAMETER Value
    The raw compiled directive value
  .PARAMETER ConstantMap
    Static constant names and their manifest-safe replacement values
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw compiled directive value')]
    [AllowEmptyString()]
    [string]$Value,

    [Parameter(HelpMessage = 'Static constant names and their manifest-safe replacement values')]
    [System.Collections.IDictionary]$ConstantMap = [ordered]@{}
  )

  $Builder = [System.Text.StringBuilder]::new($Value.Length)
  $UnresolvedConstants = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $Index = 0
  while ($Index -lt $Value.Length) {
    if ($Value[$Index] -ne '{') {
      $null = $Builder.Append($Value[$Index])
      $Index++
      continue
    }

    if ($Index + 1 -lt $Value.Length -and $Value[$Index + 1] -eq '{') {
      # ExpandConstEx2 treats doubled opening braces outside constants as one literal brace.
      $null = $Builder.Append('{')
      $Index += 2
      continue
    }

    $EndIndex = Find-InnoConstantEnd -Value $Value -StartIndex $Index
    if ($EndIndex -lt 0) {
      $null = $UnresolvedConstants.Add($Value.Substring($Index))
      $null = $Builder.Append($Value.Substring($Index))
      break
    }

    $ConstantText = $Value.Substring($Index, $EndIndex - $Index + 1)
    $ConstantName = $Value.Substring($Index + 1, $EndIndex - $Index - 1)
    if ($ConstantMap.Contains($ConstantName) -and $null -ne $ConstantMap[$ConstantName]) {
      $null = $Builder.Append([string]$ConstantMap[$ConstantName])
    } else {
      $null = $UnresolvedConstants.Add($ConstantText)
      $null = $Builder.Append($ConstantText)
    }
    $Index = $EndIndex + 1
  }

  $DecodedValue = $Builder.ToString()
  return [pscustomobject]@{
    Value               = $UnresolvedConstants.Count -eq 0 ? $DecodedValue : $null
    DecodedValue        = $DecodedValue
    IsResolved          = $UnresolvedConstants.Count -eq 0
    UnresolvedConstants = [string[]]@($UnresolvedConstants)
  }
}

function ConvertFrom-InnoEscapedString {
  <#
  .SYNOPSIS
    Decode escaped literal opening braces in an Inno Setup directive value
  .PARAMETER Value
    The raw compiled directive value
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw compiled directive value')]
    [AllowEmptyString()]
    [string]$Value
  )

  return (Get-InnoStaticStringInfo -Value $Value).DecodedValue
}

function Get-InnoDefaultDirectoryConstantMap {
  <#
  .SYNOPSIS
    Get deterministic Inno directory constants as WinGet environment-variable paths
  .PARAMETER DefaultScope
    The default administrative or non-administrative install scope
  .PARAMETER InstallIn64BitMode
    Whether every supported target architecture uses Inno 64-bit install mode
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [AllowNull()]
    [string]$DefaultScope,

    [AllowNull()]
    [Nullable[bool]]$InstallIn64BitMode
  )

  # Map only deterministic built-in constants to WinGet-style environment paths.
  # Dynamic {code:*} constants are intentionally left unresolved elsewhere.
  $Map = [ordered]@{
    'win'           = '%SystemRoot%'
    'sysnative'     = '%SystemRoot%\System32'
    'sd'            = '%SystemDrive%'
    'localappdata'  = '%LocalAppData%'
    'userappdata'   = '%AppData%'
    'commonappdata' = '%ProgramData%'
    'userpf'        = '%LocalAppData%\Programs'
    'usercf'        = '%LocalAppData%\Programs\Common'
    'userfonts'     = '%LocalAppData%\Microsoft\Windows\Fonts'
    'commonfonts'   = '%SystemRoot%\Fonts'
    'commonpf32'    = '%ProgramFiles(x86)%'
    'pf32'          = '%ProgramFiles(x86)%'
    'commonpf64'    = '%ProgramFiles%'
    'pf64'          = '%ProgramFiles%'
    'commoncf32'    = '%ProgramFiles(x86)%\Common Files'
    'cf32'          = '%ProgramFiles(x86)%\Common Files'
    'commoncf64'    = '%ProgramFiles%\Common Files'
    'cf64'          = '%ProgramFiles%\Common Files'
  }

  # Generic Program Files constants depend on the install-mode expression and
  # are omitted when that expression is not statically uniform.
  if ($null -ne $InstallIn64BitMode) {
    $Map['commonpf'] = $Map[[bool]$InstallIn64BitMode ? 'commonpf64' : 'commonpf32']
    $Map['pf'] = $Map['commonpf']
    $Map['commoncf'] = $Map[[bool]$InstallIn64BitMode ? 'commoncf64' : 'commoncf32']
    $Map['cf'] = $Map['commoncf']
  }

  # auto* constants select user or common roots from default scope; unresolved
  # or dual defaults deliberately leave those constants unmapped.
  if ($DefaultScope -eq 'user') {
    foreach ($Name in @('autopf', 'autopf32', 'autopf64')) { $Map[$Name] = $Map['userpf'] }
    foreach ($Name in @('autocf', 'autocf32', 'autocf64')) { $Map[$Name] = $Map['usercf'] }
    $Map['autoappdata'] = $Map['userappdata']
    $Map['autofonts'] = $Map['userfonts']
  } elseif ($DefaultScope -eq 'machine') {
    $Map['autopf32'] = $Map['commonpf32']
    $Map['autopf64'] = $Map['commonpf64']
    $Map['autocf32'] = $Map['commoncf32']
    $Map['autocf64'] = $Map['commoncf64']
    if ($null -ne $InstallIn64BitMode) {
      $Map['autopf'] = $Map['commonpf']
      $Map['autocf'] = $Map['commoncf']
    }
    $Map['autoappdata'] = $Map['commonappdata']
    $Map['autofonts'] = $Map['commonfonts']
  }

  return $Map
}

function Get-InnoUninstallRegKeyBaseName {
  <#
  .SYNOPSIS
    Convert an expanded Inno AppId to the built-in uninstall registry key base name
  .PARAMETER AppId
    The statically expanded AppId
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The statically expanded AppId')]
    [string]$AppId
  )

  if ($AppId.Length -le 57 -or $AppId.ToCharArray().Where({ [int]$_ -gt 126 }, 'First').Count -gt 0) {
    return $AppId
  }

  $Crc32 = Get-BinaryCrc32 -Bytes ([System.Text.Encoding]::ASCII.GetBytes($AppId))
  return $AppId.Substring(0, 48) + '~' + $Crc32.ToString('x8')
}

function Get-InnoProductCode {
  <#
  .SYNOPSIS
    Get the built-in Inno Apps & Features key name used as the WinGet ProductCode
  .PARAMETER AppId
    The statically expanded AppId
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The statically expanded AppId')]
    [string]$AppId
  )

  return "$(Get-InnoUninstallRegKeyBaseName -AppId $AppId)_is1"
}

function Resolve-InnoDefaultDirectory {
  <#
  .SYNOPSIS
    Resolve the common deterministic directory constants used in DefaultDirName
  .PARAMETER Value
    The raw DefaultDirName value
  .PARAMETER DefaultScope
    Scope or elevation evidence used to classify user, machine, or conditional installation.
  .PARAMETER InstallIn64BitMode
    Target architecture evidence used to reproduce the installer payload or directory selection.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The raw DefaultDirName value')]
    [AllowEmptyString()]
    [string]$Value,

    [AllowNull()]
    [string]$DefaultScope,

    [AllowNull()]
    [Nullable[bool]]$InstallIn64BitMode
  )

  $ConstantMap = Get-InnoDefaultDirectoryConstantMap -DefaultScope $DefaultScope -InstallIn64BitMode $InstallIn64BitMode
  return (Get-InnoStaticStringInfo -Value $Value -ConstantMap $ConstantMap).Value
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

    # The serialized setup signature, not PE FileVersion, selects every
    # version-dependent string count, fixed offset, flag layout, and digest size.
    $PEInfo = Get-InnoPEInfo -Path $InstallerPath
    $VersionNumber = Get-InnoVersionNumber -Version $SignatureMatch.Groups[1].Value
    $Layout = Get-InnoLayout -VersionNumber $VersionNumber -UnicodeVariant ([bool]$SignatureMatch.Groups[2].Success)
    $HeaderBlockInfo = Get-InnoHeaderBlockInfo -Path $InstallerPath -Offset0 $OffsetTable.Offset0 -Layout $Layout
    $HeaderBytes = $HeaderBlockInfo.Bytes
    $HeaderValues = Read-InnoHeaderStrings -Bytes $HeaderBytes -Layout $Layout
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBytes -Layout $Layout
    $HeaderArchitectureData = Get-InnoHeaderArchitectureData -HeaderValues $HeaderValues -PEInfo $PEInfo -HeaderFixedData $HeaderFixedData -Layout $Layout
    $AppsAndFeaturesEntryInfo = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -VersionNumber $VersionNumber
    $Warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($Warning in $HeaderArchitectureData.Warnings) { $Warnings.Add($Warning) }
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      $Warnings.Add('The installer payload files are encrypted; static metadata is available, but extraction requires the setup password.')
    }
    if (-not $AppsAndFeaturesEntryInfo.IsResolved) {
      $Warnings.Add('CreateUninstallRegKey or Uninstallable is a dynamic expression, so Apps & Features registration cannot be determined statically.')
    }

    $AppNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[0]
    $AppVerNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[1]
    $RawAppId = $HeaderValues[2]
    $AppIdInfo = Get-InnoStaticStringInfo -Value $RawAppId
    $AppPublisherInfo = Get-InnoStaticStringInfo -Value $HeaderValues[4]
    $AppVersionInfo = Get-InnoStaticStringInfo -Value $HeaderValues[9]
    $DefaultDirName = $HeaderValues[10]
    $UninstallDisplayNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[14]

    $DefaultScope = Convert-InnoPrivilegeToScope -PrivilegesRequired $HeaderFixedData.PrivilegesRequired

    # PrivilegesRequiredOverridesAllowed exposes explicit command-line scope
    # selection; without it only the compiled default scope is supported.
    $SupportedScopes = if ($HeaderFixedData.SupportsCommandLineScopeOverride -and $DefaultScope) {
      @('user', 'machine')
    } elseif ($DefaultScope) {
      @($DefaultScope)
    } else {
      @()
    }
    $SupportedArchitectures = @($HeaderArchitectureData.SupportedArchitectures)
    $InstallIn64BitMode = $HeaderArchitectureData.InstallIn64BitMode

    $DefaultDirectoryConstantMap = Get-InnoDefaultDirectoryConstantMap -DefaultScope $DefaultScope -InstallIn64BitMode $InstallIn64BitMode
    $DefaultDirInfo = Get-InnoStaticStringInfo -Value $DefaultDirName -ConstantMap $DefaultDirectoryConstantMap
    $ResolvedDefaultDirName = $DefaultDirInfo.Value

    # A resolved root token is stronger scope evidence than the launcher PE
    # architecture. Dynamic {code:...} paths remain unresolved and do not guess.
    $Scope = if ($ResolvedDefaultDirName -and $ResolvedDefaultDirName -match '^(?i)%(?:ProgramFiles(?:\(x86\))?|ProgramData|SystemRoot|SystemDrive)%') {
      'machine'
    } elseif ($ResolvedDefaultDirName -and $ResolvedDefaultDirName -match '^(?i)%(?:LocalAppData|AppData|UserProfile)%') {
      'user'
    } else {
      $null
    }

    $DisplayNameInfo = if (-not [string]::IsNullOrWhiteSpace($HeaderValues[14])) {
      $UninstallDisplayNameInfo
    } elseif (-not [string]::IsNullOrWhiteSpace($HeaderValues[1])) {
      $AppVerNameInfo
    } else {
      $AppNameInfo
    }
    $DisplayName = $DisplayNameInfo.Value
    $UninstallRegKeyBaseName = if ($AppIdInfo.IsResolved -and -not [string]::IsNullOrWhiteSpace($AppIdInfo.Value)) {
      Get-InnoUninstallRegKeyBaseName -AppId $AppIdInfo.Value
    } else {
      $null
    }
    # Inno appends _is1 to the normalized AppId only when its own uninstall key
    # is enabled; wrapper installers that suppress ARP receive no ProductCode.
    $ProductCode = if ($AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true -and $UninstallRegKeyBaseName) {
      "${UninstallRegKeyBaseName}_is1"
    } else {
      $null
    }

    $UnresolvedConstants = [ordered]@{}

    # Preserve dynamic-field evidence explicitly so callers can distinguish an
    # absent value from one that depends on runtime Pascal Script code.
    $StaticFieldInfo = [ordered]@{
      AppName              = $AppNameInfo
      AppVerName           = $AppVerNameInfo
      AppId                = $AppIdInfo
      AppPublisher         = $AppPublisherInfo
      AppVersion           = $AppVersionInfo
      DefaultDirName       = $DefaultDirInfo
      UninstallDisplayName = $UninstallDisplayNameInfo
    }
    foreach ($FieldInfo in $StaticFieldInfo.GetEnumerator()) {
      if (-not $FieldInfo.Value.IsResolved) { $UnresolvedConstants[$FieldInfo.Key] = $FieldInfo.Value.UnresolvedConstants }
    }
    $UnresolvedFields = @(
      if (-not $AppIdInfo.IsResolved -or $null -eq $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry) { 'ProductCode' }
      if (-not $AppPublisherInfo.IsResolved) { 'Publisher' }
      if (-not $AppVersionInfo.IsResolved) { 'DisplayVersion' }
      if (-not $DefaultDirInfo.IsResolved) { 'DefaultInstallLocation' }
      if (-not $DisplayNameInfo.IsResolved) { 'DisplayName' }
    )

    return [pscustomobject]@{
      Path                                     = $InstallerPath
      InstallerType                            = 'Inno'
      DisplayVersion                           = $AppVersionInfo.Value
      DisplayName                              = $DisplayName
      Publisher                                = $AppPublisherInfo.Value
      ProductCode                              = $ProductCode
      UpgradeCode                              = $null
      AppsAndFeaturesProductCode               = $ProductCode
      UninstallRegKeyBaseName                  = $UninstallRegKeyBaseName
      DefaultInstallLocation                   = $ResolvedDefaultDirName
      Scope                                    = $Scope
      DefaultScope                             = $DefaultScope
      SupportedScopes                          = $SupportedScopes
      SupportsDualScope                        = $SupportedScopes.Count -gt 1
      PrivilegesRequired                       = $HeaderFixedData.PrivilegesRequired
      PrivilegesRequiredOverridesAllowed       = $HeaderFixedData.PrivilegesRequiredOverridesAllowed
      SupportsCommandLineScopeOverride         = $HeaderFixedData.SupportsCommandLineScopeOverride
      WritesAppsAndFeaturesEntry               = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry
      CreateUninstallRegKey                    = $AppsAndFeaturesEntryInfo.CreateUninstallRegKey
      Uninstallable                            = $AppsAndFeaturesEntryInfo.Uninstallable
      CreatesUninstallRegistryKey              = $AppsAndFeaturesEntryInfo.CreatesUninstallRegistryKey
      RegistersUninstaller                     = $AppsAndFeaturesEntryInfo.RegistersUninstaller
      CreateUninstallRegKeyResolved            = $AppsAndFeaturesEntryInfo.CreateUninstallRegKeyResolved
      UninstallableResolved                    = $AppsAndFeaturesEntryInfo.UninstallableResolved
      ArchitecturesAllowed                     = $HeaderArchitectureData.ArchitecturesAllowed
      ArchitecturesInstallIn64BitMode          = $HeaderArchitectureData.ArchitecturesInstallIn64BitMode
      EffectiveArchitecturesAllowed            = $HeaderArchitectureData.EffectiveArchitecturesAllowed
      EffectiveArchitecturesInstallIn64BitMode = $HeaderArchitectureData.EffectiveArchitecturesInstallIn64BitMode
      PackedArchitecturesAllowed               = $HeaderArchitectureData.PackedArchitecturesAllowed
      PackedArchitecturesInstallIn64BitMode    = $HeaderArchitectureData.PackedArchitecturesInstallIn64BitMode
      InstallIn64BitMode                       = $InstallIn64BitMode
      SupportedArchitectures                   = $SupportedArchitectures
      UnsupportedArchitectures                 = @($HeaderArchitectureData.UnsupportedArchitectures)
      InstallerArchitecture                    = $PEInfo.Architecture
      AppName                                  = $AppNameInfo.DecodedValue
      AppVerName                               = $AppVerNameInfo.DecodedValue
      AppVersion                               = $AppVersionInfo.DecodedValue
      AppId                                    = $AppIdInfo.DecodedValue
      ResolvedAppId                            = $AppIdInfo.Value
      RawAppId                                 = $RawAppId
      RawDefaultDirName                        = $DefaultDirName
      UninstallDisplayName                     = $UninstallDisplayNameInfo.DecodedValue
      UnresolvedFields                         = $UnresolvedFields
      UnresolvedConstants                      = [pscustomobject]$UnresolvedConstants
      Signature                                = $Signature
      VersionNumber                            = $VersionNumber
      EncryptionUse                            = $HeaderBlockInfo.EncryptionHeader.EncryptionUse
      IsHeaderEncrypted                        = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Full'
      FilesEncrypted                           = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -in @('Files', 'Full')
      CompressMethod                           = $HeaderFixedData.CompressMethod
      Warnings                                 = $Warnings.ToArray()
      ParserVersionInfo                        = [pscustomobject]@{
        SignatureVersion              = $SignatureMatch.Groups[1].Value
        HeaderStringCount             = $Layout.HeaderStringCount
        HeaderAnsiStringCount         = $Layout.HeaderAnsiStringCount
        FileEntryStringCount          = $Layout.FileEntryStringCount
        FileEntryAnsiStringCount      = $Layout.FileEntryAnsiStringCount
        FileLocationEntrySize         = $Layout.FileLocationEntrySize
        FileLocationDigestAlgorithm   = $Layout.FileLocationDigestAlgorithm
        FileLocationStartOffsetSize   = $Layout.FileLocationStartOffsetSize
        FixedHeaderArchitectureFormat = $Layout.ArchitecturesEncoding
        UsesInt64BlockHeader          = $Layout.UsesInt64BlockHeader
        OffsetTableVersion            = $OffsetTable.Version
      }
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
    Read the built-in Apps & Features ProductCode from an Inno Setup installer
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
    if ([string]::IsNullOrWhiteSpace($Info.ProductCode)) { throw 'The Inno Setup installer does not expose a built-in Apps & Features ProductCode' }
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

  if ($Layout.StringEncoding -ne 'Ansi') { throw 'The legacy Inno 5.x header reader only accepts ANSI layouts' }

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $HeaderValues = Read-InnoReaderStrings -Reader $Reader -Count ($Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount) -Encoding (Get-InnoAnsiEncoding)
    $HeaderFixedSize = Get-InnoVersion5HeaderFixedSize -VersionNumber $VersionNumber
    # Old ANSI installers persist the fixed metadata immediately after the main header strings.
    $Reader.BaseStream.Seek($Script:INNO_LEAD_BYTES_SIZE, 'Current') | Out-Null

    $Counts = [ordered]@{
      NumLanguageEntries        = $Reader.ReadInt32()
      NumCustomMessageEntries   = $Reader.ReadInt32()
      NumPermissionEntries      = $Reader.ReadInt32()
      NumTypeEntries            = $Reader.ReadInt32()
      NumComponentEntries       = $Reader.ReadInt32()
      NumTaskEntries            = $Reader.ReadInt32()
      NumDirEntries             = $Reader.ReadInt32()
      NumFileEntries            = $Reader.ReadInt32()
      NumFileLocationEntries    = $Reader.ReadInt32()
      NumIconEntries            = $Reader.ReadInt32()
      NumIniEntries             = $Reader.ReadInt32()
      NumRegistryEntries        = $Reader.ReadInt32()
      NumInstallDeleteEntries   = $Reader.ReadInt32()
      NumUninstallDeleteEntries = $Reader.ReadInt32()
      NumRunEntries             = $Reader.ReadInt32()
      NumUninstallRunEntries    = $Reader.ReadInt32()
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
    # Inno serializes tables in a fixed order. Skip each preceding table using
    # its declared count and versioned record width to reach the file table.
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

    # Read only extraction-relevant fields; payload bytes live in the second
    # metadata block and are joined through LocationEntry rather than guessed.
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
          SourceFilename     = $Strings[0]
          DestName           = $Strings[1]
          InstallFontName    = $Strings[2]
          StrongAssemblyName = $Strings[3]
          Components         = $Strings[4]
          Tasks              = $Strings[5]
          Languages          = $Strings[6]
          Check              = $Strings[7]
          AfterInstall       = $Strings[8]
          BeforeInstall      = $Strings[9]
          LocationEntry      = $LocationEntry
          Attribs            = $Attribs
          ExternalSize       = $ExternalSize
          PermissionsEntry   = $PermissionsEntry
          Options            = $Options
          FileType           = $FileType
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
    VersionInfoValid         = [bool]($Value -band 0x0001)
    VersionInfoNotValid      = [bool]($Value -band 0x0002)
    TimeStampInUtc           = [bool]($Value -band 0x0004)
    IsUninstallExecutable    = [bool]($Value -band 0x0008)
    CallInstructionOptimized = [bool]($Value -band 0x0010)
    TouchApplied             = [bool]($Value -band 0x0020)
    ChunkEncrypted           = [bool]($Value -band 0x0040)
    ChunkCompressed          = [bool]($Value -band 0x0080)
    SolidBreak               = [bool]($Value -band 0x0100)
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

  # When no trusted count is available, exact divisibility by the fixed record
  # size is required before deriving one from the block length.
  if ($Count -le 0) {
    if (($Bytes.Length % $Script:INNO_FILE_LOCATION_ENTRY_SIZE) -ne 0) { throw 'The Inno Setup file location block size is invalid' }
    $Count = [int]($Bytes.Length / $Script:INNO_FILE_LOCATION_ENTRY_SIZE)
  }

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)

  try {
    $Locations = [System.Collections.Generic.List[object]]::new()

    # Location records describe slice/chunk coordinates and integrity evidence;
    # they do not contain destination names.
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

function Get-InnoExtractionHeader {
  <#
  .SYNOPSIS
    Read the versioned entry counts needed for targeted Inno payload extraction
  .PARAMETER Bytes
    The decompressed first metadata block
  .PARAMETER Layout
    The source-backed Inno serialization layout
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The decompressed first metadata block')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The source-backed Inno serialization layout')]
    [pscustomobject]$Layout
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)
  try {
    $HeaderValues = switch ($Layout.StringEncoding) {
      'Unicode' {
        $Wide = Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderStringCount -Encoding ([System.Text.Encoding]::Unicode)
        $null = Read-InnoReaderStrings -Reader $Reader -Count $Layout.HeaderAnsiStringCount -Encoding (Get-InnoAnsiEncoding)
        $Wide
      }
      'Ansi' {
        Read-InnoReaderStrings -Reader $Reader -Count ($Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount) -Encoding (Get-InnoAnsiEncoding)
      }
      default { throw "Unsupported Inno Setup header string encoding: $($Layout.StringEncoding)" }
    }

    # Non-Unicode 5.x headers persist a 256-bit ANSI lead-byte set before the counts.
    if ($Layout.VersionNumber -lt 6000 -and $Layout.StringEncoding -eq 'Ansi') {
      if ($Reader.BaseStream.Position + $Script:INNO_LEAD_BYTES_SIZE -gt $Reader.BaseStream.Length) {
        throw 'The Inno Setup header lead-byte set is truncated'
      }
      $Reader.BaseStream.Seek($Script:INNO_LEAD_BYTES_SIZE, 'Current') | Out-Null
    }

    $CountNames = [System.Collections.Generic.List[string]]::new()
    $CountNames.AddRange([string[]]@(
        'NumLanguageEntries', 'NumCustomMessageEntries', 'NumPermissionEntries',
        'NumTypeEntries', 'NumComponentEntries', 'NumTaskEntries', 'NumDirEntries'
      ))
    if ($Layout.VersionNumber -ge 6500) { $CountNames.Add('NumISSigKeyEntries') }
    $CountNames.AddRange([string[]]@(
        'NumFileEntries', 'NumFileLocationEntries', 'NumIconEntries', 'NumIniEntries',
        'NumRegistryEntries', 'NumInstallDeleteEntries', 'NumUninstallDeleteEntries',
        'NumRunEntries', 'NumUninstallRunEntries'
      ))

    $Counts = [ordered]@{}
    foreach ($CountName in $CountNames) {
      if ($Reader.BaseStream.Position + 4 -gt $Reader.BaseStream.Length) { throw 'The Inno Setup entry counts are truncated' }
      $Count = $Reader.ReadInt32()
      if ($Count -lt 0 -or $Count -gt 500000) { throw "The Inno Setup $CountName value is invalid: $Count" }
      $Counts[$CountName] = $Count
    }

    return [pscustomobject]@{
      HeaderValues = $HeaderValues
      Counts       = [pscustomobject]$Counts
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

function Read-InnoFileEntryAtOffset {
  <#
  .SYNOPSIS
    Read the extraction-relevant prefix of one versioned Inno file entry
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Offset
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER FileLocationCount
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Offset,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][ValidateRange(0, 500000)][int]$FileLocationCount
  )

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)
  try {
    # Modern file entries are variable-length. Read the version-selected string
    # prefix, optional verification record, then validate its location index.
    $Reader.BaseStream.Position = $Offset
    $Encoding = $Layout.StringEncoding -eq 'Unicode' ? [System.Text.Encoding]::Unicode : (Get-InnoAnsiEncoding)
    $Strings = Read-InnoReaderStrings -Reader $Reader -Count $Layout.FileEntryStringCount -Encoding $Encoding -MaximumLength $Script:INNO_MAX_ENTRY_STRING_SIZE

    $VerificationAllowedKeys = $null
    $VerificationHash = $null
    $VerificationType = $null
    # Verification fields were added in newer generations and must not shift the
    # following fixed fields for older layouts.
    if ($Layout.FileEntryHasVerification) {
      $VerificationAllowedKeys = (Read-InnoReaderStrings -Reader $Reader -Count 1 -Encoding (Get-InnoAnsiEncoding) -MaximumLength $Script:INNO_MAX_ENTRY_STRING_SIZE)[0]
      $VerificationHash = $Reader.ReadBytes(32)
      if ($VerificationHash.Length -ne 32) { throw 'The Inno Setup file verification hash is truncated' }
      $VerificationType = $Reader.ReadByte()
      if ($VerificationType -gt 2) { throw "The Inno Setup file verification type is invalid: $VerificationType" }
    }

    if ($Reader.BaseStream.Position + 24 -gt $Reader.BaseStream.Length) { throw 'The Inno Setup file entry is truncated' }
    $Reader.BaseStream.Seek(20, 'Current') | Out-Null # MinVersion + OnlyBelowVersion
    $LocationEntry = $Reader.ReadInt32()
    if ($LocationEntry -lt -1 -or $LocationEntry -ge $FileLocationCount) {
      throw "The Inno Setup file location index is invalid: $LocationEntry"
    }

    return [pscustomobject]@{
      RecordOffset            = $Offset
      SourceFilename          = $Strings[0]
      DestName                = $Strings[1]
      InstallFontName         = $Strings[2]
      StrongAssemblyName      = $Strings[3]
      Components              = $Strings[4]
      Tasks                   = $Strings[5]
      Languages               = $Strings[6]
      Check                   = $Strings[7]
      AfterInstall            = $Strings[8]
      BeforeInstall           = $Strings[9]
      Excludes                = $Layout.FileEntryStringCount -gt 10 ? $Strings[10] : $null
      DownloadISSigSource     = $Layout.FileEntryStringCount -gt 11 ? $Strings[11] : $null
      DownloadUserName        = $Layout.FileEntryStringCount -gt 12 ? $Strings[12] : $null
      DownloadPassword        = $Layout.FileEntryStringCount -gt 13 ? $Strings[13] : $null
      ExtractArchivePassword  = $Layout.FileEntryStringCount -gt 14 ? $Strings[14] : $null
      VerificationAllowedKeys = $VerificationAllowedKeys
      VerificationHash        = $VerificationHash
      VerificationType        = $VerificationType
      LocationEntry           = $LocationEntry
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

function Find-InnoFileEntry {
  <#
  .SYNOPSIS
    Locate exact named file entries without deserializing unrelated versioned tables
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER FileLocationCount
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER Language
    Language or template selector applied to format metadata.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateRange(1, 500000)][int]$FileLocationCount,
    [string]$Language
  )

  if ($Name.IndexOfAny([char[]]'*?[') -ge 0) {
    throw 'Static Inno file extraction currently requires an exact file name, not a wildcard pattern'
  }

  $Encoding = $Layout.StringEncoding -eq 'Unicode' ? [System.Text.Encoding]::Unicode : (Get-InnoAnsiEncoding)
  $NeedleValues = [System.Collections.Generic.List[string]]::new(4)
  $SeenNeedles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  foreach ($NeedleValue in [string[]]@($Name, [System.IO.Path]::GetFileName($Name), $Name.ToLowerInvariant(), $Name.ToUpperInvariant())) {
    if (-not [string]::IsNullOrWhiteSpace($NeedleValue) -and $SeenNeedles.Add($NeedleValue)) {
      $NeedleValues.Add($NeedleValue)
    }
  }

  $TestCandidate = {
    param([int]$Start, [int]$LocationCount, [string]$SelectedLanguage)
    try {
      $Entry = Read-InnoFileEntryAtOffset -Bytes $Bytes -Offset $Start -Layout $Layout -FileLocationCount $LocationCount
    } catch {
      return $null
    }
    $CandidateNames = [string[]]@(
      $Entry.SourceFilename, $Entry.DestName,
      [System.IO.Path]::GetFileName($Entry.SourceFilename),
      [System.IO.Path]::GetFileName($Entry.DestName)
    )
    $MatchesName = $false
    foreach ($CandidateName in $CandidateNames) {
      if (-not [string]::IsNullOrWhiteSpace($CandidateName) -and
        ($CandidateName.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase) -or
        $CandidateName.EndsWith("\$Name", [System.StringComparison]::OrdinalIgnoreCase))) {
        $MatchesName = $true
        break
      }
    }
    if (-not $MatchesName) { return $null }
    if (-not [string]::IsNullOrWhiteSpace($SelectedLanguage)) {
      $MatchesLanguage = $false
      foreach ($EntryLanguage in ($Entry.Languages -split '[,\s]+')) {
        if ($EntryLanguage.Equals($SelectedLanguage, [System.StringComparison]::OrdinalIgnoreCase)) {
          $MatchesLanguage = $true
          break
        }
      }
      if (-not $MatchesLanguage) { return $null }
    }
    return $Entry
  }

  $TestStringStart = {
    param([int]$StringStart, [int]$LocationCount, [string]$SelectedLanguage)

    # The exact string can be SourceFilename (the entry start) or DestName
    # (immediately after SourceFilename). Test both without scanning whole tables.
    $Entry = & $TestCandidate $StringStart $LocationCount $SelectedLanguage
    if ($Entry) { return $Entry }

    $MinimumStart = [Math]::Max(0, $StringStart - $Script:INNO_MAX_FILE_ENTRY_PATH_SCAN)
    $PreviousMatches = 0
    for ($PreviousStart = $StringStart - 4; $PreviousStart -ge $MinimumStart; $PreviousStart--) {
      $ExpectedLength = $StringStart - $PreviousStart - 4
      if ($Bytes[$PreviousStart + 3] -ne 0 -or [System.BitConverter]::ToInt32($Bytes, $PreviousStart) -ne $ExpectedLength) { continue }
      if ($Layout.StringEncoding -eq 'Unicode' -and ($ExpectedLength % 2) -ne 0) { continue }
      $PreviousMatches++
      $Entry = & $TestCandidate $PreviousStart $LocationCount $SelectedLanguage
      if ($Entry) { return $Entry }
      if ($PreviousMatches -ge 8) { break }
    }
    return $null
  }

  # Prefer an exact serialized string. Inno commonly stores DestName as the
  # bare output name, making this path independent of unrelated name repeats.
  foreach ($NeedleValue in $NeedleValues) {
    $Needle = $Encoding.GetBytes($NeedleValue)
    if ($Needle.Length -eq 0) { continue }
    $SerializedNeedle = [byte[]]::new(4 + $Needle.Length)
    [System.BitConverter]::GetBytes($Needle.Length).CopyTo($SerializedNeedle, 0)
    $Needle.CopyTo($SerializedNeedle, 4)
    foreach ($StringStart in (Find-BinaryPattern -Bytes $Bytes -Pattern $SerializedNeedle -Maximum 64)) {
      $Entry = & $TestStringStart ([int]$StringStart) $FileLocationCount $Language
      if ($Entry) { return $Entry }
    }
  }

  # If the name is only the final component of a serialized path, locate the
  # length field whose payload ends with the matched bytes, then test that field
  # as SourceFilename or DestName. The scan is bounded to a valid path-sized window.
  foreach ($NeedleValue in $NeedleValues) {
    $Needle = $Encoding.GetBytes($NeedleValue)
    if ($Needle.Length -eq 0) { continue }
    foreach ($Occurrence in (Find-BinaryPattern -Bytes $Bytes -Pattern $Needle -Maximum 16)) {
      $StringEnd = [int]$Occurrence + $Needle.Length
      $MinimumStart = [Math]::Max(0, $StringEnd - $Script:INNO_MAX_FILE_ENTRY_PATH_SCAN)
      for ($StringStart = $StringEnd - 4; $StringStart -ge $MinimumStart; $StringStart--) {
        $ExpectedLength = $StringEnd - $StringStart - 4
        if ($Bytes[$StringStart + 3] -ne 0 -or [System.BitConverter]::ToInt32($Bytes, $StringStart) -ne $ExpectedLength) { continue }
        if ($Layout.StringEncoding -eq 'Unicode' -and ($ExpectedLength % 2) -ne 0) { continue }
        $Entry = & $TestStringStart $StringStart $FileLocationCount $Language
        if ($Entry) { return $Entry }
      }
    }
  }

  throw "No valid Inno Setup file entry matched: $Name"
}

function ConvertFrom-InnoFileLocationFlags {
  <#
  .SYNOPSIS
    Decode legacy or compact Inno file-location flags
  .PARAMETER Value
    Format-specific field or value interpreted according to the current record/version.
  .PARAMETER Legacy
    Selects the legacy record flag layout documented by the detected installer generation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][uint16]$Value,
    [Parameter(Mandatory)][bool]$Legacy
  )

  if ($Legacy) {
    return [pscustomobject]@{
      VersionInfoValid         = [bool]($Value -band 0x0001)
      VersionInfoNotValid      = [bool]($Value -band 0x0002)
      TimeStampInUtc           = [bool]($Value -band 0x0004)
      IsUninstallExecutable    = [bool]($Value -band 0x0008)
      CallInstructionOptimized = [bool]($Value -band 0x0010)
      TouchApplied             = [bool]($Value -band 0x0020)
      ChunkEncrypted           = [bool]($Value -band 0x0040)
      ChunkCompressed          = [bool]($Value -band 0x0080)
      SolidBreak               = [bool]($Value -band 0x0100)
    }
  }

  return [pscustomobject]@{
    VersionInfoValid         = [bool]($Value -band 0x01)
    VersionInfoNotValid      = $false
    TimeStampInUtc           = [bool]($Value -band 0x02)
    IsUninstallExecutable    = $false
    CallInstructionOptimized = [bool]($Value -band 0x04)
    TouchApplied             = $false
    ChunkEncrypted           = [bool]($Value -band 0x08)
    ChunkCompressed          = [bool]($Value -band 0x10)
    SolidBreak               = $false
  }
}

function Read-InnoFileLocation {
  <#
  .SYNOPSIS
    Parse one indexed record from the versioned Inno file-location metadata block
  .PARAMETER Bytes
    Bounded format record or payload bytes interpreted by this function; the input array is not modified.
  .PARAMETER Count
    Declared record count or parser count limit; malformed or excessive counts are rejected.
  .PARAMETER Index
    Current record position or zero-based index within the validated table.
  .PARAMETER Layout
    Previously validated layout evidence containing the coordinate ranges needed by this operation.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(1, 500000)][int]$Count,
    [Parameter(Mandatory)][ValidateRange(0, 499999)][int]$Index,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $ExpectedLength = [long]$Count * $Layout.FileLocationEntrySize

  # Exact table sizing prevents a wrong version layout from silently indexing
  # into adjacent compressed-block data.
  if ($ExpectedLength -ne $Bytes.LongLength) {
    throw "The Inno Setup file location block size is invalid: expected $ExpectedLength bytes, found $($Bytes.LongLength)"
  }
  if ($Index -ge $Count) { throw "The Inno Setup file location index is invalid: $Index" }

  $Stream = [System.IO.MemoryStream]::new($Bytes, $false)
  $Reader = [System.IO.BinaryReader]::new($Stream)
  try {
    $Reader.BaseStream.Position = [long]$Index * $Layout.FileLocationEntrySize
    $FirstSlice = $Reader.ReadInt32()
    $LastSlice = $Reader.ReadInt32()
    $StartOffset = if ($Layout.FileLocationStartOffsetSize -eq 8) { $Reader.ReadInt64() } else { [long]$Reader.ReadInt32() }
    $ChunkSuboffset = $Reader.ReadInt64()
    $OriginalSize = $Reader.ReadInt64()
    $ChunkCompressedSize = $Reader.ReadInt64()
    $Digest = $Reader.ReadBytes($Layout.FileLocationDigestSize)
    $TimeStamp = $Reader.ReadBytes(8)
    $FileVersionMS = $Reader.ReadUInt32()
    $FileVersionLS = $Reader.ReadUInt32()
    $RawFlags = if ($Layout.FileLocationUsesLegacyFlags) { [uint16]$Reader.ReadUInt16() } else { [uint16]$Reader.ReadByte() }
    $Sign = if ($Layout.FileLocationHasSign) { $Reader.ReadByte() } else { $null }
    $Flags = ConvertFrom-InnoFileLocationFlags -Value $RawFlags -Legacy $Layout.FileLocationUsesLegacyFlags

    if ($FirstSlice -lt 0 -or $LastSlice -lt $FirstSlice -or $StartOffset -lt 0 -or
      $ChunkSuboffset -lt 0 -or $OriginalSize -lt 0 -or $ChunkCompressedSize -lt 0) {
      throw "The Inno Setup file location entry $Index contains invalid bounds"
    }

    return [pscustomobject]@{
      Index               = $Index
      FirstSlice          = $FirstSlice
      LastSlice           = $LastSlice
      StartOffset         = $StartOffset
      ChunkSuboffset      = $ChunkSuboffset
      OriginalSize        = $OriginalSize
      ChunkCompressedSize = $ChunkCompressedSize
      DigestAlgorithm     = $Layout.FileLocationDigestAlgorithm
      Digest              = $Digest
      Sha1                = $Layout.FileLocationDigestAlgorithm -eq 'SHA1' ? $Digest : $null
      Sha256              = $Layout.FileLocationDigestAlgorithm -eq 'SHA256' ? $Digest : $null
      TimeStamp           = $TimeStamp
      FileVersionMS       = $FileVersionMS
      FileVersionLS       = $FileVersionLS
      RawFlags            = $RawFlags
      Flags               = $Flags
      Sign                = $Sign
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
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

  # Legacy 5.x targeted lookup tests only structurally plausible string-record
  # starts and validates the fixed trailer before accepting a name match.
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
        SourceFilename     = $Strings[0]
        DestName           = $Strings[1]
        InstallFontName    = $Strings[2]
        StrongAssemblyName = $Strings[3]
        Components         = $Strings[4]
        Tasks              = $Strings[5]
        Languages          = $Strings[6]
        Check              = $Strings[7]
        AfterInstall       = $Strings[8]
        BeforeInstall      = $Strings[9]
        LocationEntry      = $LocationEntry
        Attribs            = $Attribs
        ExternalSize       = $ExternalSize
        PermissionsEntry   = $PermissionsEntry
        Options            = $Options
        FileType           = $FileType
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
    [byte[]]$Bytes,

    [Parameter(HelpMessage = 'The source-file offset represented by the first byte')]
    [uint32]$AddressOffset = 0
  )

  if ($Bytes.Length -lt 5) { return }

  $Limit = $Bytes.Length - 4
  $Index = 0
  while ($Index -lt $Limit) {
    if ($Bytes[$Index] -eq 0xE8 -or $Bytes[$Index] -eq 0xE9) {
      $Index++
      if ($Bytes[$Index + 3] -eq 0x00 -or $Bytes[$Index + 3] -eq 0xFF) {
        $Address = [uint32](($AddressOffset + $Index + 4) -band 0xFFFFFFFFL)
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
    [byte[]]$Bytes,

    [Parameter(HelpMessage = 'The source-file offset represented by the first byte')]
    [uint32]$AddressOffset = 0,

    [Parameter(HelpMessage = 'The number of valid bytes at the start of the buffer')]
    [ValidateRange(-1, [int]::MaxValue)]
    [int]$Count = -1
  )

  if ($Count -lt 0) { $Count = $Bytes.Length }
  Import-InnoCallTransform
  [Dumplings.InstallerParsers.InnoCallTransform]::Decode($Bytes, $Count, $AddressOffset)
}

function Open-InnoFileChunkDecoder {
  <#
  .SYNOPSIS
    Create the decoder selected by the compiled Inno CompressMethod
  .PARAMETER Stream
    The bounded chunk stream positioned after the Inno chunk marker
  .PARAMETER CompressionMethod
    The compiled Inno compression method
  .PARAMETER Compressed
    Whether this chunk is compressed
  .PARAMETER CompressedSize
    The complete bounded chunk length, including LZMA properties
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateSet('Stored', 'Zlib', 'BZip2', 'Lzma', 'Lzma2')][string]$CompressionMethod,
    [Parameter(Mandatory)][bool]$Compressed,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$CompressedSize
  )

  if (-not $Compressed) {
    return [pscustomobject]@{ Stream = $Stream; Decoder = $null }
  }
  if ($CompressionMethod -eq 'Stored') { throw 'The Inno Setup chunk is marked compressed but CompressMethod is stored' }

  $Properties = $null
  $PropertyLength = switch ($CompressionMethod) {
    'Lzma' { 5 }
    'Lzma2' { 1 }
    default { 0 }
  }
  if ($CompressedSize -lt $PropertyLength) { throw 'The Inno Setup compressed chunk properties are truncated' }
  if ($PropertyLength -gt 0) {
    $Properties = [byte[]]::new($PropertyLength)
    $Read = $Stream.Read($Properties, 0, $PropertyLength)
    if ($Read -ne $PropertyLength) { throw 'The Inno Setup compressed chunk properties are truncated' }
  }

  $Decoder = New-InstallerDecompressionStream -Algorithm $CompressionMethod -Stream $Stream -Properties $Properties `
    -CompressedSize ($CompressedSize - $PropertyLength) -LeaveOpen
  return [pscustomobject]@{ Stream = $Decoder; Decoder = $Decoder }
}

function Write-InnoFilePayload {
  <#
  .SYNOPSIS
    Stream one unencrypted embedded Inno payload to disk and verify its digest
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER Offset1
    Byte offset in the coordinate system named by this function: absolute file, PE/resource, overlay, or record relative.
  .PARAMETER Location
    Current structured format node or record being interpreted.
  .PARAMETER CompressionMethod
    Compression framing or bounded decoder selected from validated format metadata.
  .PARAMETER OutputPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset1,
    [Parameter(Mandatory)][pscustomobject]$Location,
    [Parameter(Mandatory)][string]$CompressionMethod,
    [Parameter(Mandatory)][string]$OutputPath
  )

  if ($Location.Flags.ChunkEncrypted) { throw 'Encrypted Inno Setup file chunks require the setup password and are not supported' }

  # This path handles a single embedded setup.exe data stream. External slices
  # and password-encrypted chunks require runtime inputs unavailable statically.
  if ($Offset1 -eq 0 -or $Location.FirstSlice -ne 0 -or $Location.LastSlice -ne 0) {
    throw 'Disk-spanning Inno Setup payload extraction requires the external setup slice files and is not supported by this path'
  }
  if ($Location.OriginalSize -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -or
    $Location.ChunkSuboffset -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -or
    $Location.OriginalSize -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE - $Location.ChunkSuboffset) {
    throw "The Inno Setup payload exceeds the $($Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE)-byte extraction limit"
  }

  $InstallerPath = (Get-Item -LiteralPath $Path -Force).FullName
  $InstallerStream = [System.IO.File]::OpenRead($InstallerPath)
  $ChunkRange = $null
  $Decoder = $null
  $Hash = $null
  $OutputStream = $null
  $Buffer = $null
  $TemporaryPath = "$OutputPath.$([guid]::NewGuid().ToString('N')).partial"
  try {
    $ChunkOffset = [long]$Offset1 + [long]$Location.StartOffset
    if ($ChunkOffset -lt 0 -or $ChunkOffset -gt $InstallerStream.Length - 4 -or
      $Location.ChunkCompressedSize -gt $InstallerStream.Length - $ChunkOffset - 4) {
      throw 'The Inno Setup file chunk is outside the installer'
    }
    $ChunkMagic = [System.Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $InstallerStream -Offset $ChunkOffset -Count 4))
    if ($ChunkMagic -ne $Script:INNO_CHUNK_MAGIC) { throw 'The Inno Setup chunk marker is invalid' }

    # Bound the decoder to the catalog-declared chunk so it cannot consume a
    # following chunk, signature, or certificate table on malformed input.
    $ChunkRange = New-BoundedReadStream -Stream $InstallerStream -Offset ($ChunkOffset + 4) -Length $Location.ChunkCompressedSize -LeaveOpen
    $DecoderInfo = Open-InnoFileChunkDecoder -Stream $ChunkRange -CompressionMethod $CompressionMethod `
      -Compressed $Location.Flags.ChunkCompressed -CompressedSize $Location.ChunkCompressedSize
    $PayloadStream = $DecoderInfo.Stream
    $Decoder = $DecoderInfo.Decoder

    # Solid chunks must be decoded from their beginning. Reuse one pooled
    # buffer for prefix discard and payload output to avoid LOH churn.
    $Buffer = [System.Buffers.ArrayPool[byte]]::Shared.Rent($Script:INNO_PAYLOAD_BUFFER_SIZE)
    $DiscardRemaining = [long]$Location.ChunkSuboffset
    while ($DiscardRemaining -gt 0) {
      $Requested = [int][Math]::Min($Script:INNO_PAYLOAD_BUFFER_SIZE, $DiscardRemaining)
      $Read = $PayloadStream.Read($Buffer, 0, $Requested)
      if ($Read -le 0) { throw 'The Inno Setup solid chunk ended before the file suboffset' }
      $DiscardRemaining -= $Read
    }

    $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($OutputPath)) -ItemType Directory -Force
    $OutputStream = [System.IO.File]::Open($TemporaryPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $HashAlgorithm = $Location.DigestAlgorithm -eq 'SHA256' ?
    [System.Security.Cryptography.HashAlgorithmName]::SHA256 :
    [System.Security.Cryptography.HashAlgorithmName]::SHA1
    $Hash = [System.Security.Cryptography.IncrementalHash]::CreateHash($HashAlgorithm)

    $Remaining = [long]$Location.OriginalSize
    $AddressOffset = [uint32]0

    # Decode, reverse the optional CALL/JMP filter, hash, and write each block in
    # one pass. The final path is replaced only after the stored digest matches.
    while ($Remaining -gt 0) {
      $BlockLength = [int][Math]::Min($Script:INNO_PAYLOAD_BUFFER_SIZE, $Remaining)
      $TotalRead = 0
      while ($TotalRead -lt $BlockLength) {
        $Read = $PayloadStream.Read($Buffer, $TotalRead, $BlockLength - $TotalRead)
        if ($Read -le 0) { throw 'The Inno Setup file payload is truncated' }
        $TotalRead += $Read
      }

      if ($Location.Flags.CallInstructionOptimized) {
        Convert-InnoCallInstructions5309 -Bytes $Buffer -AddressOffset $AddressOffset -Count $BlockLength
        $AddressOffset = [uint32](([uint64]$AddressOffset + [uint64]$BlockLength) -band 0xFFFFFFFFL)
      }
      $Hash.AppendData($Buffer, 0, $BlockLength)
      $OutputStream.Write($Buffer, 0, $BlockLength)
      $Remaining -= $BlockLength
    }

    $ActualDigest = $Hash.GetHashAndReset()
    if (-not (Test-BinarySequence -Left $ActualDigest -Right $Location.Digest)) {
      throw "The extracted Inno Setup file does not match its stored $($Location.DigestAlgorithm) digest"
    }
    $OutputStream.Dispose()
    $OutputStream = $null
    [System.IO.File]::Move($TemporaryPath, $OutputPath, $true)
    return Get-Item -LiteralPath $OutputPath -Force
  } finally {
    if ($OutputStream) { $OutputStream.Dispose() }
    if ($Hash) { $Hash.Dispose() }
    if ($Decoder) { $Decoder.Dispose() }
    if ($ChunkRange) { $ChunkRange.Dispose() }
    if ($Buffer) { [System.Buffers.ArrayPool[byte]]::Shared.Return($Buffer, $false) }
    $InstallerStream.Dispose()
    if (Test-Path -LiteralPath $TemporaryPath) { Remove-Item -LiteralPath $TemporaryPath -Force }
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
            return , $FileCandidate.Bytes
          }
          $CandidateFailures.Add("$($FileCandidate.Name): SHA1 digest mismatch")
        } else {
          return , $FileCandidate.Bytes
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
    Extract an exact named file from an unencrypted Inno Setup installer without executing it
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER DestinationPath
    The directory where matching files should be written
  .PARAMETER Name
    The exact source, destination, or base file name to extract; wildcard extraction is not supported
  .PARAMETER Language
    An optional Inno Setup language name used to disambiguate language-specific payloads
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The exact source, destination, or base file name to extract')]
    [string]$Name,

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

    # Parse the first metadata block once to obtain counts, compression method,
    # encryption state, and the exact versioned file-entry layout.
    $HeaderBlockInfo = Get-InnoHeaderBlockInfo -Path $InstallerPath -Offset0 $OffsetTable.Offset0 -Layout $Layout
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      throw 'The Inno Setup payload files are encrypted and require the setup password'
    }
    $Header = Get-InnoExtractionHeader -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
    if ($Header.Counts.NumFileLocationEntries -le 0) { throw 'The Inno Setup installer does not contain embedded file locations' }
    $FindArguments = @{
      Bytes             = $HeaderBlockInfo.Bytes
      Layout            = $Layout
      Name              = $Name
      FileLocationCount = $Header.Counts.NumFileLocationEntries
    }
    if ($PSBoundParameters.ContainsKey('Language')) { $FindArguments.Language = $Language }

    # Resolve one deterministic file entry before opening the separate indexed
    # location block that points to compressed payload bytes.
    $Entry = Find-InnoFileEntry @FindArguments

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

    if ($Entry.LocationEntry -lt 0) {
      throw "The Inno Setup file entry '$($Entry.SourceFilename)' does not reference an embedded payload"
    }
    $Location = Read-InnoFileLocation -Bytes $LocationBlockInfo.Bytes -Count $Header.Counts.NumFileLocationEntries `
      -Index $Entry.LocationEntry -Layout $Layout

    # DestName controls the installed relative path; fall back to the source base
    # name only when the compiled destination field is empty.
    $RelativePath = if ([string]::IsNullOrWhiteSpace($Entry.DestName)) {
      [System.IO.Path]::GetFileName($Entry.SourceFilename)
    } else {
      $Entry.DestName
    }
    $OutputPath = Resolve-InnoExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath

    return Write-InnoFilePayload -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location `
      -CompressionMethod $HeaderFixedData.CompressMethod -OutputPath $OutputPath
  }
}

Export-ModuleMember -Function Get-InnoInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno, Read-UnsupportedArchitecturesFromInno, Test-InnoUnsupportedArchitecture, Test-InnoAppsAndFeaturesEntry, Expand-InnoInstaller
