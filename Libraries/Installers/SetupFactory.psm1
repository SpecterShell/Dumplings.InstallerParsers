# SPDX-License-Identifier: GPL-3.0-or-later
# Format sources: historical Indigo Rose media, https://github.com/fragglet/lhasa, https://github.com/CybercentreCanada/sfextract, https://github.com/Puyodead1/SFUnpacker, https://codeberg.org/CYBERDEV/defactory, and https://github.com/madler/zlib
# Setup Factory 3.1-10 static parser. Setup Factory 3.1 structures were independently derived from historical media and its Crusher archive behavior was implemented from Lhasa's ISC-licensed LH5 decoder. Later format details are derived from sfextract (MIT), SFUnpacker (LGPL-3.0-or-later), and defactory (GPL-3.0-or-later); see Assets/THIRD-PARTY-NOTICES.md.
#
# Binary structure consumed by this parser (overlay-relative, LE integers):
#
#   Setup Factory 3.1 multi-file media
#   +-- SETUP.EXE: 16-bit MZ/NE launcher
#   +-- IRDATA.IRD: Crusher ARQ records
#   |   `-- [magic:4][version:u16][name length:u16][name][descriptor:33][payload]
#   |       +-- IRDATA.DAT: product and installed-file catalogs
#   |       +-- IRSETUP.EXE: setup runtime
#   |       `-- IRUNIN31.EXE: uninstaller runtime
#   `-- *.??_: independently compressed installed-file streams
#
#   Setup Factory 4-10 PE overlay
#   +-- v4: E0..E6, count:u8, 16-byte names
#   +-- v5/v6: E0..E7, count:u32, 16/260-byte names
#   +-- v7: E0..E7, runtime-size:u32, 260-byte names
#   `-- v8-10: doubled E0..E7, runtime-size:i64, 264-byte names
#       -> repeated [name][packed size][CRC32][compressed outer bytes]
#       -> optional CDependencyFile payloads
#       -> CFileInfo/CSetupFileData application payload streams
#
#   irsetup.dat (MFC serialization in versions 4-6)
#   +-- product and generated-uninstaller objects
#   +-- [count:u16][FFFF][schema:u16][class name][records...]
#   |   +-- v4: CRegistryData, CINIData
#   |   +-- v5: CRegistryData, CExecuteData, CFileOpData, CINIData, CVarRegistry
#   |   `-- v6: generic CAction lists
#   `-- nested CConditionData lists; class tags can reference an earlier archive-global declaration
#
# Only the first 2,000 irsetup.exe bytes are XORed with 07. File records use the
# supported bounded compression framing. irsetup.dat supplies structured
# session variables, uninstall settings, installed-file records, and literal
# Lua registry evidence. Setup Factory 10 adds one reserved byte before each
# installed-file compression flag; structurally validated candidate layouts
# keep that revision separate from the common outer container.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactory7Signature = [byte[]](0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7)
$Script:SetupFactory8PlusSignature = [byte[]](0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7)
$Script:SetupFactoryFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'SetupFactoryFormatCatalog.psd1')
$Script:SetupFactoryMaximumEntries = 100000
$Script:SetupFactory31MaximumLauncherBytes = 16777216
$Script:SetupFactoryMaximumFileBytes = 1073741824
$Script:SetupFactoryMaximumExpandedBytes = 17179869184
$Script:SetupFactoryMaximumScriptStringBytes = 65535
$Script:SetupFactoryActionNames6 = @{
  0 = 'Latest Version'; 1 = 'Download (FTP)'; 2 = 'HTTP Download'; 3 = 'Execute'; 4 = 'Open Document'; 5 = 'Unzip Files'; 6 = 'Close Program'
  7 = 'Copy Files'; 8 = 'Delete Files'; 9 = 'Rename File'; 10 = 'Create Directory'; 11 = 'Remove Directory'; 12 = 'Read from Registry'
  13 = 'Read from INI File'; 14 = 'Assign Value'; 17 = 'Modify Registry'; 18 = 'Modify INI File'; 19 = 'Submit to Web'; 20 = 'Show Message Box'
  21 = 'Read File Association'; 22 = 'Abort Setup'; 24 = 'Send Email'; 26 = 'Upload File FTP'; 28 = 'Show Yes/No Dialog'; 29 = 'Read File Information'
  30 = 'Find String'; 31 = 'Mid String'; 32 = 'Left String'; 33 = 'Right String'; 34 = 'Length of String'; 35 = 'Move Files'; 36 = 'Read Text File'
  37 = 'Write to Text File'; 38 = 'Generate Random Value'; 39 = 'Zip Files'; 42 = 'Count Text Lines'; 43 = 'Delete Text Line'; 44 = 'Find Text Line'
  45 = 'Get Text Line'; 46 = 'Insert Text Line'; 50 = 'Create Shortcut'; 51 = 'Remove Shortcut'; 52 = 'Install File'; 53 = 'Register File'
  54 = 'Register Font'; 55 = 'Check Internet Connection'; 56 = 'Set File Attributes'; 57 = 'Stop Service'; 58 = 'Pause Service'; 59 = 'Continue Service'
  60 = 'Delete Service'; 61 = 'Query Service'; 62 = 'Start Service'; 63 = 'Create Service'; 70 = 'Count Delimited Strings'; 71 = 'Get Delimited String'
  72 = 'Parse Path'; 73 = 'Search for File'; 74 = 'Move File on Reboot'; 75 = 'Delete File on Reboot'; 76 = 'Run File on Reboot'
  77 = 'Call DLL Function'; 78 = 'Format Number'; 79 = 'Write to Log File'; 80 = 'Get Disk Space'; 100 = 'IF'; 101 = 'END IF'; 102 = 'WHILE'
  103 = 'END WHILE'; 104 = 'GOTO Label'; 105 = 'Label'; 200 = 'Comment'; 201 = 'Blank line'
}

function ConvertFrom-SetupFactoryText {
  <#
  .SYNOPSIS
    Decode a Setup Factory string using UTF-8 with a legacy Windows fallback.
  .PARAMETER Bytes
    Buffer containing one string or textual script range.
  .PARAMETER Offset
    Zero-based start offset in Bytes. Direct range decoding avoids allocating a sliced copy for every project string.
  .PARAMETER Count
    Number of bytes to decode. A negative value selects every byte after Offset.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
    [ValidateRange(0, [int]::MaxValue)][int]$Offset = 0,
    [int]$Count = -1
  )

  if ($Offset -gt $Bytes.Length) { throw 'The Setup Factory text offset is outside the input buffer' }
  if ($Count -lt 0) { $Count = $Bytes.Length - $Offset }
  if ($Count -gt $Bytes.Length - $Offset) { throw 'The Setup Factory text range is outside the input buffer' }

  try {
    return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes, $Offset, $Count)
  } catch [Text.DecoderFallbackException] {
    # Setup Factory 7 and earlier media commonly stores project text in the
    # active Western Windows code page rather than UTF-8.
    return [Text.Encoding]::GetEncoding(1252).GetString($Bytes, $Offset, $Count)
  }
}

function Read-SetupFactoryExactByte {
  <#
  .SYNOPSIS
    Read an exact sequential byte range from a Setup Factory stream.
  .PARAMETER Stream
    Seekable input stream positioned at the first byte to consume. The caller owns the stream; this function advances Position by Count.
  .PARAMETER Count
    Exact number of bytes to read, in bytes. Truncated input throws.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][System.IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Count
  )
  $Offset = $Stream.Position
  $Buffer = Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Count
  $Stream.Position = $Offset + $Count
  return , $Buffer
}

function Read-SetupFactoryUInt32 {
  <#
  .SYNOPSIS
    Read one sequential unsigned 32-bit little-endian field.
  .PARAMETER Stream
    Seekable input stream positioned at the four-byte field. The caller owns the stream; Position advances by four bytes.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  [BitConverter]::ToUInt32((Read-SetupFactoryExactByte -Stream $Stream -Count 4), 0)
}

function Read-SetupFactoryInt64 {
  <#
  .SYNOPSIS
    Read one sequential signed 64-bit little-endian field.
  .PARAMETER Stream
    Seekable input stream positioned at the eight-byte field. The caller owns the stream; Position advances by eight bytes.
  #>
  [OutputType([long])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  [BitConverter]::ToInt64((Read-SetupFactoryExactByte -Stream $Stream -Count 8), 0)
}

function Get-SetupFactoryCrc32 {
  <#
  .SYNOPSIS
    Compute the CRC32 stored beside a Setup Factory file record.
  .PARAMETER Bytes
    Fully expanded file bytes covered by the record CRC. The byte array is not modified.
  #>
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  return Get-BinaryCrc32 -Bytes $Bytes
}

function Expand-SetupFactoryCompressedData {
  <#
  .SYNOPSIS
    Decode one bounded Setup Factory file-record payload.
  .PARAMETER Bytes
    Complete record payload including its compression properties/framing. The input byte array is not modified.
  .PARAMETER MaximumBytes
    Maximum permitted expanded output in bytes. Declared and actual output must both fit this limit.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )
  if ($Bytes.Length -eq 0) { return , $Bytes }
  Import-InstallerArchiveDependency
  $CompressedStream = $null
  $Output = [IO.MemoryStream]::new()
  try {
    # Setup Factory generations use distinct framing around their compressed records. Identify the
    # framing from its properties bytes and declared output length before constructing a decoder.
    if ($Bytes.Length -ge 13 -and $Bytes[0] -eq 0x5D -and $Bytes[1] -eq 0) {
      $Properties = $Bytes[0..4]
      $Expected = [BitConverter]::ToInt64($Bytes, 5)
      if ($Expected -lt 0 -or $Expected -gt $MaximumBytes) { throw 'The Setup Factory LZMA output exceeds the configured limit' }
      $CompressedStream = [IO.MemoryStream]::new($Bytes, 13, $Bytes.Length - 13, $false)
      $null = Expand-InstallerCompressedStream -Algorithm Lzma -Stream $CompressedStream -Destination $Output -MaximumBytes $MaximumBytes -Properties $Properties -CompressedSize ($Bytes.Length - 13) -UncompressedSize $Expected
    } elseif ($Bytes.Length -ge 10 -and $Bytes[0] -eq 0x18) {
      $Properties = [byte[]]@($Bytes[0])
      $Expected = [BitConverter]::ToInt64($Bytes, 1)
      if ($Expected -lt 0 -or $Expected -gt $MaximumBytes) { throw 'The Setup Factory LZMA2 output exceeds the configured limit' }
      $CompressedStream = [IO.MemoryStream]::new($Bytes, 9, $Bytes.Length - 9, $false)
      $null = Expand-InstallerCompressedStream -Algorithm Lzma2 -Stream $CompressedStream -Destination $Output -MaximumBytes $MaximumBytes -Properties $Properties -UncompressedSize $Expected
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -in 0, 1 -and $Bytes[1] -in 4, 5, 6) {
      # Setup Factory 7 can use PKWARE implode. Load the small bounded decoder only when its
      # dictionary/literal property pair is structurally valid.
      if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.PkwareBlast').Type) {
        $DecoderSource = Join-Path $PSScriptRoot '..\..\Assets\Source\SetupFactory\PkwareBlast.cs'
        if (-not (Test-Path -LiteralPath $DecoderSource)) { throw "The PKWARE decoder source is missing: $DecoderSource" }
        Add-Type -Path $DecoderSource
      }
      return , ([Dumplings.InstallerParsers.PkwareBlast]::Decode($Bytes, $MaximumBytes))
    } else {
      throw 'The Setup Factory compression format is not recognized'
    }

    return , ($Output.ToArray())
  } finally {
    if ($CompressedStream) { $CompressedStream.Dispose() }
    $Output.Dispose()
  }
}

function Get-SetupFactorySessionVariable {
  <#
  .SYNOPSIS
    Read the bounded CSessionVar table from irsetup.dat bytes.
  .PARAMETER Bytes
    Complete irsetup.dat content. Offsets found by this function are relative to this byte array.
  #>
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  $Variables = @{}
  $Pattern = [Text.Encoding]::ASCII.GetBytes('CSessionVar')
  # CSessionVar can occur in ordinary script text, so treat each bounded occurrence as a candidate
  # and accept it only when the count and every length-prefixed record are consistent.
  $Offsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Maximum 4)
  foreach ($Offset in $Offsets) {
    if ($Offset -lt 8) { continue }
    $Count = [BitConverter]::ToUInt16($Bytes, $Offset - 8)
    if ($Count -gt 4096) { continue }
    $Cursor = $Offset + $Pattern.Length
    try {
      for ($Index = 0; $Index -lt $Count; $Index++) {
        if ($Cursor + 5 -gt $Bytes.Length) { throw 'truncated' }
        $Cursor += 4
        $NameLength = $Bytes[$Cursor++]
        if ($NameLength -eq 0 -or $Cursor + $NameLength + 1 -gt $Bytes.Length) { throw 'invalid name' }
        $Name = ConvertFrom-SetupFactoryText -Bytes $Bytes -Offset $Cursor -Count $NameLength
        $Cursor += $NameLength
        $ValueLength = $Bytes[$Cursor++]
        if ($Cursor + $ValueLength + 6 -gt $Bytes.Length) { throw 'invalid value' }
        $Value = if ($ValueLength) { ConvertFrom-SetupFactoryText -Bytes $Bytes -Offset $Cursor -Count $ValueLength } else { '' }
        $Cursor += $ValueLength + 6
        $Variables[$Name] = $Value
      }
      if ($Variables.Count) { break }
    } catch {
      # A malformed candidate is not a partial table: discard all values and try the next marker.
      $Variables.Clear()
    }
  }
  return $Variables
}

function Resolve-SetupFactoryVariable {
  <#
  .SYNOPSIS
    Resolve literal percent-delimited Setup Factory session variables.
  .PARAMETER Value
    Source value containing zero or more percent-delimited variable names.
  .PARAMETER Variables
    Parsed CSessionVar name/value map.
  .PARAMETER Depth
    Current recursion depth. Internal recursive calls increment it; resolution stops at 32.
  .PARAMETER Stack
    Variable names already being resolved, used to reject cycles.
  #>
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][hashtable]$Variables,
    [int]$Depth = 0,
    [string[]]$Stack = @()
  )
  if ($null -eq $Value -or $Depth -ge 32) { return $null }
  $Result = $Value
  # Resolve only values present in the parsed session table. Cycles, unknown variables, and the
  # depth bound intentionally produce no inferred manifest value.
  foreach ($Match in [regex]::Matches($Value, '%[^%]+%')) {
    $Name = $Match.Value
    if ($Stack -contains $Name -or -not $Variables.ContainsKey($Name)) { return $null }
    $RawReplacement = [string]$Variables[$Name]
    # Legacy metadata can explicitly mark a manifest-safe system variable as terminal by mapping
    # it to itself. Treat that identity mapping as resolved instead of reporting a cycle.
    $Replacement = if ($RawReplacement -ceq $Name) { $Name } else { Resolve-SetupFactoryVariable -Value $RawReplacement -Variables $Variables -Depth ($Depth + 1) -Stack ($Stack + $Name) }
    if ($null -eq $Replacement) { return $null }
    $Result = $Result.Replace($Name, $Replacement)
  }
  return $Result
}

function Read-SetupFactoryDataInteger {
  <#
  .SYNOPSIS
    Read one bounded little-endian integer from an irsetup.dat byte array.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset. The function advances it by Size.
  .PARAMETER Size
    Integer width in bytes.
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateSet(1, 2, 4, 8)][int]$Size
  )

  $Cursor = [long]$Offset.Value
  if ($Cursor -lt 0 -or $Cursor + $Size -gt $Bytes.LongLength) { throw 'The Setup Factory project integer is truncated' }
  $Value = switch ($Size) {
    1 { [long]$Bytes[$Cursor] }
    2 { [long][BitConverter]::ToUInt16($Bytes, [int]$Cursor) }
    4 { [long][BitConverter]::ToUInt32($Bytes, [int]$Cursor) }
    8 { [long][BitConverter]::ToInt64($Bytes, [int]$Cursor) }
  }
  $Offset.Value = $Cursor + $Size
  return $Value
}

function Read-SetupFactoryDataBoolean {
  <#
  .SYNOPSIS
    Read one serialized Setup Factory Boolean and reject non-Boolean values.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset. The function advances it by one byte.
  .PARAMETER FieldName
    Source-backed field name included in malformed-record errors.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][string]$FieldName
  )

  $Value = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1
  if ($Value -gt 1) { throw "The Setup Factory $FieldName field has unsupported serialized Boolean value $Value" }
  return [bool]$Value
}

function Read-SetupFactoryDataStringList {
  <#
  .SYNOPSIS
    Read one bounded MFC CStringList from Setup Factory project data.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset.
  .PARAMETER MaximumCount
    Maximum accepted number of strings before allocation or iteration.
  .PARAMETER FieldName
    Source-backed list name included in malformed-record errors.
  #>
  [OutputType([string[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$MaximumCount,
    [Parameter(Mandatory)][string]$FieldName
  )

  $Count = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2
  if ($Count -gt $MaximumCount) { throw "The Setup Factory $FieldName count exceeds the configured limit" }
  $Values = [Collections.Generic.List[string]]::new([int]$Count)
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Values.Add((Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Small))
  }
  return $Values.ToArray()
}

function Read-SetupFactoryDataWordArray {
  <#
  .SYNOPSIS
    Read one bounded MFC CWordArray from Setup Factory project data.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset.
  .PARAMETER MaximumCount
    Maximum accepted number of unsigned 16-bit entries.
  .PARAMETER FieldName
    Source-backed array name included in malformed-record errors.
  #>
  [OutputType([uint16[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$MaximumCount,
    [Parameter(Mandatory)][string]$FieldName
  )

  $Count = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2
  if ($Count -gt $MaximumCount) { throw "The Setup Factory $FieldName count exceeds the configured limit" }
  $Values = [uint16[]]::new([int]$Count)
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $Values[$Index] = [uint16](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  }
  return $Values
}

function Move-SetupFactoryDataOffset {
  <#
  .SYNOPSIS
    Advance an irsetup.dat cursor through one bounded serialized span.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset.
  .PARAMETER Count
    Number of bytes to skip. Callers must document whether the span is proven padding, known but unused data, or behavior-relevant data whose semantics remain unresolved.
  #>
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Count
  )

  $Next = [long]$Offset.Value + $Count
  if ($Next -lt [long]$Offset.Value -or $Next -gt $Bytes.LongLength) { throw 'The Setup Factory project field is truncated' }
  $Offset.Value = $Next
}

function Read-SetupFactoryDataString {
  <#
  .SYNOPSIS
    Read one Setup Factory length-prefixed project string.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based byte offset.
  .PARAMETER Width
    Length framing: Small uses uint8, Big uses uint16, and Variable uses uint8 with 0xFF followed by uint16.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateSet('Small', 'Big', 'Variable')][string]$Width
  )

  $Length = if ($Width -eq 'Big') {
    Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2
  } else {
    $First = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1
    if ($Width -eq 'Variable' -and $First -eq 0xFF) { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2 } else { $First }
  }
  if ($Length -gt $Script:SetupFactoryMaximumScriptStringBytes) { throw 'The Setup Factory project string exceeds the configured limit' }
  if ([long]$Offset.Value + $Length -gt $Bytes.LongLength) { throw 'The Setup Factory project string is truncated' }
  if ($Length -eq 0) { return '' }
  $Value = ConvertFrom-SetupFactoryText -Bytes $Bytes -Offset ([int]$Offset.Value) -Count ([int]$Length)
  $Offset.Value = [long]$Offset.Value + $Length
  return $Value.Split("`0", 2)[0]
}

function Test-SetupFactoryLegacyMetadataText {
  <#
  .SYNOPSIS
    Test whether a decoded legacy metadata field is safe textual evidence.
  .PARAMETER Value
    Decoded Windows-1252 or UTF-8 project string.
  #>
  [OutputType([bool])]
  param ([AllowEmptyString()][string]$Value)

  if ($null -eq $Value -or $Value.Length -gt $Script:SetupFactoryMaximumScriptStringBytes) { return $false }
  foreach ($Character in $Value.ToCharArray()) {
    if ([char]::IsControl($Character) -and $Character -notin "`t", "`r", "`n") { return $false }
  }
  return $true
}

function Read-SetupFactoryBooleanByte {
  <#
  .SYNOPSIS
    Read a serialized Setup Factory Boolean after validating its byte representation.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable zero-based cursor advanced by one byte.
  .PARAMETER FieldName
    Structural field name included in malformed-input errors.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][string]$FieldName
  )

  $Value = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1
  if ($Value -notin 0, 1) { throw "The Setup Factory $FieldName Boolean has the invalid byte value $Value" }
  return [bool]$Value
}

function Read-SetupFactoryProjectDataCandidate {
  <#
  .SYNOPSIS
    Decode the silent-installation fields from one candidate modern CProjectData record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Zero-based candidate offset. The record begins with the CProjectData schema and is validated through the first CHeadingFont schema field.
  .OUTPUTS
    A structured project-data prefix containing the silent-mode flags and their byte offsets. Malformed candidates throw and must not be used as installer evidence.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$Offset
  )

  $Cursor = $Offset
  if ((Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 4) -ne 1) { throw 'The Setup Factory CProjectData schema is unsupported' }
  $CreateLog = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CProjectData.CreateLog'
  $LogFilename = Read-SetupFactoryDataString -Bytes $Bytes -Offset ([ref]$Cursor) -Width Variable
  if (-not (Test-SetupFactoryLegacyMetadataText -Value $LogFilename)) { throw 'The Setup Factory CProjectData log filename is not valid text' }

  $WriteMode = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 1
  $ActionDetailLevel = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 1
  if ($WriteMode -gt 3 -or $ActionDetailLevel -gt 3) { throw 'The Setup Factory CProjectData logging enum is outside the supported range' }

  $SilentFlagOffset = $Cursor
  $SupportsSilentInstallation = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CProjectData.EnableSilentMode'
  $StartsInSilentMode = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CProjectData.StartInSilentMode'
  $VerifyArchive = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CProjectData.VerifyArchive'
  $UserProfile = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CProjectData.UserProfile'

  # CProjectData embeds CMainWindowSettings immediately after its own flags. Validate the
  # complete fixed prefix and the following CHeadingFont schema so arbitrary byte sequences
  # cannot be mistaken for the silent-installation setting.
  if ((Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 4) -ne 1) { throw 'The Setup Factory CMainWindowSettings schema is unsupported' }
  $ShowBackground = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CMainWindowSettings.ShowBackground'
  $WindowStyle = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 4
  $WindowAppearance = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 4
  if ($WindowStyle -gt 16 -or $WindowAppearance -gt 16) { throw 'The Setup Factory CMainWindowSettings enum is outside the supported range' }
  # These three serialized COLORREF values control the solid background and gradient colors.
  # They are UI-only and cannot alter the silent-installation capability being established here.
  Move-SetupFactoryDataOffset -Bytes $Bytes -Offset ([ref]$Cursor) -Count 12
  $ImageFile = Read-SetupFactoryDataString -Bytes $Bytes -Offset ([ref]$Cursor) -Width Variable
  $UseCustomIcon = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CMainWindowSettings.UseCustomIcon'
  $CustomIcon = Read-SetupFactoryDataString -Bytes $Bytes -Offset ([ref]$Cursor) -Width Variable
  $HideTaskbarIcon = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CMainWindowSettings.HideTaskbarIcon'
  $AlwaysOnTop = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset ([ref]$Cursor) -FieldName 'CMainWindowSettings.AlwaysOnTop'
  $Headline = Read-SetupFactoryDataString -Bytes $Bytes -Offset ([ref]$Cursor) -Width Variable
  foreach ($TextValue in $ImageFile, $CustomIcon, $Headline) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $TextValue)) { throw 'The Setup Factory CMainWindowSettings record contains invalid text' }
  }
  if ((Read-SetupFactoryDataInteger -Bytes $Bytes -Offset ([ref]$Cursor) -Size 4) -ne 1) { throw 'The Setup Factory CHeadingFont schema is unsupported' }

  [pscustomobject][ordered]@{
    Offset                     = $Offset
    EndOffset                  = $Cursor
    SilentFlagOffset           = $SilentFlagOffset
    SupportsSilentInstallation = $SupportsSilentInstallation
    StartsInSilentMode         = $StartsInSilentMode
    CreateLog                  = $CreateLog
    LogFilename                = $LogFilename
    WriteMode                  = $WriteMode
    ActionDetailLevel          = $ActionDetailLevel
    VerifyArchive              = $VerifyArchive
    UserProfile                = $UserProfile
    ShowBackground             = $ShowBackground
    WindowStyle                = $WindowStyle
    WindowAppearance           = $WindowAppearance
    ImageFile                  = $ImageFile
    UseCustomIcon              = $UseCustomIcon
    CustomIcon                 = $CustomIcon
    HideTaskbarIcon            = $HideTaskbarIcon
    AlwaysOnTop                = $AlwaysOnTop
    Headline                   = $Headline
  }
}

function Get-SetupFactorySilentInstallationInfo {
  <#
  .SYNOPSIS
    Resolve whether an exact Setup Factory artifact enables its documented /S mode.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER MetadataRoute
    Generation-specific metadata route selected by the outer parser.
  .OUTPUTS
    A tri-state result. Setup Factory 3.1, 4, and 5 predate silent mode, Setup Factory 6 implements /S unconditionally, and later releases use the compiled CProjectData flags.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][string]$MetadataRoute
  )

  if ($MetadataRoute -in 'irdat-v3.1', 'irdat-v4', 'irdat-v5') {
    return [pscustomobject][ordered]@{
      IsResolved                 = $true
      SupportsSilentInstallation = $false
      StartsInSilentMode         = $false
      CandidateCount             = 0
      Evidence                   = [pscustomobject][ordered]@{
        MetadataRoute = $MetadataRoute
        Reason        = 'GenerationPredatesSilentMode'
        Source        = 'Setup Factory 6.0 builder help: What''s New in 6.0 identifies /S silent installations as a new feature'
      }
    }
  }

  if ($MetadataRoute -eq 'irdat-v6') {
    return [pscustomobject][ordered]@{
      IsResolved                 = $true
      SupportsSilentInstallation = $true
      # Version 6 always accepts /S, but its separate project default for starting silently is
      # not needed to establish the switch and has not been assigned an unproven byte offset.
      StartsInSilentMode         = $null
      CandidateCount             = 0
      Evidence                   = [pscustomobject][ordered]@{
        MetadataRoute = $MetadataRoute
        Reason        = 'GenerationImplementsSilentMode'
        Switch        = '/S'
        Source        = 'Setup Factory 6.0 builder help: Silent Mode (/S)'
      }
    }
  }

  if ($MetadataRoute -notin 'irdat-v7', 'irdat-v8-plus') {
    return [pscustomobject][ordered]@{
      IsResolved                 = $false
      SupportsSilentInstallation = $null
      StartsInSilentMode         = $null
      CandidateCount             = 0
      Evidence                   = [pscustomobject][ordered]@{ MetadataRoute = $MetadataRoute; Reason = 'UnsupportedMetadataRoute' }
    }
  }

  $Offsets = [Collections.Generic.HashSet[long]]::new()
  # The schema dword and CreateLog Boolean provide a cheap index. Full record validation below
  # supplies the actual evidence and rejects coincidental matches in scripts or payload data.
  foreach ($Pattern in [byte[][]]@([byte[]](1, 0, 0, 0, 0), [byte[]](1, 0, 0, 0, 1))) {
    foreach ($CandidateOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Maximum 65536)) { $null = $Offsets.Add($CandidateOffset) }
  }

  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($CandidateOffset in @($Offsets | Sort-Object)) {
    try {
      $Candidates.Add((Read-SetupFactoryProjectDataCandidate -Bytes $Bytes -Offset $CandidateOffset))
    } catch {
      # Candidate scanning intentionally rejects malformed schema prefixes. A parser diagnostic is
      # emitted only when the complete scan cannot identify one authoritative project record.
    }
  }

  if ($Candidates.Count -eq 1) {
    $Candidate = $Candidates[0]
    return [pscustomobject][ordered]@{
      IsResolved                 = $true
      SupportsSilentInstallation = $Candidate.SupportsSilentInstallation
      StartsInSilentMode         = $Candidate.StartsInSilentMode
      CandidateCount             = 1
      Evidence                   = $Candidate
    }
  }

  if ($Candidates.Count -gt 1) {
    $SupportValues = @($Candidates | ForEach-Object SupportsSilentInstallation | Sort-Object -Unique)
    $StartupValues = @($Candidates | ForEach-Object StartsInSilentMode | Sort-Object -Unique)
    # Duplicate serialized records occur in some repackaged media. Their physical owner is
    # ambiguous, but unanimous flag values still prove the same manifest behavior. Conflicting
    # records remain unresolved instead of selecting an arbitrary first or last candidate.
    if ($SupportValues.Count -eq 1 -and $StartupValues.Count -eq 1) {
      return [pscustomobject][ordered]@{
        IsResolved                 = $true
        SupportsSilentInstallation = [bool]$SupportValues[0]
        StartsInSilentMode         = [bool]$StartupValues[0]
        CandidateCount             = $Candidates.Count
        Evidence                   = [pscustomobject][ordered]@{
          MetadataRoute    = $MetadataRoute
          Reason           = 'ProjectDataConsensus'
          CandidateOffsets = [long[]]@($Candidates | ForEach-Object Offset)
          Candidates       = $Candidates.ToArray()
        }
      }
    }
  }

  $CandidateOffsets = [Collections.Generic.List[long]]::new()
  foreach ($Candidate in $Candidates) { $CandidateOffsets.Add([long]$Candidate.Offset) }
  [pscustomobject][ordered]@{
    IsResolved                 = $false
    SupportsSilentInstallation = $null
    StartsInSilentMode         = $null
    CandidateCount             = $Candidates.Count
    Evidence                   = [pscustomobject][ordered]@{ MetadataRoute = $MetadataRoute; Reason = $Candidates.Count -eq 0 ? 'ProjectDataNotFound' : 'ProjectDataConflict'; CandidateOffsets = $CandidateOffsets.ToArray() }
  }
}

function Read-SetupFactoryClassic4Metadata {
  <#
  .SYNOPSIS
    Decode the fixed Setup Factory 4 global settings and built-in uninstall objects.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes. The cursor starts at the first CGeneralData field.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $CursorValue = 0L
  $Cursor = [ref]$CursorValue
  # Setup Factory 4 writes embedded member objects without MFC class descriptors here. Walking
  # CGeneralData and CConclusionData is therefore the structural boundary for CUninInfo.
  $General = [pscustomobject][ordered]@{
    Offset              = 0L
    SetupTitle          = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
    WizardEnabled       = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.WizardEnabled'
    WizardStyle         = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
    LanguageFile        = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
    LanguageMode        = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 1
    FolderAnimation     = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
    GeneralFlags        = [bool[]]@(
      Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.Flag18'
      Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.Flag19'
      Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.Flag1A'
      Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.Flag1B'
    )
    EvaluationCount     = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 4
    EvaluationMessage   = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
    EvaluationEnabled   = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $Cursor -FieldName 'CGeneralData.EvaluationEnabled'
    EvaluationTimestamp = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 4
    EndOffset           = 0L
  }
  $General.EndOffset = [long]$Cursor.Value

  $GeneralTextValues = $General.SetupTitle, $General.WizardStyle, $General.LanguageFile, $General.FolderAnimation, $General.EvaluationMessage
  if (@($GeneralTextValues | Where-Object { -not (Test-SetupFactoryLegacyMetadataText -Value $_) }).Count) {
    throw 'The Setup Factory 4 global settings contain invalid text fields'
  }
  $ImageOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('CImageInfo')) -Maximum 16)
  if ($ImageOffsets.Count -ne 1) { throw 'The Setup Factory 4 global settings do not contain one unique CImageInfo table' }

  # Two source-backed Setup Factory 4 runtimes serialize CConclusionData differently. Try only
  # those exact layouts and require the following CUninInfo object to validate structurally.
  $ConclusionOffset = [long]$Cursor.Value
  $CandidateErrors = [Collections.Generic.List[string]]::new()
  foreach ($ConclusionLayout in 'Object24', 'Scalar32') {
    try {
      $CandidateCursorValue = $ConclusionOffset
      $CandidateCursor = [ref]$CandidateCursorValue
      if ($ConclusionLayout -eq 'Object24') {
        $Conclusion = [pscustomobject][ordered]@{
          Offset          = $ConclusionOffset
          Layout          = $ConclusionLayout
          ObservedFlag04  = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CConclusionData.Flag04'
          ObservedText08  = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
          ObservedText0C  = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
          ObservedFlag10  = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CConclusionData.Flag10'
          ObservedFlag11  = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CConclusionData.Flag11'
          ObservedText14  = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
          ObservedText18  = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
          ObservedFlag1C  = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CConclusionData.Flag1C'
          ObservedValue20 = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $CandidateCursor -Size 4
          EndOffset       = 0L
        }
      } else {
        $Conclusion = [pscustomobject][ordered]@{
          Offset          = $ConclusionOffset
          Layout          = $ConclusionLayout
          ObservedFlag04  = $null
          ObservedText08  = $null
          ObservedText0C  = $null
          ObservedFlag10  = $null
          ObservedFlag11  = $null
          ObservedText14  = $null
          ObservedText18  = $null
          ObservedFlag1C  = $null
          ObservedValue20 = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $CandidateCursor -Size 4
          EndOffset       = 0L
        }
      }
      $Conclusion.EndOffset = [long]$CandidateCursor.Value

      $UninstallOffset = [long]$CandidateCursor.Value
      $Uninstall = [pscustomobject][ordered]@{
        Offset                  = $UninstallOffset
        IncludeUninstall        = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CUninInfo.IncludeUninstall'
        ControlPanelDescription = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        UniqueRegistryKey       = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        ShortcutDescription     = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        RemoveDescription       = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        AdditionalText          = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        ShowWizard              = Read-SetupFactoryBooleanByte -Bytes $Bytes -Offset $CandidateCursor -FieldName 'CUninInfo.ShowWizard'
        WelcomeTitle            = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        WelcomeText             = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        CompletionTitle         = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        CompletionText          = Read-SetupFactoryDataString -Bytes $Bytes -Offset $CandidateCursor -Width Variable
        EndOffset               = 0L
      }
      $Uninstall.EndOffset = [long]$CandidateCursor.Value

      $CandidateTextValues = @(
        $Conclusion.ObservedText08, $Conclusion.ObservedText0C, $Conclusion.ObservedText14, $Conclusion.ObservedText18,
        $Uninstall.ControlPanelDescription, $Uninstall.UniqueRegistryKey, $Uninstall.ShortcutDescription,
        $Uninstall.RemoveDescription, $Uninstall.AdditionalText, $Uninstall.WelcomeTitle,
        $Uninstall.WelcomeText, $Uninstall.CompletionTitle, $Uninstall.CompletionText
      )
      if (@($CandidateTextValues | Where-Object { $null -ne $_ -and -not (Test-SetupFactoryLegacyMetadataText -Value $_) }).Count) {
        throw 'the conclusion or uninstall object contains invalid text fields'
      }
      if ($Uninstall.IncludeUninstall -and ([string]::IsNullOrWhiteSpace($Uninstall.ControlPanelDescription) -or [string]::IsNullOrWhiteSpace($Uninstall.UniqueRegistryKey))) {
        throw 'the enabled uninstaller has no Control Panel description or uninstall-key name'
      }
      if ($Uninstall.EndOffset -gt $ImageOffsets[0]) { throw 'the global objects do not terminate before the CImageInfo table' }
      break
    } catch {
      $CandidateErrors.Add("$ConclusionLayout`: $($_.Exception.Message)")
      $Conclusion = $null
      $Uninstall = $null
    }
  }
  if (-not $Uninstall) { throw "No supported Setup Factory 4 CConclusionData layout matched: $($CandidateErrors -join '; ')" }

  # CGeneralData has no package publisher or version fields. Keep the ARP display name separate
  # from package identity so callers do not infer either absent value from marketing text.
  $Product = [pscustomobject][ordered]@{
    Offset                 = 0L
    ProductName            = $null
    CompanyName            = $null
    ProductTagline         = $null
    ProductVersion         = $null
    Copyright              = $null
    InformationUrl         = $null
    DefaultInstallLocation = $null
    ShortcutFolder         = $null
    SetupTitle             = $General.SetupTitle
    EndOffset              = $General.EndOffset
  }
  return [pscustomobject][ordered]@{
    Variables       = @{}
    Product         = $Product
    Uninstall       = $Uninstall
    General         = $General
    Conclusion      = $Conclusion
    MetadataProfile = "Classic4-$($Conclusion.Layout)"
  }
}

function Read-SetupFactoryLegacyProductMetadata {
  <#
  .SYNOPSIS
    Decode the structurally framed Setup Factory 5/6 product-information block.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER MinimumOffset
    Lowest candidate offset. A validated CPasswordData class narrows this boundary when the optional password table exists.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MinimumOffset
  )

  $Candidates = [ordered]@{}
  $Ranges = [Collections.Generic.List[object]]::new()
  # Built media serializes the product block shortly before CImageInfo. Restrict the primary scan
  # to those neighborhoods, while retaining a bounded fallback for projects without image data.
  foreach ($ImageOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('CImageInfo')) -Maximum 16)) {
    if ($ImageOffset -le $MinimumOffset) { continue }
    $Ranges.Add([pscustomobject]@{ Start = [Math]::Max($MinimumOffset, $ImageOffset - 8192); End = $ImageOffset })
  }
  if (-not $Ranges.Count) { $Ranges.Add([pscustomobject]@{ Start = $MinimumOffset; End = $Bytes.LongLength }) }

  foreach ($Range in $Ranges) {
    for ($CandidateOffset = [long]$Range.Start; $CandidateOffset -lt [long]$Range.End - 16; $CandidateOffset++) {
      $FirstLength = $Bytes[$CandidateOffset]
      # The product object follows a terminated fixed-field region. Requiring its zero boundary
      # rejects offsets inside preceding UI strings that can otherwise form accidental length chains.
      if ($CandidateOffset -eq 0 -or $Bytes[$CandidateOffset - 1] -ne 0 -or $FirstLength -eq 0 -or $FirstLength -eq 0xFF -or $FirstLength -gt 200) { continue }
      $CandidateStart = $CandidateOffset
      $Cursor = [ref]$CandidateStart
      try {
        $Values = [Collections.Generic.List[string]]::new(8)
        for ($Index = 0; $Index -lt 8; $Index++) { $Values.Add((Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable)) }
        if ([long]$Cursor.Value + 3 -gt $Bytes.LongLength -or $Bytes[$Cursor.Value] -ne 0 -or $Bytes[$Cursor.Value + 1] -ne 3 -or $Bytes[$Cursor.Value + 2] -gt 1) { continue }
        $LogCursor = [ref]([long]$Cursor.Value + 3)
        $LogPath = Read-SetupFactoryDataString -Bytes $Bytes -Offset $LogCursor -Width Variable
        if ([long]$LogCursor.Value -gt [long]$Range.End) { continue }
        if (@($Values | Where-Object { -not (Test-SetupFactoryLegacyMetadataText $_) }).Count -or -not (Test-SetupFactoryLegacyMetadataText $LogPath)) { continue }
        if ([string]::IsNullOrWhiteSpace($Values[0]) -or $Values[0].IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) { continue }
        if ([string]::IsNullOrWhiteSpace($Values[6]) -or $Values[6] -notmatch '(?:%[^%]+%|[A-Za-z]:\\|\\)') { continue }

        $Candidates[[string]$CandidateOffset] = [pscustomobject][ordered]@{
          Offset                 = $CandidateOffset
          ProductName            = $Values[0]
          CompanyName            = $Values[1]
          ProductTagline         = $Values[2]
          ProductVersion         = $Values[3]
          Copyright              = $Values[4]
          InformationUrl         = $Values[5]
          DefaultInstallLocation = $Values[6]
          ShortcutFolder         = $Values[7]
          CreateInstallLog       = [bool]$Bytes[$Cursor.Value + 2]
          InstallLogPath         = $LogPath
          EndOffset              = [long]$LogCursor.Value
        }
      } catch {
        # Most byte offsets are not object boundaries. Reject malformed candidates and continue
        # until the fixed product trailer proves one complete block.
      }
    }
  }

  $Resolved = @($Candidates.Values)
  if ($Resolved.Count -ne 1) { throw "The Setup Factory legacy product block has $($Resolved.Count) structurally valid candidates; exactly one is required" }
  return $Resolved[0]
}

function Read-SetupFactoryLegacyUninstallMetadata {
  <#
  .SYNOPSIS
    Decode the Setup Factory 5/6 built-in uninstall and Control Panel settings.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER MinimumOffset
    Lowest candidate offset, narrowed to the CPasswordData class when that optional table exists.
  .PARAMETER MaximumOffset
    First byte of the validated product-information block. Uninstall settings must precede it.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MinimumOffset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$MaximumOffset
  )

  $Candidates = [ordered]@{}
  foreach ($Suffix in 'irunin.ini', 'irunin.dat') {
    foreach ($SuffixOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes($Suffix)) -Maximum 32)) {
      if ($SuffixOffset -le $MinimumOffset -or $SuffixOffset -ge $MaximumOffset) { continue }
      $SearchStart = [Math]::Max($MinimumOffset + 1, $SuffixOffset - 1024)
      for ($CandidateOffset = [long]$SearchStart; $CandidateOffset -lt $SuffixOffset; $CandidateOffset++) {
        $IncludeUninstall = $Bytes[$CandidateOffset - 1]
        if ($IncludeUninstall -gt 1) { continue }
        $CandidateStart = $CandidateOffset
        $Cursor = [ref]$CandidateStart
        try {
          $ControlPanelDescription = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
          $UniqueRegistryKey = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
          if ($Cursor.Value -ge $MaximumOffset) { continue }
          $CreateShortcut = $Bytes[$Cursor.Value]
          $Cursor.Value++
          $ShortcutDescription = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
          if ($Cursor.Value -ge $MaximumOffset) { continue }
          $UseExternalIcon = $Bytes[$Cursor.Value]
          $Cursor.Value++
          $ExternalIconPath = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
          $ConfigurationStart = [long]$Cursor.Value
          $ConfigurationFile = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Cursor -Width Variable
          if ($CreateShortcut -gt 1 -or $UseExternalIcon -gt 1) { continue }
          if ([string]::IsNullOrWhiteSpace($ControlPanelDescription) -or [string]::IsNullOrWhiteSpace($UniqueRegistryKey)) { continue }
          if ($ConfigurationFile -notmatch '(?i)irunin\.(?:ini|dat)$') { continue }
          if ($SuffixOffset -lt $ConfigurationStart -or $SuffixOffset -ge $Cursor.Value) { continue }
          $TextValues = @($ControlPanelDescription, $UniqueRegistryKey, $ShortcutDescription, $ExternalIconPath, $ConfigurationFile)
          if (@($TextValues | Where-Object { -not (Test-SetupFactoryLegacyMetadataText $_) }).Count) { continue }

          $Candidates[[string]$CandidateOffset] = [pscustomobject][ordered]@{
            Offset                  = $CandidateOffset - 1
            IncludeUninstall        = [bool]$IncludeUninstall
            ControlPanelDescription = $ControlPanelDescription
            UniqueRegistryKey       = $UniqueRegistryKey
            CreateShortcut          = [bool]$CreateShortcut
            ShortcutDescription     = $ShortcutDescription
            UseExternalIcon         = [bool]$UseExternalIcon
            ExternalIconPath        = $ExternalIconPath
            ConfigurationFile       = $ConfigurationFile
            EndOffset               = [long]$Cursor.Value
          }
        } catch {
          # Candidate offsets around irunin.ini commonly land inside strings or action records.
          # Only the complete ordered field sequence is accepted.
        }
      }
    }
  }

  $Resolved = @($Candidates.Values)
  if ($Resolved.Count -ne 1) { throw "The Setup Factory legacy uninstall block has $($Resolved.Count) structurally valid candidates; exactly one is required" }
  return $Resolved[0]
}

function Get-SetupFactoryLegacyMetadata {
  <#
  .SYNOPSIS
    Recover Setup Factory 5/6 product variables and built-in ARP configuration.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $PasswordMarkers = @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes('CPasswordData')) -Maximum 16)
  # CPasswordData precedes the global product settings in projects that configure a password, but
  # Setup Factory omits the class entirely otherwise. The product and uninstall framing remains
  # authoritative; zero is a safe fallback because both readers search bounded structural ranges.
  $MinimumOffset = if ($PasswordMarkers.Count) { [long]($PasswordMarkers | Measure-Object -Minimum).Minimum } else { 0L }
  $Product = Read-SetupFactoryLegacyProductMetadata -Bytes $Bytes -MinimumOffset $MinimumOffset
  $Uninstall = Read-SetupFactoryLegacyUninstallMetadata -Bytes $Bytes -MinimumOffset $MinimumOffset -MaximumOffset $Product.Offset

  $Variables = @{
    '%ProductName%'    = $Product.ProductName
    '%ProductVer%'     = $Product.ProductVersion
    '%CompanyName%'    = $Product.CompanyName
    '%ProductTagline%' = $Product.ProductTagline
    '%Copyright%'      = $Product.Copyright
    '%InfoURL%'        = $Product.InformationUrl
    '%AppDir%'         = $Product.DefaultInstallLocation
    '%AppFolder%'      = $Product.DefaultInstallLocation
    '%SCFolderTitle%'  = $Product.ShortcutFolder
    '%ProgramFiles%'   = '%ProgramFiles%'
  }
  return [pscustomobject][ordered]@{
    Variables = $Variables
    Product   = $Product
    Uninstall = $Uninstall
  }
}

function ConvertTo-SetupFactoryRegistryRoot {
  <#
  .SYNOPSIS
    Convert a legacy Setup Factory registry-root enum to a canonical hive name.
  .PARAMETER Value
    Builder-serialized root value.
  .PARAMETER Generation
    Legacy runtime generation that defines the serialized root enum. Setup Factory 4 omits HKCC,
    while Setup Factory 5 and 6 insert it between HKCR and HKCU.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][int]$Value,
    [Parameter(Mandatory)][ValidateSet('Classic4', 'Legacy5', 'Legacy6')][string]$Generation
  )

  if ($Generation -eq 'Classic4') {
    switch ($Value) {
      0 { return 'HKCR' }
      1 { return 'HKCU' }
      2 { return 'HKLM' }
      3 { return 'HKU' }
      default { return $null }
    }
  }
  switch ($Value) {
    0 { return 'HKCR' }
    1 { return 'HKCC' }
    2 { return 'HKCU' }
    3 { return 'HKLM' }
    4 { return 'HKU' }
    default { return $null }
  }
}

function ConvertTo-SetupFactoryRegistryValueType {
  <#
  .SYNOPSIS
    Convert a generation-specific Setup Factory registry-value enum to a Win32 value type.
  .PARAMETER Value
    Serialized registry-value type.
  .PARAMETER Generation
    Legacy project generation whose enum table defines Value.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][int]$Value,
    [Parameter(Mandatory)][ValidateSet('Classic4', 'Legacy5', 'Legacy6')][string]$Generation
  )

  if ($Generation -in 'Classic4', 'Legacy5') {
    switch ($Value) {
      0 { return 'REG_DWORD' }
      1 { return 'REG_SZ' }
      default { return $null }
    }
  }
  switch ($Value) {
    1 { return 'REG_SZ' }
    2 { return 'REG_EXPAND_SZ' }
    3 { return 'REG_BINARY' }
    4 { return 'REG_DWORD' }
    7 { return 'REG_MULTI_SZ' }
    default { return $null }
  }
}

function Read-SetupFactoryRegistryRecord4 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 4 CRegistryData object.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable byte offset positioned at the first CRegistryData field, after any MFC class tag.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset
  )

  $StartOffset = [long]$Offset.Value
  # The 4.0.0.1 runtime serializer writes the action and hive bytes first, followed by the key,
  # value type, value name, and value data. This differs from the later version 5 object layout.
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $RootCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TypeCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Name = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  if ($Action -notin 0, 1, 2) { throw "The Setup Factory 4 registry action $Action is invalid" }
  if ($RootCode -notin 0, 1, 2, 3) { throw "The Setup Factory 4 registry root $RootCode is invalid" }
  if (-not (Test-SetupFactoryLegacyMetadataText -Value $Key) -or -not (Test-SetupFactoryLegacyMetadataText -Value $Name) -or -not (Test-SetupFactoryLegacyMetadataText -Value $Value)) {
    throw 'The Setup Factory 4 registry record contains invalid text'
  }

  [pscustomobject][ordered]@{
    Offset         = $StartOffset
    EndOffset      = [long]$Offset.Value
    IsComplete     = $true
    Action         = $Action
    ActionName     = @('CreateKey', 'DeleteKey', 'SetValue')[$Action]
    RootCode       = $RootCode
    Root           = ConvertTo-SetupFactoryRegistryRoot -Value $RootCode -Generation Classic4
    Key            = $Key
    Name           = $Name
    TypeCode       = $TypeCode
    Type           = ConvertTo-SetupFactoryRegistryValueType -Value $TypeCode -Generation Classic4
    Value          = $Value
    ConditionCount = 0
    ConditionState = 'True'
    Phase          = 'Install'
  }
}

function Get-SetupFactoryRegistryCatalog4 {
  <#
  .SYNOPSIS
    Recover the Setup Factory 4 install-time CRegistryData list.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)

  $Marker = [Text.Encoding]::ASCII.GetBytes('CRegistryData')
  foreach ($MarkerOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 8)) {
    # CObList::Serialize writes [count][FFFF][schema][class-name length][class name] before the
    # first object. Empty lists have no class marker and therefore correctly resolve as absent.
    if ($MarkerOffset -lt 8 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 6) -ne 0xFFFF -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 4) -ne 1 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 2) -ne $Marker.Length) { continue }
    $Count = [int][BitConverter]::ToUInt16($Bytes, $MarkerOffset - 8)
    if ($Count -eq 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { continue }
    $Entries = [Collections.Generic.List[object]]::new($Count)
    $Cursor = [ref]([long]($MarkerOffset + $Marker.Length))
    $ClassReference = $null
    $ErrorMessage = $null
    for ($Index = 0; $Index -lt $Count; $Index++) {
      try {
        if ($Index -gt 0) {
          $Reference = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
          if (($Reference -band 0x8000) -eq 0) { throw 'The CRegistryData object reference is invalid' }
          if ($null -eq $ClassReference) { $ClassReference = $Reference }
          elseif ($Reference -ne $ClassReference) { throw 'The CRegistryData object reference changed inside the table' }
        }
        $Entries.Add((Read-SetupFactoryRegistryRecord4 -Bytes $Bytes -Offset $Cursor))
      } catch {
        $ErrorMessage = $_.Exception.Message
        break
      }
    }

    $RegistryWrites = @($Entries | Where-Object { $_.Action -eq 2 -and $_.Root -and $_.Type } | ForEach-Object {
        [pscustomobject][ordered]@{
          Root           = $_.Root
          Key            = $_.Key
          Name           = $_.Name
          Value          = $_.Value
          Type           = $_.Type
          ActionOffset   = $_.Offset
          ActionPhase    = $_.Phase
          ConditionState = $_.ConditionState
        }
      })
    return [pscustomobject][ordered]@{
      IsPresent       = $true
      IsComplete      = $Entries.Count -eq $Count -and -not $ErrorMessage
      Error           = $ErrorMessage
      DeclaredCount   = $Count
      Entries         = $Entries.ToArray()
      RegistryWrites  = $RegistryWrites
      UnresolvedCount = @($Entries | Where-Object { $_.Action -eq 2 -and (-not $_.Root -or -not $_.Type) }).Count + ($Count - $Entries.Count)
    }
  }

  return [pscustomobject][ordered]@{ IsPresent = $false; IsComplete = $true; Error = $null; DeclaredCount = 0; Entries = @(); RegistryWrites = @(); UnresolvedCount = 0 }
}

function Read-SetupFactoryConditionRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CConditionData advanced comparison.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable byte offset positioned at the first CConditionData field, after its MFC class tag.
  .PARAMETER Width
    CString length framing used by the owning Setup Factory table. Registry records use Variable; installed-file records use Small.
  .PARAMETER Type
    Optional MFC object declaration or reference tag associated with this condition.
  .PARAMETER ClassName
    Optional MFC runtime class name declared by the containing list.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [ValidateSet('Small', 'Variable')][string]$Width = 'Variable',
    [uint16]$Type = 0,
    [AllowNull()][string]$ClassName
  )

  $StartOffset = [long]$Offset.Value
  # The runtime evaluator consumes ValueA, ValueB, and Operator. The remaining members are
  # serialized by CConditionData but are not read by the comparison path, so retain their offsets
  # without assigning unsupported semantics.
  $ValueA = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width $Width
  $ValueB = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width $Width
  $Operator = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $ObservedInteger10 = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $ObservedInteger14 = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $ObservedText18 = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width $Width
  $ObservedText1C = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width $Width
  foreach ($Text in $ValueA, $ValueB, $ObservedText18, $ObservedText1C) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 condition contains invalid text' }
  }
  $OperatorName = ConvertFrom-SetupFactoryLegacyConditionOperator -Value $Operator
  $EndOffset = [long]$Offset.Value

  [pscustomobject][ordered]@{
    Type              = $Type
    ClassName         = $ClassName
    Offset            = $StartOffset
    EndOffset         = $EndOffset
    RecordLength      = $EndOffset - $StartOffset
    ValueA            = $ValueA
    ValueB            = $ValueB
    LeftOperand       = $ValueA
    RightOperand      = $ValueB
    Operator          = $Operator
    OperatorName      = $OperatorName
    IsSupported       = $null -ne $OperatorName
    Comparison        = 'CaseInsensitiveLexical'
    ObservedInteger10 = $ObservedInteger10
    ObservedInteger14 = $ObservedInteger14
    ObservedText18    = $ObservedText18
    ObservedText1C    = $ObservedText1C
    ReservedValues    = [uint32[]]@($ObservedInteger10, $ObservedInteger14)
    ReservedStrings   = [string[]]@($ObservedText18, $ObservedText1C)
    RawRecord         = [Convert]::ToHexString([byte[]]$Bytes[[int]$StartOffset..([int]$EndOffset - 1)])
  }
}

function Read-SetupFactoryConditionList5 {
  <#
  .SYNOPSIS
    Decode a counted MFC CObList of Setup Factory 5 CConditionData objects.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable byte offset positioned after the uint16 condition count.
  .PARAMETER Count
    Number of serialized CConditionData objects.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateRange(0, 65535)][int]$Count
  )

  if ($Count -eq 0) { return @() }
  if ($Count -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory 5 condition count exceeds the configured limit' }

  # MFC declares a runtime class only on its first use in the complete archive. A later list can
  # therefore begin with a high-bit class reference even for its first object. The owning Setup
  # Factory serializers require CConditionData here, so accept either framing while still
  # requiring every later object in the list to use one stable reference.
  $Tag = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $ClassName = 'CConditionData'
  $ClassReference = $null
  $FirstRecordType = [uint16]$Tag
  if ($Tag -eq 0xFFFF) {
    $Schema = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
    if ($Schema -ne 1) { throw "The Setup Factory 5 CConditionData schema $Schema is unsupported" }
    $ClassName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Big
    if ($ClassName -cne 'CConditionData') { throw "The Setup Factory 5 condition list declares unexpected class '$ClassName'" }
  } elseif (($Tag -band 0x8000) -ne 0) {
    $ClassReference = $Tag
  } else {
    throw 'The Setup Factory 5 condition-list class declaration or reference is invalid'
  }

  $Conditions = [Collections.Generic.List[object]]::new($Count)
  for ($Index = 0; $Index -lt $Count; $Index++) {
    $RecordType = $FirstRecordType
    if ($Index -gt 0) {
      $Reference = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
      if (($Reference -band 0x8000) -eq 0) { throw 'The Setup Factory 5 CConditionData object reference is invalid' }
      if ($null -eq $ClassReference) { $ClassReference = $Reference }
      elseif ($Reference -ne $ClassReference) { throw 'The Setup Factory 5 CConditionData object reference changed inside the list' }
      $RecordType = [uint16]$Reference
    }
    $Conditions.Add((Read-SetupFactoryConditionRecord5 -Bytes $Bytes -Offset $Offset -Type $RecordType -ClassName $ClassName))
  }
  return $Conditions.ToArray()
}

function Read-SetupFactoryRegistryRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CRegistryData object.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable byte offset positioned at the first CRegistryData field, after any MFC class tag. The function advances through the record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset
  )

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $RootCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Name = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TypeCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ExistingValueAction = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Separator = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Flags = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Reserved24 = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4
  $Reserved28 = Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4
  $Label = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable

  # CRegistryData embeds a CObList of advanced conditions after the common OS, package, and
  # language selectors. Decode the complete list even when its outcome depends on runtime state so
  # the cursor remains aligned for later registry records.
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ReservedIntegers = [long[]]@(
    (Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4),
    (Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4),
    (Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4),
    (Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  )
  $ReservedStrings = [string[]]@(
    (Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable),
    (Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable),
    (Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable),
    (Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable)
  )

  # The runtime treats -1 as every supported operating system, package 0 as no package filter,
  # and language None as no language filter. Advanced comparisons may reference session variables
  # or runtime state and therefore remain Unknown rather than being guessed here.
  $CommonConditionState = if ($Reserved24 -eq [uint32]::MaxValue -and $Reserved28 -eq 0 -and $Label -in '', 'None') { 'True' }
  elseif ($Reserved24 -eq 0) { 'False' }
  else { 'Unknown' }
  $ConditionState = if ($CommonConditionState -eq 'False') { 'False' }
  elseif ($ConditionCount -gt 0 -or $CommonConditionState -eq 'Unknown') { 'Unknown' }
  else { 'True' }

  if ($Action -notin 0, 1, 2, 3) { throw "The Setup Factory 5 registry action $Action is invalid" }
  if ($RootCode -notin 0, 1, 2, 3, 4) { throw "The Setup Factory 5 registry root $RootCode is invalid" }
  [pscustomobject][ordered]@{
    Offset              = $StartOffset
    EndOffset           = [long]$Offset.Value
    IsComplete          = $true
    Action              = $Action
    ActionName          = @('CreateKey', 'DeleteKey', 'SetValue', 'DeleteValue')[$Action]
    RootCode            = $RootCode
    Root                = ConvertTo-SetupFactoryRegistryRoot -Value $RootCode -Generation Legacy5
    Key                 = $Key
    Name                = $Name
    TypeCode            = $TypeCode
    Type                = ConvertTo-SetupFactoryRegistryValueType -Value $TypeCode -Generation Legacy5
    Value               = $Value
    ExistingValueAction = $ExistingValueAction
    Separator           = $Separator
    Flags               = $Flags
    Label               = $Label
    ConditionCount      = $ConditionCount
    Conditions          = $Conditions
    ConditionState      = $ConditionState
    OperatingSystemMask = $Reserved24
    PackageSelector     = $Reserved28
    LanguageSelector    = $Label
    Reserved24          = $Reserved24
    Reserved28          = $Reserved28
    ReservedIntegers    = $ReservedIntegers
    ReservedStrings     = $ReservedStrings
  }
}

function Get-SetupFactoryRegistryCatalog5 {
  <#
  .SYNOPSIS
    Recover the counted Setup Factory 5 CRegistryData table.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the built-in uninstall configuration. A CRegistryData table before this offset contains installation actions; a later table contains uninstall actions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$UninstallOffset
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes('CRegistryData')
  foreach ($MarkerOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 8)) {
    # MFC writes [list count][FFFF][schema=1][big-string length][class name] before the first object.
    if ($MarkerOffset -lt 8 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 6) -ne 0xFFFF -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 4) -ne 1 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 2) -ne $Marker.Length) { continue }
    $Count = [int][BitConverter]::ToUInt16($Bytes, $MarkerOffset - 8)
    if ($Count -gt $Script:SetupFactoryMaximumEntries) { continue }
    $Entries = [Collections.Generic.List[object]]::new($Count)
    $Cursor = [ref]([long]($MarkerOffset + $Marker.Length))
    $ClassReference = $null
    $ErrorMessage = $null
    for ($Index = 0; $Index -lt $Count; $Index++) {
      try {
        if ($Index -gt 0) {
          $Reference = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
          if (($Reference -band 0x8000) -eq 0) { throw 'The CRegistryData object reference is invalid' }
          if ($null -eq $ClassReference) { $ClassReference = $Reference }
          elseif ($Reference -ne $ClassReference) { throw 'The CRegistryData object reference changed inside the table' }
        }
        $Record = Read-SetupFactoryRegistryRecord5 -Bytes $Bytes -Offset $Cursor
        $Record | Add-Member -NotePropertyName Phase -NotePropertyValue ($MarkerOffset -lt $UninstallOffset ? 'Install' : 'Uninstall')
        $Entries.Add($Record)
      } catch {
        $ErrorMessage = $_.Exception.Message
        break
      }
    }

    # The exact class header, bounded count, and at least one decoded object distinguish a real
    # table from textual references to the class name elsewhere in project data.
    if ($Count -eq 0 -or $Entries.Count) {
      $RegistryWrites = @($Entries | Where-Object { $_.Phase -eq 'Install' -and $_.ConditionState -eq 'True' -and $_.Action -eq 2 -and $_.Root -and $_.Type } | ForEach-Object {
          [pscustomobject][ordered]@{
            Root           = $_.Root
            Key            = $_.Key
            Name           = $_.Name
            Value          = $_.Value
            Type           = $_.Type
            ActionOffset   = $_.Offset
            ActionPhase    = $_.Phase
            ConditionState = $_.ConditionState
          }
        })
      return [pscustomobject][ordered]@{
        IsPresent       = $true
        IsComplete      = $Entries.Count -eq $Count -and -not $ErrorMessage
        Error           = $ErrorMessage
        DeclaredCount   = $Count
        Entries         = $Entries.ToArray()
        RegistryWrites  = $RegistryWrites
        UnresolvedCount = @($Entries | Where-Object { $_.Phase -eq 'Install' -and $_.Action -eq 2 -and ($_.ConditionState -eq 'Unknown' -or -not $_.Root -or -not $_.Type) }).Count + ($Count - $Entries.Count)
      }
    }
  }

  return [pscustomobject][ordered]@{ IsPresent = $false; IsComplete = $true; Error = $null; DeclaredCount = 0; Entries = @(); RegistryWrites = @(); UnresolvedCount = 0 }
}

function Get-SetupFactoryLegacyConditionState5 {
  <#
  .SYNOPSIS
    Reduce Setup Factory 5 command selectors to a conservative three-valued state.
  .PARAMETER OperatingSystemMask
    Serialized 32-bit operating-system selector. All bits set means every supported system; zero rejects every system.
  .PARAMETER PackageSelector
    Serialized package selector. Zero means that the command is not tied to an optional package.
  .PARAMETER LanguageSelector
    Serialized language name. Empty and None apply to every runtime language.
  .PARAMETER Conditions
    Decoded CConditionData comparisons. Their operands can depend on runtime variables, so a non-empty list remains Unknown.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][uint32]$OperatingSystemMask,
    [Parameter(Mandatory)][uint32]$PackageSelector,
    [AllowEmptyString()][string]$LanguageSelector,
    [AllowEmptyCollection()][object[]]$Conditions = @()
  )

  if ($OperatingSystemMask -eq 0) { return 'False' }
  if ($OperatingSystemMask -ne [uint32]::MaxValue -or $PackageSelector -ne 0 -or $LanguageSelector -notin '', 'None' -or $Conditions.Count) { return 'Unknown' }
  return 'True'
}

function Get-SetupFactoryLegacyActionPhase5 {
  <#
  .SYNOPSIS
    Resolve a Setup Factory 5 command timing code or generated-uninstaller placement.
  .PARAMETER TableOffset
    Offset of the owning MFC table relative to decompressed irsetup.dat.
  .PARAMETER UninstallOffset
    Offset where the generated-uninstaller configuration begins.
  .PARAMETER TimingCode
    Source-backed Execute/File Operation timing enum used by installation commands.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][long]$TableOffset,
    [Parameter(Mandatory)][long]$UninstallOffset,
    [Parameter(Mandatory)][uint32]$TimingCode
  )

  if ($TableOffset -ge $UninstallOffset) { return 'Uninstall' }
  switch ($TimingCode) {
    0 { return 'Startup' }
    1 { return 'BeforeInstalling' }
    2 { return 'AfterInstalling' }
    3 { return 'Shutdown' }
    default { return 'Unknown' }
  }
}

function Get-SetupFactoryLegacyObjectTable {
  <#
  .SYNOPSIS
    Decode one declared MFC object table from legacy irsetup.dat data.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER ClassName
    Exact MFC runtime class name expected in the table declaration.
  .PARAMETER RecordReader
    Private record-reader function that accepts Bytes and a mutable Offset reference.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateSet('CExecuteData', 'CFileOpData', 'CINIData', 'CVarRegistry')][string]$ClassName,
    [Parameter(Mandatory)][ValidateSet('Read-SetupFactoryExecuteRecord5', 'Read-SetupFactoryFileOperationRecord5', 'Read-SetupFactoryIniRecord4', 'Read-SetupFactoryIniRecord5', 'Read-SetupFactoryRegistryVariableRecord5')][string]$RecordReader
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes($ClassName)
  foreach ($MarkerOffset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 16)) {
    # MFC CObList framing is [count:u16][new-class:FFFF][schema:u16][name-length:u16][name].
    # Matching the full declaration avoids treating diagnostic strings in project data as tables.
    if ($MarkerOffset -lt 8 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 6) -ne 0xFFFF -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 4) -ne 1 -or [BitConverter]::ToUInt16($Bytes, $MarkerOffset - 2) -ne $Marker.Length) { continue }
    $Count = [int][BitConverter]::ToUInt16($Bytes, $MarkerOffset - 8)
    if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { continue }

    $Entries = [Collections.Generic.List[object]]::new($Count)
    $Cursor = [ref]([long]($MarkerOffset + $Marker.Length))
    $ClassReference = $null
    $ErrorMessage = $null
    for ($Index = 0; $Index -lt $Count; $Index++) {
      try {
        $ObjectReference = [uint16]0xFFFF
        if ($Index -gt 0) {
          $ObjectReference = [uint16](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
          if (($ObjectReference -band 0x8000) -eq 0) { throw "The $ClassName object reference is invalid" }
          if ($null -eq $ClassReference) { $ClassReference = $ObjectReference }
          elseif ($ObjectReference -ne $ClassReference) { throw "The $ClassName object reference changed inside the table" }
        }
        $Record = & $RecordReader -Bytes $Bytes -Offset $Cursor
        $Record | Add-Member -NotePropertyName ObjectReference -NotePropertyValue $ObjectReference
        $Entries.Add($Record)
      } catch {
        $ErrorMessage = $_.Exception.Message
        break
      }
    }

    return [pscustomobject][ordered]@{
      IsPresent       = $true
      IsComplete      = $Entries.Count -eq $Count -and -not $ErrorMessage
      Error           = $ErrorMessage
      ClassName       = $ClassName
      MarkerOffset    = [long]$MarkerOffset
      EndOffset       = [long]$Cursor.Value
      DeclaredCount   = $Count
      ClassReference  = $ClassReference
      Entries         = $Entries.ToArray()
      UnresolvedCount = ($Count - $Entries.Count)
    }
  }

  return [pscustomobject][ordered]@{ IsPresent = $false; IsComplete = $true; Error = $null; ClassName = $ClassName; MarkerOffset = $null; EndOffset = $null; DeclaredCount = 0; ClassReference = $null; Entries = @(); UnresolvedCount = 0 }
}

function Read-SetupFactoryExecuteRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CExecuteData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Target = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Arguments = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $WorkingDirectory = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $WaitCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $RunModeCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $PromptForDiskCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DiskTitle = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TimingCode = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $ObservedFlag16 = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($Target, $Arguments, $WorkingDirectory, $DiskTitle, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 execute command contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Action               = $Action
    ActionName           = @('ExecuteProgram', 'OpenDocument', 'OpenUrl', 'PrintDocument', 'ExploreFolder', 'PlayMultimedia')[$Action]
    Category             = 'Execution'
    Target               = $Target
    Arguments            = $Arguments
    WorkingDirectory     = $WorkingDirectory
    WaitForProgram       = $WaitCode -in 0, 1 ? [bool]$WaitCode : $null
    WaitCode             = $WaitCode
    RunModeCode          = $RunModeCode
    RunMode              = @('Normal', 'Maximized', 'Minimized')[$RunModeCode]
    PromptForDisk        = $PromptForDiskCode -in 0, 1 ? [bool]$PromptForDiskCode : $null
    PromptForDiskCode    = $PromptForDiskCode
    DiskTitle            = $DiskTitle
    TimingCode           = $TimingCode
    ObservedFlag16       = $ObservedFlag16
    OperatingSystemMask  = $OperatingSystemMask
    PackageSelector      = $PackageSelector
    LanguageSelector     = $LanguageSelector
    ConditionCount       = $ConditionCount
    Conditions           = $Conditions
    ConditionState       = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Read-SetupFactoryFileOperationRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CFileOpData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Source = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Destination = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConfirmCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $SuppressErrorsCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $PromptForDiskCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DiskTitle = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $TimingCode = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($Source, $Destination, $DiskTitle, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 file operation contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Action               = $Action
    ActionName           = @('Copy', 'Delete', 'Move', 'Rename', 'MakeDirectory', 'RemoveDirectory')[$Action]
    Category             = 'FileSystem'
    Source               = $Source
    Destination          = $Destination
    ConfirmWithUser      = $ConfirmCode -in 0, 1 ? [bool]$ConfirmCode : $null
    ConfirmCode          = $ConfirmCode
    SuppressErrors       = $SuppressErrorsCode -in 0, 1 ? [bool]$SuppressErrorsCode : $null
    SuppressErrorsCode   = $SuppressErrorsCode
    PromptForDisk        = $PromptForDiskCode -in 0, 1 ? [bool]$PromptForDiskCode : $null
    PromptForDiskCode    = $PromptForDiskCode
    DiskTitle            = $DiskTitle
    TimingCode           = $TimingCode
    OperatingSystemMask  = $OperatingSystemMask
    PackageSelector      = $PackageSelector
    LanguageSelector     = $LanguageSelector
    ConditionCount       = $ConditionCount
    Conditions           = $Conditions
    ConditionState       = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Read-SetupFactoryIniRecord4 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 4 CINIData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $FileName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Section = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $OperatingSystemMask = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  foreach ($Text in $FileName, $Section, $Key, $Value, $LanguageSelector) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 4 INI command contains invalid text' }
  }
  $ConditionState = if ($OperatingSystemMask -eq 0) { 'False' } elseif ($OperatingSystemMask -eq 0x1F -and $LanguageSelector -in '', 'None') { 'True' } else { 'Unknown' }

  [pscustomobject][ordered]@{
    Offset                = $StartOffset
    EndOffset             = [long]$Offset.Value
    Action                = $Action
    ActionName            = $Action -eq 1 ? 'SetValue' : $null
    Category              = 'Ini'
    FileName              = $FileName
    Section               = $Section
    Key                   = $Key
    Value                 = $Value
    OperatingSystemMask   = $OperatingSystemMask
    OperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask $OperatingSystemMask
    LanguageSelector      = $LanguageSelector
    ConditionState        = $ConditionState
  }
}

function Read-SetupFactoryIniRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CINIData command.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $Action = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $FileName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Section = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Value = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ExistingValueAction = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Separator = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $Flags = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $OperatingSystemMask = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $PackageSelector = [uint32](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  $LanguageSelector = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ConditionCount = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
  $Conditions = @(Read-SetupFactoryConditionList5 -Bytes $Bytes -Offset $Offset -Count $ConditionCount)
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($FileName, $Section, $Key, $Value, $Separator, $LanguageSelector) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 INI command contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset                  = $StartOffset
    EndOffset               = [long]$Offset.Value
    Action                  = $Action
    ActionName              = @('SetValue', 'DeleteKey', 'DeleteSection')[$Action]
    Category                = 'Ini'
    FileName                = $FileName
    Section                 = $Section
    Key                     = $Key
    Value                   = $Value
    ExistingValueAction     = $ExistingValueAction
    ExistingValueActionName = @('Overwrite', 'DoNotOverwrite', 'Prepend', 'PrependIfMissing', 'Append', 'AppendIfMissing', 'Increment', 'Decrement')[$ExistingValueAction]
    Separator               = $Separator
    Flags                   = $Flags
    OperatingSystemMask     = $OperatingSystemMask
    PackageSelector         = $PackageSelector
    LanguageSelector        = $LanguageSelector
    ConditionCount          = $ConditionCount
    Conditions              = $Conditions
    ConditionState          = Get-SetupFactoryLegacyConditionState5 -OperatingSystemMask $OperatingSystemMask -PackageSelector $PackageSelector -LanguageSelector $LanguageSelector -Conditions $Conditions
    ObservedPolicyValues    = $ObservedIntegers
    ObservedPolicyText      = $ObservedStrings
  }
}

function Read-SetupFactoryRegistryVariableRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CVarRegistry variable source.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned after the owning MFC class tag or object reference.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $StartOffset = [long]$Offset.Value
  $VariableName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $RootCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $Key = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ValueName = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $UseKeyExistenceCode = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 1)
  $DefaultValue = Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable
  $ObservedIntegers = [uint32[]](1..4 | ForEach-Object { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 })
  $ObservedStrings = [string[]](1..4 | ForEach-Object { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable })
  foreach ($Text in @($VariableName, $Key, $ValueName, $DefaultValue) + $ObservedStrings) {
    if (-not (Test-SetupFactoryLegacyMetadataText -Value $Text)) { throw 'The Setup Factory 5 registry variable contains invalid text' }
  }

  [pscustomobject][ordered]@{
    Offset               = $StartOffset
    EndOffset            = [long]$Offset.Value
    Category             = 'VariableRead'
    VariableName         = $VariableName
    RootCode             = $RootCode
    Root                 = ConvertTo-SetupFactoryRegistryRoot -Value $RootCode -Generation Legacy5
    Key                  = $Key
    ValueName            = $ValueName
    UseKeyExistence      = $UseKeyExistenceCode -in 0, 1 ? [bool]$UseKeyExistenceCode : $null
    UseKeyExistenceCode  = $UseKeyExistenceCode
    DefaultValue         = $DefaultValue
    ObservedPolicyValues = $ObservedIntegers
    ObservedPolicyText   = $ObservedStrings
  }
}

function Get-SetupFactoryActionCatalog4 {
  <#
  .SYNOPSIS
    Compose Setup Factory 4 registry and INI command evidence.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the generated-uninstaller configuration.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][long]$UninstallOffset)

  $Registry = Get-SetupFactoryRegistryCatalog4 -Bytes $Bytes
  $Ini = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CINIData -RecordReader Read-SetupFactoryIniRecord4
  foreach ($Entry in $Ini.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue ($Ini.MarkerOffset -ge $UninstallOffset ? 'Uninstall' : 'Install') }
  $UnknownActions = @($Ini.Entries | Where-Object { -not $_.ActionName })
  $Errors = @($Registry.Error, $Ini.Error) | Where-Object { $_ }

  [pscustomobject][ordered]@{
    IsPresent                  = $Registry.IsPresent -or $Ini.IsPresent
    IsComplete                 = $Registry.IsComplete -and $Ini.IsComplete
    Error                      = $Errors -join '; '
    DeclaredCount              = $Registry.DeclaredCount + $Ini.DeclaredCount
    Entries                    = [object[]]@($Registry.Entries) + [object[]]@($Ini.Entries)
    RegistryWrites             = $Registry.RegistryWrites
    RegistryCatalog            = $Registry
    IniCatalog                 = $Ini
    VariableAssignments        = @()
    ExecutionActions           = @()
    FileSystemActions          = @()
    IniActions                 = $Ini.Entries
    VariableReads              = @()
    UserInteractionActions     = @()
    InstallabilityActions      = @()
    ShortcutActions            = @()
    ServiceActions             = @()
    RebootActions              = @()
    ExternalCodeActions        = @()
    UnknownActions             = $UnknownActions
    UnresolvedCount            = $Registry.UnresolvedCount
    UnresolvedActionCount      = $Ini.UnresolvedCount + $UnknownActions.Count
    UnresolvedControlFlowCount = 0
  }
}

function Get-SetupFactoryActionCatalog5 {
  <#
  .SYNOPSIS
    Compose Setup Factory 5 registry, execute, file-operation, INI, and registry-variable evidence.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the generated-uninstaller configuration.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][long]$UninstallOffset)

  $Registry = Get-SetupFactoryRegistryCatalog5 -Bytes $Bytes -UninstallOffset $UninstallOffset
  $Execute = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CExecuteData -RecordReader Read-SetupFactoryExecuteRecord5
  $FileOperation = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CFileOpData -RecordReader Read-SetupFactoryFileOperationRecord5
  $Ini = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CINIData -RecordReader Read-SetupFactoryIniRecord5
  $RegistryVariable = Get-SetupFactoryLegacyObjectTable -Bytes $Bytes -ClassName CVarRegistry -RecordReader Read-SetupFactoryRegistryVariableRecord5

  foreach ($Entry in $Execute.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue (Get-SetupFactoryLegacyActionPhase5 -TableOffset $Execute.MarkerOffset -UninstallOffset $UninstallOffset -TimingCode $Entry.TimingCode) }
  foreach ($Entry in $FileOperation.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue (Get-SetupFactoryLegacyActionPhase5 -TableOffset $FileOperation.MarkerOffset -UninstallOffset $UninstallOffset -TimingCode $Entry.TimingCode) }
  foreach ($Entry in $Ini.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue ($Ini.MarkerOffset -ge $UninstallOffset ? 'Uninstall' : 'Install') }
  foreach ($Entry in $RegistryVariable.Entries) { $Entry | Add-Member -NotePropertyName Phase -NotePropertyValue 'VariableResolution' }

  $Tables = @($Registry, $Execute, $FileOperation, $Ini, $RegistryVariable)
  $AllEntries = [object[]]@($Registry.Entries) + [object[]]@($Execute.Entries) + [object[]]@($FileOperation.Entries) + [object[]]@($Ini.Entries) + [object[]]@($RegistryVariable.Entries)
  $UnknownActions = @($Execute.Entries + $FileOperation.Entries + $Ini.Entries | Where-Object { $_.PSObject.Properties['ActionName'] -and -not $_.ActionName })
  $UserInteractionActions = @($Execute.Entries + $FileOperation.Entries | Where-Object { $_.PromptForDisk -eq $true -or ($_.PSObject.Properties['ConfirmWithUser'] -and $_.ConfirmWithUser -eq $true) })
  $Errors = @($Tables.Error | Where-Object { $_ })

  [pscustomobject][ordered]@{
    IsPresent                  = @($Tables | Where-Object IsPresent).Count -gt 0
    IsComplete                 = @($Tables | Where-Object { -not $_.IsComplete }).Count -eq 0
    Error                      = $Errors -join '; '
    DeclaredCount              = ($Tables.DeclaredCount | Measure-Object -Sum).Sum
    Entries                    = $AllEntries
    RegistryWrites             = $Registry.RegistryWrites
    RegistryCatalog            = $Registry
    ExecuteCatalog             = $Execute
    FileOperationCatalog       = $FileOperation
    IniCatalog                 = $Ini
    RegistryVariableCatalog    = $RegistryVariable
    VariableAssignments        = @()
    ExecutionActions           = $Execute.Entries
    FileSystemActions          = $FileOperation.Entries
    IniActions                 = $Ini.Entries
    VariableReads              = $RegistryVariable.Entries
    UserInteractionActions     = $UserInteractionActions
    InstallabilityActions      = $UserInteractionActions
    ShortcutActions            = @()
    ServiceActions             = @()
    RebootActions              = @()
    ExternalCodeActions        = @()
    UnknownActions             = $UnknownActions
    UnresolvedCount            = $Registry.UnresolvedCount
    UnresolvedActionCount      = ($Tables.UnresolvedCount | Measure-Object -Sum).Sum + $UnknownActions.Count
    UnresolvedControlFlowCount = 0
  }
}

function Get-SetupFactoryActionDescriptor6 {
  <#
  .SYNOPSIS
    Identify one Setup Factory 6 action ID using the builder runtime's action vocabulary.
  .PARAMETER ActionId
    Numeric CAction identifier stored in member I04.
  .OUTPUTS
    Action name, broad behavior category, and projection status. Unknown IDs remain explicit instead of receiving guessed semantics.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][ValidateRange(0, 1024)][int]$ActionId)

  $Name = $Script:SetupFactoryActionNames6[$ActionId]
  $Category = switch ($ActionId) {
    { $_ -in 0, 1, 2, 19, 24, 26, 55 } { 'Network'; break }
    { $_ -in 3, 4 } { 'Execution'; break }
    { $_ -in 5, 7, 8, 9, 10, 11, 18, 23, 35, 36, 37, 39, 42, 43, 44, 45, 46, 50, 51, 52, 53, 54, 56 } { 'FileSystem'; break }
    { $_ -in 6 } { 'Process'; break }
    { $_ -in 12, 17, 21 } { 'Registry'; break }
    { $_ -in 13, 14, 29, 30, 31, 32, 33, 34, 38, 70, 71, 72, 73, 78, 80 } { 'Data'; break }
    { $_ -in 20, 28 } { 'UserInteraction'; break }
    { $_ -in 22, 100, 101, 102, 103, 104, 105 } { 'ControlFlow'; break }
    { $_ -in 57, 58, 59, 60, 61, 62, 63 } { 'Service'; break }
    { $_ -in 74, 75, 76 } { 'Reboot'; break }
    { $_ -in 77 } { 'ExternalCode'; break }
    { $_ -in 79, 200, 201 } { 'Informational'; break }
    default { 'Unknown' }
  }
  $ProjectionStatus = if ($ActionId -in 3, 4, 12, 14, 17, 28, 50, 74, 75, 76, 77, 100, 102, 104, 105, 200) { 'Decoded' }
  elseif ($Name) { 'Catalogued' }
  else { 'Unknown' }

  [pscustomobject][ordered]@{
    Name             = $Name
    Category         = $Category
    ProjectionStatus = $ProjectionStatus
  }
}

function Get-SetupFactoryActionDetails6 {
  <#
  .SYNOPSIS
    Project source-backed CAction members into named operands for selected Setup Factory 6 actions.
  .PARAMETER ActionId
    Numeric action identifier.
  .PARAMETER Fields
    Complete generic CAction member map decoded by Read-SetupFactoryActionRecord6.
  .OUTPUTS
    A named operand object for actions whose member meanings are established by the 6.0 builder runtime, or null when only action identity is known.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateRange(0, 1024)][int]$ActionId,
    [Parameter(Mandatory)][pscustomobject]$Fields
  )

  $Values = switch ($ActionId) {
    3 { [ordered]@{ FilePath = [string]$Fields.S0C; Arguments = [string]$Fields.S2C; WorkingDirectory = [string]$Fields.S30; RunMode = [int]$Fields.I38; WaitForReturn = [bool]$Fields.I34 }; break }
    4 { [ordered]@{ FilePath = [string]$Fields.S0C; Verb = [string]$Fields.S3C; WorkingDirectory = [string]$Fields.S30; RunMode = [int]$Fields.I38 }; break }
    12 { [ordered]@{ VariableName = [string]$Fields.S60; DefaultValue = [string]$Fields.S64; Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Fields.I78) -Generation Legacy6; SubKey = [string]$Fields.S74; ValueName = [string]$Fields.S68; TrueIfExists = [bool]$Fields.I6C; ExpandEnvironmentStrings = [bool]$Fields.I98 }; break }
    14 { [ordered]@{ VariableName = [string]$Fields.S60; Value = [string]$Fields.S58; EvaluateAsExpression = [bool]$Fields.I6C }; break }
    17 {
      $OperationId = [int]$Fields.I38
      [ordered]@{ Operation = $OperationId -in 0..3 ? @('CreateKey', 'DeleteKey', 'SetValue', 'DeleteValue')[$OperationId] : $null; OperationId = $OperationId; Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Fields.I78) -Generation Legacy6; SubKey = [string]$Fields.S74; ValueName = [string]$Fields.S58; Value = [string]$Fields.S68; Type = ConvertTo-SetupFactoryRegistryValueType -Value ([int]$Fields.I90) -Generation Legacy6 }
      break
    }
    28 { [ordered]@{ Title = [string]$Fields.S64; Message = [string]$Fields.S68; ResultVariable = [string]$Fields.S60; YesValue = [string]$Fields.SA0; NoValue = [string]$Fields.SA4 }; break }
    50 { [ordered]@{ Folder = [string]$Fields.S58; Description = [string]$Fields.S68; TargetPath = [string]$Fields.S0C; Arguments = [string]$Fields.S2C; WorkingDirectory = [string]$Fields.S30; IconIndex = [int]$Fields.I98; ExternalIconPath = [string]$Fields.SA0; RunMode = [int]$Fields.I38 }; break }
    74 { [ordered]@{ SourcePath = [string]$Fields.S58; DestinationPath = [string]$Fields.S5C }; break }
    75 { [ordered]@{ FilePath = [string]$Fields.S58 }; break }
    76 { [ordered]@{ FilePath = [string]$Fields.S58; Arguments = [string]$Fields.S2C }; break }
    77 { [ordered]@{ DllPath = [string]$Fields.S0C; FunctionName = [string]$Fields.S08; Arguments = [string]$Fields.S2C; ReturnType = [int]$Fields.I38 }; break }
    100 { [ordered]@{ Expression = [string]$Fields.S54 }; break }
    102 { [ordered]@{ Expression = [string]$Fields.S54 }; break }
    104 { [ordered]@{ TargetLabel = [string]$Fields.S5C }; break }
    105 { [ordered]@{ Label = [string]$Fields.S5C }; break }
    200 { [ordered]@{ Text = [string]$Fields.S68 }; break }
    default { $null }
  }
  if ($null -ne $Values) { [pscustomobject]$Values }
}

function Resolve-SetupFactoryActionCondition6 {
  <#
  .SYNOPSIS
    Resolve the Boolean subset of a Setup Factory 6 action expression.
  .PARAMETER Expression
    CAction condition text using Setup Factory variables and textual or symbolic Boolean operators.
  .PARAMETER IdentifierState
    Known three-valued states accumulated from earlier literal Boolean assignments in the same uncertainties-free action path.
  .OUTPUTS
    The shared Boolean-evaluator result augmented with the original and normalized expressions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyString()][string]$Expression,
    [Parameter(Mandatory)][Collections.IDictionary]$IdentifierState
  )

  # The Setup Factory editor serializes AND/OR/NOT and wraps built-in variables in percent signs.
  # Normalize only that Boolean surface syntax; comparisons, arithmetic, functions, and quoted
  # values intentionally remain unsupported and resolve to Unknown.
  $NormalizedExpression = $Expression -replace '(?i)\bAND\b', '&&' -replace '(?i)\bOR\b', '||' -replace '(?i)\bNOT\b', '!'
  $NormalizedStates = [ordered]@{}
  foreach ($Match in [regex]::Matches($NormalizedExpression, '%(?<Name>[A-Za-z_][A-Za-z0-9_]*)%')) {
    $OriginalName = $Match.Value
    $NormalizedName = "SF_$($Match.Groups['Name'].Value)"
    $NormalizedExpression = $NormalizedExpression.Replace($OriginalName, $NormalizedName)
    foreach ($Key in $IdentifierState.Keys) {
      if ([string]$Key -ieq $OriginalName) { $NormalizedStates[$NormalizedName] = $IdentifierState[$Key]; break }
    }
  }
  foreach ($Key in $IdentifierState.Keys) {
    if ([string]$Key -notmatch '^%.*%$') { $NormalizedStates[[string]$Key] = $IdentifierState[$Key] }
  }

  $Result = Resolve-InstallerBooleanExpression -Expression $NormalizedExpression -IdentifierState $NormalizedStates
  $Result | Add-Member -NotePropertyName Expression -NotePropertyValue $Expression
  $Result | Add-Member -NotePropertyName NormalizedExpression -NotePropertyValue $NormalizedExpression
  return $Result
}

function Read-SetupFactoryActionRecord6 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 6 CAction object using the runtime serializer layout.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable offset positioned at the CAction schema field, after its MFC class declaration or reference tag.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset
  )

  $StartOffset = [long]$Offset.Value
  $SchemaVersion = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4)
  if ($SchemaVersion -ne 1) { throw "The Setup Factory 6 CAction schema $SchemaVersion is unsupported" }
  $Layout = @(
    @('I04', 'Integer'), @('S08', 'String'), @('S0C', 'String'), @('S10', 'String'), @('S14', 'String'), @('S18', 'String'),
    @('I1C', 'Integer'), @('I20', 'Integer'), @('I24', 'Integer'), @('I28', 'Integer'), @('S2C', 'String'), @('S30', 'String'),
    @('I34', 'Integer'), @('I38', 'Integer'), @('S3C', 'String'), @('I40', 'Integer'), @('S44', 'String'), @('I48', 'Integer'),
    @('I4C', 'Integer'), @('I50', 'Integer'), @('S54', 'String'), @('S58', 'String'), @('S5C', 'String'), @('S60', 'String'),
    @('S64', 'String'), @('S68', 'String'), @('I6C', 'Integer'), @('S70', 'String'), @('S74', 'String'), @('I78', 'Integer'),
    @('I8C', 'Integer'), @('S7C', 'String'), @('S80', 'String'), @('S84', 'String'), @('S88', 'String'), @('IB0', 'Integer'),
    @('SB4', 'String'), @('IB8', 'Integer'), @('SBC', 'String'), @('I90', 'Integer'), @('I94', 'Integer'), @('I98', 'Integer'),
    @('I9C', 'Integer'), @('SA0', 'String'), @('SA4', 'String'), @('SA8', 'String'), @('SAC', 'String')
  )
  $Fields = [ordered]@{}
  foreach ($Field in $Layout) {
    $Fields[$Field[0]] = if ($Field[1] -eq 'Integer') { Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 4 } else { Read-SetupFactoryDataString -Bytes $Bytes -Offset $Offset -Width Variable }
  }
  $ActionId = [int]$Fields.I04
  if ($ActionId -lt 0 -or $ActionId -gt 1024) { throw "The Setup Factory 6 action ID $ActionId is outside the supported structural range" }
  $Descriptor = Get-SetupFactoryActionDescriptor6 -ActionId $ActionId
  $FieldObject = [pscustomobject]$Fields
  [pscustomobject][ordered]@{
    Offset           = $StartOffset
    EndOffset        = [long]$Offset.Value
    Schema           = $SchemaVersion
    ActionId         = $ActionId
    ActionName       = $Descriptor.Name
    Category         = $Descriptor.Category
    ProjectionStatus = $Descriptor.ProjectionStatus
    Details          = Get-SetupFactoryActionDetails6 -ActionId $ActionId -Fields $FieldObject
    Fields           = $FieldObject
  }
}

function Get-SetupFactoryActionCatalog6 {
  <#
  .SYNOPSIS
    Recover counted Setup Factory 6 CAction lists and deterministic install-time registry writes.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER UninstallOffset
    Start of the built-in uninstall configuration. Action lists after this boundary belong to the generated uninstaller.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$UninstallOffset
  )

  $Marker = [Text.Encoding]::ASCII.GetBytes('CAction')
  $MarkerOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Marker -Maximum 8)
  $ClassMarker = $MarkerOffsets | Where-Object { $_ -ge 8 -and [BitConverter]::ToUInt16($Bytes, $_ - 6) -eq 0xFFFF -and [BitConverter]::ToUInt16($Bytes, $_ - 4) -eq 1 -and [BitConverter]::ToUInt16($Bytes, $_ - 2) -eq $Marker.Length } | Select-Object -First 1
  if ($null -eq $ClassMarker) {
    return [pscustomobject][ordered]@{
      IsPresent = $false; IsComplete = $true; Error = $null; Groups = @(); Entries = @(); RegistryWrites = @(); VariableAssignments = @(); ExecutionActions = @()
      UserInteractionActions = @(); InstallabilityActions = @(); ShortcutActions = @(); ServiceActions = @(); RebootActions = @(); ExternalCodeActions = @()
      UnknownActions = @(); UnresolvedCount = 0; UnresolvedControlFlowCount = 0
    }
  }

  $Groups = [Collections.Generic.List[object]]::new()
  # Copy the caller-provided boundary into the list-reader closure explicitly. Besides making the
  # ownership clear, this keeps static analysis from treating the captured parameter as unused.
  $UninstallBoundary = $UninstallOffset
  $ReadGroup = {
    param ([long]$ObjectPrefixOffset, [int]$Count, [bool]$HasClassDeclaration, [int]$Ordinal)
    if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { throw "The Setup Factory 6 action-list count $Count is invalid" }
    $Records = [Collections.Generic.List[object]]::new($Count)
    $Cursor = if ($HasClassDeclaration) { [ref]([long]($ClassMarker + $Marker.Length)) } else { [ref]([long]($ObjectPrefixOffset + 2)) }
    $Reference = $HasClassDeclaration ? $null : [int][BitConverter]::ToUInt16($Bytes, [int]$ObjectPrefixOffset)
    if ($null -ne $Reference -and ($Reference -band 0x8000) -eq 0) { throw 'The Setup Factory 6 CAction class reference is invalid' }
    for ($Index = 0; $Index -lt $Count; $Index++) {
      if ($Index -gt 0) {
        $CurrentReference = [int](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Cursor -Size 2)
        if ($null -eq $Reference) { $Reference = $CurrentReference }
        if (($CurrentReference -band 0x8000) -eq 0 -or $CurrentReference -ne $Reference) { throw 'The Setup Factory 6 CAction reference changed inside a counted list' }
      }
      $Records.Add((Read-SetupFactoryActionRecord6 -Bytes $Bytes -Offset $Cursor))
    }
    $Phase = if ($ObjectPrefixOffset -ge $UninstallBoundary) { 'Uninstall' } else {
      @('Startup', 'BeforeInstalling', 'AfterInstalling', 'Shutdown')[[Math]::Min($Ordinal, 3)]
    }
    foreach ($Record in $Records) { $Record | Add-Member -NotePropertyName Phase -NotePropertyValue $Phase }
    return [pscustomobject][ordered]@{ Offset = $ObjectPrefixOffset; EndOffset = [long]$Cursor.Value; Count = $Count; Phase = $Phase; ClassReference = $Reference; Entries = $Records.ToArray() }
  }

  $ErrorMessage = $null
  try {
    $FirstCount = [int][BitConverter]::ToUInt16($Bytes, $ClassMarker - 8)
    $Groups.Add((& $ReadGroup -ObjectPrefixOffset ($ClassMarker - 6) -Count $FirstCount -HasClassDeclaration $true -Ordinal 0))

    # Later lists start with [count:u16][class-reference:u16]. Scan only for complete counted lists;
    # internal object references cannot pass the count/end-boundary checks for their enclosing list.
    $SearchOffset = [long]$Groups[0].EndOffset
    while ($SearchOffset + 8 -le $Bytes.LongLength) {
      $Accepted = $false
      for ($Prefix = $SearchOffset + 2; $Prefix + 8 -le $Bytes.LongLength; $Prefix++) {
        $Reference = [int][BitConverter]::ToUInt16($Bytes, [int]$Prefix)
        if (($Reference -band 0x8000) -eq 0 -or [BitConverter]::ToInt32($Bytes, [int]$Prefix + 2) -ne 1) { continue }
        $Count = [int][BitConverter]::ToUInt16($Bytes, [int]$Prefix - 2)
        if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { continue }
        try {
          $Group = & $ReadGroup -ObjectPrefixOffset $Prefix -Count $Count -HasClassDeclaration $false -Ordinal $Groups.Count
          # A complete list must stop before another object of the same MFC class; otherwise the
          # preceding bytes were an accidental count inside an existing list.
          if ($Group.EndOffset + 2 -le $Bytes.LongLength -and [BitConverter]::ToUInt16($Bytes, [int]$Group.EndOffset) -eq $Reference) { continue }
          $Groups.Add($Group)
          $SearchOffset = $Group.EndOffset
          $Accepted = $true
          break
        } catch {
          continue
        }
      }
      if (-not $Accepted) { break }
    }
  } catch {
    $ErrorMessage = $_.Exception.Message
  }

  $AllEntries = [Collections.Generic.List[object]]::new()
  foreach ($Group in $Groups) { $AllEntries.AddRange([object[]]$Group.Entries) }
  $RegistryWrites = [Collections.Generic.List[object]]::new()
  $VariableAssignments = [Collections.Generic.List[object]]::new()
  $ExecutionActions = [Collections.Generic.List[object]]::new()
  $UserInteractionActions = [Collections.Generic.List[object]]::new()
  $InstallabilityActions = [Collections.Generic.List[object]]::new()
  $ShortcutActions = [Collections.Generic.List[object]]::new()
  $ServiceActions = [Collections.Generic.List[object]]::new()
  $RebootActions = [Collections.Generic.List[object]]::new()
  $ExternalCodeActions = [Collections.Generic.List[object]]::new()
  $UnknownActions = [Collections.Generic.List[object]]::new()
  $UnresolvedCount = 0
  $UnresolvedControlFlowCount = 0
  foreach ($Group in $Groups) {
    # CAction lists contain their own block controls. Track IF and WHILE nesting so every effect
    # carries the condition state under which the runtime reaches it. Runtime variable expressions
    # remain Unknown; the parser never executes project actions against the host.
    $ConditionStack = [Collections.Generic.List[object]]::new()
    $IdentifierState = [ordered]@{}
    foreach ($Action in $Group.Entries) {
      $ParentState = $ConditionStack.Count ? [string]$ConditionStack[$ConditionStack.Count - 1].State : 'True'
      if ($Action.ActionId -in 100, 102) {
        $ResolvedCondition = Resolve-SetupFactoryActionCondition6 -Expression ([string]$Action.Fields.S54) -IdentifierState $IdentifierState
        $ConditionState = Merge-InstallerConditionState -State @($ParentState, $ResolvedCondition.State) -Operator All
        $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ConditionState
        $Action | Add-Member -NotePropertyName ConditionEvidence -NotePropertyValue $ResolvedCondition
        $ConditionStack.Add([pscustomobject]@{ ActionId = $Action.ActionId; State = $ConditionState })
        if ($Action.ActionId -eq 102 -and $ConditionState -eq 'Unknown') { $UnresolvedControlFlowCount++ }
        continue
      }
      if ($Action.ActionId -in 101, 103) {
        $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ParentState
        $ExpectedOpen = $Action.ActionId -eq 101 ? 100 : 102
        if (-not $ConditionStack.Count -or $ConditionStack[$ConditionStack.Count - 1].ActionId -ne $ExpectedOpen) {
          $UnresolvedCount++
          $UnresolvedControlFlowCount++
        } else {
          $ConditionStack.RemoveAt($ConditionStack.Count - 1)
        }
        continue
      }

      $ConditionState = $ParentState
      $Action | Add-Member -NotePropertyName ConditionState -NotePropertyValue $ConditionState
      if (-not $Action.ActionName) {
        $UnknownActions.Add($Action)
        if ($Action.Phase -ne 'Uninstall' -and $ConditionState -ne 'False') { $UnresolvedControlFlowCount++ }
        continue
      }

      # GOTO changes which subsequent records run. Preserve the exact label target, but do not
      # pretend a single-pass walk can model branches that depend on unresolved runtime state.
      if ($Action.ActionId -eq 104 -and $ConditionState -ne 'False') { $UnresolvedControlFlowCount++ }
      if ($Action.ActionId -eq 14) {
        $VariableAssignments.Add($Action)
        $VariableName = [string]$Action.Details.VariableName
        $LiteralValue = [string]$Action.Details.Value
        if (-not $Action.Details.EvaluateAsExpression -and $VariableName -match '^%[A-Za-z_][A-Za-z0-9_]*%$' -and $LiteralValue -in 'TRUE', 'FALSE') {
          if ($ConditionState -eq 'True') { $IdentifierState[$VariableName] = $LiteralValue -eq 'TRUE' ? 'True' : 'False' }
          elseif ($ConditionState -eq 'Unknown') { $IdentifierState[$VariableName] = 'Unknown' }
        }
      }
      if ($Action.ActionId -in 3, 4) { $ExecutionActions.Add($Action) }
      if ($Action.ActionId -in 20, 28) { $UserInteractionActions.Add($Action) }
      if ($Action.ActionId -in 6, 22, 55) { $InstallabilityActions.Add($Action) }
      if ($Action.ActionId -in 50, 51) { $ShortcutActions.Add($Action) }
      if ($Action.ActionId -in 57, 58, 59, 60, 61, 62, 63) { $ServiceActions.Add($Action) }
      if ($Action.ActionId -in 74, 75, 76) { $RebootActions.Add($Action) }
      if ($Action.ActionId -eq 77) { $ExternalCodeActions.Add($Action) }

      # Registry writes are projected only for installation phases, reachable Set Value actions,
      # and source-backed root/type enums. Other operations remain in the action catalog.
      if ($Group.Phase -eq 'Uninstall' -or $Action.ActionId -ne 17) { continue }
      if ($ConditionState -eq 'Unknown') { $UnresolvedCount++; continue }
      if ($ConditionState -eq 'False' -or [int]$Action.Fields.I38 -ne 2) { continue }
      $Root = ConvertTo-SetupFactoryRegistryRoot -Value ([int]$Action.Fields.I78) -Generation Legacy6
      $Type = ConvertTo-SetupFactoryRegistryValueType -Value ([int]$Action.Fields.I90) -Generation Legacy6
      if (-not $Root -or -not $Type) { $UnresolvedCount++; continue }
      $RegistryWrites.Add([pscustomobject][ordered]@{
          Root           = $Root
          Key            = [string]$Action.Fields.S74
          Name           = [string]$Action.Fields.S58
          Value          = [string]$Action.Fields.S68
          Type           = $Type
          ActionOffset   = $Action.Offset
          ActionPhase    = $Action.Phase
          ConditionState = $ConditionState
        })
    }
    if ($ConditionStack.Count) {
      $UnresolvedCount += $ConditionStack.Count
      $UnresolvedControlFlowCount += $ConditionStack.Count
    }
  }

  return [pscustomobject][ordered]@{
    IsPresent                  = $true
    IsComplete                 = -not $ErrorMessage
    Error                      = $ErrorMessage
    Groups                     = $Groups.ToArray()
    Entries                    = $AllEntries.ToArray()
    RegistryWrites             = $RegistryWrites.ToArray()
    VariableAssignments        = $VariableAssignments.ToArray()
    ExecutionActions           = $ExecutionActions.ToArray()
    UserInteractionActions     = $UserInteractionActions.ToArray()
    InstallabilityActions      = $InstallabilityActions.ToArray()
    ShortcutActions            = $ShortcutActions.ToArray()
    ServiceActions             = $ServiceActions.ToArray()
    RebootActions              = $RebootActions.ToArray()
    ExternalCodeActions        = $ExternalCodeActions.ToArray()
    UnknownActions             = $UnknownActions.ToArray()
    UnresolvedCount            = $UnresolvedCount
    UnresolvedControlFlowCount = $UnresolvedControlFlowCount
  }
}

function Read-SetupFactoryLuaString {
  <#
  .SYNOPSIS
    Read one quoted literal Lua string without evaluating Lua code.
  .PARAMETER Text
    Decompiled or embedded Lua text.
  .PARAMETER Offset
    Mutable character offset positioned at optional whitespace before a quoted string.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Text,
    [Parameter(Mandatory)][ref]$Offset
  )

  while ($Offset.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Offset.Value])) { $Offset.Value++ }
  if ($Offset.Value -ge $Text.Length -or $Text[$Offset.Value] -notin "'", '"') { throw 'The Lua argument is not a literal string' }
  $Quote = $Text[$Offset.Value++]
  $Builder = [Text.StringBuilder]::new()
  while ($Offset.Value -lt $Text.Length) {
    $Character = $Text[$Offset.Value++]
    if ($Character -eq $Quote) { return $Builder.ToString() }
    if ($Character -ne '\') { $null = $Builder.Append($Character); continue }
    if ($Offset.Value -ge $Text.Length) { throw 'The Lua string ends in an escape prefix' }
    $Escape = $Text[$Offset.Value++]
    switch ($Escape) {
      'a' { $null = $Builder.Append([char]7) }
      'b' { $null = $Builder.Append([char]8) }
      'f' { $null = $Builder.Append([char]12) }
      'n' { $null = $Builder.Append("`n") }
      'r' { $null = $Builder.Append("`r") }
      't' { $null = $Builder.Append("`t") }
      'v' { $null = $Builder.Append([char]11) }
      "`n" { }
      "`r" { if ($Offset.Value -lt $Text.Length -and $Text[$Offset.Value] -eq "`n") { $Offset.Value++ } }
      'z' { while ($Offset.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Offset.Value])) { $Offset.Value++ } }
      default {
        if ([char]::IsDigit($Escape)) {
          $Digits = [string]$Escape
          while ($Digits.Length -lt 3 -and $Offset.Value -lt $Text.Length -and [char]::IsDigit($Text[$Offset.Value])) { $Digits += $Text[$Offset.Value++] }
          $Code = [int]$Digits
          if ($Code -gt 255) { throw 'The Lua decimal escape is outside the byte range' }
          $null = $Builder.Append([char]$Code)
        } elseif ($Escape -in "'", '"', '\') {
          $null = $Builder.Append($Escape)
        } else {
          # Compiled Setup Factory action text commonly contains ordinary Windows paths with
          # single backslashes. Preserve an unrecognized escape verbatim rather than silently
          # deleting the path separator while still decoding escaped quotes and backslashes.
          $null = $Builder.Append('\').Append($Escape)
        }
      }
    }
  }
  throw 'The Lua string is unterminated'
}

function Get-SetupFactoryLiteralRegistryWrite {
  <#
  .SYNOPSIS
    Recover literal Lua Registry.SetValue calls from irsetup.dat.
  .PARAMETER Bytes
    Complete irsetup.dat bytes decoded as UTF-8 for literal action parsing. Conditional or computed calls are not returned.
  .PARAMETER UnresolvedCount
    Optional reference receiving the number of Registry.SetValue calls whose arguments or registry roots could not be represented as deterministic registry evidence.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ref]$UnresolvedCount
  )
  if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value = 0 }
  # Parse quoted arguments with a small lexer instead of a quote-delimited regex. Setup Factory
  # commonly emits escaped quotes in uninstall and association commands.
  $Text = ConvertFrom-SetupFactoryText -Bytes $Bytes
  foreach ($Match in [regex]::Matches($Text, '(?i)Registry\.SetValue\s*\(')) {
    $Cursor = [ref]($Match.Index + $Match.Length)
    try {
      $Arguments = [Collections.Generic.List[string]]::new()
      for ($Index = 0; $Index -lt 4; $Index++) {
        $Arguments.Add((Read-SetupFactoryLuaString -Text $Text -Offset $Cursor))
        while ($Cursor.Value -lt $Text.Length -and [char]::IsWhiteSpace($Text[$Cursor.Value])) { $Cursor.Value++ }
        if ($Index -lt 3) {
          if ($Cursor.Value -ge $Text.Length -or $Text[$Cursor.Value] -ne ',') { throw 'The Lua argument separator is missing' }
          $Cursor.Value++
        }
      }
      if ($Arguments[0] -notmatch '^(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT)$') {
        if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value++ }
        continue
      }
      [pscustomobject]@{
        Root  = $Arguments[0]
        Key   = $Arguments[1]
        Name  = $Arguments[2]
        Value = $Arguments[3]
        Type  = 'REG_SZ'
      }
    } catch {
      # Computed arguments, long-bracket strings, and malformed calls are not deterministic
      # registry evidence. The aggregate parser reports their count as unresolved Lua effects.
      if ($null -ne $UnresolvedCount) { $UnresolvedCount.Value++ }
      continue
    }
  }
}

function ConvertTo-SetupFactoryFilePolicy {
  <#
  .SYNOPSIS
    Compose the source-backed installation policy attached to one payload record.
  .PARAMETER Values
    Generation-specific policy fields. Missing keys remain null rather than being treated as disabled.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Values)

  $OverwritePolicy = if ($Values.ContainsKey('OverwriteMode')) {
    switch ([byte]$Values['OverwriteMode']) {
      0 { 'SameOrOlder' }
      1 { 'Older' }
      2 { 'Always' }
      3 { 'Never' }
      4 { 'AskUser' }
      default { $null }
    }
  } else { $null }
  $ShortcutLocations = $Values.ContainsKey('ShortcutLocations') -and $null -ne $Values['ShortcutLocations'] ? [string[]]@($Values['ShortcutLocations']) : [string[]]@()
  $OperatingSystemConditions = $Values.ContainsKey('OperatingSystemConditions') -and $null -ne $Values['OperatingSystemConditions'] ? [uint16[]]@($Values['OperatingSystemConditions']) : [uint16[]]@()
  $BuildConfigurations = $Values.ContainsKey('BuildConfigurations') -and $null -ne $Values['BuildConfigurations'] ? [string[]]@($Values['BuildConfigurations']) : [string[]]@()
  $LegacySelectionValues = $Values.ContainsKey('LegacySelectionValues') -and $null -ne $Values['LegacySelectionValues'] ? [string[]]@($Values['LegacySelectionValues']) : [string[]]@()
  $LegacyAdvancedConditions = $Values.ContainsKey('LegacyAdvancedConditions') -and $null -ne $Values['LegacyAdvancedConditions'] ? [object[]]@($Values['LegacyAdvancedConditions']) : [object[]]@()

  [pscustomobject][ordered]@{
    Recurse                       = $Values.ContainsKey('Recurse') ? [bool]$Values['Recurse'] : $null
    MatchMode                     = $Values.ContainsKey('MatchMode') ? [byte]$Values['MatchMode'] : $null
    UseTrueVersion                = $Values.ContainsKey('UseTrueVersion') ? [bool]$Values['UseTrueVersion'] : $null
    ProductVersionMS              = $Values.ContainsKey('ProductVersionMS') ? [uint32]$Values['ProductVersionMS'] : $null
    ProductVersionLS              = $Values.ContainsKey('ProductVersionLS') ? [uint32]$Values['ProductVersionLS'] : $null
    FileVersionMS                 = $Values.ContainsKey('FileVersionMS') ? [uint32]$Values['FileVersionMS'] : $null
    FileVersionLS                 = $Values.ContainsKey('FileVersionLS') ? [uint32]$Values['FileVersionLS'] : $null
    FileDateMS                    = $Values.ContainsKey('FileDateMS') ? [uint32]$Values['FileDateMS'] : $null
    FileDateLS                    = $Values.ContainsKey('FileDateLS') ? [uint32]$Values['FileDateLS'] : $null
    OverwriteMode                 = $Values.ContainsKey('OverwriteMode') ? [byte]$Values['OverwriteMode'] : $null
    OverwritePolicy               = $OverwritePolicy
    CreateBackup                  = $Values.ContainsKey('CreateBackup') ? [bool]$Values['CreateBackup'] : $null
    ProtectFile                   = $Values.ContainsKey('ProtectFile') ? [bool]$Values['ProtectFile'] : $null
    ShortcutLocations             = $ShortcutLocations
    StartScreenPinning            = $Values.ContainsKey('StartScreenPinning') ? [bool]$Values['StartScreenPinning'] : $null
    UseExternalIcon               = $Values.ContainsKey('UseExternalIcon') ? [bool]$Values['UseExternalIcon'] : $null
    IconIndex                     = $Values.ContainsKey('IconIndex') ? [uint32]$Values['IconIndex'] : $null
    ShortcutWindowMode            = $Values.ContainsKey('ShortcutWindowMode') ? [byte]$Values['ShortcutWindowMode'] : $null
    ShortcutHotKey                = $Values.ContainsKey('ShortcutHotKey') ? [uint16]$Values['ShortcutHotKey'] : $null
    AppUserModelID                = $Values.ContainsKey('AppUserModelID') ? [string]$Values['AppUserModelID'] : $null
    RegisterTrueTypeFont          = $Values.ContainsKey('RegisterTrueTypeFont') ? [bool]$Values['RegisterTrueTypeFont'] : $null
    RegisterWithDllRegisterServer = $Values.ContainsKey('RegisterWithDllRegisterServer') ? [bool]$Values['RegisterWithDllRegisterServer'] : $null
    RegisterTypeLibrary           = $Values.ContainsKey('RegisterTypeLibrary') ? [bool]$Values['RegisterTypeLibrary'] : $null
    SuppressInUseNotice           = $Values.ContainsKey('SuppressInUseNotice') ? [bool]$Values['SuppressInUseNotice'] : $null
    UseOriginalAttributes         = $Values.ContainsKey('UseOriginalAttributes') ? [bool]$Values['UseOriginalAttributes'] : $null
    ForcedAttributes              = $Values.ContainsKey('ForcedAttributes') ? [uint32]$Values['ForcedAttributes'] : $null
    DisableCrcCheck               = $Values.ContainsKey('DisableCrcCheck') ? [bool]$Values['DisableCrcCheck'] : $null
    InstallOrder                  = $Values.ContainsKey('InstallOrder') ? [uint32]$Values['InstallOrder'] : $null
    NeverRemove                   = $Values.ContainsKey('NeverRemove') ? [bool]$Values['NeverRemove'] : $null
    SharedSystemFile              = $Values.ContainsKey('SharedSystemFile') ? [bool]$Values['SharedSystemFile'] : $null
    OperatingSystemConditions     = $OperatingSystemConditions
    RuntimeCondition              = $Values.ContainsKey('RuntimeCondition') ? [string]$Values['RuntimeCondition'] : $null
    BuildConfigurations           = $BuildConfigurations
    PackageSelector               = $Values.ContainsKey('PackageSelector') ? [string]$Values['PackageSelector'] : $null
    StoreOnly                     = $Values.ContainsKey('StoreOnly') ? [bool]$Values['StoreOnly'] : $null
    LegacyPolicySchema            = $Values.ContainsKey('LegacyPolicySchema') ? [uint16]$Values['LegacyPolicySchema'] : $null
    LegacyVersionWords            = $Values.ContainsKey('LegacyVersionWords') -and $null -ne $Values['LegacyVersionWords'] ? [uint32[]]@($Values['LegacyVersionWords']) : [uint32[]]@()
    LegacyOperatingSystemMask     = $Values.ContainsKey('LegacyOperatingSystemMask') ? [uint32]$Values['LegacyOperatingSystemMask'] : $null
    LegacyOperatingSystemPolicy   = $Values.ContainsKey('LegacyOperatingSystemPolicy') ? $Values['LegacyOperatingSystemPolicy'] : $null
    LegacyLanguageCondition       = $Values.ContainsKey('LegacyLanguageCondition') ? [uint32]$Values['LegacyLanguageCondition'] : $null
    LegacySelectionValues         = $LegacySelectionValues
    LegacyAdvancedConditions      = $LegacyAdvancedConditions
  }
}

function Get-SetupFactoryLegacyOperatingSystemPolicy {
  <#
  .SYNOPSIS
    Decode the operating-system mask used by Setup Factory 4 or 5 file conditions.
  .PARAMETER Generation
    Runtime generation whose mask table and evaluator define the bit meanings.
  .PARAMETER Mask
    Raw unsigned mask serialized in the CFileInfo record.
  .OUTPUTS
    A policy object preserving the raw and evaluated masks, selected targets, ignored bits, and whether the runtime accepts every OS generation it understands.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][ValidateSet('Classic4', 'Legacy5')][string]$Generation,
    [Parameter(Mandatory)][uint32]$Mask
  )

  $Definitions = if ($Generation -ceq 'Classic4') {
    @(
      [pscustomobject]@{ Bit = [uint32]0x01; Name = 'Windows 3.1 or Win32s' }
      [pscustomobject]@{ Bit = [uint32]0x02; Name = 'Windows 95' }
      [pscustomobject]@{ Bit = [uint32]0x04; Name = 'Windows NT 3' }
      [pscustomobject]@{ Bit = [uint32]0x08; Name = 'Windows NT 4' }
      [pscustomobject]@{ Bit = [uint32]0x10; Name = 'Any OS' }
    )
  } else {
    @(
      [pscustomobject]@{ Bit = [uint32]0x01; Name = 'Windows 95' }
      [pscustomobject]@{ Bit = [uint32]0x02; Name = 'Windows 98' }
      [pscustomobject]@{ Bit = [uint32]0x04; Name = 'Windows NT 3.51' }
      [pscustomobject]@{ Bit = [uint32]0x08; Name = 'Windows NT 4' }
      [pscustomobject]@{ Bit = [uint32]0x10; Name = 'Windows 2000' }
      [pscustomobject]@{ Bit = [uint32]0x20; Name = 'Windows ME' }
      [pscustomobject]@{ Bit = [uint32]0x40; Name = 'Windows XP' }
    )
  }
  $KnownMask = [uint32]($Generation -ceq 'Classic4' ? 0x1F : 0x7F)
  $EvaluatedMask = [uint32]($Mask -band $KnownMask)
  $Targets = [Collections.Generic.List[string]]::new()
  foreach ($Definition in $Definitions) {
    if (($EvaluatedMask -band $Definition.Bit) -ne 0) { $Targets.Add($Definition.Name) }
  }
  # SF4 has an explicit AnyOS branch. SF5 enumerates every OS understood by that runtime;
  # selecting all seven branches is therefore its equivalent unrestricted policy.
  $AcceptsEveryKnownOperatingSystem = if ($Generation -ceq 'Classic4') {
    ($EvaluatedMask -band 0x10) -ne 0
  } else {
    $EvaluatedMask -eq $KnownMask
  }

  [pscustomobject][ordered]@{
    Generation                       = $Generation
    RawMask                          = $Mask
    EvaluatedMask                    = $EvaluatedMask
    KnownMask                        = $KnownMask
    IgnoredMask                      = [uint32]($Mask -band ([uint32]::MaxValue -bxor $KnownMask))
    Targets                          = $Targets.ToArray()
    AcceptsEveryKnownOperatingSystem = $AcceptsEveryKnownOperatingSystem
    IsRestricted                     = -not $AcceptsEveryKnownOperatingSystem
  }
}

function ConvertFrom-SetupFactoryLegacyConditionOperator {
  <#
  .SYNOPSIS
    Map a Setup Factory 5 CConditionData operator value to its runtime comparison.
  .PARAMETER Value
    Unsigned operator value serialized at object offset 0x0C.
  .OUTPUTS
    The source-backed operator name, or null when the runtime treats the value as a failed condition.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][uint32]$Value)

  switch ($Value) {
    0 { return 'Equals' }
    1 { return 'GreaterThan' }
    2 { return 'LessThan' }
    3 { return 'GreaterThanOrEqual' }
    4 { return 'LessThanOrEqual' }
    5 { return 'NotEqual' }
    default { return $null }
  }
}

function ConvertTo-SetupFactoryInstalledFileRecord {
  <#
  .SYNOPSIS
    Normalize one generation-specific installed-file record.
  .PARAMETER Values
    Parsed record fields. Unknown format fields stay outside this common projection.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][hashtable]$Values)

  if ([string]::IsNullOrWhiteSpace([string]$Values['FileName'])) { throw 'The Setup Factory installed-file record has an empty filename' }
  foreach ($SizeName in 'PackedSize', 'ExpandedSize') {
    $Size = [long]$Values[$SizeName]
    if ($Size -lt 0 -or $Size -gt $Script:SetupFactoryMaximumFileBytes) { throw "The Setup Factory installed-file $SizeName is invalid" }
  }
  [pscustomobject][ordered]@{
    Name                     = [string]$Values['FileName']
    FileName                 = [string]$Values['FileName']
    SourcePath               = [string]$Values['SourcePath']
    SourceDirectory          = [string]$Values['SourceDirectory']
    Description              = [string]$Values['Description']
    DestinationPath          = [string]$Values['DestinationPath']
    StorageClass             = [string]$Values['StorageClass']
    IsEmbedded               = $true
    Title                    = [string]$Values['Title']
    Components               = [string]$Values['Components']
    Condition                = [string]$Values['Condition']
    InstallType              = [string]$Values['InstallType']
    Packages                 = $Values.ContainsKey('Packages') -and $null -ne $Values['Packages'] ? [string[]]@($Values['Packages']) : [string[]]@()
    Notes                    = [string]$Values['Notes']
    ShortcutLocation         = [string]$Values['ShortcutLocation']
    ShortcutComment          = [string]$Values['ShortcutComment']
    ShortcutDescription      = [string]$Values['ShortcutDescription']
    ShortcutArguments        = [string]$Values['ShortcutArguments']
    ShortcutWorkingDirectory = [string]$Values['ShortcutWorkingDirectory']
    IconPath                 = [string]$Values['IconPath']
    FontRegistryName         = [string]$Values['FontRegistryName']
    PackedSize               = [long]$Values['PackedSize']
    ExpandedSize             = [long]$Values['ExpandedSize']
    Crc32                    = [uint32]$Values['Crc32']
    IsCompressed             = [bool]$Values['IsCompressed']
    Attributes               = $Values['Attributes']
    CreationTime             = $Values['CreationTime']
    LastWriteTime            = $Values['LastWriteTime']
    Policy                   = $Values['Policy']
    RecordOffset             = [long]$Values['RecordOffset']
  }
}

function Read-SetupFactoryFileRecord4 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 4 CFileInfo record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable record offset.
  .PARAMETER SubType
    CFileInfo class subtype controlling the legacy trailing fields.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset, [Parameter(Mandatory)][uint16]$SubType)

  $Start = [long]$Offset.Value
  $PackedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Crc32 = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $SourcePath = Read-SetupFactoryDataString $Bytes $Offset Variable
  $Year = Read-SetupFactoryDataInteger $Bytes $Offset 2
  $Month = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Day = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Hour = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Minute = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Second = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 1
  if ($Year -lt 1900 -or $Month -notin 1..12 -or $Day -notin 1..31 -or $Hour -gt 23 -or $Minute -gt 59 -or $Second -gt 59) { throw 'The Setup Factory 4 file timestamp is invalid' }
  # CFileInfo serializes four words next to the timestamp and overwrite settings. They feed the
  # legacy file-comparison path, but their individual product/file-version roles are not proven.
  # Preserve them under an explicitly legacy name rather than inventing modern field semantics.
  $LegacyVersionWords = [uint32[]]::new(4)
  foreach ($Index in 0..3) { $LegacyVersionWords[$Index] = [uint32](Read-SetupFactoryDataInteger $Bytes $Offset 4) }
  $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $OriginalAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Destination = Read-SetupFactoryDataString $Bytes $Offset Variable
  $OverwriteMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreateShortcut = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateShortcut'
  $ShortcutDescription = Read-SetupFactoryDataString $Bytes $Offset Variable
  $ShortcutLocation = Read-SetupFactoryDataString $Bytes $Offset Variable
  $ShortcutArguments = Read-SetupFactoryDataString $Bytes $Offset Variable
  $ShortcutWorkingDirectory = Read-SetupFactoryDataString $Bytes $Offset Variable
  $IconIndex = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutHotKey = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutWindowMode = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Components = Read-SetupFactoryDataString $Bytes $Offset Variable
  $RegisterTrueTypeFont = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTrueTypeFont'
  $FontRegistryName = Read-SetupFactoryDataString $Bytes $Offset Variable
  $RegisterWithDllRegisterServer = $null
  $IsCompressed = $true
  $LegacyOperatingSystemMask = $null
  $UseTrueVersion = $null
  $FileVersionMS = $null
  $FileVersionLS = $null
  if ($SubType -eq 0) {
    # The original schema ends after the font metadata and always uses compressed storage.
  } elseif ($SubType -eq 1) {
    # The first revised schema adds ActiveX registration and an inverse compression selector.
    $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
    $IsCompressed = -not (Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreUncompressed')
  } elseif ($SubType -eq 2) {
    $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
    $IsCompressed = -not (Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreUncompressed')
    # Schema 2 adds an OS eligibility mask and the optional true-file-version comparison. Runtime
    # code reads VS_FIXEDFILEINFO only when UseTrueVersion is set, then compares dwFileVersionMS/LS
    # with these two words. Package selection remains the preceding Components string.
    $LegacyOperatingSystemMask = Read-SetupFactoryDataInteger $Bytes $Offset 1
    $UseTrueVersion = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseTrueVersion'
    $FileVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
    $FileVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  } else {
    throw "Unsupported Setup Factory 4 CFileInfo schema '$SubType'"
  }
  $FileName = [IO.Path]::GetFileName($SourcePath.Replace('/', '\'))
  $ShortcutLocations = $CreateShortcut ? [string[]]@('Custom') : [string[]]@()
  $PolicyValues = @{
    OverwriteMode = [byte]$OverwriteMode; ShortcutLocations = $ShortcutLocations; IconIndex = [uint32]$IconIndex; ShortcutWindowMode = [byte]$ShortcutWindowMode; ShortcutHotKey = [uint16]$ShortcutHotKey
    RegisterTrueTypeFont = $RegisterTrueTypeFont; UseOriginalAttributes = $true; ForcedAttributes = [uint32]$OriginalAttributes
    LegacyPolicySchema = $SubType; LegacyVersionWords = $LegacyVersionWords; PackageSelector = $Components
  }
  if ($null -ne $RegisterWithDllRegisterServer) { $PolicyValues['RegisterWithDllRegisterServer'] = $RegisterWithDllRegisterServer }
  if ($null -ne $LegacyOperatingSystemMask) {
    $PolicyValues['LegacyOperatingSystemMask'] = [byte]$LegacyOperatingSystemMask
    $PolicyValues['LegacyOperatingSystemPolicy'] = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Classic4 -Mask ([byte]$LegacyOperatingSystemMask)
    $PolicyValues['UseTrueVersion'] = $UseTrueVersion
    $PolicyValues['FileVersionMS'] = [uint32]$FileVersionMS
    $PolicyValues['FileVersionLS'] = [uint32]$FileVersionLS
  }
  $Policy = ConvertTo-SetupFactoryFilePolicy -Values $PolicyValues
  ConvertTo-SetupFactoryInstalledFileRecord -Values @{
    FileName = $FileName; SourcePath = $SourcePath; DestinationPath = $Destination; StorageClass = 'Archive'; Components = $Components
    ShortcutLocation = $ShortcutLocation; ShortcutDescription = $ShortcutDescription; ShortcutArguments = $ShortcutArguments; ShortcutWorkingDirectory = $ShortcutWorkingDirectory; FontRegistryName = $FontRegistryName; Policy = $Policy
    PackedSize = $PackedSize; ExpandedSize = $ExpandedSize; Crc32 = $Crc32; IsCompressed = $IsCompressed; Attributes = [uint32]$OriginalAttributes; RecordOffset = $Start
    LastWriteTime = try { [datetime]::new([int]$Year, [int]$Month, [int]$Day, [int]$Hour, [int]$Minute, [int]$Second) } catch { $null }
  }
}

function Read-SetupFactoryFileRecord5 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 5 CFileInfo record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable record offset.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $Start = [long]$Offset.Value
  $SourceFile = Read-SetupFactoryDataString $Bytes $Offset Small
  $FileName = Read-SetupFactoryDataString $Bytes $Offset Small
  $SourceDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $null = Read-SetupFactoryDataString $Bytes $Offset Small
  $StorageClass = Read-SetupFactoryDataString $Bytes $Offset Small
  $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $OriginalAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreationTime = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 4 # Access time is not manifest evidence.
  $Timestamp = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $UseTrueVersion = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseTrueVersion'
  $ProductVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ProductVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Destination = Read-SetupFactoryDataString $Bytes $Offset Small
  $OverwriteMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreateBackup = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateBackup'
  $ProtectFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'ProtectFile'
  $CreateAppFolderShortcut = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateAppFolderShortcut'
  $CreateDesktopShortcut = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateDesktopShortcut'
  $ShortcutDescription = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutArguments = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutWorkingDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $UseExternalIcon = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseExternalIcon'
  $IconPath = Read-SetupFactoryDataString $Bytes $Offset Small
  $IconIndex = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutWindowMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Components = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterTrueTypeFont = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTrueTypeFont'
  $FontRegistryName = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
  $RegisterTypeLibrary = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTypeLibrary'
  $SuppressInUseNotice = Read-SetupFactoryDataBoolean $Bytes $Offset 'SuppressInUseNotice'
  $IsCompressed = Read-SetupFactoryDataBoolean $Bytes $Offset 'Compress'
  $UseOriginalAttributes = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseOriginalAttributes'
  $ForcedAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $NeverRemove = Read-SetupFactoryDataBoolean $Bytes $Offset 'NeverRemove'
  $SharedSystemFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'SharedSystemFile'
  # The version-5 File Properties Conditions tab serializes the accepted Windows versions and
  # selected global language before its list of advanced Boolean conditions.
  $LegacyOperatingSystemMask = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $LegacyLanguageCondition = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $OptionCount = Read-SetupFactoryDataInteger $Bytes $Offset 2
  if ($OptionCount -gt 64) { throw 'The Setup Factory 5 file option count exceeds the configured limit' }
  $LegacyAdvancedConditions = [Collections.Generic.List[object]]::new()
  if ($OptionCount) {
    $OptionType = Read-SetupFactoryDataInteger $Bytes $Offset 2
    $OptionClassName = $null
    if ($OptionType -eq 0xFFFF) {
      $null = Read-SetupFactoryDataInteger $Bytes $Offset 2
      $OptionClassName = Read-SetupFactoryDataString $Bytes $Offset Big
    } elseif (($OptionType -band 0xFF00) -notin 0x8000, 0x8100) { throw 'The Setup Factory 5 file option table is malformed' }
    $ClassReference = $null
    for ($Index = 0; $Index -lt $OptionCount; $Index++) {
      $RecordType = [uint16]$OptionType
      if ($Index -gt 0) {
        # Later CConditionData objects use one stable high-bit MFC class reference instead of
        # repeating the first object's class declaration.
        $RecordType = [uint16](Read-SetupFactoryDataInteger -Bytes $Bytes -Offset $Offset -Size 2)
        if (($RecordType -band 0x8000) -eq 0) { throw 'The Setup Factory 5 file option object reference is invalid' }
        if ($null -eq $ClassReference) { $ClassReference = $RecordType }
        elseif ($RecordType -ne $ClassReference) { throw 'The Setup Factory 5 file option object reference changed inside the list' }
      }
      $LegacyAdvancedConditions.Add((Read-SetupFactoryConditionRecord5 -Bytes $Bytes -Offset $Offset -Width Small -Type $RecordType -ClassName $OptionClassName))
    }
  }
  $PackedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Crc32 = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $StoreOnly = Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreOnly'
  $LegacyTrailerValues = [uint32[]]::new(8)
  for ($Index = 0; $Index -lt $LegacyTrailerValues.Count; $Index++) { $LegacyTrailerValues[$Index] = [uint32](Read-SetupFactoryDataInteger $Bytes $Offset 4) }
  $DisableCrcCheck = [bool]([byte]$LegacyTrailerValues[4])
  # The final four strings are builder-side file metadata that the Setup Factory 6 importer does
  # not project into CSetupFileData. Read them structurally so non-empty values cannot desynchronize the table.
  for ($Index = 0; $Index -lt 4; $Index++) { $null = Read-SetupFactoryDataString $Bytes $Offset Small }
  $ShortcutLocations = @()
  if ($CreateAppFolderShortcut) { $ShortcutLocations += 'ApplicationShortcutFolder' }
  if ($CreateDesktopShortcut) { $ShortcutLocations += 'Desktop' }
  $LegacyOperatingSystemPolicy = Get-SetupFactoryLegacyOperatingSystemPolicy -Generation Legacy5 -Mask ([uint32]$LegacyOperatingSystemMask)
  $Policy = ConvertTo-SetupFactoryFilePolicy -Values @{
    UseTrueVersion = $UseTrueVersion; ProductVersionMS = [uint32]$ProductVersionMS; ProductVersionLS = [uint32]$ProductVersionLS; FileVersionMS = [uint32]$FileVersionMS; FileVersionLS = [uint32]$FileVersionLS; FileDateMS = [uint32]$FileDateMS; FileDateLS = [uint32]$FileDateLS
    OverwriteMode = [byte]$OverwriteMode; CreateBackup = $CreateBackup; ProtectFile = $ProtectFile; ShortcutLocations = [string[]]$ShortcutLocations; UseExternalIcon = $UseExternalIcon; IconIndex = [uint32]$IconIndex; ShortcutWindowMode = [byte]$ShortcutWindowMode
    RegisterTrueTypeFont = $RegisterTrueTypeFont; RegisterWithDllRegisterServer = $RegisterWithDllRegisterServer; RegisterTypeLibrary = $RegisterTypeLibrary; SuppressInUseNotice = $SuppressInUseNotice; UseOriginalAttributes = $UseOriginalAttributes; ForcedAttributes = [uint32]$ForcedAttributes
    DisableCrcCheck = $DisableCrcCheck; NeverRemove = $NeverRemove; SharedSystemFile = $SharedSystemFile; StoreOnly = $StoreOnly; PackageSelector = $Components; LegacyOperatingSystemMask = [uint32]$LegacyOperatingSystemMask; LegacyOperatingSystemPolicy = $LegacyOperatingSystemPolicy; LegacyLanguageCondition = [uint32]$LegacyLanguageCondition; LegacyAdvancedConditions = $LegacyAdvancedConditions.ToArray()
  }
  ConvertTo-SetupFactoryInstalledFileRecord -Values @{
    FileName = $FileName; SourcePath = $SourceFile; SourceDirectory = $SourceDirectory; DestinationPath = $Destination; StorageClass = $StorageClass; Components = $Components
    ShortcutDescription = $ShortcutDescription; ShortcutArguments = $ShortcutArguments; ShortcutWorkingDirectory = $ShortcutWorkingDirectory; IconPath = $IconPath; FontRegistryName = $FontRegistryName; Policy = $Policy
    PackedSize = $PackedSize; ExpandedSize = $ExpandedSize; Crc32 = $Crc32; IsCompressed = $IsCompressed; RecordOffset = $Start
    Attributes = $UseOriginalAttributes ? [uint32]$OriginalAttributes : [uint32]$ForcedAttributes
    CreationTime = if ($CreationTime) { [DateTimeOffset]::FromUnixTimeSeconds($CreationTime).LocalDateTime } else { $null }
    LastWriteTime = if ($Timestamp) { [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).LocalDateTime } else { $null }
  }
}

function Read-SetupFactoryFileRecord6 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 6 CFileInfo record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable record offset.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $Start = [long]$Offset.Value
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $SourceFile = Read-SetupFactoryDataString $Bytes $Offset Small
  $FileName = Read-SetupFactoryDataString $Bytes $Offset Small
  $SourceDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $null = Read-SetupFactoryDataString $Bytes $Offset Small
  $StorageClass = Read-SetupFactoryDataString $Bytes $Offset Small
  $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $OriginalAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreationTime = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 4 # Access time is not manifest evidence.
  $Timestamp = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $UseTrueVersion = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseTrueVersion'
  $ProductVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ProductVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Destination = Read-SetupFactoryDataString $Bytes $Offset Small
  $OverwriteMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreateBackup = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateBackup'
  $ProtectFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'ProtectFile'
  $CreateAppFolderShortcut = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateAppFolderShortcut'
  $CreateDesktopShortcut = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateDesktopShortcut'
  $ShortcutDescription = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutArguments = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutWorkingDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $UseExternalIcon = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseExternalIcon'
  $IconPath = Read-SetupFactoryDataString $Bytes $Offset Small
  $IconIndex = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutWindowMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $Components = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterTrueTypeFont = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTrueTypeFont'
  $FontRegistryName = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
  $RegisterTypeLibrary = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTypeLibrary'
  $SuppressInUseNotice = Read-SetupFactoryDataBoolean $Bytes $Offset 'SuppressInUseNotice'
  $IsCompressed = Read-SetupFactoryDataBoolean $Bytes $Offset 'Compress'
  $UseOriginalAttributes = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseOriginalAttributes'
  $ForcedAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $NeverRemove = Read-SetupFactoryDataBoolean $Bytes $Offset 'NeverRemove'
  $SharedSystemFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'SharedSystemFile'
  $LegacyCondition = Read-SetupFactoryDataString $Bytes $Offset Small
  $LegacyInstallType = Read-SetupFactoryDataString $Bytes $Offset Small
  $LegacySelectionValues = Read-SetupFactoryDataStringList $Bytes $Offset 64 'file option'
  $PackedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Crc32 = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $StoreOnly = Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreOnly'
  $LegacyTrailerValues = [uint32[]]::new(8)
  for ($Index = 0; $Index -lt $LegacyTrailerValues.Count; $Index++) { $LegacyTrailerValues[$Index] = [uint32](Read-SetupFactoryDataInteger $Bytes $Offset 4) }
  $DisableCrcCheck = [bool]([byte]$LegacyTrailerValues[4])
  # These builder-side strings are not projected by the version-6 importer, but parsing them
  # explicitly keeps the media table aligned when they are not empty.
  for ($Index = 0; $Index -lt 4; $Index++) { $null = Read-SetupFactoryDataString $Bytes $Offset Small }
  $ShortcutLocations = @()
  if ($CreateAppFolderShortcut) { $ShortcutLocations += 'ApplicationShortcutFolder' }
  if ($CreateDesktopShortcut) { $ShortcutLocations += 'Desktop' }
  $Policy = ConvertTo-SetupFactoryFilePolicy -Values @{
    UseTrueVersion = $UseTrueVersion; ProductVersionMS = [uint32]$ProductVersionMS; ProductVersionLS = [uint32]$ProductVersionLS; FileVersionMS = [uint32]$FileVersionMS; FileVersionLS = [uint32]$FileVersionLS; FileDateMS = [uint32]$FileDateMS; FileDateLS = [uint32]$FileDateLS
    OverwriteMode = [byte]$OverwriteMode; CreateBackup = $CreateBackup; ProtectFile = $ProtectFile; ShortcutLocations = [string[]]$ShortcutLocations; UseExternalIcon = $UseExternalIcon; IconIndex = [uint32]$IconIndex; ShortcutWindowMode = [byte]$ShortcutWindowMode
    RegisterTrueTypeFont = $RegisterTrueTypeFont; RegisterWithDllRegisterServer = $RegisterWithDllRegisterServer; RegisterTypeLibrary = $RegisterTypeLibrary; SuppressInUseNotice = $SuppressInUseNotice; UseOriginalAttributes = $UseOriginalAttributes; ForcedAttributes = [uint32]$ForcedAttributes
    DisableCrcCheck = $DisableCrcCheck; NeverRemove = $NeverRemove; SharedSystemFile = $SharedSystemFile; RuntimeCondition = $LegacyCondition; PackageSelector = $LegacyInstallType; StoreOnly = $StoreOnly; LegacySelectionValues = [string[]]$LegacySelectionValues
  }
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 2
  ConvertTo-SetupFactoryInstalledFileRecord -Values @{
    FileName = $FileName; SourcePath = $SourceFile; SourceDirectory = $SourceDirectory; DestinationPath = $Destination; StorageClass = $StorageClass; Components = $Components; Condition = $LegacyCondition; InstallType = $LegacyInstallType
    ShortcutDescription = $ShortcutDescription; ShortcutArguments = $ShortcutArguments; ShortcutWorkingDirectory = $ShortcutWorkingDirectory; IconPath = $IconPath; FontRegistryName = $FontRegistryName; Policy = $Policy
    PackedSize = $PackedSize; ExpandedSize = $ExpandedSize; Crc32 = $Crc32; IsCompressed = $IsCompressed; RecordOffset = $Start
    Attributes = $UseOriginalAttributes ? [uint32]$OriginalAttributes : [uint32]$ForcedAttributes
    CreationTime = if ($CreationTime) { [DateTimeOffset]::FromUnixTimeSeconds($CreationTime).LocalDateTime } else { $null }
    LastWriteTime = if ($Timestamp) { [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).LocalDateTime } else { $null }
  }
}

function Read-SetupFactoryFileRecord7 {
  <#
  .SYNOPSIS
    Decode one Setup Factory 7 CSetupFileData record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable record offset.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $Start = [long]$Offset.Value
  $RecordSchema = Read-SetupFactoryDataInteger $Bytes $Offset 4
  if ($RecordSchema -ne 1) { throw "Unsupported Setup Factory 7 CSetupFileData schema '$RecordSchema'" }
  # This byte is CArchive object-reference framing serialized before CSetupFileData fields. It is
  # validated as a Boolean but does not describe installation policy for the payload.
  $null = Read-SetupFactoryDataBoolean $Bytes $Offset 'FieldReference'
  $SourceFile = Read-SetupFactoryDataString $Bytes $Offset Small
  $FileName = Read-SetupFactoryDataString $Bytes $Offset Small
  $SourceDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $null = Read-SetupFactoryDataString $Bytes $Offset Small
  $StorageClass = Read-SetupFactoryDataString $Bytes $Offset Small
  $Description = Read-SetupFactoryDataString $Bytes $Offset Small
  $Recurse = Read-SetupFactoryDataBoolean $Bytes $Offset 'Recurse'
  $MatchMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $OriginalAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreationTime = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 4 # Access time is not manifest evidence.
  $Timestamp = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $UseTrueVersion = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseTrueVersion'
  $ProductVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ProductVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Destination = Read-SetupFactoryDataString $Bytes $Offset Small
  $OverwriteMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreateBackup = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateBackup'
  $ProtectFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'ProtectFile'
  $ShortcutFlags = [bool[]]::new(7)
  foreach ($Index in 0..6) { $ShortcutFlags[$Index] = Read-SetupFactoryDataBoolean $Bytes $Offset "ShortcutLocation[$Index]" }
  $ShortcutLocation = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutComment = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutDescription = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutArguments = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutWorkingDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $UseExternalIcon = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseExternalIcon'
  $IconPath = Read-SetupFactoryDataString $Bytes $Offset Small
  $IconIndex = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutWindowMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $ShortcutHotKey = Read-SetupFactoryDataInteger $Bytes $Offset 2
  $RegisterTrueTypeFont = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTrueTypeFont'
  $FontRegistryName = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
  $RegisterTypeLibrary = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTypeLibrary'
  $SuppressInUseNotice = Read-SetupFactoryDataBoolean $Bytes $Offset 'SuppressInUseNotice'
  $IsCompressed = Read-SetupFactoryDataBoolean $Bytes $Offset 'Compress'
  $UseOriginalAttributes = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseOriginalAttributes'
  $ForcedAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $DisableCrcCheck = Read-SetupFactoryDataBoolean $Bytes $Offset 'DisableCrcCheck'
  $InstallOrder = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $NeverRemove = Read-SetupFactoryDataBoolean $Bytes $Offset 'NeverRemove'
  $SharedSystemFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'SharedSystemFile'
  $OperatingSystemConditions = Read-SetupFactoryDataWordArray $Bytes $Offset 64 'operating-system condition'
  $Condition = Read-SetupFactoryDataString $Bytes $Offset Small
  $BuildConfigurations = Read-SetupFactoryDataStringList $Bytes $Offset 128 'build-configuration'
  $InstallType = Read-SetupFactoryDataString $Bytes $Offset Small
  $Packages = Read-SetupFactoryDataStringList $Bytes $Offset 4096 'file package'
  $Notes = Read-SetupFactoryDataString $Bytes $Offset Small
  $PackedSize = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Crc32 = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $StoreOnly = Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreOnly'
  $ShortcutLocationNames = 'StartMenuRoot', 'StartMenuPrograms', 'ApplicationShortcutFolder', 'Startup', 'Desktop', 'QuickLaunch', 'Custom'
  $ShortcutLocations = for ($Index = 0; $Index -lt $ShortcutFlags.Count; $Index++) { if ($ShortcutFlags[$Index]) { $ShortcutLocationNames[$Index] } }
  $Policy = ConvertTo-SetupFactoryFilePolicy -Values @{
    Recurse = $Recurse; MatchMode = [byte]$MatchMode; UseTrueVersion = $UseTrueVersion; ProductVersionMS = [uint32]$ProductVersionMS; ProductVersionLS = [uint32]$ProductVersionLS; FileVersionMS = [uint32]$FileVersionMS; FileVersionLS = [uint32]$FileVersionLS; FileDateMS = [uint32]$FileDateMS; FileDateLS = [uint32]$FileDateLS
    OverwriteMode = [byte]$OverwriteMode; CreateBackup = $CreateBackup; ProtectFile = $ProtectFile; ShortcutLocations = [string[]]$ShortcutLocations; UseExternalIcon = $UseExternalIcon; IconIndex = [uint32]$IconIndex; ShortcutWindowMode = [byte]$ShortcutWindowMode; ShortcutHotKey = [uint16]$ShortcutHotKey
    RegisterTrueTypeFont = $RegisterTrueTypeFont; RegisterWithDllRegisterServer = $RegisterWithDllRegisterServer; RegisterTypeLibrary = $RegisterTypeLibrary; SuppressInUseNotice = $SuppressInUseNotice; UseOriginalAttributes = $UseOriginalAttributes; ForcedAttributes = [uint32]$ForcedAttributes
    DisableCrcCheck = $DisableCrcCheck; InstallOrder = [uint32]$InstallOrder; NeverRemove = $NeverRemove; SharedSystemFile = $SharedSystemFile; OperatingSystemConditions = [uint16[]]$OperatingSystemConditions; RuntimeCondition = $Condition; BuildConfigurations = [string[]]$BuildConfigurations; PackageSelector = $InstallType; StoreOnly = $StoreOnly
  }
  ConvertTo-SetupFactoryInstalledFileRecord -Values @{
    FileName = $FileName; SourcePath = $SourceFile; SourceDirectory = $SourceDirectory; Description = $Description; DestinationPath = $Destination; StorageClass = $StorageClass; Condition = $Condition; InstallType = $InstallType; Packages = [string[]]$Packages; Notes = $Notes
    ShortcutLocation = $ShortcutLocation; ShortcutComment = $ShortcutComment; ShortcutDescription = $ShortcutDescription; ShortcutArguments = $ShortcutArguments; ShortcutWorkingDirectory = $ShortcutWorkingDirectory; IconPath = $IconPath; FontRegistryName = $FontRegistryName; Policy = $Policy
    PackedSize = $PackedSize; ExpandedSize = $ExpandedSize; Crc32 = $Crc32; IsCompressed = $IsCompressed; RecordOffset = $Start; Attributes = $UseOriginalAttributes ? [uint32]$OriginalAttributes : [uint32]$ForcedAttributes
    CreationTime = if ($CreationTime) { [DateTimeOffset]::FromUnixTimeSeconds($CreationTime).LocalDateTime } else { $null }
    LastWriteTime = if ($Timestamp) { [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).LocalDateTime } else { $null }
  }
}

function Read-SetupFactoryFileRecord8Plus {
  <#
  .SYNOPSIS
    Decode one Setup Factory 8-10 CSetupFileData record.
  .PARAMETER Bytes
    Complete decompressed irsetup.dat bytes.
  .PARAMETER Offset
    Mutable record offset.
  .PARAMETER DestinationPolicyLength
    Number of serialized destination and shortcut-location policy bytes. Setup Factory 9.1.1 and later add StartScreenPinning as the eleventh byte.
  .PARAMETER HasAppUserModelID
    Indicates that the record serializes AppUserModelID between the shortcut hot key and TrueType-font policy.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ref]$Offset,
    [Parameter(Mandatory)][ValidateSet(10, 11)][int]$DestinationPolicyLength,
    [Parameter(Mandatory)][bool]$HasAppUserModelID
  )

  $Start = [long]$Offset.Value
  $SourceFile = Read-SetupFactoryDataString $Bytes $Offset Small
  $FileName = Read-SetupFactoryDataString $Bytes $Offset Small
  $SourceDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $null = Read-SetupFactoryDataString $Bytes $Offset Small
  $StorageClass = Read-SetupFactoryDataString $Bytes $Offset Small
  $Description = Read-SetupFactoryDataString $Bytes $Offset Small
  $Recurse = Read-SetupFactoryDataBoolean $Bytes $Offset 'Recurse'
  $MatchMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Offset 8
  $OriginalAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreationTimeMarker = Read-SetupFactoryDataInteger $Bytes $Offset 4
  if ($CreationTimeMarker -ne 2147483658L) { throw 'The Setup Factory creation-time marker is invalid' }
  $CreationTime = Read-SetupFactoryDataInteger $Bytes $Offset 8
  $AccessTimeMarker = Read-SetupFactoryDataInteger $Bytes $Offset 4
  if ($AccessTimeMarker -ne 2147483658L) { throw 'The Setup Factory access-time marker is invalid' }
  $null = Read-SetupFactoryDataInteger $Bytes $Offset 8 # Access time is not manifest evidence.
  $LastWriteTimeMarker = Read-SetupFactoryDataInteger $Bytes $Offset 4
  if ($LastWriteTimeMarker -ne 2147483658L) { throw 'The Setup Factory modification-time marker is invalid' }
  $LastWriteTime = Read-SetupFactoryDataInteger $Bytes $Offset 8
  $UseTrueVersion = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseTrueVersion'
  $ProductVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ProductVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileVersionLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateMS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $FileDateLS = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $Destination = Read-SetupFactoryDataString $Bytes $Offset Small
  $OverwriteMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $CreateBackup = Read-SetupFactoryDataBoolean $Bytes $Offset 'CreateBackup'
  $ProtectFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'ProtectFile'
  $ShortcutFlags = [bool[]]::new(7)
  foreach ($Index in 0..6) { $ShortcutFlags[$Index] = Read-SetupFactoryDataBoolean $Bytes $Offset "ShortcutLocation[$Index]" }
  $StartScreenPinning = if ($DestinationPolicyLength -eq 11) { Read-SetupFactoryDataBoolean $Bytes $Offset 'StartScreenPinning' } else { $null }
  $ShortcutLocation = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutComment = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutDescription = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutArguments = Read-SetupFactoryDataString $Bytes $Offset Small
  $ShortcutWorkingDirectory = Read-SetupFactoryDataString $Bytes $Offset Small
  $UseExternalIcon = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseExternalIcon'
  $IconPath = Read-SetupFactoryDataString $Bytes $Offset Small
  $IconIndex = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $ShortcutWindowMode = Read-SetupFactoryDataInteger $Bytes $Offset 1
  $ShortcutHotKey = Read-SetupFactoryDataInteger $Bytes $Offset 2
  $AppUserModelID = if ($HasAppUserModelID) { Read-SetupFactoryDataString $Bytes $Offset Small } else { $null }
  $RegisterTrueTypeFont = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTrueTypeFont'
  $FontRegistryName = Read-SetupFactoryDataString $Bytes $Offset Small
  $RegisterWithDllRegisterServer = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterWithDllRegisterServer'
  $RegisterTypeLibrary = Read-SetupFactoryDataBoolean $Bytes $Offset 'RegisterTypeLibrary'
  $SuppressInUseNotice = Read-SetupFactoryDataBoolean $Bytes $Offset 'SuppressInUseNotice'
  $IsCompressed = Read-SetupFactoryDataBoolean $Bytes $Offset 'Compress'
  $UseOriginalAttributes = Read-SetupFactoryDataBoolean $Bytes $Offset 'UseOriginalAttributes'
  $ForcedAttributes = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $DisableCrcCheck = Read-SetupFactoryDataBoolean $Bytes $Offset 'DisableCrcCheck'
  $InstallOrder = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $NeverRemove = Read-SetupFactoryDataBoolean $Bytes $Offset 'NeverRemove'
  $SharedSystemFile = Read-SetupFactoryDataBoolean $Bytes $Offset 'SharedSystemFile'
  $OperatingSystemConditions = Read-SetupFactoryDataWordArray $Bytes $Offset 128 'operating-system condition'
  $Condition = Read-SetupFactoryDataString $Bytes $Offset Small
  $BuildConfigurations = Read-SetupFactoryDataStringList $Bytes $Offset 128 'build-configuration'
  $InstallType = Read-SetupFactoryDataString $Bytes $Offset Small
  $Packages = Read-SetupFactoryDataStringList $Bytes $Offset 4096 'file package'
  $Notes = Read-SetupFactoryDataString $Bytes $Offset Small
  $PackedSize = Read-SetupFactoryDataInteger $Bytes $Offset 8
  $Crc32 = Read-SetupFactoryDataInteger $Bytes $Offset 4
  $StoreOnly = Read-SetupFactoryDataBoolean $Bytes $Offset 'StoreOnly'
  $ShortcutLocationNames = 'StartMenuRoot', 'StartMenuPrograms', 'ApplicationShortcutFolder', 'Startup', 'Desktop', 'QuickLaunch', 'Custom'
  $ShortcutLocations = for ($Index = 0; $Index -lt $ShortcutFlags.Count; $Index++) { if ($ShortcutFlags[$Index]) { $ShortcutLocationNames[$Index] } }
  $PolicyValues = @{
    Recurse = $Recurse; MatchMode = [byte]$MatchMode; UseTrueVersion = $UseTrueVersion; ProductVersionMS = [uint32]$ProductVersionMS; ProductVersionLS = [uint32]$ProductVersionLS; FileVersionMS = [uint32]$FileVersionMS; FileVersionLS = [uint32]$FileVersionLS; FileDateMS = [uint32]$FileDateMS; FileDateLS = [uint32]$FileDateLS
    OverwriteMode = [byte]$OverwriteMode; CreateBackup = $CreateBackup; ProtectFile = $ProtectFile; ShortcutLocations = [string[]]$ShortcutLocations; UseExternalIcon = $UseExternalIcon; IconIndex = [uint32]$IconIndex; ShortcutWindowMode = [byte]$ShortcutWindowMode; ShortcutHotKey = [uint16]$ShortcutHotKey
    RegisterTrueTypeFont = $RegisterTrueTypeFont; RegisterWithDllRegisterServer = $RegisterWithDllRegisterServer; RegisterTypeLibrary = $RegisterTypeLibrary; SuppressInUseNotice = $SuppressInUseNotice; UseOriginalAttributes = $UseOriginalAttributes; ForcedAttributes = [uint32]$ForcedAttributes
    DisableCrcCheck = $DisableCrcCheck; InstallOrder = [uint32]$InstallOrder; NeverRemove = $NeverRemove; SharedSystemFile = $SharedSystemFile; OperatingSystemConditions = [uint16[]]$OperatingSystemConditions; RuntimeCondition = $Condition; BuildConfigurations = [string[]]$BuildConfigurations; PackageSelector = $InstallType; StoreOnly = $StoreOnly
  }
  if ($DestinationPolicyLength -eq 11) { $PolicyValues['StartScreenPinning'] = $StartScreenPinning }
  if ($HasAppUserModelID) { $PolicyValues['AppUserModelID'] = $AppUserModelID }
  $Policy = ConvertTo-SetupFactoryFilePolicy -Values $PolicyValues
  ConvertTo-SetupFactoryInstalledFileRecord -Values @{
    FileName = $FileName; SourcePath = $SourceFile; SourceDirectory = $SourceDirectory; Description = $Description; DestinationPath = $Destination; StorageClass = $StorageClass; Condition = $Condition
    InstallType = $InstallType; Packages = [string[]]$Packages; Notes = $Notes; ShortcutLocation = $ShortcutLocation; ShortcutComment = $ShortcutComment
    ShortcutDescription = $ShortcutDescription; ShortcutArguments = $ShortcutArguments; ShortcutWorkingDirectory = $ShortcutWorkingDirectory; IconPath = $IconPath; FontRegistryName = $FontRegistryName
    PackedSize = $PackedSize; ExpandedSize = $ExpandedSize; Crc32 = $Crc32; IsCompressed = $IsCompressed; RecordOffset = $Start
    Attributes = $UseOriginalAttributes ? [uint32]$OriginalAttributes : [uint32]$ForcedAttributes; Policy = $Policy
    CreationTime = if ($CreationTime) { [DateTimeOffset]::FromUnixTimeSeconds($CreationTime).LocalDateTime } else { $null }
    LastWriteTime = if ($LastWriteTime) { [DateTimeOffset]::FromUnixTimeSeconds($LastWriteTime).LocalDateTime } else { $null }
  }
}

function ConvertTo-SetupFactoryPayloadRelativePath {
  <#
  .SYNOPSIS
    Convert an installed destination into a safe extraction-relative path.
  .PARAMETER FileName
    Installed file basename.
  .PARAMETER DestinationPath
    Setup Factory destination expression.
  .PARAMETER Variables
    Session variables used to resolve deterministic destination expressions.
  .PARAMETER InstallLocation
    Resolved application root, when available.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$FileName, [AllowEmptyString()][string]$DestinationPath, [Parameter(Mandatory)][hashtable]$Variables, [AllowNull()][string]$InstallLocation)

  $RawDestination = $DestinationPath.Trim().TrimEnd('\', '/')
  $ResolvedDestination = Resolve-SetupFactoryVariable -Value $RawDestination -Variables $Variables
  $RelativeDirectory = $null
  if ($RawDestination -match '^(?i)%AppFolder%(?:[\\/](?<tail>.*))?$') {
    $RelativeDirectory = $Matches['tail']
  } elseif ($ResolvedDestination -and $InstallLocation -and $ResolvedDestination.StartsWith($InstallLocation.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    $RelativeDirectory = $ResolvedDestination.Substring($InstallLocation.TrimEnd('\', '/').Length).TrimStart('\', '/')
  } else {
    $Namespace = ($RawDestination -replace '%', '' -replace '^[A-Za-z]:', { 'drive-' + $_.Value[0] } -replace '[<>:"|?*]', '_').TrimStart('\', '/')
    $RelativeDirectory = if ($Namespace) { Join-Path '_destinations' $Namespace } else { '_destinations\unspecified' }
  }
  $RelativePath = if ($RelativeDirectory) { Join-Path $RelativeDirectory $FileName } else { $FileName }
  if ([IO.Path]::IsPathRooted($RelativePath) -or $RelativePath -split '[\\/]' -contains '..') { throw "The Setup Factory installed path '$RelativePath' is unsafe" }
  return $RelativePath.Replace('/', '\')
}

function Get-SetupFactoryDependencyFileCatalog {
  <#
  .SYNOPSIS
    Decode bundled prerequisite records that physically precede installed files.
  .PARAMETER Bytes
    Decompressed irsetup.dat bytes.
  .PARAMETER PayloadDataOffset
    Absolute installer offset immediately after the outer container records.
  .PARAMETER FileLength
    Total installer length used to bound dependency payload ranges.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$PayloadDataOffset,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$FileLength
  )

  $ClassName = 'CDependencyFile'
  $Markers = @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes($ClassName)) -Maximum 32)
  if (-not $Markers.Count) {
    return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $true; PayloadDataEndOffset = $PayloadDataOffset; Error = $null }
  }

  $Candidates = [Collections.Generic.List[object]]::new()
  $Errors = [Collections.Generic.List[string]]::new()
  foreach ($Marker in $Markers) {
    if ($Marker -lt 8) { continue }
    try {
      $Cursor = [ref]([long]$Marker - 8)
      $Count = Read-SetupFactoryDataInteger $Bytes $Cursor 2
      $Sentinel = Read-SetupFactoryDataInteger $Bytes $Cursor 2
      $null = Read-SetupFactoryDataInteger $Bytes $Cursor 2
      $ParsedClassName = Read-SetupFactoryDataString $Bytes $Cursor Big
      if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries -or $Sentinel -ne 0xFFFF -or $ParsedClassName -cne $ClassName) { continue }

      $PayloadOffset = $PayloadDataOffset
      $Entries = [Collections.Generic.List[object]]::new()
      for ($Index = 0; $Index -lt $Count; $Index++) {
        # CDependencyFile begins with a four-byte object/version field. It is structural framing;
        # prerequisite execution policy is not inferred from this value.
        Move-SetupFactoryDataOffset $Bytes $Cursor 4
        $SourcePath = Read-SetupFactoryDataString $Bytes $Cursor Small
        $ExpandedSize = Read-SetupFactoryDataInteger $Bytes $Cursor 8
        $PackedSize = Read-SetupFactoryDataInteger $Bytes $Cursor 8
        $RepeatedSourcePath = Read-SetupFactoryDataString $Bytes $Cursor Small
        $null = Read-SetupFactoryDataInteger $Bytes $Cursor 2
        $Label = Read-SetupFactoryDataString $Bytes $Cursor Small
        if ([string]::IsNullOrWhiteSpace($SourcePath) -or $SourcePath -cne $RepeatedSourcePath) { throw 'The Setup Factory dependency-file paths are malformed' }
        if ($PackedSize -le 0 -or $ExpandedSize -le 0 -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes -or $ExpandedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The Setup Factory dependency-file size is invalid' }
        if ($PackedSize -gt $FileLength - $PayloadOffset) { throw 'The Setup Factory dependency-file payload is outside the installer' }
        $FileName = [IO.Path]::GetFileName($SourcePath.Replace('/', '\'))
        if ([string]::IsNullOrWhiteSpace($FileName)) { throw 'The Setup Factory dependency-file name is empty' }
        $Entries.Add([pscustomobject][ordered]@{
            Name = Join-Path '_dependencies' $FileName; FileName = $FileName; SourcePath = $SourcePath; Label = $Label
            Kind = 'DependencyPayload'; DataOffset = $PayloadOffset; PackedSize = $PackedSize; ExpandedSize = $ExpandedSize
            IsCompressed = $PackedSize -ne $ExpandedSize; IsXored = $false; IsEmbedded = $true; Crc32 = [uint32]0
          })
        $PayloadOffset += $PackedSize
        if ($Index -lt $Count - 1) {
          # MFC object-list framing inserts a two-byte separator between dependency records.
          Move-SetupFactoryDataOffset $Bytes $Cursor 2
        }
      }
      $Candidates.Add([pscustomobject][ordered]@{ Entries = $Entries.ToArray(); IsComplete = $true; PayloadDataEndOffset = $PayloadOffset; Error = $null })
    } catch {
      $Errors.Add($_.Exception.Message)
    }
  }

  if ($Candidates.Count -eq 1) { return $Candidates[0] }
  if ($Candidates.Count -gt 1) { return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $false; PayloadDataEndOffset = $PayloadDataOffset; Error = 'Multiple structurally valid dependency-file tables were found' } }
  return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $false; PayloadDataEndOffset = $PayloadDataOffset; Error = ($Errors | Select-Object -First 1) }
}

function Get-SetupFactoryInstalledFileCatalog {
  <#
  .SYNOPSIS
    Decode the generation-specific installed-file table and assign physical payload ranges.
  .PARAMETER Bytes
    Decompressed irsetup.dat bytes.
  .PARAMETER Catalog
    Validated outer catalog whose PayloadDataOffset points at the first installed-file payload.
  .PARAMETER Variables
    Parsed session variables used only for deterministic destination projection.
  .PARAMETER PayloadDataOffset
    Absolute installer offset after any bundled prerequisite payloads.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][psobject]$Catalog,
    [Parameter(Mandatory)][hashtable]$Variables,
    [ValidateRange(0, [long]::MaxValue)][long]$PayloadDataOffset = $Catalog.PayloadDataOffset
  )

  $ProfileId = [string]$Catalog.Overlay.ProfileId
  $ClassName = $ProfileId -in 'setup-factory-4', 'setup-factory-5', 'setup-factory-6' ? 'CFileInfo' : 'CSetupFileData'
  $Markers = @(Find-BinaryPattern -Bytes $Bytes -Pattern ([Text.Encoding]::ASCII.GetBytes($ClassName)) -Maximum 32)
  if (-not $Markers.Count) {
    return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $false; CanExtract = $false; CanExtractPartial = $false; ExtractableEntryCount = 0; UnavailableEntryCount = 0; ClassName = $ClassName; DeclaredPayloadBytes = $null; PayloadDataEndOffset = $null; Error = "The $ClassName table was not found" }
  }

  $Errors = [Collections.Generic.List[string]]::new()
  $Candidates = [Collections.Generic.List[object]]::new()
  foreach ($Marker in $Markers) {
    if ($Marker -lt 8) { continue }
    try {
      $HeaderOffset = [ref]([long]$Marker - 8)
      $Count = Read-SetupFactoryDataInteger $Bytes $HeaderOffset 2
      $Sentinel = Read-SetupFactoryDataInteger $Bytes $HeaderOffset 2
      $SubType = Read-SetupFactoryDataInteger $Bytes $HeaderOffset 2
      $ParsedClassName = Read-SetupFactoryDataString $Bytes $HeaderOffset Big
      if ($Count -gt $Script:SetupFactoryMaximumEntries -or $Sentinel -ne 0xFFFF -or $ParsedClassName -cne $ClassName) { continue }
      $LayoutCandidates = if ($ProfileId -eq 'setup-factory-8-plus') {
        @(
          [pscustomobject]@{ DestinationPolicyLength = 10; HasAppUserModelID = $false }
          [pscustomobject]@{ DestinationPolicyLength = 11; HasAppUserModelID = $false }
          [pscustomobject]@{ DestinationPolicyLength = 11; HasAppUserModelID = $true }
        )
      } else {
        @([pscustomobject]@{ DestinationPolicyLength = 0; HasAppUserModelID = $false })
      }
      foreach ($Layout in $LayoutCandidates) {
        try {
          $Cursor = [ref]([long]$HeaderOffset.Value)
          $Records = [Collections.Generic.List[object]]::new()
          if ($ProfileId -eq 'setup-factory-8-plus') {
            # The first modern record follows the table's class descriptor directly. Later
            # records add a two-byte MFC class reference before the same schema/field-reference pair.
            $RecordSchema = Read-SetupFactoryDataInteger $Bytes $Cursor 4
            if ($RecordSchema -ne 1) { throw "Unsupported Setup Factory CSetupFileData schema '$RecordSchema'" }
            $null = Read-SetupFactoryDataBoolean $Bytes $Cursor 'FieldReference'
          }
          for ($Index = 0; $Index -lt $Count; $Index++) {
            $Record = switch ($ProfileId) {
              'setup-factory-4' { Read-SetupFactoryFileRecord4 $Bytes $Cursor $SubType }
              'setup-factory-5' { Read-SetupFactoryFileRecord5 $Bytes $Cursor }
              'setup-factory-6' { Read-SetupFactoryFileRecord6 $Bytes $Cursor }
              'setup-factory-7' { Read-SetupFactoryFileRecord7 $Bytes $Cursor }
              'setup-factory-8-plus' { Read-SetupFactoryFileRecord8Plus $Bytes $Cursor $Layout.DestinationPolicyLength $Layout.HasAppUserModelID }
              default { throw "Unsupported Setup Factory installed-file profile '$ProfileId'" }
            }
            $Records.Add($Record)
            if ($Index -lt $Count - 1 -and $ProfileId -in 'setup-factory-4', 'setup-factory-5', 'setup-factory-7') {
              # These MFC generations serialize a two-byte object-list separator between records.
              Move-SetupFactoryDataOffset $Bytes $Cursor 2
            } elseif ($Index -lt $Count - 1 -and $ProfileId -eq 'setup-factory-8-plus') {
              $ClassReference = Read-SetupFactoryDataInteger $Bytes $Cursor 2
              if (($ClassReference -band 0x8000) -eq 0) { throw 'The Setup Factory CSetupFileData class reference is malformed' }
              $RecordSchema = Read-SetupFactoryDataInteger $Bytes $Cursor 4
              if ($RecordSchema -ne 1) { throw "Unsupported Setup Factory CSetupFileData schema '$RecordSchema'" }
              $null = Read-SetupFactoryDataBoolean $Bytes $Cursor 'FieldReference'
            }
          }

          $PayloadOffset = $PayloadDataOffset
          $DeclaredPayloadBytes = 0L
          foreach ($Record in $Records) { $DeclaredPayloadBytes += $Record.PackedSize }
          $PayloadLayoutEnded = $false
          $ExtractableEntryCount = 0
          $Projected = [Collections.Generic.List[object]]::new()
          foreach ($Record in $Records) {
            # Some web/primer media contains a valid sequential prefix followed by catalog-only
            # records. Once one record no longer fits, later records cannot be assigned offsets:
            # skipping the missing record would incorrectly reinterpret its truncated bytes.
            $HasPhysicalRange = -not $PayloadLayoutEnded -and $Record.PackedSize -le $Catalog.FileLength - $PayloadOffset
            if (-not $HasPhysicalRange) { $PayloadLayoutEnded = $true }
            $Record.IsEmbedded = $HasPhysicalRange
            $Record | Add-Member -NotePropertyName DataOffset -NotePropertyValue ($HasPhysicalRange ? $PayloadOffset : $null)
            $Record.Name = ConvertTo-SetupFactoryPayloadRelativePath -FileName $Record.FileName -DestinationPath $Record.DestinationPath -Variables $Variables -InstallLocation (Resolve-SetupFactoryVariable -Value '%AppFolder%' -Variables $Variables)
            $Record | Add-Member -NotePropertyName Kind -NotePropertyValue 'InstalledFile'
            $Projected.Add($Record)
            if ($HasPhysicalRange) {
              $PayloadOffset += $Record.PackedSize
              $ExtractableEntryCount++
            }
          }
          $UnavailableEntryCount = $Records.Count - $ExtractableEntryCount
          $CanExtract = $UnavailableEntryCount -eq 0
          $Candidates.Add([pscustomobject][ordered]@{
              Entries = $Projected.ToArray(); IsComplete = $true; CanExtract = $CanExtract; CanExtractPartial = $ExtractableEntryCount -gt 0 -and -not $CanExtract; ExtractableEntryCount = $ExtractableEntryCount; UnavailableEntryCount = $UnavailableEntryCount; ClassName = $ClassName; ClassOffset = $Marker - 8
              RecordEndOffset = $Cursor.Value; DestinationPolicyLength = $Layout.DestinationPolicyLength ? $Layout.DestinationPolicyLength : $null
              HasAppUserModelID = [bool]$Layout.HasAppUserModelID
              DeclaredPayloadBytes = $DeclaredPayloadBytes; PayloadDataEndOffset = $ExtractableEntryCount ? $PayloadOffset : $null; Error = $null
            })
        } catch { $Errors.Add($_.Exception.Message) }
      }
    } catch { $Errors.Add($_.Exception.Message) }
  }

  $UniqueCandidates = @($Candidates | Sort-Object ClassOffset, DestinationPolicyLength, HasAppUserModelID -Unique)
  if ($UniqueCandidates.Count -eq 1) { return $UniqueCandidates[0] }
  if ($UniqueCandidates.Count -gt 1) {
    # Prefer a layout whose file records map to a bounded sequential payload. If neither
    # candidate does, the longest structurally decoded table remains useful catalog evidence.
    $Best = @($UniqueCandidates | Sort-Object CanExtract, ExtractableEntryCount, RecordEndOffset -Descending)
    if ($Best.Count -eq 1 -or ($Best[0].CanExtract -and -not $Best[1].CanExtract) -or $Best[0].ExtractableEntryCount -gt $Best[1].ExtractableEntryCount -or $Best[0].RecordEndOffset -gt $Best[1].RecordEndOffset) { return $Best[0] }
    return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $false; CanExtract = $false; CanExtractPartial = $false; ExtractableEntryCount = 0; UnavailableEntryCount = 0; ClassName = $ClassName; DeclaredPayloadBytes = $null; PayloadDataEndOffset = $null; Error = 'Multiple structurally valid installed-file table layouts were found' }
  }
  return [pscustomobject][ordered]@{ Entries = @(); IsComplete = $false; CanExtract = $false; CanExtractPartial = $false; ExtractableEntryCount = 0; UnavailableEntryCount = 0; ClassName = $ClassName; DeclaredPayloadBytes = $null; PayloadDataEndOffset = $null; Error = ($Errors | Select-Object -First 1) }
}

function Get-SetupFactoryFilePolicySummary {
  <#
  .SYNOPSIS
    Summarize behavior-affecting file policy across a decoded installed-file catalog.
  .PARAMETER Entry
    Installed-file records returned by Get-SetupFactoryInstalledFileCatalog.
  #>
  [OutputType([pscustomobject])]
  param ([AllowEmptyCollection()][object[]]$Entry)

  $AskUserOverwrite = [Collections.Generic.List[string]]::new()
  $UnknownOverwrite = [Collections.Generic.List[string]]::new()
  $Conditional = [Collections.Generic.List[string]]::new()
  $SelfRegistering = [Collections.Generic.List[string]]::new()
  $FontRegistration = [Collections.Generic.List[string]]::new()
  $SuppressInUse = [Collections.Generic.List[string]]::new()
  $NeverRemove = [Collections.Generic.List[string]]::new()
  $Shared = [Collections.Generic.List[string]]::new()
  $StoreOnly = [Collections.Generic.List[string]]::new()
  $Shortcuts = [Collections.Generic.List[string]]::new()
  $Protected = [Collections.Generic.List[string]]::new()
  $Backup = [Collections.Generic.List[string]]::new()
  $CrcDisabled = [Collections.Generic.List[string]]::new()

  foreach ($File in @($Entry)) {
    if ($null -eq $File.Policy) { continue }
    $Policy = $File.Policy
    if ($Policy.OverwritePolicy -ceq 'AskUser') { $AskUserOverwrite.Add($File.Name) }
    elseif ($null -ne $Policy.OverwriteMode -and $null -eq $Policy.OverwritePolicy) { $UnknownOverwrite.Add($File.Name) }

    $OperatingSystemConditions = @($Policy.OperatingSystemConditions)
    $HasNonDefaultOperatingSystemCondition = $OperatingSystemConditions.Count -gt 0 -and ($OperatingSystemConditions[0] -ne 0x8000 -or @($OperatingSystemConditions | Select-Object -Skip 1 | Where-Object { $_ -ne 0xFFFF }).Count -gt 0)
    $HasPackageSelection = -not [string]::IsNullOrWhiteSpace([string]$Policy.PackageSelector) -and $Policy.PackageSelector -cne 'None'
    $HasLegacyOperatingSystemCondition = $null -ne $Policy.LegacyOperatingSystemPolicy -and $Policy.LegacyOperatingSystemPolicy.IsRestricted
    $HasLegacyLanguageCondition = $null -ne $Policy.LegacyLanguageCondition -and $Policy.LegacyLanguageCondition -ne 0
    $HasLegacyAdvancedCondition = @($Policy.LegacyAdvancedConditions).Count -gt 0
    if (-not [string]::IsNullOrWhiteSpace([string]$Policy.RuntimeCondition) -or $HasNonDefaultOperatingSystemCondition -or $HasPackageSelection -or @($File.Packages).Count -gt 0 -or @($Policy.LegacySelectionValues).Count -gt 0 -or $HasLegacyOperatingSystemCondition -or $HasLegacyLanguageCondition -or $HasLegacyAdvancedCondition) { $Conditional.Add($File.Name) }
    if ($Policy.RegisterWithDllRegisterServer -or $Policy.RegisterTypeLibrary) { $SelfRegistering.Add($File.Name) }
    if ($Policy.RegisterTrueTypeFont) { $FontRegistration.Add($File.Name) }
    if ($Policy.SuppressInUseNotice) { $SuppressInUse.Add($File.Name) }
    if ($Policy.NeverRemove) { $NeverRemove.Add($File.Name) }
    if ($Policy.SharedSystemFile) { $Shared.Add($File.Name) }
    if ($Policy.StoreOnly) { $StoreOnly.Add($File.Name) }
    if (@($Policy.ShortcutLocations).Count -gt 0) { $Shortcuts.Add($File.Name) }
    if ($Policy.ProtectFile) { $Protected.Add($File.Name) }
    if ($Policy.CreateBackup) { $Backup.Add($File.Name) }
    if ($Policy.DisableCrcCheck) { $CrcDisabled.Add($File.Name) }
  }

  [pscustomobject][ordered]@{
    EntryCount                 = @($Entry).Count
    AskUserOverwriteEntries    = $AskUserOverwrite.ToArray()
    UnknownOverwriteEntries    = $UnknownOverwrite.ToArray()
    ConditionalEntries         = $Conditional.ToArray()
    SelfRegisteringEntries     = $SelfRegistering.ToArray()
    FontRegistrationEntries    = $FontRegistration.ToArray()
    SuppressInUseNoticeEntries = $SuppressInUse.ToArray()
    NeverRemoveEntries         = $NeverRemove.ToArray()
    SharedSystemFileEntries    = $Shared.ToArray()
    StoreOnlyEntries           = $StoreOnly.ToArray()
    ShortcutEntries            = $Shortcuts.ToArray()
    ProtectedEntries           = $Protected.ToArray()
    BackupEntries              = $Backup.ToArray()
    CrcCheckDisabledEntries    = $CrcDisabled.ToArray()
  }
}

function Read-SetupFactoryInstalledFileData {
  <#
  .SYNOPSIS
    Read, decompress, and verify one installed-file payload.
  .PARAMETER Stream
    Caller-owned installer stream.
  .PARAMETER Entry
    Installed-file record returned by Get-SetupFactoryInstalledFileCatalog.
  .PARAMETER MaximumBytes
    Maximum permitted expanded bytes.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][psobject]$Entry, [Parameter(Mandatory)][long]$MaximumBytes)

  if (-not $Entry.IsEmbedded -or $null -eq $Entry.DataOffset) { throw "The physical payload offset for Setup Factory file '$($Entry.Name)' is not proven" }
  if ($Entry.ExpandedSize -gt $MaximumBytes) { throw "The Setup Factory installed file '$($Entry.Name)' exceeds the configured limit" }
  $Stream.Position = $Entry.DataOffset
  $Packed = Read-SetupFactoryExactByte -Stream $Stream -Count ([int]$Entry.PackedSize)
  if ($Entry.PackedSize -eq 0) {
    # Legacy projects can deliberately install an empty placeholder file while retaining the
    # record's compression flag. No compressed member exists in that case.
    if ($Entry.ExpandedSize -ne 0) { throw "The Setup Factory installed file '$($Entry.Name)' has no packed data for its declared expanded size" }
    [byte[]]$Expanded = [byte[]]::new(0)
  } elseif ($Entry.IsCompressed) {
    [byte[]]$Expanded = Expand-SetupFactoryCompressedData -Bytes $Packed -MaximumBytes $MaximumBytes
  } else {
    [byte[]]$Expanded = $Packed
  }
  if ($Expanded.LongLength -ne $Entry.ExpandedSize) { throw "The Setup Factory installed file '$($Entry.Name)' has an unexpected expanded size" }
  if ($Entry.Crc32 -ne 0 -and (Get-SetupFactoryCrc32 $Expanded) -ne $Entry.Crc32) { throw "The Setup Factory installed file '$($Entry.Name)' failed its CRC check" }
  return , $Expanded
}

function Test-SetupFactoryLegacyCatalog {
  <#
  .SYNOPSIS
    Validate a Setup Factory 4, 5, or 6 outer catalog without decoding entries.
  .PARAMETER Stream
    Caller-owned installer stream. The original position is restored before return.
  .PARAMETER OverlayOffset
    Absolute offset of the first generation-signature byte.
  .PARAMETER CountInSignature
    Read the version 4 entry count from overlay byte 7 instead of a uint32 after the full signature.
  .PARAMETER NameSize
    Fixed catalog-name width in bytes: 16 for versions 4 and 5, or 260 for version 6.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][ValidateRange(0, [long]::MaxValue)][long]$OverlayOffset,
    [switch]$CountInSignature,
    [Parameter(Mandatory)][ValidateSet(16, 260)][int]$NameSize
  )

  $OriginalPosition = $Stream.Position
  try {
    $Stream.Position = $OverlayOffset + ($CountInSignature ? 7 : 8)
    $Count = if ($CountInSignature) { $Stream.ReadByte() } else { Read-SetupFactoryUInt32 -Stream $Stream }
    if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { return $false }
    $HasScript = $false
    for ($EntryIndex = 0; $EntryIndex -lt $Count; $EntryIndex++) {
      if ($NameSize + 8 -gt $Stream.Length - $Stream.Position) { return $false }
      $Name = (ConvertFrom-SetupFactoryText -Bytes (Read-SetupFactoryExactByte -Stream $Stream -Count $NameSize)).Split("`0", 2)[0]
      if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { return $false }
      if ($Name -ceq 'irsetup.dat') { $HasScript = $true }
      $PackedSize = [long](Read-SetupFactoryUInt32 -Stream $Stream)
      $null = Read-SetupFactoryUInt32 -Stream $Stream
      if ($PackedSize -lt 0 -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes -or $PackedSize -gt $Stream.Length - $Stream.Position) { return $false }
      $Stream.Position += $PackedSize
    }
    return $HasScript
  } catch {
    return $false
  } finally {
    $Stream.Position = $OriginalPosition
  }
}

function Import-SetupFactoryCrusherDecoder {
  <#
  .SYNOPSIS
    Load the bounded Crusher LH5 decoder used by Setup Factory 3.1 media.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.CrusherLh5Decoder').Type) { return }
  $SourcePath = Join-Path $PSScriptRoot '..\..\Assets\Source\SetupFactory\CrusherLh5Decoder.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.CrusherLh5Decoder'
}

function Read-SetupFactory31DuplicatedString {
  <#
  .SYNOPSIS
    Read one Setup Factory 3.1 string whose 16-bit byte length is serialized twice.
  .PARAMETER Bytes
    Complete decompressed IRDATA.DAT byte array.
  .PARAMETER Offset
    Mutable zero-based cursor. The value advances past both lengths and the string bytes.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][ref]$Offset)

  $Cursor = [int]$Offset.Value
  if ($Cursor -lt 0 -or $Cursor + 4 -gt $Bytes.Length) { throw 'A Setup Factory 3.1 string header is truncated' }
  $FirstLength = [BitConverter]::ToUInt16($Bytes, $Cursor)
  $SecondLength = [BitConverter]::ToUInt16($Bytes, $Cursor + 2)
  if ($FirstLength -ne $SecondLength) { throw 'A Setup Factory 3.1 duplicated string length does not match' }
  if ($FirstLength -gt $Script:SetupFactoryMaximumScriptStringBytes -or $FirstLength -gt $Bytes.Length - $Cursor - 4) { throw 'A Setup Factory 3.1 string exceeds its bounded record' }
  $Value = ConvertFrom-SetupFactoryText -Bytes $Bytes -Offset ($Cursor + 4) -Count $FirstLength
  $Offset.Value = $Cursor + 4 + $FirstLength
  return $Value
}

function Get-SetupFactory31ArqCatalog {
  <#
  .SYNOPSIS
    Parse the Crusher ARQ archive stored as Setup Factory 3.1 IRDATA.IRD.
  .PARAMETER Path
    Path to IRDATA.IRD. Returned offsets are absolute within this file.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
  $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
  $Entries = [Collections.Generic.List[object]]::new()
  $TotalExpandedBytes = 0L
  try {
    while ($true) {
      $RecordOffset = $Stream.Position
      if (41 -gt $Stream.Length - $RecordOffset) { throw 'The Setup Factory 3.1 Crusher catalog is truncated' }
      $Prefix = Read-SetupFactoryExactByte -Stream $Stream -Count 8
      if (-not (Test-BinarySequence -Left $Prefix[0..3] -Right ([byte[]](0x67, 0x57, 0x04, 0x01)))) { throw "The Setup Factory 3.1 Crusher record at offset $RecordOffset has invalid magic" }
      $ArchiveVersion = [BitConverter]::ToUInt16($Prefix, 4)
      if ($ArchiveVersion -ne 0x1230) { throw "Unsupported Setup Factory 3.1 Crusher archive version 0x$($ArchiveVersion.ToString('X4'))" }
      $NameLength = [BitConverter]::ToUInt16($Prefix, 6)
      if ($NameLength -gt 260 -or $NameLength -gt $Stream.Length - $Stream.Position - 33) { throw 'A Setup Factory 3.1 Crusher filename is invalid or truncated' }
      $Name = if ($NameLength) { ConvertFrom-SetupFactoryText -Bytes (Read-SetupFactoryExactByte -Stream $Stream -Count $NameLength) } else { '' }
      $Descriptor = Read-SetupFactoryExactByte -Stream $Stream -Count 33

      # An empty name is the 41-byte end record. Its other fields are a runtime-owned template and
      # are deliberately ignored rather than assigned semantics.
      if ($NameLength -eq 0) {
        if ($Stream.Position -ne $Stream.Length) { throw 'The Setup Factory 3.1 Crusher archive contains data after its end record' }
        break
      }
      if ([string]::IsNullOrWhiteSpace($Name) -or $Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'A Setup Factory 3.1 Crusher record has an invalid filename' }

      $PackedSize = [long][BitConverter]::ToUInt32($Descriptor, 10)
      $ExpandedSize = [long][BitConverter]::ToUInt32($Descriptor, 14)
      $Crc32 = [BitConverter]::ToUInt32($Descriptor, 18)
      $Method = $Descriptor[22]
      if ($Method -notin 1, 2) { throw "Setup Factory 3.1 Crusher record '$Name' uses unsupported method $Method" }
      if ($Method -eq 1 -and $PackedSize -ne $ExpandedSize) { throw "Stored Setup Factory 3.1 Crusher record '$Name' has inconsistent sizes" }
      if ($PackedSize -gt $Script:SetupFactoryMaximumFileBytes -or $ExpandedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw "Setup Factory 3.1 Crusher record '$Name' exceeds the per-file limit" }
      if ($PackedSize -gt $Stream.Length - $Stream.Position) { throw "Setup Factory 3.1 Crusher record '$Name' is truncated" }
      $TotalExpandedBytes += $ExpandedSize
      if ($TotalExpandedBytes -gt $Script:SetupFactoryMaximumExpandedBytes) { throw 'The Setup Factory 3.1 Crusher catalog exceeds the total expansion limit' }

      $Entries.Add([pscustomobject][ordered]@{
          Name            = $Name
          Kind            = $Name -ieq 'IRDATA.DAT' ? 'Metadata' : ($Name -ieq 'IRSETUP.EXE' ? 'Runtime' : ($Name -ieq 'IRUNIN31.EXE' ? 'UninstallerRuntime' : 'ContainerEntry'))
          SourcePath      = $File.FullName
          RecordOffset    = $RecordOffset
          DataOffset      = $Stream.Position
          PackedSize      = $PackedSize
          ExpandedSize    = $ExpandedSize
          Crc32           = [uint32]$Crc32
          CrcTarget       = 'Packed'
          Compression     = $Method -eq 1 ? 'Stored' : 'CrusherLh5'
          CompressionCode = $Method
          FileMode        = [char]$Descriptor[0]
          Attributes      = $Descriptor[1]
          DosDateTime     = [BitConverter]::ToUInt32($Descriptor, 2)
          IsEmbedded      = $true
        })
      $Stream.Position += $PackedSize
      if ($Entries.Count -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory 3.1 Crusher catalog exceeds the entry-count limit' }
    }
  } finally {
    $Stream.Dispose()
  }

  if (@($Entries | Where-Object Name -CEQ 'IRDATA.DAT').Count -ne 1 -or @($Entries | Where-Object Name -CEQ 'IRSETUP.EXE').Count -ne 1) { throw 'The Crusher archive is not a Setup Factory 3.1 bootstrap catalog' }
  [pscustomobject][ordered]@{
    Path               = $File.FullName
    FileLength         = $File.Length
    ArchiveVersion     = 0x1230
    Entries            = $Entries.ToArray()
    TotalExpandedBytes = $TotalExpandedBytes
  }
}

function Copy-SetupFactory31EntryData {
  <#
  .SYNOPSIS
    Decode one validated Setup Factory 3.1 ARQ or companion-file record.
  .PARAMETER Entry
    Entry returned by Get-SetupFactory31ArqCatalog or Read-SetupFactory31ProjectData.
  .PARAMETER Destination
    Caller-owned writable and seekable output stream. It must be empty on entry.
  .PARAMETER MaximumBytes
    Maximum permitted expanded output in bytes.
  #>
  [OutputType([long])]
  param ([Parameter(Mandatory)][psobject]$Entry, [Parameter(Mandatory)][IO.Stream]$Destination, [Parameter(Mandatory)][long]$MaximumBytes)

  if (-not $Destination.CanWrite -or -not $Destination.CanSeek -or $Destination.Length -ne 0) { throw 'Setup Factory 3.1 extraction requires an empty writable and seekable destination stream' }
  if (-not $Entry.SourcePath -or -not (Test-Path -LiteralPath $Entry.SourcePath -PathType Leaf)) { throw "Setup Factory 3.1 source media for '$($Entry.Name)' is unavailable" }
  if ($Entry.ExpandedSize -gt $MaximumBytes) { throw "Setup Factory 3.1 entry '$($Entry.Name)' exceeds the configured limit" }
  Import-SetupFactoryCrusherDecoder
  $Source = [IO.File]::Open($Entry.SourcePath, 'Open', 'Read', 'ReadWrite')
  try {
    if ($Entry.CrcTarget -eq 'Packed') {
      $PackedView = New-BoundedReadStream -Stream $Source -Offset $Entry.DataOffset -Length $Entry.PackedSize -LeaveOpen
      try { $ActualPackedCrc = Get-BinaryCrc32 -Stream $PackedView -MaximumBytes $Entry.PackedSize }
      finally { $PackedView.Dispose() }
      if ($ActualPackedCrc -ne $Entry.Crc32) { throw "Setup Factory 3.1 entry '$($Entry.Name)' failed its packed CRC32 check" }
    }
    if ($Entry.Compression -eq 'Stored') {
      $Source.Position = $Entry.DataOffset
      $null = Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes $MaximumBytes -ExpectedBytes $Entry.ExpandedSize
    } elseif ($Entry.Compression -eq 'CrusherLh5') {
      $null = [Dumplings.InstallerParsers.CrusherLh5Decoder]::Decode($Source, $Entry.DataOffset, $Entry.PackedSize, $Destination, $Entry.ExpandedSize, $MaximumBytes)
    } elseif ($Entry.Compression -eq 'CrusherLh5Extended') {
      $null = [Dumplings.InstallerParsers.CrusherLh5Decoder]::DecodeSetupFactory31($Source, $Entry.DataOffset, $Entry.PackedSize, $Destination, $Entry.ExpandedSize, $MaximumBytes)
    } else {
      throw "Setup Factory 3.1 entry '$($Entry.Name)' has unsupported compression '$($Entry.Compression)'"
    }
  } finally {
    $Source.Dispose()
  }
  if ($Destination.Length -ne $Entry.ExpandedSize) { throw "Setup Factory 3.1 entry '$($Entry.Name)' has an unexpected expanded size" }
  $Destination.Flush()
  if ($Entry.CrcTarget -ne 'Packed') {
    $Destination.Position = 0
    $ActualCrc = Get-BinaryCrc32 -Stream $Destination -MaximumBytes $MaximumBytes
    if ($ActualCrc -ne $Entry.Crc32) { throw "Setup Factory 3.1 entry '$($Entry.Name)' failed its expanded CRC32 check" }
  }
  $Destination.Position = $Destination.Length
  return $Destination.Length
}

function Read-SetupFactory31ArqEntryData {
  <#
  .SYNOPSIS
    Materialize one small Setup Factory 3.1 ARQ entry for metadata analysis.
  .PARAMETER Entry
    ARQ entry returned by Get-SetupFactory31ArqCatalog.
  .PARAMETER MaximumBytes
    Maximum permitted expanded output in bytes.
  #>
  [OutputType([byte[]])]
  param ([Parameter(Mandatory)][psobject]$Entry, [Parameter(Mandatory)][long]$MaximumBytes)

  $Output = [IO.MemoryStream]::new()
  try {
    $null = Copy-SetupFactory31EntryData -Entry $Entry -Destination $Output -MaximumBytes $MaximumBytes
    return , $Output.ToArray()
  } finally {
    $Output.Dispose()
  }
}

function Read-SetupFactory31ProjectData {
  <#
  .SYNOPSIS
    Decode Setup Factory 3.1 identity and installed-file records from IRDATA.DAT.
  .PARAMETER Bytes
    Complete CRC-validated IRDATA.DAT bytes.
  .PARAMETER MediaRoot
    Directory containing the companion compressed payload files.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][byte[]]$Bytes, [Parameter(Mandatory)][string]$MediaRoot)

  if ($Bytes.Length -lt 32 -or -not (Test-BinarySequence -Left $Bytes[0..3] -Right ([byte[]](0x3A, 0xD0, 0x00, 0x7B))) -or [BitConverter]::ToUInt32($Bytes, 4) -ne 0x00000000ABCD1234) { throw 'IRDATA.DAT does not contain the Setup Factory 3.1 project header' }
  $FormatMajor = [BitConverter]::ToUInt16($Bytes, 8)
  $FormatMinor = [BitConverter]::ToUInt16($Bytes, 10)
  $FormatRevision = [BitConverter]::ToUInt16($Bytes, 12)
  if ($FormatMajor -ne 3 -or $FormatMinor -ne 1) { throw "Unsupported multi-file Setup Factory metadata version $FormatMajor.$FormatMinor.$FormatRevision" }

  $ProductMarker = [byte[]](0x3A, 0xD2, 0x00, 0x7B)
  $ProductOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $ProductMarker -Maximum 2)
  if ($ProductOffsets.Count -ne 1) { throw 'Setup Factory 3.1 metadata does not contain exactly one product record' }
  $Cursor = [int]$ProductOffsets[0] + 4
  $SourceDirectory = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
  $ProductName = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
  $ProgramGroup = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
  $InstallLocation = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
  $SourceDrive = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
  if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -ne 0x7D) { throw 'The Setup Factory 3.1 product record is malformed' }

  $GroupMarker = [byte[]](0x3A, 0x01, 0x80, 0x7B)
  $GroupOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $GroupMarker -Maximum 2)
  if ($GroupOffsets.Count -ne 1) { throw 'Setup Factory 3.1 metadata does not contain exactly one installed-file group' }
  $Cursor = [int]$GroupOffsets[0] + 4
  if ($Cursor + 2 -gt $Bytes.Length) { throw 'The Setup Factory 3.1 installed-file count is truncated' }
  $FileCount = [BitConverter]::ToUInt16($Bytes, $Cursor)
  $Cursor += 2
  if ($FileCount -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory 3.1 installed-file count exceeds the configured limit' }

  # SF3.1 writes every companion beside IRDATA.IRD. Enumerating only that directory prevents an unrelated subtree from becoming media evidence or forcing an unbounded PowerShell array.
  $AvailableFiles = [Collections.Generic.List[IO.FileInfo]]::new()
  foreach ($AvailablePath in [IO.Directory]::EnumerateFiles($MediaRoot, '*', [IO.SearchOption]::TopDirectoryOnly)) {
    $AvailableFiles.Add([IO.FileInfo]::new($AvailablePath))
    if ($AvailableFiles.Count -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory 3.1 media directory contains too many files' }
  }
  $Entries = [Collections.Generic.List[object]]::new()
  $TotalExpandedBytes = 0L
  for ($Index = 0; $Index -lt $FileCount; $Index++) {
    if ($Cursor + 4 -gt $Bytes.Length -or -not (Test-BinarySequence -Left $Bytes[$Cursor..($Cursor + 3)] -Right ([byte[]](0x3A, 0xC8, 0x00, 0x7B)))) { throw "Setup Factory 3.1 installed-file record $Index has invalid framing" }
    $Cursor += 4
    $ProjectSourcePath = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
    $InstallName = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
    if ($Cursor + 39 -gt $Bytes.Length) { throw "Setup Factory 3.1 installed-file record '$InstallName' is truncated" }
    $DosDateTime = [BitConverter]::ToUInt32($Bytes, $Cursor); $Cursor += 4
    $ExpandedSize = [long][BitConverter]::ToUInt32($Bytes, $Cursor); $Cursor += 4
    $FileAttributes = $Bytes[$Cursor]
    $CreateShortcut = $Bytes[$Cursor + 1] -ne 0
    $RecordFlags = $Bytes[$Cursor + 2]
    $Cursor += 3
    $ShortName = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
    if ($Cursor + 28 -gt $Bytes.Length) { throw "Setup Factory 3.1 installed-file record '$InstallName' has a truncated policy block" }
    $PolicyBytes = $Bytes[$Cursor..($Cursor + 27)]; $Cursor += 28
    $Description = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
    $MediaName = Read-SetupFactory31DuplicatedString -Bytes $Bytes -Offset ([ref]$Cursor)
    if ($Cursor + 30 -gt $Bytes.Length) { throw "Setup Factory 3.1 installed-file record '$InstallName' has a truncated payload descriptor" }
    $Crc32 = [BitConverter]::ToUInt32($Bytes, $Cursor); $Cursor += 4
    $PackedSize = [long][BitConverter]::ToUInt32($Bytes, $Cursor); $Cursor += 4
    $PayloadFlags = $Bytes[$Cursor..($Cursor + 21)]; $Cursor += 22
    if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -ne 0x7D) { throw "Setup Factory 3.1 installed-file record '$InstallName' has no closing marker" }
    $Cursor++
    if ([string]::IsNullOrWhiteSpace($InstallName) -or [string]::IsNullOrWhiteSpace($MediaName)) { throw 'A Setup Factory 3.1 installed-file record has an empty logical or media name' }
    $null = Resolve-SafeExtractionPath -DestinationPath $MediaRoot -RelativePath $InstallName
    if ($ExpandedSize -gt $Script:SetupFactoryMaximumFileBytes -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw "Setup Factory 3.1 installed file '$InstallName' exceeds the per-file limit" }
    $TotalExpandedBytes += $ExpandedSize
    if ($TotalExpandedBytes -gt $Script:SetupFactoryMaximumExpandedBytes) { throw 'The Setup Factory 3.1 installed-file table exceeds the total expansion limit' }

    $MediaFile = try { Resolve-UniqueInstallerFile -Item $AvailableFiles -Pattern $MediaName -BasePath $MediaRoot -Description "Setup Factory 3.1 companion '$MediaName'" } catch { $null }
    $MediaError = if (-not $MediaFile) { 'Missing' } elseif ($MediaFile.Length -ne $PackedSize) { 'SizeMismatch' } else { $null }
    $Entries.Add([pscustomobject][ordered]@{
        Name              = $InstallName.Replace('/', '\')
        Kind              = 'InstalledFile'
        ProjectSourcePath = $ProjectSourcePath
        SourceName        = $MediaName
        SourcePath        = $MediaFile ? $MediaFile.FullName : $null
        DataOffset        = 0L
        PackedSize        = $PackedSize
        ExpandedSize      = $ExpandedSize
        Crc32             = [uint32]$Crc32
        CrcTarget         = 'Expanded'
        Compression       = $PackedSize -eq $ExpandedSize ? 'Stored' : 'CrusherLh5Extended'
        IsCompressed      = $PackedSize -ne $ExpandedSize
        IsEmbedded        = -not $MediaError
        MediaError        = $MediaError
        DosDateTime       = $DosDateTime
        FileAttributes    = $FileAttributes
        CreateShortcut    = $CreateShortcut
        RecordFlags       = $RecordFlags
        ShortName         = $ShortName
        Description       = $Description
        PolicyBytes       = $PolicyBytes
        PayloadFlags      = $PayloadFlags
      })
  }
  if ($Cursor -ge $Bytes.Length -or $Bytes[$Cursor] -ne 0x7D) { throw 'The Setup Factory 3.1 installed-file group has no closing marker' }

  [pscustomobject][ordered]@{
    FormatVersion          = "$FormatMajor.$FormatMinor.$FormatRevision"
    SourceDirectory        = $SourceDirectory
    ProductName            = $ProductName
    ProgramGroup           = $ProgramGroup
    DefaultInstallLocation = $InstallLocation
    SourceDrive            = $SourceDrive
    Entries                = $Entries.ToArray()
    TotalExpandedBytes     = $TotalExpandedBytes
    IsComplete             = @($Entries | Where-Object MediaError).Count -eq 0
  }
}

function Get-SetupFactory31Media {
  <#
  .SYNOPSIS
    Resolve and validate a Setup Factory 3.1 launcher and its companion IRDATA.IRD.
  .PARAMETER Path
    Path to SETUP.EXE or IRDATA.IRD in one Setup Factory 3.1 media directory.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $InputFile = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
  $MediaRoot = $InputFile.Directory.FullName
  $LauncherPath = Join-Path $MediaRoot 'SETUP.EXE'
  $ArchivePath = Join-Path $MediaRoot 'IRDATA.IRD'
  if ($InputFile.Name -ieq 'IRDATA.IRD') { $ArchivePath = $InputFile.FullName }
  elseif ($InputFile.Name -ieq 'SETUP.EXE') { $LauncherPath = $InputFile.FullName }
  else { throw 'Setup Factory 3.1 multi-file parsing requires SETUP.EXE or IRDATA.IRD' }
  if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { throw 'Setup Factory 3.1 companion IRDATA.IRD is missing' }

  if (Test-Path -LiteralPath $LauncherPath -PathType Leaf) {
    $LauncherFile = Get-Item -LiteralPath $LauncherPath -Force
    if ($LauncherFile.Length -gt $Script:SetupFactory31MaximumLauncherBytes) { throw 'The Setup Factory 3.1 launcher exceeds the configured size limit' }
    $LauncherBytes = [IO.File]::ReadAllBytes($LauncherFile.FullName)
    if ($LauncherBytes.Length -lt 64 -or $LauncherBytes[0] -ne 0x4D -or $LauncherBytes[1] -ne 0x5A) { throw 'The Setup Factory 3.1 launcher is not an MZ executable' }
    $NewHeaderOffset = [BitConverter]::ToUInt32($LauncherBytes, 0x3C)
    if ($NewHeaderOffset + 2 -gt $LauncherBytes.Length -or $LauncherBytes[$NewHeaderOffset] -ne 0x4E -or $LauncherBytes[$NewHeaderOffset + 1] -ne 0x45) { throw 'The Setup Factory 3.1 launcher does not contain its expected 16-bit NE runtime' }
    if (@(Find-BinaryPattern -Bytes $LauncherBytes -Pattern ([Text.Encoding]::ASCII.GetBytes('\IRDATA.IRD')) -Maximum 1).Count -ne 1 -or @(Find-BinaryPattern -Bytes $LauncherBytes -Pattern ([Text.Encoding]::ASCII.GetBytes('IRSETUP.EXE')) -Maximum 1).Count -ne 1) { throw 'The NE launcher does not contain the Setup Factory 3.1 companion bootstrap references' }
  } elseif ($InputFile.Name -ieq 'SETUP.EXE') {
    throw 'The Setup Factory 3.1 launcher is missing'
  }

  $ArqCatalog = Get-SetupFactory31ArqCatalog -Path $ArchivePath
  $MetadataEntry = @($ArqCatalog.Entries | Where-Object Name -CEQ 'IRDATA.DAT')
  $MetadataBytes = Read-SetupFactory31ArqEntryData -Entry $MetadataEntry[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
  $Metadata = Read-SetupFactory31ProjectData -Bytes $MetadataBytes -MediaRoot $MediaRoot
  [pscustomobject][ordered]@{
    Path           = $InputFile.FullName
    MediaRoot      = $MediaRoot
    LauncherPath   = (Test-Path -LiteralPath $LauncherPath -PathType Leaf) ? (Get-Item -LiteralPath $LauncherPath).FullName : $null
    ArchivePath    = (Get-Item -LiteralPath $ArchivePath).FullName
    ArchiveCatalog = $ArqCatalog
    Metadata       = $Metadata
  }
}

function Test-SetupFactory31Media {
  <#
  .SYNOPSIS
    Test whether a path belongs to structurally valid Setup Factory 3.1 multi-file media.
  .PARAMETER Path
    Path to SETUP.EXE or IRDATA.IRD.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][string]$Path)
  try { $null = Get-SetupFactory31Media -Path $Path; return $true } catch { return $false }
}

function Expand-SetupFactory31Media {
  <#
  .SYNOPSIS
    Expand installed or raw Setup Factory 3.1 multi-file entries.
  .PARAMETER Media
    Validated media context returned by Get-SetupFactory31Media.
  .PARAMETER DestinationPath
    Root directory for safe extraction.
  .PARAMETER Name
    Exact name or wildcard selecting installed paths, or ARQ member names with RawEntries.
  .PARAMETER RawEntries
    Extract IRDATA.DAT, IRSETUP.EXE, IRUNIN31.EXE, and other physical ARQ members instead of application payloads.
  .PARAMETER CollisionAction
    Behavior applied only when an output collision occurs.
  .PARAMETER MaximumExpandedBytes
    Maximum total number of output bytes.
  #>
  [OutputType([IO.FileInfo[]])]
  param (
    [Parameter(Mandatory)][psobject]$Media,
    [Parameter(Mandatory)][string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawEntries,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [long]$MaximumExpandedBytes = $Script:SetupFactoryMaximumExpandedBytes
  )

  $Entries = $RawEntries ? $Media.ArchiveCatalog.Entries : $Media.Metadata.Entries
  $SelectedEntries = @($Entries | Where-Object { Test-ExtractionPattern -Path $_.Name -Pattern $Name })
  $Missing = @($SelectedEntries | Where-Object { -not $_.IsEmbedded })
  if ($Missing.Count) { throw "The Setup Factory 3.1 media is missing or has an invalid companion for '$($Missing[0].Name)'" }

  $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
  $null = New-Item -ItemType Directory -Path $DestinationPath -Force
  $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Written = 0L
  foreach ($Entry in $SelectedEntries) {
    $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
    if (-not $Target.ShouldWrite) { continue }
    $Remaining = [Math]::Min($MaximumExpandedBytes - $Written, $Script:SetupFactoryMaximumFileBytes)
    if ($Remaining -le 0) { throw 'The Setup Factory 3.1 expansion exceeds the configured limit' }
    $Parent = [IO.Path]::GetDirectoryName($Target.Path)
    if ($Parent) { $null = New-Item -ItemType Directory -Path $Parent -Force }
    $TemporaryPath = "$($Target.Path).Dumplings-$([guid]::NewGuid().ToString('N')).tmp"
    $Output = [IO.File]::Open($TemporaryPath, 'CreateNew', 'ReadWrite', 'None')
    try {
      $Length = Copy-SetupFactory31EntryData -Entry $Entry -Destination $Output -MaximumBytes $Remaining
    } finally {
      $Output.Dispose()
    }
    try {
      $Written += $Length
      if ($Written -gt $MaximumExpandedBytes) { throw 'The Setup Factory 3.1 expansion exceeds the configured limit' }
      [IO.File]::Move($TemporaryPath, $Target.Path, $true)
      Get-Item -LiteralPath $Target.Path
    } finally {
      Remove-Item -LiteralPath $TemporaryPath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-SetupFactory31Info {
  <#
  .SYNOPSIS
    Compose the common parser result for Setup Factory 3.1 multi-file media.
  .PARAMETER Path
    Path to SETUP.EXE or IRDATA.IRD.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $Media = Get-SetupFactory31Media -Path $Path
  $Metadata = $Media.Metadata
  $Diagnostics = [Collections.Generic.List[object]]::new()
  $UnresolvedFields = [Collections.Generic.List[string]]::new()
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentUnsupportedByGeneration' -Source 'SetupFactory' -Message 'Setup Factory 3.1 predates the /S silent-installation feature and is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence ([ordered]@{ MetadataRoute = 'irdat-v3.1'; Reason = 'GenerationPredatesSilentMode' })))
  $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.NoWindowsArpByGeneration' -Source 'SetupFactory' -Message 'Setup Factory 3.1 targets Windows 3.1 Program Manager and predates the Windows Add/Remove Programs registry contract.' -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
  foreach ($Field in 'DisplayVersion', 'Publisher', 'Scope') { $UnresolvedFields.Add($Field) }
  $UnavailableEntries = @($Metadata.Entries | Where-Object MediaError)
  if ($UnavailableEntries.Count) {
    $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.MultiFileCompanionMissing' -Source 'SetupFactory' -Message "$($UnavailableEntries.Count) Setup Factory 3.1 companion payload file(s) are missing or do not match their declared packed sizes." -Kind Incomplete -Areas Extraction -AffectedFields InstallationMetadata -Evidence $UnavailableEntries))
    $UnresolvedFields.Add('InstallationMetadata.Files')
  }
  $EmptyAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite @()
  $RuntimeEntry = $Media.ArchiveCatalog.Entries | Where-Object Name -CEQ 'IRSETUP.EXE' | Select-Object -First 1
  $EmbeddedRuntimeInfo = [pscustomobject][ordered]@{
    IsPresent           = $true
    IsReadable          = $true
    IsTrusted           = $false
    IsProfileCompatible = $true
    Version             = $null
    MajorVersion        = $null
    ProductName         = $null
    OriginalFilename    = 'IRSETUP.EXE'
    FileDescription     = $null
    MatchingProfileIds  = @('setup-factory-3.1-multifile')
    Error               = $null
    Entry               = $RuntimeEntry
  }
  $EmptyActions = [pscustomobject][ordered]@{
    VariableAssignments = @(); ExecutionActions = @(); FileSystemActions = @(); IniActions = @(); VariableReads = @(); UserInteractionActions = @(); InstallabilityActions = @(); ShortcutActions = @(); ServiceActions = @(); RebootActions = @(); ExternalCodeActions = @(); UnknownActions = @()
  }
  [pscustomobject][ordered]@{
    Path                         = $Media.Path
    InstallerType                = 'exe'
    ProductCode                  = $null
    UpgradeCode                  = $null
    DisplayName                  = $Metadata.ProductName
    DisplayVersion               = $null
    Publisher                    = $null
    Scope                        = $null
    DefaultInstallLocation       = $Metadata.DefaultInstallLocation
    WritesAppsAndFeaturesEntry   = $false
    AppsAndFeaturesProductCode   = $null
    AppsAndFeaturesInstallerType = $null
    AppsAndFeaturesEntries       = @()
    Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
    UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object -Unique)
    Family                       = 'Setup Factory'
    RegistryWrites               = @()
    RegistryArpEntries           = @()
    RegistryAssociationInfo      = $EmptyAssociationInfo
    Protocols                    = @()
    FileExtensions               = @()
    ContainerEntries             = $Media.ArchiveCatalog.Entries
    DependencyPayloads           = @()
    PayloadCatalog               = $Metadata.Entries
    InstalledFileCatalog         = [pscustomobject][ordered]@{ Entries = $Metadata.Entries; IsComplete = $Metadata.IsComplete; CanExtract = $Metadata.IsComplete; CanExtractPartial = @($Metadata.Entries | Where-Object IsEmbedded).Count -gt 0; ExtractableEntryCount = @($Metadata.Entries | Where-Object IsEmbedded).Count; UnavailableEntryCount = $UnavailableEntries.Count }
    FilePolicySummary            = [pscustomobject][ordered]@{}
    ExtractedFiles               = @()
    CanExpand                    = $Metadata.IsComplete
    CanExpandPartial             = @($Metadata.Entries | Where-Object IsEmbedded).Count -gt 0
    CanExpandRawEntries          = $true
    SupportsSilentInstallation   = $false
    StartsInSilentMode           = $false
    InstallerSwitches            = [pscustomobject][ordered]@{}
    InstallModes                 = [string[]]@('interactive')
    SilentInstallationEvidence   = [pscustomobject][ordered]@{ MetadataRoute = 'irdat-v3.1'; Reason = 'GenerationPredatesSilentMode' }
    ProductMetadata              = [pscustomobject][ordered]@{ ProductName = $Metadata.ProductName; ProgramGroup = $Metadata.ProgramGroup; SourceDirectory = $Metadata.SourceDirectory; SourceDrive = $Metadata.SourceDrive; DefaultInstallLocation = $Metadata.DefaultInstallLocation }
    UninstallConfiguration       = [pscustomobject][ordered]@{ RuntimeEntry = 'IRUNIN31.EXE'; RegistrationModel = 'Windows3xProgramManager'; WritesAppsAndFeaturesEntry = $false }
    LegacyActionCatalog          = $null
    ActionEffects                = $EmptyActions
    VariableAssignments          = @()
    ExecutionActions             = @()
    FileSystemActions            = @()
    IniActions                   = @()
    VariableReads                = @()
    UserInteractionActions       = @()
    InstallabilityActions        = @()
    Shortcuts                    = @($Metadata.Entries | Where-Object CreateShortcut | ForEach-Object { [pscustomobject][ordered]@{ Name = $_.ShortName; Target = $_.Name; Description = $_.Description } })
    ServiceActions               = @()
    RebootActions                = @()
    ExternalCodeActions          = @()
    EmbeddedRuntimeInfo          = $EmbeddedRuntimeInfo
    ParserVersionInfo            = [pscustomobject][ordered]@{ Family = 'Setup Factory'; MajorVersion = 3; BuilderVersion = $Metadata.FormatVersion; BuilderVersionSource = 'IRDATA.DAT project header'; OuterRuntimeVersion = $null; EmbeddedRuntimeVersion = $Metadata.FormatVersion; ProfileId = 'setup-factory-3.1-multifile'; FormatGeneration = 'MultiFile31'; MetadataRoute = 'irdat-v3.1'; MetadataProfile = 'SetupFactory31Records'; HeaderRoute = 'crusher-arq-companion-media'; HeaderPrefixLength = 0; OverlayOffset = $null }
  }
}

function Get-SetupFactoryOverlayInfo {
  <#
  .SYNOPSIS
    Locate the PE overlay and classify its Setup Factory archive profile.
  .PARAMETER Path
    Path to the installer PE. The returned Offset and Length are absolute file byte ranges.
  .PARAMETER Stream
    Optional caller-owned seekable installer stream. Its original position is restored before return.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [IO.Stream]$Stream
  )
  $File = Get-Item -LiteralPath $Path -Force
  $OwnedStream = $null
  if (-not $Stream) {
    $OwnedStream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Stream = $OwnedStream
  }
  if (-not $Stream.CanSeek) { throw 'Setup Factory overlay analysis requires a seekable stream' }
  $OriginalPosition = $Stream.Position
  try {
    # Setup Factory stores its generation signature at the PE overlay boundary. Restrict probing to
    # that boundary so similar bytes in PE resources or payload data cannot classify the file.
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    $Stream.Position = $OverlayOffset
    $Probe = Read-SetupFactoryExactByte -Stream $Stream -Count ([Math]::Min(32, [int]($Stream.Length - $OverlayOffset)))
    $ProbeHex = [BitConverter]::ToString($Probe)

    # Product projects can replace the launcher's version resource. Accept it as
    # builder evidence only while the PE still identifies the Indigo Rose runtime.
    $VersionText = ([string]$File.VersionInfo.ProductVersion).Replace(', ', '.').Replace(',', '.')
    $VersionMatch = [regex]::Match($VersionText, '^(?<major>\d+)\.(?<minor>\d+)(?:\.(?<build>\d+))?(?:\.(?<revision>\d+))?$')
    $IdentifiesRuntime = (
      [string]$File.VersionInfo.OriginalFilename -match '^suf(?:\d+)?_launch\.exe$' -and
      [string]$File.VersionInfo.ProductName -match '^Setup Factory(?: \d+(?:\.\d+)?)? Runtime$'
    ) -or (
      [string]$File.VersionInfo.OriginalFilename -ieq 'setup.exe' -and
      [string]$File.VersionInfo.InternalName -match '^suf\d+_setup$' -and
      [string]$File.VersionInfo.ProductName -match '^Setup Factory(?: \d+(?:\.\d+)?)? Runtime$'
    ) -or (
      [string]$File.VersionInfo.OriginalFilename -ieq 'setup.exe' -and
      [string]$File.VersionInfo.ProductName -ieq 'setup' -and
      [string]$File.VersionInfo.FileDescription -match '^Setup Factory(?: .*?)? Setup Launcher$'
    )
    $BuilderVersion = if ($IdentifiesRuntime -and $VersionMatch.Success) { $VersionMatch.Value }
    $BuilderMajorVersion = if ($BuilderVersion) { [int]$VersionMatch.Groups['major'].Value } else { $null }

    $FormatProfile = $null
    $HeaderPrefixLength = 0
    if ($Probe.Length -ge 16 -and $ProbeHex.StartsWith([BitConverter]::ToString($Script:SetupFactory8PlusSignature), [StringComparison]::Ordinal)) {
      $FormatProfile = $Script:SetupFactoryFormatCatalog.Profiles.Modern8Plus
      $HeaderPrefixLength = 26
    } elseif ($Probe.Length -ge 8 -and $ProbeHex.StartsWith([BitConverter]::ToString($Script:SetupFactory7Signature), [StringComparison]::Ordinal)) {
      # Setup Factory 7.3 and later usually inserts one byte after the magic, but
      # one 7.0.3 runtime does not. Select the prefix by proving that the declared
      # runtime range starts with the first two bytes of "MZ" XOR 0x07.
      foreach ($CandidatePrefix in 8, 9) {
        if ($OverlayOffset + $CandidatePrefix + 6 -gt $Stream.Length) { continue }
        $Stream.Position = $OverlayOffset + $CandidatePrefix
        $CandidateSize = Read-SetupFactoryUInt32 -Stream $Stream
        if ($CandidateSize -le 0 -or $CandidateSize -gt $Script:SetupFactoryMaximumFileBytes -or $CandidateSize -gt $Stream.Length - $Stream.Position) { continue }
        $EncodedMz = Read-SetupFactoryExactByte -Stream $Stream -Count 2
        if (($EncodedMz[0] -bxor 7) -eq 0x4D -and ($EncodedMz[1] -bxor 7) -eq 0x5A) {
          $FormatProfile = $Script:SetupFactoryFormatCatalog.Profiles.Modern7
          $HeaderPrefixLength = $CandidatePrefix
          break
        }
      }
      if (-not $FormatProfile) {
        # The application can replace the launcher's version resource. Validate
        # the fixed-width catalog itself before using release identity as a tie-breaker.
        $LegacyCandidates = $BuilderMajorVersion -eq 6 ? @(6, 5) : @(5, 6)
        foreach ($LegacyVersion in $LegacyCandidates) {
          $NameSize = $LegacyVersion -eq 5 ? 16 : 260
          if (Test-SetupFactoryLegacyCatalog -Stream $Stream -OverlayOffset $OverlayOffset -NameSize $NameSize) {
            $FormatProfile = $Script:SetupFactoryFormatCatalog.Profiles["Legacy$LegacyVersion"]
            break
          }
        }
      }
    } elseif ($Probe.Length -ge 8 -and $ProbeHex.StartsWith('E0-E1-E2-E3-E4-E5-E6', [StringComparison]::Ordinal) -and (Test-SetupFactoryLegacyCatalog -Stream $Stream -OverlayOffset $OverlayOffset -CountInSignature -NameSize 16)) {
      $FormatProfile = $Script:SetupFactoryFormatCatalog.Profiles.Classic4
    }

    [pscustomobject][ordered]@{
      Version              = $BuilderMajorVersion ?? 0
      BuilderVersion       = $BuilderVersion
      BuilderVersionSource = $BuilderVersion ? 'TrustedOuterRuntimeVersionResource' : $null
      ProfileId            = if ($FormatProfile) { $FormatProfile.Id } else { $null }
      FormatGeneration     = if ($FormatProfile) { $FormatProfile.FormatGeneration } else { $null }
      HeaderRoute          = if ($FormatProfile) { $FormatProfile.HeaderRoute } else { $null }
      MetadataRoute        = if ($FormatProfile) { $FormatProfile.MetadataRoute } else { $null }
      HeaderPrefixLength   = $HeaderPrefixLength
      IsSupported          = [bool]($FormatProfile -and $FormatProfile.IsSupported)
      SupportsMetadata     = [bool]($FormatProfile -and $FormatProfile.SupportsMetadata)
      Offset               = $OverlayOffset
      Length               = $Stream.Length - $OverlayOffset
    }
  } finally {
    if ($OwnedStream) { $OwnedStream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function Read-SetupFactoryOuterCatalogRecord {
  <#
  .SYNOPSIS
    Read a validated sequence of Setup Factory outer-resource records.
  .PARAMETER Stream
    Caller-owned installer stream positioned at the first record.
  .PARAMETER Count
    Number of records declared by the outer catalog.
  .PARAMETER ProfileId
    Structural profile controlling name and size widths.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][long]$Count, [Parameter(Mandatory)][string]$ProfileId)

  if ($Count -le 0 -or $Count -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory entry count is invalid or exceeds the configured limit' }
  $Entries = [Collections.Generic.List[object]]::new()
  for ($EntryIndex = 0; $EntryIndex -lt $Count; $EntryIndex++) {
    $NameSize = switch ($ProfileId) {
      { $_ -in 'setup-factory-4', 'setup-factory-5' } { 16; break }
      { $_ -in 'setup-factory-6', 'setup-factory-7' } { 260; break }
      default { 264 }
    }
    $EntryName = (ConvertFrom-SetupFactoryText -Bytes (Read-SetupFactoryExactByte -Stream $Stream -Count $NameSize)).Split("`0", 2)[0]
    if ([string]::IsNullOrWhiteSpace($EntryName) -or $EntryName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw "Setup Factory catalog entry $EntryIndex has an invalid name" }
    $PackedSize = if ($ProfileId -eq 'setup-factory-8-plus') { Read-SetupFactoryInt64 -Stream $Stream } else { [long](Read-SetupFactoryUInt32 -Stream $Stream) }
    $ExpectedCrc = Read-SetupFactoryUInt32 -Stream $Stream
    if ($ProfileId -eq 'setup-factory-8-plus') { $Stream.Position += 4 }
    if ($PackedSize -lt 0 -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw "Setup Factory entry '$EntryName' has an invalid size" }
    if ($PackedSize -gt $Stream.Length - $Stream.Position) { throw "The Setup Factory entry '$EntryName' is truncated" }
    $Entries.Add([pscustomobject][ordered]@{
        Name = $EntryName; Kind = 'ContainerEntry'; DataOffset = $Stream.Position; PackedSize = $PackedSize
        Crc32 = [uint32]$ExpectedCrc; IsXored = $false
      })
    $Stream.Position += $PackedSize
  }
  if (@($Entries | Where-Object Name -CEQ 'irsetup.dat').Count -ne 1) { throw 'The Setup Factory outer catalog does not contain exactly one irsetup.dat entry' }
  [pscustomobject][ordered]@{ Entries = $Entries.ToArray(); EndOffset = $Stream.Position }
}

function Get-SetupFactoryModern8OuterCatalog {
  <#
  .SYNOPSIS
    Resolve the optional Lua-runtime branch by validating both complete catalog layouts.
  .PARAMETER Stream
    Caller-owned installer stream positioned immediately after irsetup.exe.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][IO.Stream]$Stream)

  $Start = $Stream.Position
  $Candidates = [Collections.Generic.List[object]]::new()
  try {
    $Stream.Position = $Start
    $Count = Read-SetupFactoryUInt32 $Stream
    $Records = Read-SetupFactoryOuterCatalogRecord -Stream $Stream -Count $Count -ProfileId 'setup-factory-8-plus'
    $Candidates.Add([pscustomobject][ordered]@{ LuaEntry = $null; Records = $Records })
  } catch {
    # This branch is a structural candidate. A failure discards it so the
    # optional-Lua route can still be tested independently.
  }
  try {
    $Stream.Position = $Start
    $LuaSize = Read-SetupFactoryInt64 $Stream
    if ($LuaSize -le 0 -or $LuaSize -gt $Script:SetupFactoryMaximumFileBytes -or $LuaSize -gt $Stream.Length - $Stream.Position) { throw 'The embedded Lua runtime size is invalid' }
    $LuaOffset = $Stream.Position
    if ($LuaSize -lt 2) { throw 'The embedded Lua runtime is too small' }
    $Magic = Read-SetupFactoryExactByte -Stream $Stream -Count 2
    if ($Magic[0] -ne 0x4D -or $Magic[1] -ne 0x5A) { throw 'The optional Lua runtime is not a PE image' }
    $Stream.Position = $LuaOffset + $LuaSize
    $Count = Read-SetupFactoryUInt32 $Stream
    $Records = Read-SetupFactoryOuterCatalogRecord -Stream $Stream -Count $Count -ProfileId 'setup-factory-8-plus'
    $Candidates.Add([pscustomobject][ordered]@{
        LuaEntry = [pscustomobject][ordered]@{ Name = 'lua5.1.dll'; Kind = 'RuntimeDependency'; DataOffset = $LuaOffset; PackedSize = $LuaSize; Crc32 = $null; IsXored = $false }
        Records  = $Records
      })
  } catch {
    # This branch is a structural candidate. Aggregate failure is reported only
    # after both possible layouts have been rejected.
  }
  if ($Candidates.Count -ne 1) {
    if ($Candidates.Count -gt 1) { throw 'The Setup Factory optional Lua branch is structurally ambiguous' }
    throw 'Neither Setup Factory 8+ outer-catalog layout is structurally valid'
  }
  $Selected = $Candidates[0]
  $Stream.Position = $Selected.Records.EndOffset
  return $Selected
}

function Get-SetupFactoryArchiveCatalog {
  <#
  .SYNOPSIS
    Parse the bounded outer file catalog without decoding payload entries.
  .PARAMETER Path
    Path to a Setup Factory installer. Returned offsets are absolute file offsets.
  .PARAMETER Stream
    Optional caller-owned seekable installer stream. Its original position is restored before return.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [IO.Stream]$Stream
  )

  $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
  # Version 3.1 is companion media rather than a PE overlay. Dispatch it before opening the
  # requested file as the later single-file stream, and preserve source paths on every ARQ entry.
  if ($File.Name -ieq 'IRDATA.IRD' -or ($File.Name -ieq 'SETUP.EXE' -and (Test-Path -LiteralPath (Join-Path $File.Directory.FullName 'IRDATA.IRD') -PathType Leaf))) {
    $Media = Get-SetupFactory31Media -Path $File.FullName
    $FormatProfile31 = $Script:SetupFactoryFormatCatalog.Profiles.MultiFile31
    return [pscustomobject][ordered]@{
      Path              = $Media.Path
      FileLength        = $Media.ArchiveCatalog.FileLength
      Overlay           = [pscustomobject][ordered]@{
        Version = 3; BuilderVersion = $Media.Metadata.FormatVersion; BuilderVersionSource = 'IRDATA.DAT project header'; ProfileId = $FormatProfile31.Id; FormatGeneration = $FormatProfile31.FormatGeneration; HeaderRoute = $FormatProfile31.HeaderRoute; MetadataRoute = $FormatProfile31.MetadataRoute; HeaderPrefixLength = 0; IsSupported = $true; SupportsMetadata = $true; Offset = $null; Length = $Media.ArchiveCatalog.FileLength
      }
      Entries           = $Media.ArchiveCatalog.Entries
      PayloadDataOffset = $null
      MediaRoot         = $Media.MediaRoot
      Metadata          = $Media.Metadata
    }
  }
  $Entries = [Collections.Generic.List[object]]::new()
  $OwnedStream = $null
  if (-not $Stream) {
    $OwnedStream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Stream = $OwnedStream
  }
  if (-not $Stream.CanSeek) { throw 'Setup Factory catalog analysis requires a seekable stream' }
  $OriginalPosition = $Stream.Position
  try {
    $Overlay = Get-SetupFactoryOverlayInfo -Path $File.FullName -Stream $Stream
    if (-not $Overlay.ProfileId) { throw 'The file is not a recognized Setup Factory installer' }
    if (-not $Overlay.IsSupported) { throw "The Setup Factory profile '$($Overlay.FormatGeneration)' is recognized but not yet supported" }

    if ($Overlay.ProfileId -eq 'setup-factory-4') {
      # Classic 4 omits the final E7 signature byte and uses that byte as the
      # catalog count. No separate embedded setup runtime precedes the records.
      $Stream.Position = $Overlay.Offset + 7
      $Count = $Stream.ReadByte()
      if ($Count -lt 0) { throw 'The Setup Factory 4 entry count is truncated' }
    } elseif ($Overlay.ProfileId -in 'setup-factory-5', 'setup-factory-6') {
      # Versions 5 and 6 place a 32-bit count directly after the full magic.
      $Stream.Position = $Overlay.Offset + 8
      $Count = Read-SetupFactoryUInt32 -Stream $Stream
    } else {
      # Versions 7 and later add a lightly transformed setup runtime before the
      # outer catalog. Their prefix and size widths differ by physical profile.
      $Stream.Position = $Overlay.Offset + $Overlay.HeaderPrefixLength
      $RuntimeSize = if ($Overlay.ProfileId -eq 'setup-factory-7') {
        [long](Read-SetupFactoryUInt32 -Stream $Stream)
      } else {
        Read-SetupFactoryInt64 -Stream $Stream
      }
      if ($RuntimeSize -le 0 -or $RuntimeSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The embedded Setup Factory runtime size is invalid' }
      if ($RuntimeSize -gt $Stream.Length - $Stream.Position) { throw 'The embedded Setup Factory runtime is truncated' }
      $Entries.Add([pscustomobject][ordered]@{
          Name       = 'irsetup.exe'
          Kind       = 'Runtime'
          DataOffset = $Stream.Position
          PackedSize = $RuntimeSize
          Crc32      = $null
          IsXored    = $true
        })
      $Stream.Position += $RuntimeSize
      $Count = Read-SetupFactoryUInt32 -Stream $Stream
    }

    if ($Overlay.ProfileId -eq 'setup-factory-8-plus') {
      # Rewind over the provisional uint32 count and validate both the direct-catalog and
      # optional-lua-runtime routes. No entry-count threshold participates in dispatch.
      $Stream.Position -= 4
      $ModernCatalog = Get-SetupFactoryModern8OuterCatalog -Stream $Stream
      if ($ModernCatalog.LuaEntry) { $Entries.Add($ModernCatalog.LuaEntry) }
      foreach ($Entry in $ModernCatalog.Records.Entries) { $Entries.Add($Entry) }
      $PayloadDataOffset = $ModernCatalog.Records.EndOffset
    } else {
      $Records = Read-SetupFactoryOuterCatalogRecord -Stream $Stream -Count $Count -ProfileId $Overlay.ProfileId
      foreach ($Entry in $Records.Entries) { $Entries.Add($Entry) }
      $PayloadDataOffset = $Records.EndOffset
    }

    [pscustomobject][ordered]@{
      Path              = $File.FullName
      FileLength        = $Stream.Length
      Overlay           = $Overlay
      Entries           = $Entries.ToArray()
      PayloadDataOffset = $PayloadDataOffset
    }
  } finally {
    if ($OwnedStream) { $OwnedStream.Dispose() } else { $Stream.Position = $OriginalPosition }
  }
}

function Read-SetupFactoryCatalogEntryData {
  <#
  .SYNOPSIS
    Read and decode one previously validated catalog entry.
  .PARAMETER Stream
    Caller-owned installer stream. Position advances through the selected entry.
  .PARAMETER Entry
    Entry returned by Get-SetupFactoryArchiveCatalog.
  .PARAMETER MaximumBytes
    Maximum permitted decoded byte count.
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Entry,
    [Parameter(Mandatory)][ValidateRange(1, [long]::MaxValue)][long]$MaximumBytes
  )

  if ($Entry.PackedSize -gt $MaximumBytes -and $Entry.Kind -ne 'ContainerEntry') { throw "Setup Factory entry '$($Entry.Name)' exceeds the configured limit" }
  $Stream.Position = $Entry.DataOffset
  $Bytes = Read-SetupFactoryExactByte -Stream $Stream -Count ([int]$Entry.PackedSize)
  if ($Entry.Kind -eq 'ContainerEntry') {
    $Bytes = Expand-SetupFactoryCompressedData -Bytes $Bytes -MaximumBytes $MaximumBytes
    if ($Entry.Crc32 -ne 0 -and (Get-SetupFactoryCrc32 -Bytes $Bytes) -ne $Entry.Crc32) { throw "The Setup Factory entry '$($Entry.Name)' failed its CRC check" }
  } elseif ($Entry.IsXored) {
    # The setup runtime transforms only its first 2,000 bytes with XOR 0x07.
    for ($Index = 0; $Index -lt [Math]::Min(2000, $Bytes.Length); $Index++) { $Bytes[$Index] = $Bytes[$Index] -bxor 7 }
  }
  return , $Bytes
}

function Get-SetupFactoryEmbeddedRuntimeInfo {
  <#
  .SYNOPSIS
    Read release identity from the embedded Setup Factory runtime without executing it.
  .PARAMETER Stream
    Caller-owned installer stream. Its original position is restored before return.
  .PARAMETER Catalog
    Validated archive catalog returned by Get-SetupFactoryArchiveCatalog.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][psobject]$Catalog
  )

  $RuntimeEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.exe')
  if ($RuntimeEntries.Count -ne 1) {
    return [pscustomobject][ordered]@{
      IsPresent           = $RuntimeEntries.Count -gt 0
      IsReadable          = $false
      IsTrusted           = $false
      IsProfileCompatible = $null
      Version             = $null
      MajorVersion        = $null
      ProductName         = $null
      OriginalFilename    = $null
      FileDescription     = $null
      MatchingProfileIds  = @()
      Error               = "The Setup Factory catalog contains $($RuntimeEntries.Count) embedded runtime entries; exactly one is required for release classification."
    }
  }

  $OriginalPosition = $Stream.Position
  try {
    # Release classification is optional evidence. Keep its allocation much smaller than the
    # general payload limit so an oversized runtime cannot inflate routine metadata analysis.
    $RuntimeBytes = Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $RuntimeEntries[0] -MaximumBytes 67108864
    $RuntimeStream = [IO.MemoryStream]::new($RuntimeBytes, $false)
    try {
      $Layout = Get-PELayout -Stream $RuntimeStream
      if (-not $Layout) { throw 'The decoded embedded runtime is not a valid PE image.' }
      $Strings = Get-PEVersionStringTable -Stream $RuntimeStream -Layout $Layout
    } finally {
      $RuntimeStream.Dispose()
    }

    $VersionProperty = $Strings.PSObject.Properties['ProductVersion'] ?? $Strings.PSObject.Properties['FileVersion']
    $ProductProperty = $Strings.PSObject.Properties['ProductName']
    $OriginalFilenameProperty = $Strings.PSObject.Properties['OriginalFilename']
    $DescriptionProperty = $Strings.PSObject.Properties['FileDescription']
    $VersionText = if ($VersionProperty) { ([string]$VersionProperty.Value).Replace(', ', '.').Replace(',', '.') } else { '' }
    $VersionMatch = [regex]::Match($VersionText, '^(?<major>\d+)\.(?<minor>\d+)(?:\.(?<build>\d+))?(?:\.(?<revision>\d+))?$')
    $MajorVersion = $VersionMatch.Success ? [int]$VersionMatch.Groups['major'].Value : $null
    $ProductName = $ProductProperty ? [string]$ProductProperty.Value : $null
    $OriginalFilename = $OriginalFilenameProperty ? [string]$OriginalFilenameProperty.Value : $null

    # Match release identity independently from the selected structural profile. This permits a
    # precise conflict diagnostic while keeping binary framing authoritative for dispatch.
    $MatchingProfiles = [Collections.Generic.List[string]]::new()
    foreach ($FormatProfile in $Script:SetupFactoryFormatCatalog.Profiles.Values) {
      $ProductMatches = @($FormatProfile.RuntimeProducts | Where-Object { $ProductName -match $_ }).Count -gt 0
      $FilenameMatches = @($FormatProfile.RuntimeFiles | Where-Object { $OriginalFilename -match $_ }).Count -gt 0
      if ($VersionMatch.Success -and $MajorVersion -in $FormatProfile.RuntimeMajors -and $ProductMatches -and $FilenameMatches) { $MatchingProfiles.Add([string]$FormatProfile.Id) }
    }
    $IsTrusted = $MatchingProfiles.Count -gt 0
    [pscustomobject][ordered]@{
      IsPresent           = $true
      IsReadable          = $true
      IsTrusted           = $IsTrusted
      IsProfileCompatible = $IsTrusted ? ($Catalog.Overlay.ProfileId -in $MatchingProfiles) : $null
      Version             = $VersionMatch.Success ? $VersionMatch.Value : $null
      MajorVersion        = $MajorVersion
      ProductName         = $ProductName
      OriginalFilename    = $OriginalFilename
      FileDescription     = $DescriptionProperty ? [string]$DescriptionProperty.Value : $null
      MatchingProfileIds  = $MatchingProfiles.ToArray()
      Error               = $null
    }
  } catch {
    [pscustomobject][ordered]@{
      IsPresent           = $true
      IsReadable          = $false
      IsTrusted           = $false
      IsProfileCompatible = $null
      Version             = $null
      MajorVersion        = $null
      ProductName         = $null
      OriginalFilename    = $null
      FileDescription     = $null
      MatchingProfileIds  = @()
      Error               = $_.Exception.Message
    }
  } finally {
    $Stream.Position = $OriginalPosition
  }
}

function Expand-SetupFactoryInstaller {
  <#
  .SYNOPSIS
    Expand a Setup Factory 3.1-10 installer without executing it
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select installed paths, or outer record names with RawEntries.
  .PARAMETER RawEntries
    Extract outer bootstrap records such as irsetup.exe and irsetup.dat plus separately framed bundled prerequisite payloads instead of installed application files.
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple records resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [switch]$RawEntries,
    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')][string]$CollisionAction = 'Prompt',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:SetupFactoryMaximumExpandedBytes
  )
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-SetupFactory-' + [guid]::NewGuid().ToString('N'))
    }
    if ($File.Name -ieq 'IRDATA.IRD' -or ($File.Name -ieq 'SETUP.EXE' -and (Test-Path -LiteralPath (Join-Path $File.Directory.FullName 'IRDATA.IRD') -PathType Leaf))) {
      $Media = Get-SetupFactory31Media -Path $File.FullName
      Expand-SetupFactory31Media -Media $Media -DestinationPath $DestinationPath -Name $Name -RawEntries:$RawEntries -CollisionAction $CollisionAction -MaximumExpandedBytes $MaximumExpandedBytes
      return
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -ItemType Directory -Path $DestinationPath -Force
    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Written = 0L
    try {
      $Catalog = Get-SetupFactoryArchiveCatalog -Path $File.FullName -Stream $Stream
      if ($RawEntries) {
        # Raw mode includes the bootstrap catalog and any separately framed bundled
        # prerequisites. Decode irsetup.dat only to locate those physical records;
        # malformed prerequisite metadata must not hide otherwise valid outer entries.
        $Entries = [Collections.Generic.List[object]]::new()
        foreach ($Entry in $Catalog.Entries) { $Entries.Add($Entry) }
        $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
        if ($ScriptEntries.Count -eq 1) {
          $ScriptBytes = Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
          $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $ScriptBytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
          if ($DependencyCatalog.IsComplete) {
            foreach ($Entry in $DependencyCatalog.Entries) { $Entries.Add($Entry) }
          }
        }
        $Entries = $Entries.ToArray()
      } else {
        $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
        if ($ScriptEntries.Count -ne 1) { throw "The Setup Factory catalog contains $($ScriptEntries.Count) irsetup.dat entries; exactly one is required" }
        $ScriptBytes = Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
        $Variables = if ($Catalog.Overlay.MetadataRoute -in 'irdat-v5', 'irdat-v6') {
          try { (Get-SetupFactoryLegacyMetadata -Bytes $ScriptBytes).Variables } catch { @{} }
        } elseif ($Catalog.Overlay.SupportsMetadata) {
          Get-SetupFactorySessionVariable -Bytes $ScriptBytes
        } else {
          @{}
        }
        $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $ScriptBytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
        if (-not $DependencyCatalog.IsComplete) { throw "The Setup Factory dependency-file table could not be decoded: $($DependencyCatalog.Error)" }
        $InstalledCatalog = Get-SetupFactoryInstalledFileCatalog -Bytes $ScriptBytes -Catalog $Catalog -Variables $Variables -PayloadDataOffset $DependencyCatalog.PayloadDataEndOffset
        if (-not $InstalledCatalog.IsComplete) { throw "The Setup Factory installed-file table could not be decoded: $($InstalledCatalog.Error)" }
        $Entries = $InstalledCatalog.Entries
      }

      $SelectedEntries = @($Entries | Where-Object { Test-ExtractionPattern -Path $_.Name -Pattern $Name })
      if (-not $RawEntries) {
        $UnavailableEntries = @($SelectedEntries | Where-Object { -not $_.IsEmbedded -or $null -eq $_.DataOffset })
        if ($UnavailableEntries.Count) { throw "The Setup Factory media does not contain a proven physical payload range for $($UnavailableEntries.Count) selected installed file(s), beginning with '$($UnavailableEntries[0].Name)'" }
      }
      foreach ($Entry in $SelectedEntries) {
        $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $Entry.Name `
          -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
        if (-not $Target.ShouldWrite) { continue }
        $Remaining = [Math]::Min($MaximumExpandedBytes - $Written, $Script:SetupFactoryMaximumFileBytes)
        if ($Remaining -le 0) { throw 'The Setup Factory expansion exceeds the configured limit' }
        $Expanded = if ($RawEntries) {
          if ($Entry.Kind -eq 'DependencyPayload') { Read-SetupFactoryInstalledFileData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining }
          else { Read-SetupFactoryCatalogEntryData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining }
        } else {
          Read-SetupFactoryInstalledFileData -Stream $Stream -Entry $Entry -MaximumBytes $Remaining
        }
        $Written += $Expanded.LongLength
        if ($Written -gt $MaximumExpandedBytes) { throw 'The Setup Factory expansion exceeds the configured limit' }
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        [IO.File]::WriteAllBytes($Target.Path, $Expanded)
        Get-Item -LiteralPath $Target.Path
      }
    } finally {
      $Stream.Dispose()
    }
  }
}

function Get-SetupFactoryArpEntry {
  <#
  .SYNOPSIS
    Project literal uninstall-key writes into ARP entry evidence.
  .PARAMETER RegistryWrite
    Literal Setup Factory registry writes recovered from irsetup.dat.
  .PARAMETER Variables
    Session-variable map used to resolve key paths and values.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RegistryWrite,
    [Parameter(Mandatory)][hashtable]$Variables
  )

  $Entries = [ordered]@{}
  foreach ($Write in $RegistryWrite) {
    # HKCR is valid association evidence but cannot own an Add/Remove Programs
    # registration. Only HKLM and HKCU map to Win32 uninstall roots.
    if ($Write.Root -notmatch '^(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER)$') { continue }
    $Key = Resolve-SetupFactoryVariable -Value ([string]$Write.Key) -Variables $Variables
    if (-not $Key) { continue }
    $Match = [regex]::Match($Key, '(?i)^Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\(?<code>[^\\]+)$')
    if (-not $Match.Success) { continue }

    $Identity = "$(($Write.Root -replace '^HKEY_LOCAL_MACHINE$', 'HKLM' -replace '^HKEY_CURRENT_USER$', 'HKCU').ToUpperInvariant())\$Key"
    if (-not $Entries.Contains($Identity)) {
      $Entries[$Identity] = [ordered]@{
        RegistryIdentity     = $Identity
        Root                 = $Write.Root
        Key                  = $Key
        ProductCode          = $Match.Groups['code'].Value
        DisplayName          = $null
        DisplayVersion       = $null
        Publisher            = $null
        InstallLocation      = $null
        DisplayIcon          = $null
        UninstallString      = $null
        QuietUninstallString = $null
        SystemComponent      = 0
      }
    }
    $Entry = $Entries[$Identity]
    $Value = Resolve-SetupFactoryVariable -Value ([string]$Write.Value) -Variables $Variables
    switch -Regex ([string]$Write.Name) {
      '^DisplayName$' { $Entry.DisplayName = $Value }
      '^DisplayVersion$' { $Entry.DisplayVersion = $Value }
      '^Publisher$' { $Entry.Publisher = $Value }
      '^InstallLocation$' { $Entry.InstallLocation = $Value }
      '^DisplayIcon$' { $Entry.DisplayIcon = $Value }
      '^UninstallString$' { $Entry.UninstallString = $Value }
      '^QuietUninstallString$' { $Entry.QuietUninstallString = $Value }
      '^SystemComponent$' { $Entry.SystemComponent = if ($Value -match '^\d+$') { [int]$Value } else { $Value } }
    }
  }

  foreach ($Entry in $Entries.Values) {
    [pscustomobject][ordered]@{
      RegistryIdentity     = $Entry.RegistryIdentity
      Root                 = $Entry.Root
      Key                  = $Entry.Key
      ProductCode          = $Entry.ProductCode
      DisplayName          = $Entry.DisplayName
      DisplayVersion       = $Entry.DisplayVersion
      Publisher            = $Entry.Publisher
      InstallLocation      = $Entry.InstallLocation
      DisplayIcon          = $Entry.DisplayIcon
      UninstallString      = $Entry.UninstallString
      QuietUninstallString = $Entry.QuietUninstallString
      SystemComponent      = $Entry.SystemComponent
      Scope                = $Entry.Root -match '^(?:HKCU|HKEY_CURRENT_USER)$' ? 'user' : 'machine'
      IsVisible            = $Entry.SystemComponent -ne 1 -and -not [string]::IsNullOrWhiteSpace($Entry.DisplayName)
    }
  }
}

function Get-SetupFactoryInfo {
  <#
  .SYNOPSIS
    Read structured Setup Factory product and ARP metadata
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    $File = Get-Item -LiteralPath (Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf) -Force
    if ($File.Name -ieq 'IRDATA.IRD' -or ($File.Name -ieq 'SETUP.EXE' -and (Test-Path -LiteralPath (Join-Path $File.Directory.FullName 'IRDATA.IRD') -PathType Leaf))) {
      return Get-SetupFactory31Info -Path $File.FullName
    }
    $ScriptStream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      $Catalog = Get-SetupFactoryArchiveCatalog -Path $File.FullName -Stream $ScriptStream
      $Overlay = $Catalog.Overlay
      $EmbeddedRuntimeInfo = Get-SetupFactoryEmbeddedRuntimeInfo -Stream $ScriptStream -Catalog $Catalog
      $ScriptEntries = @($Catalog.Entries | Where-Object Name -CEQ 'irsetup.dat')
      if ($ScriptEntries.Count -ne 1) { throw "The Setup Factory catalog contains $($ScriptEntries.Count) irsetup.dat entries; exactly one is required" }
      # Metadata analysis decodes only irsetup.dat. It no longer writes a
      # temporary extraction tree or returns paths that disappear after cleanup.
      $Bytes = Read-SetupFactoryCatalogEntryData -Stream $ScriptStream -Entry $ScriptEntries[0] -MaximumBytes $Script:SetupFactoryMaximumFileBytes
    } finally {
      $ScriptStream.Dispose()
    }

    $Diagnostics = [Collections.Generic.List[object]]::new()
    $UnresolvedFields = [Collections.Generic.List[string]]::new()
    $SilentInstallationInfo = Get-SetupFactorySilentInstallationInfo -Bytes $Bytes -MetadataRoute $Overlay.MetadataRoute
    if ($SilentInstallationInfo.IsResolved) {
      if (-not $SilentInstallationInfo.SupportsSilentInstallation) {
        $EvidenceReason = $SilentInstallationInfo.Evidence.PSObject.Properties['Reason']
        if ($EvidenceReason -and $EvidenceReason.Value -ceq 'GenerationPredatesSilentMode') {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentUnsupportedByGeneration' -Source 'SetupFactory' -Message 'This Setup Factory generation predates the /S silent-installation feature and is interactive-only.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
        } else {
          $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentDisabled' -Source 'SetupFactory' -Message 'The compiled Setup Factory project disables silent installation, so the documented /S switch is not valid for this artifact.' -Kind Unsupported -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
        }
      }
    } else {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentSupportUnresolved' -Source 'SetupFactory' -Message 'The compiled Setup Factory silent-installation setting could not be resolved for this structural generation; do not infer /S support from runtime strings alone.' -Kind Incomplete -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentInstallationInfo.Evidence))
      $UnresolvedFields.Add('InstallerSwitches')
      $UnresolvedFields.Add('InstallModes')
    }
    if (-not $EmbeddedRuntimeInfo.IsReadable) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.EmbeddedRuntimeUnreadable' -Source 'SetupFactory' -Message "The embedded Setup Factory runtime could not be used as release evidence: $($EmbeddedRuntimeInfo.Error)" -Kind Incomplete -Areas Detection -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId; Error = $EmbeddedRuntimeInfo.Error })))
    } elseif (-not $EmbeddedRuntimeInfo.IsTrusted) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.EmbeddedRuntimeIdentityUnrecognized' -Source 'SetupFactory' -Message 'The embedded runtime is a valid PE image, but its version-resource identity does not match a catalogued Setup Factory generation.' -Kind Ambiguous -Areas Detection -Evidence $EmbeddedRuntimeInfo))
    } elseif (-not $EmbeddedRuntimeInfo.IsProfileCompatible) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.StructuralProfileMismatch' -Source 'SetupFactory' -Message "The embedded Setup Factory $($EmbeddedRuntimeInfo.Version) runtime identifies a different release family than the structurally validated '$($Overlay.ProfileId)' container." -Kind Mismatch -Areas Detection -Evidence $EmbeddedRuntimeInfo))
    }
    if ($Overlay.BuilderVersion -and $EmbeddedRuntimeInfo.IsTrusted -and $Overlay.Version -ne $EmbeddedRuntimeInfo.MajorVersion) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Release.MajorVersionConflict' -Source 'SetupFactory' -Message "Trusted outer runtime version '$($Overlay.BuilderVersion)' and embedded runtime version '$($EmbeddedRuntimeInfo.Version)' identify different Setup Factory major releases." -Kind Mismatch -Areas Detection -Evidence ([ordered]@{ OuterVersion = $Overlay.BuilderVersion; EmbeddedVersion = $EmbeddedRuntimeInfo.Version })))
    }
    # Resolve product variables through the generation-specific metadata route. Versions 5 and 6
    # use fixed object blocks; versions 7 and later use CSessionVar records.
    $LegacyMetadata = $null
    $LegacyMetadataError = $null
    if ($Overlay.MetadataRoute -eq 'irdat-v4') {
      try {
        $LegacyMetadata = Read-SetupFactoryClassic4Metadata -Bytes $Bytes
        $Variables = $LegacyMetadata.Variables
      } catch {
        $LegacyMetadataError = $_.Exception.Message
        $Variables = @{}
      }
    } elseif ($Overlay.MetadataRoute -in 'irdat-v5', 'irdat-v6') {
      try {
        $LegacyMetadata = Get-SetupFactoryLegacyMetadata -Bytes $Bytes
        $Variables = $LegacyMetadata.Variables
      } catch {
        $LegacyMetadataError = $_.Exception.Message
        $Variables = @{}
      }
    } elseif ($Overlay.SupportsMetadata) {
      $Variables = Get-SetupFactorySessionVariable -Bytes $Bytes
    } else {
      $Variables = @{}
    }
    $DependencyCatalog = Get-SetupFactoryDependencyFileCatalog -Bytes $Bytes -PayloadDataOffset $Catalog.PayloadDataOffset -FileLength $Catalog.FileLength
    $InstalledPayloadOffset = $DependencyCatalog.IsComplete ? $DependencyCatalog.PayloadDataEndOffset : $Catalog.PayloadDataOffset
    $InstalledCatalog = Get-SetupFactoryInstalledFileCatalog -Bytes $Bytes -Catalog $Catalog -Variables $Variables -PayloadDataOffset $InstalledPayloadOffset
    if (-not $DependencyCatalog.IsComplete) { $InstalledCatalog.CanExtract = $false }
    $FilePolicySummary = Get-SetupFactoryFilePolicySummary -Entry $InstalledCatalog.Entries
    $Resolve = { param($Name) if ($Variables.ContainsKey($Name)) { Resolve-SetupFactoryVariable -Value ([string]$Variables[$Name]) -Variables $Variables } }
    $DisplayName = & $Resolve '%ProductName%'
    $DisplayVersion = & $Resolve '%ProductVer%'
    $Publisher = & $Resolve '%CompanyName%'
    $InstallLocation = & $Resolve '%AppFolder%'
    # Custom registry writes can supersede built-in uninstall behavior and also provide
    # protocol/file-association evidence. Each legacy generation has a distinct object model;
    # modern media stores literal Lua Registry.SetValue calls instead.
    $UnresolvedRegistryCallCount = 0
    $LegacyActionCatalog = $null
    if ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v4') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog4 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v5') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog5 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($LegacyMetadata -and $Overlay.MetadataRoute -eq 'irdat-v6') {
      $LegacyActionCatalog = Get-SetupFactoryActionCatalog6 -Bytes $Bytes -UninstallOffset $LegacyMetadata.Uninstall.Offset
      [object[]]$RegistryWrites = @($LegacyActionCatalog.RegistryWrites)
      $UnresolvedRegistryCallCount = $LegacyActionCatalog.UnresolvedCount
    } elseif ($Overlay.MetadataRoute -in 'irdat-v7', 'irdat-v8-plus') {
      [object[]]$RegistryWrites = @(Get-SetupFactoryLiteralRegistryWrite -Bytes $Bytes -UnresolvedCount ([ref]$UnresolvedRegistryCallCount))
    } else {
      [object[]]$RegistryWrites = @()
    }
    $ActionEffects = [pscustomobject][ordered]@{
      VariableAssignments    = @()
      ExecutionActions       = @()
      FileSystemActions      = @()
      IniActions             = @()
      VariableReads          = @()
      UserInteractionActions = @()
      InstallabilityActions  = @()
      ShortcutActions        = @()
      ServiceActions         = @()
      RebootActions          = @()
      ExternalCodeActions    = @()
      UnknownActions         = @()
    }
    if ($LegacyActionCatalog -and $Overlay.MetadataRoute -in 'irdat-v4', 'irdat-v5', 'irdat-v6') {
      foreach ($PropertyName in $ActionEffects.PSObject.Properties.Name) {
        $CatalogProperty = $LegacyActionCatalog.PSObject.Properties[$PropertyName]
        if ($CatalogProperty) { $ActionEffects.$PropertyName = [object[]]@($CatalogProperty.Value) }
      }
    }
    $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites
    $RegistryArpEntries = @(Get-SetupFactoryArpEntry -RegistryWrite $RegistryWrites -Variables $Variables)
    $VisibleRegistryArpEntries = @($RegistryArpEntries | Where-Object IsVisible)

    if ($LegacyMetadata) {
      # Legacy media stores the Control Panel description and unique uninstall key explicitly.
      # A disabled uninstaller retains these defaults in the project, so the enable byte gates ARP.
      $HasBuiltInUninstall = [bool]$LegacyMetadata.Uninstall.IncludeUninstall
      $BuiltInProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $LegacyMetadata.Uninstall.UniqueRegistryKey -Variables $Variables }
      if ($HasBuiltInUninstall) {
        $LegacyArpDisplayName = Resolve-SetupFactoryVariable -Value $LegacyMetadata.Uninstall.ControlPanelDescription -Variables $Variables
        if ($LegacyArpDisplayName) { $DisplayName = $LegacyArpDisplayName }
      }
    } else {
      $ProductExpression = '%ProductName%%ProductVer%'
      $ExpressionBytes = [Text.Encoding]::UTF8.GetBytes($ProductExpression)
      # The modern built-in uninstaller composes its ARP key from ProductName and ProductVer.
      # Require that exact structured expression before returning the resolved ProductCode.
      $HasBuiltInUninstall = $Overlay.SupportsMetadata -and @(Find-BinaryPattern -Bytes $Bytes -Pattern $ExpressionBytes -Maximum 1).Count -gt 0
      $BuiltInProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $ProductExpression -Variables $Variables }
    }

    # An explicit uninstall-key record is more precise than the built-in defaults.
    # Multiple visible keys remain entry evidence but do not collapse into one ProductCode.
    $PrimaryArp = $VisibleRegistryArpEntries.Count -eq 1 ? $VisibleRegistryArpEntries[0] : $null
    $ProductCode = $PrimaryArp ? $PrimaryArp.ProductCode : $BuiltInProductCode
    if ($PrimaryArp) {
      if ($PrimaryArp.DisplayName) { $DisplayName = $PrimaryArp.DisplayName }
      if ($PrimaryArp.DisplayVersion) { $DisplayVersion = $PrimaryArp.DisplayVersion }
      if ($PrimaryArp.Publisher) { $Publisher = $PrimaryArp.Publisher }
      if ($PrimaryArp.InstallLocation) { $InstallLocation = $PrimaryArp.InstallLocation }
    }

    $RegistryArpScopes = @($VisibleRegistryArpEntries | ForEach-Object { $_.Scope } | Sort-Object -Unique)
    $Scope = if ($RegistryArpScopes.Count -eq 1) { $RegistryArpScopes[0] }
    elseif ($RegistryArpScopes.Count -gt 1) { $null }
    elseif ($InstallLocation -match '^(?:%ProgramFiles|[A-Za-z]:\\Program Files(?: \(x86\))?\\)') { 'machine' }
    else { $null }

    if (-not $Overlay.SupportsMetadata) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyIrsetupDatPartial' -Source 'SetupFactory' -Message "The $($Overlay.FormatGeneration) outer catalog is supported, but its generation-specific irsetup.dat object tables are not yet decoded; metadata remains incomplete." -Kind Unsupported -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, ProductCode, Scope, DefaultInstallLocation, AppsAndFeaturesEntries))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'Scope', 'DefaultInstallLocation', 'AppsAndFeaturesEntries') { $UnresolvedFields.Add($Field) }
    } elseif ($LegacyMetadataError) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyProductBlockIncomplete' -Source 'SetupFactory' -Message "The Setup Factory legacy product or uninstall block could not be decoded: $LegacyMetadataError" -Kind Incomplete -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, ProductCode, Scope, DefaultInstallLocation, AppsAndFeaturesEntries -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute })))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'Scope', 'DefaultInstallLocation', 'AppsAndFeaturesEntries') { $UnresolvedFields.Add($Field) }
    } elseif ($Overlay.MetadataRoute -eq 'irdat-v4') {
      # Version 4 predates CSessionVar. Its global objects expose the built-in uninstall identity,
      # but do not carry the later product version, publisher, or destination variables.
      $Classic4AffectedFields = [Collections.Generic.List[string]]::new()
      foreach ($Field in 'DisplayVersion', 'Publisher', 'DefaultInstallLocation') {
        $Classic4AffectedFields.Add($Field)
        $UnresolvedFields.Add($Field)
      }
      if ([string]::IsNullOrWhiteSpace([string]$DisplayName)) {
        $Classic4AffectedFields.Add('DisplayName')
        $UnresolvedFields.Add('DisplayName')
      }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.Classic4ProductFieldsUnavailable' -Source 'SetupFactory' -Message 'Setup Factory 4 global objects expose built-in uninstall identity but do not contain the later product version, publisher, or installation-directory variables.' -Kind Incomplete -Areas Metadata -AffectedFields $Classic4AffectedFields.ToArray() -Evidence ([ordered]@{ MetadataProfile = $LegacyMetadata.MetadataProfile })))
    } elseif (-not $Variables.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.SessionVariablesUnavailable' -Source 'SetupFactory' -Message 'CSessionVar records were not found or were malformed.' -Kind Incomplete -Areas Metadata -AffectedFields DisplayName, DisplayVersion, Publisher, DefaultInstallLocation))
      foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'DefaultInstallLocation') { $UnresolvedFields.Add($Field) }
    }
    if ($LegacyActionCatalog) {
      $RegistryCatalogProperty = $LegacyActionCatalog.PSObject.Properties['RegistryCatalog']
      if ($RegistryCatalogProperty -and -not $RegistryCatalogProperty.Value.IsComplete) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyRegistryActionsPartial' -Source 'SetupFactory' -Message "The Setup Factory legacy registry table was only partially decoded: $($RegistryCatalogProperty.Value.Error)" -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, Scope, AppsAndFeaturesEntries, Protocols, FileExtensions -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute; ParsedEntryCount = @($RegistryCatalogProperty.Value.Entries).Count })))
        $UnresolvedFields.Add('RegistryActions')
      }
      if (-not $LegacyActionCatalog.IsComplete) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.LegacyActionsPartial' -Source 'SetupFactory' -Message "One or more Setup Factory legacy command tables were only partially decoded: $($LegacyActionCatalog.Error)" -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ MetadataRoute = $Overlay.MetadataRoute; ParsedEntryCount = @($LegacyActionCatalog.Entries).Count })))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
    }
    if ($Overlay.MetadataRoute -in 'irdat-v4', 'irdat-v5', 'irdat-v6' -and $LegacyActionCatalog) {
      $ActiveExecutionActions = @($ActionEffects.ExecutionActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveInteractionActions = @($ActionEffects.UserInteractionActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveInstallabilityActions = @($ActionEffects.InstallabilityActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveRebootActions = @($ActionEffects.RebootActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $ActiveExternalCodeActions = @($ActionEffects.ExternalCodeActions | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' })
      $SilentModeAssignments = @($ActionEffects.VariableAssignments | Where-Object { $_.Phase -ne 'Uninstall' -and $_.ConditionState -ne 'False' -and $_.Details.VariableName -ieq '%SilentMode%' })

      if ($Overlay.MetadataRoute -eq 'irdat-v6' -and $SilentModeAssignments.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.SilentModeAction' -Source 'SetupFactory' -Message 'A Setup Factory 6 action assigns %SilentMode% during installation. The assignment can override both the project default and the /S command-line request.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $SilentModeAssignments))
        $UnresolvedFields.Add('InstallerSwitches')
        $UnresolvedFields.Add('InstallModes')
      }
      if ($ActiveExecutionActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.ExecutionActions' -Source 'SetupFactory' -Message 'Setup Factory actions can execute or open another file during installation or shutdown. Review their condition, arguments, and payload ownership before treating /S as fully unattended.' -Kind ManualValidation -Areas Metadata, Installability -AffectedFields Dependencies, InstallerSwitches, InstallModes -Evidence $ActiveExecutionActions))
        $UnresolvedFields.Add('Dependencies')
      }
      if ($ActiveInteractionActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.UserInteractionActions' -Source 'SetupFactory' -Message 'Setup Factory contains a message or Yes/No action on a reachable or runtime-dependent installation path.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence $ActiveInteractionActions))
        $UnresolvedFields.Add('InstallerSwitches')
        $UnresolvedFields.Add('InstallModes')
      }
      if ($ActiveInstallabilityActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.RuntimeActions' -Source 'SetupFactory' -Message 'Setup Factory contains process-closing, abort, or connectivity actions whose runtime outcome can change whether installation completes.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes, InstallerSuccessCodes -Evidence $ActiveInstallabilityActions))
        $UnresolvedFields.Add('InstallerSuccessCodes')
      }
      if ($ActiveRebootActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.RebootActions' -Source 'SetupFactory' -Message 'Setup Factory schedules file operations or execution for reboot; restart behavior and return-code mapping require VM validation.' -Kind Risk -Areas Installability -AffectedFields ExpectedReturnCodes -Evidence $ActiveRebootActions))
        $UnresolvedFields.Add('ExpectedReturnCodes')
      }
      if ($ActiveExternalCodeActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ExternalCodeActions' -Source 'SetupFactory' -Message 'Setup Factory calls an external DLL function. Its registry, filesystem, prerequisite, and installability effects cannot be derived from the CAction record alone.' -Kind ManualValidation -Areas Metadata, Installability, Security -AffectedFields ProductCode, Scope, AppsAndFeaturesEntries, Protocols, FileExtensions, Dependencies, InstallerSwitches, InstallModes -Evidence $ActiveExternalCodeActions))
        foreach ($Field in 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions', 'Dependencies') { $UnresolvedFields.Add($Field) }
      }
      if ($ActionEffects.UnknownActions.Count) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.UnknownActionIds' -Source 'SetupFactory' -Message 'A Setup Factory command table contains action IDs absent from the source-backed vocabulary for that generation.' -Kind Unsupported -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence $ActionEffects.UnknownActions))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
      if ($LegacyActionCatalog.PSObject.Properties['UnresolvedControlFlowCount'] -and $LegacyActionCatalog.UnresolvedControlFlowCount -gt 0) {
        $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ActionControlFlowUnresolved' -Source 'SetupFactory' -Message "$($LegacyActionCatalog.UnresolvedControlFlowCount) Setup Factory 6 loop, jump, or malformed block path(s) depend on runtime state and were preserved without speculative execution." -Kind Ambiguous -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ Count = $LegacyActionCatalog.UnresolvedControlFlowCount })))
        $UnresolvedFields.Add('InstallationMetadata.Actions')
      }
    }
    if ($HasBuiltInUninstall -and -not $VisibleRegistryArpEntries.Count -and [string]::IsNullOrWhiteSpace([string]$BuiltInProductCode)) {
      # An enabled uninstaller proves that an ARP route exists, but unresolved variables in its key
      # do not prove the concrete registry identity required by a manifest.
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.BuiltInArpIdentityUnresolved' -Source 'SetupFactory' -Message 'The built-in uninstaller is enabled, but its uninstall-key expression could not be resolved to a concrete ProductCode.' -Kind Incomplete -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
      $UnresolvedFields.Add('ProductCode')
      $UnresolvedFields.Add('AppsAndFeaturesEntries')
    }
    if (-not $InstalledCatalog.IsComplete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.FileTableIncomplete' -Source 'SetupFactory' -Message "The generation-specific installed-file table could not be decoded: $($InstalledCatalog.Error)" -Kind Unsupported -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId; ClassName = $InstalledCatalog.ClassName })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    } elseif (-not $InstalledCatalog.CanExtract -and $InstalledCatalog.CanExtractPartial) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.Truncated' -Source 'SetupFactory' -Message 'The installed-file catalog exceeds the available payload range. The installer is incomplete or corrupt; complete prefix records remain forensic evidence only.' -Kind Invalid -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = @($InstalledCatalog.Entries).Count; ExtractableEntryCount = $InstalledCatalog.ExtractableEntryCount; UnavailableEntryCount = $InstalledCatalog.UnavailableEntryCount; DeclaredPayloadBytes = $InstalledCatalog.DeclaredPayloadBytes; AvailablePayloadBytes = $Catalog.FileLength - $InstalledPayloadOffset })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    } elseif (-not $InstalledCatalog.CanExtract) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.LayoutUnresolved' -Source 'SetupFactory' -Message 'The installed-file catalog is readable, but none of its records map to the remaining executable as the supported sequential payload layout; extraction is disabled.' -Kind Unsupported -Areas Extraction -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = @($InstalledCatalog.Entries).Count; DeclaredPayloadBytes = $InstalledCatalog.DeclaredPayloadBytes; AvailablePayloadBytes = $Catalog.FileLength - $InstalledPayloadOffset })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    }
    if ($FilePolicySummary.AskUserOverwriteEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.FileOverwritePrompt' -Source 'SetupFactory' -Message 'One or more payload files use the AskUser overwrite policy. An existing destination file can therefore make an otherwise unattended installation prompt for input.' -Kind ManualValidation -Areas Installability -AffectedFields InstallerSwitches, InstallModes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.AskUserOverwriteEntries.Count; Entries = $FilePolicySummary.AskUserOverwriteEntries })))
    }
    if ($FilePolicySummary.UnknownOverwriteEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.FileOverwritePolicyUnresolved' -Source 'SetupFactory' -Message 'One or more payload files use an overwrite-policy value that is not defined by the supported Setup Factory runtime.' -Kind Incomplete -Areas Metadata, Installability -AffectedFields InstallationMetadata, InstallerSwitches, InstallModes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.UnknownOverwriteEntries.Count; Entries = $FilePolicySummary.UnknownOverwriteEntries })))
      $UnresolvedFields.Add('InstallationMetadata.FilePolicy')
    }
    if ($FilePolicySummary.ConditionalEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ConditionalInstalledFiles' -Source 'SetupFactory' -Message 'The installed-file catalog contains operating-system, language, advanced comparison, runtime, build-configuration, or package conditions; the effective installed-file set depends on the selected installation scenario.' -Kind Ambiguous -Areas Metadata -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.ConditionalEntries.Count; Entries = $FilePolicySummary.ConditionalEntries })))
      $UnresolvedFields.Add('InstallationMetadata.Files')
    }
    if ($FilePolicySummary.SelfRegisteringEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.SelfRegistrationEffects' -Source 'SetupFactory' -Message 'One or more payload files are registered through DllRegisterServer or type-library registration. Registry effects implemented by those binaries require static inspection or VM validation.' -Kind ManualValidation -Areas Metadata -AffectedFields Protocols, FileExtensions -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.SelfRegisteringEntries.Count; Entries = $FilePolicySummary.SelfRegisteringEntries })))
      $UnresolvedFields.Add('Protocols')
      $UnresolvedFields.Add('FileExtensions')
    }
    if ($FilePolicySummary.SuppressInUseNoticeEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.InUseReplacementDeferred' -Source 'SetupFactory' -Message 'One or more payload files suppress the in-use warning. Setup Factory can defer their replacement until restart, so reboot behavior and exit-code evidence require VM validation.' -Kind Risk -Areas Installability -AffectedFields ExpectedReturnCodes -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.SuppressInUseNoticeEntries.Count; Entries = $FilePolicySummary.SuppressInUseNoticeEntries })))
      $UnresolvedFields.Add('ExpectedReturnCodes')
    }
    if ($FilePolicySummary.CrcCheckDisabledEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Security.FileCrcCheckDisabled' -Source 'SetupFactory' -Message 'The compiled project disables Setup Factory CRC verification for one or more payload files.' -Kind Risk -Areas Extraction, Security -AffectedFields InstallationMetadata -Evidence ([ordered]@{ EntryCount = $FilePolicySummary.CrcCheckDisabledEntries.Count; Entries = $FilePolicySummary.CrcCheckDisabledEntries })))
    }
    if (-not $DependencyCatalog.IsComplete) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Payload.DependencyTableIncomplete' -Source 'SetupFactory' -Message "The bundled prerequisite table could not be decoded: $($DependencyCatalog.Error)" -Kind Unsupported -Areas Extraction, Installability -AffectedFields Dependencies -Evidence ([ordered]@{ ProfileId = $Overlay.ProfileId })))
      $UnresolvedFields.Add('Dependencies')
    } elseif ($DependencyCatalog.Entries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Installability.BundledPrerequisite' -Source 'SetupFactory' -Message 'The installer bundles one or more prerequisite executables; their launch conditions and exit-code handling require static or VM validation.' -Kind ManualValidation -Areas Installability -AffectedFields Dependencies -Evidence $DependencyCatalog.Entries))
    }
    if ($Overlay.SupportsMetadata -and -not $HasBuiltInUninstall -and -not $RegistryArpEntries.Count) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.ArpConfigurationAbsent' -Source 'SetupFactory' -Message 'No built-in uninstall configuration or literal uninstall-key write was found.' -Kind Information -Areas Metadata -AffectedFields ProductCode, AppsAndFeaturesEntries))
    }
    if ($RegistryArpScopes.Count -gt 1) {
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.MixedArpScopes' -Source 'SetupFactory' -Message 'Literal uninstall-key writes target both user and machine registry hives; no single scope was selected.' -Kind Ambiguous -Areas Metadata -AffectedFields Scope, ProductCode, AppsAndFeaturesEntries -Evidence $RegistryArpEntries))
      $UnresolvedFields.Add('Scope')
    }
    if ($UnresolvedRegistryCallCount -gt 0) {
      $RegistryDiagnosticMessage = if ($LegacyActionCatalog) { "$UnresolvedRegistryCallCount legacy registry action or control-flow record(s) could not be projected as deterministic install-time evidence." } else { "$UnresolvedRegistryCallCount Registry.SetValue call(s) use computed, malformed, or unsupported arguments and were not projected as deterministic registry evidence." }
      # Opaque registry actions can always hide associations or an additional ARP row, but they do
      # not invalidate an independently proven built-in ProductCode or scope. Promote only fields
      # that still depend on unresolved calls so partial manifest updates remain actionable.
      $RegistryAffectedFields = [Collections.Generic.List[string]]::new()
      foreach ($Field in 'AppsAndFeaturesEntries', 'Protocols', 'FileExtensions') { $RegistryAffectedFields.Add($Field) }
      if ([string]::IsNullOrWhiteSpace([string]$ProductCode)) { $RegistryAffectedFields.Add('ProductCode') }
      if ([string]::IsNullOrWhiteSpace([string]$Scope)) { $RegistryAffectedFields.Add('Scope') }
      $Diagnostics.Add((New-InstallerDiagnostic -Id 'SetupFactory.Metadata.RegistryActionsUnresolved' -Source 'SetupFactory' -Message $RegistryDiagnosticMessage -Kind Incomplete -Areas Metadata -AffectedFields $RegistryAffectedFields.ToArray() -Evidence ([ordered]@{ UnresolvedCallCount = $UnresolvedRegistryCallCount })))
      foreach ($Field in $RegistryAffectedFields) { $UnresolvedFields.Add($Field) }
    }
    foreach ($Diagnostic in @($RegistryAssociationInfo.Diagnostics)) { $Diagnostics.Add($Diagnostic) }

    $WritesAppsAndFeaturesEntry = [bool]($HasBuiltInUninstall -or $VisibleRegistryArpEntries.Count)
    $AppsAndFeaturesEntries = [Collections.Generic.List[object]]::new()
    if ($VisibleRegistryArpEntries.Count) {
      foreach ($Arp in $VisibleRegistryArpEntries) {
        $ManifestEntry = [ordered]@{}
        foreach ($Field in 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode') {
          if (-not [string]::IsNullOrWhiteSpace([string]$Arp.$Field)) { $ManifestEntry[$Field] = $Arp.$Field }
        }
        $ManifestEntry.InstallerType = 'exe'
        $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
      }
    } elseif ($HasBuiltInUninstall) {
      $ManifestEntry = [ordered]@{}
      $BuiltInArpValues = [ordered]@{
        DisplayName    = $DisplayName
        DisplayVersion = $DisplayVersion
        Publisher      = $Publisher
        ProductCode    = $ProductCode
      }
      foreach ($Field in $BuiltInArpValues.Keys) {
        if (-not [string]::IsNullOrWhiteSpace([string]$BuiltInArpValues[$Field])) { $ManifestEntry[$Field] = $BuiltInArpValues[$Field] }
      }
      $ManifestEntry.InstallerType = 'exe'
      $AppsAndFeaturesEntries.Add([pscustomobject]$ManifestEntry)
    }

    $InstallerSwitches = [ordered]@{}
    $InstallModes = if ($SilentInstallationInfo.IsResolved -and $SilentInstallationInfo.SupportsSilentInstallation) {
      $InstallerSwitches['Silent'] = '/S'
      @('interactive', 'silent')
    } elseif ($SilentInstallationInfo.IsResolved) {
      @('interactive')
    } else {
      @()
    }

    # Construct the shared result from Setup Factory evidence directly.
    [pscustomobject][ordered]@{
      Path                         = $File.FullName
      InstallerType                = 'exe'
      ProductCode                  = $ProductCode
      UpgradeCode                  = $null
      DisplayName                  = $DisplayName
      DisplayVersion               = $DisplayVersion
      Publisher                    = $Publisher
      Scope                        = $Scope
      DefaultInstallLocation       = $InstallLocation
      WritesAppsAndFeaturesEntry   = $WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode   = $WritesAppsAndFeaturesEntry ? $ProductCode : $null
      AppsAndFeaturesInstallerType = $WritesAppsAndFeaturesEntry ? 'exe' : $null
      AppsAndFeaturesEntries       = $AppsAndFeaturesEntries.ToArray()
      Diagnostics                  = @(Merge-InstallerDiagnostics -Diagnostic $Diagnostics.ToArray())
      UnresolvedFields             = [string[]]@($UnresolvedFields | Sort-Object -Unique)
      Family                       = 'Setup Factory'
      RegistryWrites               = $RegistryWrites
      RegistryArpEntries           = $RegistryArpEntries
      RegistryAssociationInfo      = $RegistryAssociationInfo
      Protocols                    = $RegistryAssociationInfo.Protocols
      FileExtensions               = $RegistryAssociationInfo.FileExtensions
      ContainerEntries             = $Catalog.Entries
      DependencyPayloads           = $DependencyCatalog.Entries
      PayloadCatalog               = $InstalledCatalog.Entries
      InstalledFileCatalog         = $InstalledCatalog
      FilePolicySummary            = $FilePolicySummary
      ExtractedFiles               = @()
      CanExpand                    = [bool]$InstalledCatalog.CanExtract
      CanExpandPartial             = [bool]$InstalledCatalog.CanExtractPartial
      CanExpandRawEntries          = $true
      SupportsSilentInstallation   = $SilentInstallationInfo.SupportsSilentInstallation
      StartsInSilentMode           = $SilentInstallationInfo.StartsInSilentMode
      InstallerSwitches            = [pscustomobject]$InstallerSwitches
      InstallModes                 = [string[]]$InstallModes
      SilentInstallationEvidence   = $SilentInstallationInfo.Evidence
      ProductMetadata              = $LegacyMetadata ? $LegacyMetadata.Product : $null
      UninstallConfiguration       = $LegacyMetadata ? $LegacyMetadata.Uninstall : $null
      LegacyActionCatalog          = $LegacyActionCatalog
      ActionEffects                = $ActionEffects
      VariableAssignments          = $ActionEffects.VariableAssignments
      ExecutionActions             = $ActionEffects.ExecutionActions
      FileSystemActions            = $ActionEffects.FileSystemActions
      IniActions                   = $ActionEffects.IniActions
      VariableReads                = $ActionEffects.VariableReads
      UserInteractionActions       = $ActionEffects.UserInteractionActions
      InstallabilityActions        = $ActionEffects.InstallabilityActions
      Shortcuts                    = $ActionEffects.ShortcutActions
      ServiceActions               = $ActionEffects.ServiceActions
      RebootActions                = $ActionEffects.RebootActions
      ExternalCodeActions          = $ActionEffects.ExternalCodeActions
      EmbeddedRuntimeInfo          = $EmbeddedRuntimeInfo
      ParserVersionInfo            = [pscustomobject][ordered]@{
        Family                 = 'Setup Factory'
        MajorVersion           = $EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.MajorVersion : ($Overlay.Version -ne 0 ? $Overlay.Version : $null)
        BuilderVersion         = $Overlay.BuilderVersion ?? ($EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.Version : $null)
        BuilderVersionSource   = $Overlay.BuilderVersionSource ?? ($EmbeddedRuntimeInfo.IsTrusted ? 'EmbeddedRuntimeVersionResource' : $null)
        OuterRuntimeVersion    = $Overlay.BuilderVersion
        EmbeddedRuntimeVersion = $EmbeddedRuntimeInfo.IsTrusted ? $EmbeddedRuntimeInfo.Version : $null
        ProfileId              = $Overlay.ProfileId
        FormatGeneration       = $Overlay.FormatGeneration
        MetadataRoute          = $Overlay.MetadataRoute
        MetadataProfile        = if ($LegacyMetadata -and $LegacyMetadata.PSObject.Properties['MetadataProfile']) { $LegacyMetadata.MetadataProfile } else { $null }
        HeaderRoute            = $Overlay.HeaderRoute
        HeaderPrefixLength     = $Overlay.HeaderPrefixLength
        OverlayOffset          = $Overlay.Offset
      }
    }
  }
}

function Test-SetupFactory {
  <#
  .SYNOPSIS
    Test whether a file is a supported Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([bool])]
  param ([Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path)
  process {
    try {
      # A signature at the overlay boundary is only a candidate. Requiring the
      # complete bounded catalog rejects marker-only and truncated PE overlays.
      $null = Get-SetupFactoryArchiveCatalog -Path $Path
      return $true
    } catch {
      return $false
    }
  }
}

function Read-ProductVersionFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product version from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product name from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayName }
}
function Read-PublisherFromSetupFactory {
  <#
  .SYNOPSIS
    Read the publisher from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the ARP ProductCode from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).ProductCode }
}
function Read-ScopeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the installation scope from a Setup Factory installer
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Scope }
}

function Read-ProtocolsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal URL protocol names from Setup Factory registry actions.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Protocols }
}

function Read-FileExtensionsFromSetupFactory {
  <#
  .SYNOPSIS
    Read literal file-extension names from Setup Factory registry actions.
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  #>
  [OutputType([string[]])]
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).FileExtensions }
}

Export-ModuleMember -Function Get-SetupFactoryInfo, Expand-SetupFactoryInstaller, Test-SetupFactory, Read-ProductVersionFromSetupFactory, Read-ProductNameFromSetupFactory, Read-PublisherFromSetupFactory, Read-ProductCodeFromSetupFactory, Read-ScopeFromSetupFactory, Read-ProtocolsFromSetupFactory, Read-FileExtensionsFromSetupFactory
