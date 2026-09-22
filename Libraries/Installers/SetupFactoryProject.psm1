# SPDX-License-Identifier: GPL-3.0-or-later
# Internal SetupFactory implementation. See SetupFactory.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# SetupFactory Project layer. Internal modules are imported locally; public commands stay in the facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactoryMaximumEntries = 100000

$Script:SetupFactoryMaximumFileBytes = 1073741824

$Script:SetupFactoryMaximumScriptStringBytes = 65535

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

Export-ModuleMember -Function ConvertFrom-SetupFactoryText, Read-SetupFactoryExactByte, Read-SetupFactoryUInt32, Read-SetupFactoryInt64, Get-SetupFactoryCrc32, Expand-SetupFactoryCompressedData, Get-SetupFactorySessionVariable, Resolve-SetupFactoryVariable, Read-SetupFactoryDataInteger, Read-SetupFactoryDataBoolean, Read-SetupFactoryDataStringList, Read-SetupFactoryDataWordArray, Move-SetupFactoryDataOffset, Read-SetupFactoryDataString, Test-SetupFactoryLegacyMetadataText, Read-SetupFactoryBooleanByte, Read-SetupFactoryProjectDataCandidate, Get-SetupFactorySilentInstallationInfo, Read-SetupFactoryClassic4Metadata, Read-SetupFactoryLegacyProductMetadata, Read-SetupFactoryLegacyUninstallMetadata, Get-SetupFactoryLegacyMetadata, ConvertTo-SetupFactoryRegistryRoot, ConvertTo-SetupFactoryRegistryValueType, Read-SetupFactoryRegistryRecord4, Get-SetupFactoryRegistryCatalog4, Read-SetupFactoryConditionRecord5, Read-SetupFactoryConditionList5, Read-SetupFactoryRegistryRecord5, Get-SetupFactoryRegistryCatalog5, ConvertTo-SetupFactoryFilePolicy, Get-SetupFactoryLegacyOperatingSystemPolicy, ConvertFrom-SetupFactoryLegacyConditionOperator, ConvertTo-SetupFactoryInstalledFileRecord, Read-SetupFactoryFileRecord4, Read-SetupFactoryFileRecord5, Read-SetupFactoryFileRecord6, Read-SetupFactoryFileRecord7, Read-SetupFactoryFileRecord8Plus, ConvertTo-SetupFactoryPayloadRelativePath, Get-SetupFactoryDependencyFileCatalog, Get-SetupFactoryInstalledFileCatalog, Get-SetupFactoryFilePolicySummary
