# SPDX-License-Identifier: GPL-3.0-or-later
# Internal SetupFactory implementation. See SetupFactory.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# SetupFactory Container layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'SetupFactoryProject.psm1') -ErrorAction Stop

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
    $LauncherStream = [IO.File]::OpenRead($LauncherFile.FullName)
    try {
      # Check the opened handle, not only directory metadata, and read its exact bounded range.
      if ($LauncherStream.Length -gt $Script:SetupFactory31MaximumLauncherBytes) { throw 'The Setup Factory 3.1 launcher exceeds the configured size limit' }
      $LauncherBytes = Read-BinaryBytes -Stream $LauncherStream -Offset 0 -Count ([int]$LauncherStream.Length)
    } finally { $LauncherStream.Dispose() }
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

Export-ModuleMember -Function Read-SetupFactoryInstalledFileData, Test-SetupFactoryLegacyCatalog, Import-SetupFactoryCrusherDecoder, Read-SetupFactory31DuplicatedString, Get-SetupFactory31ArqCatalog, Copy-SetupFactory31EntryData, Read-SetupFactory31ArqEntryData, Read-SetupFactory31ProjectData, Get-SetupFactory31Media, Test-SetupFactory31Media, Expand-SetupFactory31Media, Get-SetupFactory31Info, Get-SetupFactoryOverlayInfo, Read-SetupFactoryOuterCatalogRecord, Get-SetupFactoryModern8OuterCatalog, Get-SetupFactoryArchiveCatalog, Read-SetupFactoryCatalogEntryData, Get-SetupFactoryEmbeddedRuntimeInfo
