# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Internal Inno implementation. See Inno.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# Inno Payload layer. Internal modules are imported locally; public commands stay in the facade.
Import-Module (Join-Path $PSScriptRoot 'InnoFormat.psm1') -ErrorAction Stop

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$INNO_MAX_DECOMPRESSED_BLOCK_SIZE = 1073741824

$INNO_PAYLOAD_BUFFER_SIZE = 1048576

$INNO_CHUNK_MAGIC = [System.Text.Encoding]::ASCII.GetString([byte[]](0x7A, 0x6C, 0x62, 0x1A))

$INNO_DISK_SLICE_ID_LEGACY = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x61, 0x33, 0x32, 0x1A)

$INNO_DISK_SLICE_ID_6502 = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x62, 0x33, 0x32, 0x1A)

$Script:InnoPayloadRouteDescriptors = @{
  'legacy-adler'              = [pscustomobject]@{ AlwaysCompressed = $true; CompressionFromLocation = $true }
  'chunked-always-compressed' = [pscustomobject]@{ AlwaysCompressed = $true; CompressionFromLocation = $false }
  'chunked-legacy'            = [pscustomobject]@{ AlwaysCompressed = $false; CompressionFromLocation = $false }
  'chunked-modern'            = [pscustomobject]@{ AlwaysCompressed = $false; CompressionFromLocation = $false }
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

function Import-InnoSliceStream {
  <#
  .SYNOPSIS
    Load the bounded external-media stream used for Inno disk slices.
  #>
  if (([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.InnoSliceStream').Type) { return }
  $SourcePath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '..', 'Assets', 'Source', 'Inno', 'InnoSliceStream.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.InnoSliceStream'
}

function Get-InnoDiskSliceHeaderInfo {
  <#
  .SYNOPSIS
    Validate an external Inno Setup disk-slice header.
  .PARAMETER Path
    Path to one setup-N.bin or setup-Na.bin slice.
  .PARAMETER InternalStructureVersion
    Catalogued setup structure version selecting the 32-bit idska32 or 64-bit idskb32 size record.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][int]$InternalStructureVersion
  )

  $SlicePath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $Modern = $InternalStructureVersion -ge 6502
  $HeaderLength = $Modern ? 16 : 12
  $ExpectedId = $Modern ? $Script:INNO_DISK_SLICE_ID_6502 : $Script:INNO_DISK_SLICE_ID_LEGACY
  $Stream = [IO.File]::Open($SlicePath, 'Open', 'Read', 'Read')
  try {
    if ($Stream.Length -lt $HeaderLength) { throw "The Inno Setup disk slice is shorter than its $HeaderLength-byte header: $SlicePath" }
    $Header = Read-BinaryBytes -Stream $Stream -Offset 0 -Count $HeaderLength
    if (-not (Test-BinarySequence -Left $Header[0..7] -Right $ExpectedId)) {
      $ExpectedName = $Modern ? 'idskb32' : 'idska32'
      throw "The Inno Setup disk slice does not contain the expected $ExpectedName header: $SlicePath"
    }
    $DeclaredSize = $Modern ? [BitConverter]::ToInt64($Header, 8) : [long][BitConverter]::ToUInt32($Header, 8)
    if ($DeclaredSize -ne $Stream.Length) {
      throw "The Inno Setup disk slice declares $DeclaredSize bytes but contains $($Stream.Length): $SlicePath"
    }
    return [pscustomobject]@{
      Path         = $SlicePath
      HeaderLength = $HeaderLength
      Length       = $Stream.Length
      Identifier   = $Modern ? 'idskb32' : 'idska32'
    }
  } finally { $Stream.Dispose() }
}

function Get-InnoDiskSliceFileName {
  <#
  .SYNOPSIS
    Reproduce Inno Setup's zero-based slice to physical media filename mapping.
  .PARAMETER InstallerPath
    Setup executable whose base name prefixes the external media.
  .PARAMETER Slice
    Zero-based logical slice number from a file-location record.
  .PARAMETER SlicesPerDisk
    Number of letter-suffixed slices emitted for each numbered disk.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$Slice,
    [Parameter(Mandatory)][ValidateRange(1, 26)][int]$SlicesPerDisk
  )

  $Prefix = [IO.Path]::GetFileNameWithoutExtension($InstallerPath)
  $Major = [Math]::Floor($Slice / $SlicesPerDisk) + 1
  $Minor = $Slice % $SlicesPerDisk
  if ($SlicesPerDisk -eq 1) { return "$Prefix-$Major.bin" }
  return "$Prefix-$Major$([char]([int][char]'a' + $Minor)).bin"
}

function Resolve-InnoDiskSliceSet {
  <#
  .SYNOPSIS
    Locate and validate the external slices required by one physical payload chunk.
  .PARAMETER InstallerPath
    Setup executable used for the official media filename prefix and default directory.
  .PARAMETER FirstSlice
    First zero-based slice named by the file-location record.
  .PARAMETER LastSlice
    Last zero-based slice named by the file-location record.
  .PARAMETER SlicesPerDisk
    Parsed setup-header media geometry.
  .PARAMETER InternalStructureVersion
    Catalogued structure version selecting the slice header layout.
  .PARAMETER DiskSourcePath
    Optional directories or explicit slice files searched before the installer directory.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][string]$InstallerPath,
    [Parameter(Mandatory)][int]$FirstSlice,
    [Parameter(Mandatory)][int]$LastSlice,
    [Parameter(Mandatory)][ValidateRange(1, 26)][int]$SlicesPerDisk,
    [Parameter(Mandatory)][int]$InternalStructureVersion,
    [string[]]$DiskSourcePath
  )

  $Directories = [Collections.Generic.List[string]]::new()
  $ExplicitFiles = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($SourcePath in @($DiskSourcePath)) {
    if ([string]::IsNullOrWhiteSpace($SourcePath)) { continue }
    $Resolved = Resolve-InstallerFileSystemPath -Path $SourcePath
    if (Test-Path -LiteralPath $Resolved -PathType Leaf) {
      $ExplicitFiles[[IO.Path]::GetFileName($Resolved)] = $Resolved
    } elseif (Test-Path -LiteralPath $Resolved -PathType Container) {
      $Directories.Add($Resolved)
    } else {
      throw "The Inno Setup disk source does not exist: $Resolved"
    }
  }
  $InstallerDirectory = [IO.Path]::GetDirectoryName($InstallerPath)
  if (-not $Directories.Contains($InstallerDirectory)) { $Directories.Add($InstallerDirectory) }

  $Result = [Collections.Generic.List[object]]::new()
  for ($Slice = $FirstSlice; $Slice -le $LastSlice; $Slice++) {
    $FileName = Get-InnoDiskSliceFileName -InstallerPath $InstallerPath -Slice $Slice -SlicesPerDisk $SlicesPerDisk
    $SlicePath = $null
    if (-not $ExplicitFiles.TryGetValue($FileName, [ref]$SlicePath)) {
      foreach ($Directory in $Directories) {
        $Candidate = Join-Path -Path $Directory -ChildPath $FileName
        if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
          $SlicePath = (Get-Item -LiteralPath $Candidate -Force).FullName
          break
        }
      }
    }
    if (-not $SlicePath) {
      throw "The Inno Setup external media slice is missing: $FileName"
    }
    $Header = Get-InnoDiskSliceHeaderInfo -Path $SlicePath -InternalStructureVersion $InternalStructureVersion
    $Header | Add-Member -NotePropertyName Slice -NotePropertyValue $Slice
    $Result.Add($Header)
  }
  return $Result.ToArray()
}

function Get-InnoFileChunkStream {
  <#
  .SYNOPSIS
    Open the compressed bytes of one embedded or external Inno payload chunk.
  .PARAMETER Path
    Setup executable containing metadata and, for single-file media, payload data.
  .PARAMETER Offset1
    Embedded payload base. Zero selects external disk slices.
  .PARAMETER Location
    Validated file-location record containing slice and chunk bounds.
  .PARAMETER InternalStructureVersion
    Catalogued structure version selecting disk-slice framing.
  .PARAMETER SlicesPerDisk
    Parsed setup-header media geometry.
  .PARAMETER DiskSourcePath
    Optional external-media directories or explicit files.
  #>
  [OutputType([System.IO.Stream])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset1,
    [Parameter(Mandatory)][pscustomobject]$Location,
    [Parameter(Mandatory)][int]$InternalStructureVersion,
    [int]$SlicesPerDisk = 0,
    [string[]]$DiskSourcePath
  )

  if ($Offset1 -ne 0) {
    if ($Location.FirstSlice -ne $Location.LastSlice) {
      throw 'An embedded Inno Setup payload cannot span external disk slices'
    }
    $InstallerStream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
      $ChunkOffset = [long]$Offset1 + [long]$Location.StartOffset
      if ($ChunkOffset -lt 0 -or $ChunkOffset -gt $InstallerStream.Length - 4 -or
        $Location.ChunkCompressedSize -gt $InstallerStream.Length - $ChunkOffset - 4) {
        throw 'The Inno Setup file chunk is outside the installer'
      }
      $ChunkMagic = [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $InstallerStream -Offset $ChunkOffset -Count 4))
      if ($ChunkMagic -ne $Script:INNO_CHUNK_MAGIC) { throw 'The Inno Setup chunk marker is invalid' }
      return New-BoundedReadStream -Stream $InstallerStream -Offset ($ChunkOffset + 4) -Length $Location.ChunkCompressedSize
    } catch {
      $InstallerStream.Dispose()
      throw
    }
  }

  if ($SlicesPerDisk -lt 1) {
    throw 'The Inno Setup header does not expose valid SlicesPerDisk metadata required to locate external media'
  }
  $Slices = @(Resolve-InnoDiskSliceSet -InstallerPath $Path -FirstSlice $Location.FirstSlice -LastSlice $Location.LastSlice `
      -SlicesPerDisk $SlicesPerDisk -InternalStructureVersion $InternalStructureVersion -DiskSourcePath $DiskSourcePath)
  $First = $Slices[0]
  if ($Location.StartOffset -lt $First.HeaderLength -or $Location.StartOffset -gt $First.Length - 4) {
    throw 'The Inno Setup external chunk marker is outside its first disk slice'
  }
  $FirstStream = [IO.File]::Open($First.Path, 'Open', 'Read', 'Read')
  try {
    $ChunkMagic = [Text.Encoding]::ASCII.GetString((Read-BinaryBytes -Stream $FirstStream -Offset $Location.StartOffset -Count 4))
  } finally { $FirstStream.Dispose() }
  if ($ChunkMagic -ne $Script:INNO_CHUNK_MAGIC) { throw 'The Inno Setup external chunk marker is invalid' }

  $Paths = [Collections.Generic.List[string]]::new()
  $Offsets = [Collections.Generic.List[long]]::new()
  $Lengths = [Collections.Generic.List[long]]::new()
  $Remaining = [long]$Location.ChunkCompressedSize
  for ($Index = 0; $Index -lt $Slices.Count; $Index++) {
    $Slice = $Slices[$Index]
    $Offset = $Index -eq 0 ? [long]$Location.StartOffset + 4 : [long]$Slice.HeaderLength
    $Available = [long]$Slice.Length - $Offset
    if ($Available -lt 0) { throw "The Inno Setup disk slice data range is invalid: $($Slice.Path)" }
    $Length = [Math]::Min($Remaining, $Available)
    if ($Index -lt $Slices.Count - 1 -and $Length -ne $Available) {
      throw 'The Inno Setup location record names additional slices after the compressed chunk has ended'
    }
    $Paths.Add($Slice.Path)
    $Offsets.Add($Offset)
    $Lengths.Add($Length)
    $Remaining -= $Length
  }
  if ($Remaining -ne 0) { throw 'The Inno Setup external disk slices end before the compressed chunk is complete' }

  Import-InnoSliceStream
  return [Dumplings.InstallerParsers.InnoSliceStream]::new($Paths.ToArray(), $Offsets.ToArray(), $Lengths.ToArray())
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

function Get-InnoPayloadCompressionMethod {
  <#
  .SYNOPSIS
    Resolve payload compression when an historical header schema does not yet expose CompressMethod.
  .PARAMETER Path
    Installer path containing the embedded payload stream.
  .PARAMETER Offset1
    Absolute base offset of the embedded setup data.
  .PARAMETER Location
    Validated file-location record identifying the physical chunk.
  .PARAMETER Layout
    Catalog descriptor constraining the permitted historical fallback.
  .PARAMETER SlicesPerDisk
    Parsed external-media geometry when Offset1 is zero.
  .PARAMETER DiskSourcePath
    Optional external-media directories or explicit slice paths.
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset1,
    [Parameter(Mandatory)][pscustomobject]$Location,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [int]$SlicesPerDisk = 0,
    [string[]]$DiskSourcePath
  )

  $PayloadDescriptor = $Script:InnoPayloadRouteDescriptors[$Layout.PayloadRoute]
  if (-not $PayloadDescriptor) { throw "Unsupported Inno payload route: $($Layout.PayloadRoute)" }
  if ($PayloadDescriptor.CompressionFromLocation) { return $Location.IsBZip2 ? 'BZip2' : 'Zlib' }

  $Stream = Get-InnoFileChunkStream -Path $Path -Offset1 $Offset1 -Location $Location `
    -InternalStructureVersion $Layout.InternalStructureVersion -SlicesPerDisk $SlicesPerDisk -DiskSourcePath $DiskSourcePath
  try {
    $Prefix = [byte[]]::new(3)
    $PrefixRead = $Stream.Read($Prefix, 0, 3)
    if ($PrefixRead -ne 3) { throw 'The Inno Setup compressed payload prefix is truncated' }
  } finally { $Stream.Dispose() }

  if ($Prefix[0] -eq 0x42 -and $Prefix[1] -eq 0x5A -and $Prefix[2] -eq 0x68) { return 'BZip2' }
  if (($Prefix[0] -band 0x0F) -eq 8 -and (([int]$Prefix[0] * 256 + $Prefix[1]) % 31) -eq 0) { return 'Zlib' }

  # Inno's generic LZMA block reader begins at structure 4.1.6. LZMA2 was
  # introduced after the catalogued fixed header exposes CompressMethod, so an
  # otherwise unidentified historical stream in this narrow interval is LZMA.
  if ($Layout.InternalStructureVersion -ge 4105 -and $Layout.InternalStructureVersion -lt 5303) { return 'Lzma' }
  throw 'The historical Inno Setup payload compression method could not be resolved structurally'
}

$Script:InnoCallTransformHandlers = @{
  'legacy-stream' = {
    param([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [long]$Length, $Hash)
    [Dumplings.InstallerParsers.InnoCallTransform]::DecodeStateful($InputStream, $OutputStream, $Length, $Hash)
  }
  'relative24-v1' = {
    param([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [long]$Length, $Hash)
    [Dumplings.InstallerParsers.InnoCallTransform]::DecodeLegacy($InputStream, $OutputStream, $Length, $Hash)
  }
  'relative24-v3' = {
    param([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [long]$Length, $Hash)
    [Dumplings.InstallerParsers.InnoCallTransform]::Decode($InputStream, $OutputStream, $Length, $Hash)
  }
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
  .PARAMETER PayloadRoute
    Catalogued physical payload framing route.
  .PARAMETER CallTransformRoute
    Catalogued executable CALL/JMP transform route.
  .PARAMETER InternalStructureVersion
    Catalogued setup structure version selecting external disk framing.
  .PARAMETER SlicesPerDisk
    Parsed setup-header media geometry.
  .PARAMETER DiskSourcePath
    Optional external-media directories or explicit slice paths.
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][long]$Offset1,
    [Parameter(Mandatory)][pscustomobject]$Location,
    [Parameter(Mandatory)][string]$CompressionMethod,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidateSet('legacy-adler', 'chunked-always-compressed', 'chunked-legacy', 'chunked-modern')][string]$PayloadRoute,
    [Parameter(Mandatory)][ValidateSet('legacy-stream', 'relative24-v1', 'relative24-v3')][string]$CallTransformRoute,
    [Parameter(Mandatory)][int]$InternalStructureVersion,
    [int]$SlicesPerDisk = 0,
    [string[]]$DiskSourcePath
  )

  if ($Location.Flags.ChunkEncrypted) { throw 'Encrypted Inno Setup file chunks require the setup password and are not supported' }

  if ($Location.OriginalSize -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -or
    $Location.ChunkSuboffset -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE -or
    $Location.OriginalSize -gt $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE - $Location.ChunkSuboffset) {
    throw "The Inno Setup payload exceeds the $($Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE)-byte extraction limit"
  }

  $InstallerPath = (Get-Item -LiteralPath $Path -Force).FullName
  $ChunkRange = $null
  $Decoder = $null
  $Hash = $null
  $OutputStream = $null
  $Buffer = $null
  $TemporaryPath = "$OutputPath.$([guid]::NewGuid().ToString('N')).partial"
  try {
    # Get-InnoFileChunkStream returns one exact compressed range for embedded
    # media or a forward-only logical stream spanning validated external slices.
    $ChunkRange = Get-InnoFileChunkStream -Path $InstallerPath -Offset1 $Offset1 -Location $Location `
      -InternalStructureVersion $InternalStructureVersion -SlicesPerDisk $SlicesPerDisk -DiskSourcePath $DiskSourcePath
    $PayloadDescriptor = $Script:InnoPayloadRouteDescriptors[$PayloadRoute]
    if (-not $PayloadDescriptor) { throw "Unsupported Inno payload route: $PayloadRoute" }
    $EffectiveCompressionMethod = if ($PayloadDescriptor.CompressionFromLocation -and $Location.IsBZip2) { 'BZip2' } else { $CompressionMethod }
    $IsCompressed = $PayloadDescriptor.AlwaysCompressed -or $Location.Flags.ChunkCompressed
    $DecoderInfo = Open-InnoFileChunkDecoder -Stream $ChunkRange -CompressionMethod $EffectiveCompressionMethod `
      -Compressed $IsCompressed -CompressedSize $Location.ChunkCompressedSize
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
    $HashAlgorithm = switch ($Location.DigestAlgorithm) {
      'Adler32' { $null }
      'CRC32' { $null }
      'MD5' { [System.Security.Cryptography.HashAlgorithmName]::MD5 }
      'SHA1' { [System.Security.Cryptography.HashAlgorithmName]::SHA1 }
      'SHA256' { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
      default { throw "Unsupported Inno Setup file digest algorithm: $($Location.DigestAlgorithm)" }
    }
    if ($null -ne $HashAlgorithm) {
      $Hash = [System.Security.Cryptography.IncrementalHash]::CreateHash($HashAlgorithm)
    }

    # Inno applies the CALL/JMP transform to exact 64 KiB blocks. Delegate that
    # source-defined framing to the bounded C# stream implementation; ordinary
    # files keep the pooled copy loop and never materialize the full payload.
    if ($Location.Flags.CallInstructionOptimized) {
      Import-InnoCallTransform
      $TransformHandler = $Script:InnoCallTransformHandlers[$CallTransformRoute]
      if (-not $TransformHandler) { throw "Unsupported Inno CALL/JMP transform route: $CallTransformRoute" }
      & $TransformHandler $PayloadStream $OutputStream ([long]$Location.OriginalSize) $Hash
    } else {
      $Remaining = [long]$Location.OriginalSize
      while ($Remaining -gt 0) {
        $BlockLength = [int][Math]::Min($Script:INNO_PAYLOAD_BUFFER_SIZE, $Remaining)
        $TotalRead = 0
        while ($TotalRead -lt $BlockLength) {
          $Read = $PayloadStream.Read($Buffer, $TotalRead, $BlockLength - $TotalRead)
          if ($Read -le 0) { throw 'The Inno Setup file payload is truncated' }
          $TotalRead += $Read
        }
        if ($Hash) { $Hash.AppendData($Buffer, 0, $BlockLength) }
        $OutputStream.Write($Buffer, 0, $BlockLength)
        $Remaining -= $BlockLength
      }
    }

    $OutputStream.Dispose()
    $OutputStream = $null
    $DigestMatches = switch ($Location.DigestAlgorithm) {
      'Adler32' {
        Import-InnoCallTransform
        $InputStream = [IO.File]::OpenRead($TemporaryPath)
        try {
          [uint32]$ActualValue = [Dumplings.InstallerParsers.InnoCallTransform]::ComputeAdler32($InputStream)
        } finally { $InputStream.Dispose() }
        $ActualValue -eq [BitConverter]::ToUInt32($Location.Digest, 0)
      }
      'CRC32' {
        (Get-BinaryCrc32 -Path $TemporaryPath -MaximumBytes $Location.OriginalSize) -eq [BitConverter]::ToUInt32($Location.Digest, 0)
      }
      default {
        $ActualDigest = $Hash.GetHashAndReset()
        Test-BinarySequence -Left $ActualDigest -Right $Location.Digest
      }
    }
    if (-not $DigestMatches) {
      throw "The extracted Inno Setup file does not match its stored $($Location.DigestAlgorithm) digest"
    }
    [System.IO.File]::Move($TemporaryPath, $OutputPath, $true)
    return Get-Item -LiteralPath $OutputPath -Force
  } finally {
    if ($OutputStream) { $OutputStream.Dispose() }
    if ($Hash) { $Hash.Dispose() }
    if ($Decoder) { $Decoder.Dispose() }
    if ($ChunkRange) { $ChunkRange.Dispose() }
    if ($Buffer) { [System.Buffers.ArrayPool[byte]]::Shared.Return($Buffer, $false) }
    if (Test-Path -LiteralPath $TemporaryPath) { Remove-Item -LiteralPath $TemporaryPath -Force }
  }
}

Export-ModuleMember -Function Resolve-InnoExtractionPath, Resolve-InnoVersion5FileMatch, Convert-InnoCallInstructions, Convert-InnoCallInstructions5309, Import-InnoSliceStream, Get-InnoDiskSliceHeaderInfo, Get-InnoDiskSliceFileName, Resolve-InnoDiskSliceSet, Get-InnoFileChunkStream, Open-InnoFileChunkDecoder, Get-InnoPayloadCompressionMethod, Write-InnoFilePayload
