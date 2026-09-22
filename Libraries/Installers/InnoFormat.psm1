# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Internal Inno implementation. See Inno.psm1 for format sources and the binary layout.
# Parsed operation contexts are passed explicitly; no caller-owned stream is retained globally.

# Inno Format layer. Internal modules are imported locally; public commands stay in the facade.

if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

$INNO_SETUP_ID_SIZE = 64

$INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE = 11111

$INNO_RT_RCDATA = 10

$INNO_SIGNATURE_PATTERN = '^(?<Prefix>Inno Setup Setup Data|My Inno Setup Extensions Setup Data) \((?<Version>[^)]+)\)(?: \((?<Unicode>[uU])\))?(?<Suffix>.*)$'

$INNO_OFFSET_TABLE_ID = [System.Text.Encoding]::ASCII.GetString([byte[]](0x72, 0x44, 0x6C, 0x50, 0x74, 0x53, 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A))

$INNO_LEGACY_LOADER_HEADER_OFFSET = 0x30

$INNO_LEGACY_LOADER_HEADER_ID = 0x6F6E6E49

$INNO_LEGACY_OFFSET_TABLE_IDS = @{
  'rDlPtS02' = 'legacy-s02'
  'rDlPtS04' = 'legacy-s04'
  'rDlPtS05' = 'legacy-s05'
  'rDlPtS06' = 'legacy-s06'
  'rDlPtS07' = 'legacy-s07'
}

$INNO_ENCRYPTION_HEADER_SIZE_6500 = 49

$INNO_MAX_CHUNK_SIZE = 4096

$INNO_MAX_DECOMPRESSED_BLOCK_SIZE = 1073741824

$INNO_MAX_ENTRY_STRING_SIZE = 1048576

$INNO_MAX_FILE_ENTRY_PATH_SCAN = 16384

$INNO_MAX_COMPILED_CODE_SIZE = 16777216

$INNO_LEAD_BYTES_SIZE = 32

$Script:InnoFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'InnoFormatCatalog.psd1') -SkipLimitCheck

$Script:InnoResourceOffsetTableRoutes = @{
  1 = [pscustomobject]@{ Route = 'resource-v1'; MinimumSize = 44; CrcOffset = 40; CrcLength = 40; IntegerSize = 4; Signed = $false; TotalSizeOffset = 16; Offset0Offset = 32; Offset1Offset = 36 }
  2 = [pscustomobject]@{ Route = 'resource-v2'; MinimumSize = 64; CrcOffset = 60; CrcLength = 60; IntegerSize = 8; Signed = $true; TotalSizeOffset = 16; Offset0Offset = 40; Offset1Offset = 48 }
}

$Script:InnoLegacyOffsetTableRoutes = @{
  'legacy-s02' = [pscustomobject]@{ MinimumSize = 44; CrcOffset = $null; CrcLength = 0; TotalSizeOffset = 12; Offset0Offset = 36; Offset1Offset = 40 }
  'legacy-s04' = [pscustomobject]@{ MinimumSize = 40; CrcOffset = $null; CrcLength = 0; TotalSizeOffset = 12; Offset0Offset = 32; Offset1Offset = 36 }
  'legacy-s05' = [pscustomobject]@{ MinimumSize = 40; CrcOffset = $null; CrcLength = 0; TotalSizeOffset = 12; Offset0Offset = 32; Offset1Offset = 36 }
  'legacy-s06' = [pscustomobject]@{ MinimumSize = 44; CrcOffset = 40; CrcLength = 40; TotalSizeOffset = 12; Offset0Offset = 32; Offset1Offset = 36 }
  'legacy-s07' = [pscustomobject]@{ MinimumSize = 40; CrcOffset = 36; CrcLength = 36; TotalSizeOffset = 12; Offset0Offset = 28; Offset1Offset = 32 }
}

function Copy-InnoCatalogMap {
  <#
  .SYNOPSIS
    Copy a catalog dictionary into an independently mutable ordered dictionary.
  .PARAMETER InputObject
    Catalog dictionary whose scalar and array values are copied.
  #>
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param ([Parameter(Mandatory)][System.Collections.IDictionary]$InputObject)

  $Result = [ordered]@{}
  foreach ($Key in $InputObject.Keys) {
    $Value = $InputObject[$Key]
    $Result[$Key] = if ($Value -is [array]) { @($Value) } else { $Value }
  }
  return $Result
}

function Test-InnoCatalogDelta {
  <#
  .SYNOPSIS
    Test whether one declarative catalog delta applies to a format row.
  .PARAMETER Delta
    Delta containing optional version, edition, and character-mode selectors.
  .PARAMETER Format
    Exact catalog format row being resolved.
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Delta,
    [Parameter(Mandatory)][System.Collections.IDictionary]$Format
  )

  $Version = [int]$Format.InternalStructureVersion
  if ($Delta.Contains('MinimumVersion') -and $Version -lt [int]$Delta.MinimumVersion) { return $false }
  if ($Delta.Contains('MaximumVersion') -and $Version -gt [int]$Delta.MaximumVersion) { return $false }
  if ($Delta.Contains('CharacterMode') -and $Format.CharacterMode -cne $Delta.CharacterMode) { return $false }
  if ($Delta.Contains('EditionId') -and $Format.EditionId -cne $Delta.EditionId) { return $false }
  return $true
}

function Resolve-InnoCatalogFormat {
  <#
  .SYNOPSIS
    Resolve one exact catalog row into a complete parser layout.
  .DESCRIPTION
    Applies ordered record deltas once at module runtime and projects named
    count, header-field, and file-entry schemas. Parsing functions consume the
    resolved properties and do not make version-threshold layout decisions.
  .PARAMETER Format
    Exact format row from InnoFormatCatalog.psd1.
  .PARAMETER LayoutResolution
    Evidence describing exact, ambiguous, or validated-nearest selection.
  .PARAMETER CandidateIds
    Exact format IDs that shared the observed signature and loader family.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.Collections.IDictionary]$Format,
    [string]$LayoutResolution = 'Exact',
    [string[]]$CandidateIds = @([string]$Format.Id)
  )

  $Resolved = Copy-InnoCatalogMap -InputObject $Format
  foreach ($DeltaGroupName in 'RouteDeltas', 'HeaderContentDeltas', 'RecordDeltas', 'RecordFamilyDeltas', 'HeaderFixedDeltas') {
    foreach ($Delta in $Script:InnoFormatCatalog[$DeltaGroupName]) {
      if (-not (Test-InnoCatalogDelta -Delta $Delta -Format $Format)) { continue }
      foreach ($Key in $Delta.Set.Keys) { $Resolved[$Key] = $Delta.Set[$Key] }
    }
  }

  # Inno 5.3.3 and later place SlicesPerDisk immediately before the two
  # one-byte uninstall-log and directory-warning enums. Inno 4.x has two
  # additional enums in that interval, so its exact offsets remain catalogued.
  if ($null -eq $Resolved.SlicesPerDiskOffset -and
    $null -ne $Resolved.PrivilegesRequiredOffset -and
    [int]$Resolved.PrivilegesRequiredOffset -ge 6) {
    $Resolved.SlicesPerDiskOffset = [int]$Resolved.PrivilegesRequiredOffset - 6
    $Resolved.SlicesPerDiskDefault = $null
    $Resolved.SupportsExternalDiskSlices = $true
  }

  $Resolved.VersionNumber = if ([int]$Format.InternalStructureVersion -ge 700000) { 7000 } else { [int]$Format.InternalStructureVersion }
  $Resolved.Edition = [string]$Script:InnoFormatCatalog.Editions[$Format.EditionId]
  $Resolved.StringEncoding = [string]$Format.CharacterMode
  $Resolved.HeaderCountNames = [string[]]@($Script:InnoFormatCatalog.HeaderCountSchemas[$Format.HeaderCountSchema])
  $Resolved.HeaderFields = [pscustomobject](Copy-InnoCatalogMap -InputObject $Script:InnoFormatCatalog.HeaderFieldSchemas[$Format.HeaderFieldSchema])
  $Resolved.FileEntryFields = [string[]]@($Script:InnoFormatCatalog.FileEntrySchemas[$Format.FileEntrySchema])
  if ($null -ne $Resolved.CompiledCodeStringIndex -and [int]$Resolved.CompiledCodeStringIndex -lt 0) {
    $Resolved.CompiledCodeStringIndex = [int]$Format.HeaderStringCount + [int]$Format.HeaderAnsiStringCount + [int]$Resolved.CompiledCodeStringIndex
  }
  $RecordFamilies = [ordered]@{}
  foreach ($Family in 'Language', 'CustomMessage', 'Permission', 'Type', 'Component', 'Task', 'Dir', 'ISSigKey', 'Icon', 'Ini', 'Registry', 'Delete', 'Run') {
    $SchemaProperty = "${Family}RecordSchema"
    $SchemaId = [string]$Resolved[$SchemaProperty]
    if ([string]::IsNullOrWhiteSpace($SchemaId) -or -not $Script:InnoFormatCatalog.RecordFamilySchemas.Contains($SchemaId)) {
      throw "Inno catalog format '$($Format.Id)' does not resolve a $Family record schema"
    }
    $Schema = Copy-InnoCatalogMap -InputObject $Script:InnoFormatCatalog.RecordFamilySchemas[$SchemaId]
    $Schema.Id = $SchemaId
    $Schema.CountField = switch ($Family) {
      'Language' { 'NumLanguageEntries' }
      'CustomMessage' { 'NumCustomMessageEntries' }
      'Permission' { 'NumPermissionEntries' }
      'Type' { 'NumTypeEntries' }
      'Component' { 'NumComponentEntries' }
      'Task' { 'NumTaskEntries' }
      'Dir' { 'NumDirEntries' }
      'ISSigKey' { 'NumISSigKeyEntries' }
      'Icon' { 'NumIconEntries' }
      'Ini' { 'NumIniEntries' }
      'Registry' { 'NumRegistryEntries' }
      'Delete' { $null }
      'Run' { $null }
    }
    # ANSI editions serialize both the nominal String and AnsiString fields
    # with the active ANSI code page. Unicode editions retain the split.
    if ($Format.CharacterMode -eq 'Ansi') {
      $Schema.AnsiFields = [string[]]@($Schema.Fields) + [string[]]@($Schema.AnsiFields)
      $Schema.Fields = [string[]]@()
    } else {
      $Schema.Fields = [string[]]@($Schema.Fields)
      $Schema.AnsiFields = [string[]]@($Schema.AnsiFields)
    }
    $RecordFamilies[$Family] = [pscustomobject]$Schema
  }
  $Resolved.RecordFamilies = [pscustomobject]$RecordFamilies
  $Resolved.FileLocationFlagNames = [string[]]@($Script:InnoFormatCatalog.FileLocationFlagSchemas[$Resolved.FileLocationFlagSchema])
  $Resolved.FileLocationFlagSize = [int][Math]::Ceiling($Resolved.FileLocationFlagNames.Count / 8)
  $Resolved.EncryptionHeaderSize = $Resolved.HasEncryptionHeader ? $Script:INNO_ENCRYPTION_HEADER_SIZE_6500 : 0
  $Resolved.FileLocationDigestAlgorithm = [string]$Format.ChecksumRoute
  $Resolved.FileLocationDigestSize = switch ($Format.ChecksumRoute) {
    'Adler32' { 4 }
    'CRC32' { 4 }
    'MD5' { 16 }
    'SHA1' { 20 }
    'SHA256' { 32 }
    default { throw "Unsupported Inno file-location checksum route: $($Format.ChecksumRoute)" }
  }
  $Resolved.FileLocationEntrySize = if ($Format.FileLocationSchema -eq 'location-adler') {
    41
  } else {
    8 + [int]$Resolved.FileLocationStartOffsetSize + 24 + [int]$Resolved.FileLocationDigestSize + 8 + 8 +
    $Resolved.FileLocationFlagSize + ($Resolved.FileLocationHasSign ? 1 : 0)
  }
  $Resolved.UsesLegacyCallInstructionTransform = $Format.CallTransformRoute -ne 'relative24-v3'
  $Resolved.LayoutResolution = $LayoutResolution
  $Resolved.CandidateIds = [string[]]@($CandidateIds)
  $Resolved.SupportStatus = $Format.Supported ? 'Supported' : 'Unsupported'
  return [pscustomobject]$Resolved
}

function Copy-InnoResolvedCatalogFormat {
  <#
  .SYNOPSIS
    Clone one pre-resolved Inno catalog descriptor for a parser operation.
  .DESCRIPTION
    Catalog descriptors are resolved once when the module is imported. Each
    parse receives its own top-level object so fallback validation can update
    LayoutResolution without changing the shared descriptor or another parse.
  .PARAMETER Format
    Immutable module-scoped descriptor to clone.
  .PARAMETER LayoutResolution
    Selection evidence for this parse.
  .PARAMETER CandidateIds
    Catalog rows considered for the observed signature.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$Format,
    [Parameter(Mandatory)][string]$LayoutResolution,
    [Parameter(Mandatory)][string[]]$CandidateIds
  )

  $Copy = [ordered]@{}
  foreach ($Property in $Format.PSObject.Properties) {
    $Value = $Property.Value
    $Copy[$Property.Name] = if ($Value -is [array]) {
      @($Value)
    } elseif ($Value -is [System.Collections.IDictionary]) {
      Copy-InnoCatalogMap -InputObject $Value
    } elseif ($Value -is [pscustomobject]) {
      $Nested = [ordered]@{}
      foreach ($NestedProperty in $Value.PSObject.Properties) { $Nested[$NestedProperty.Name] = $NestedProperty.Value }
      [pscustomobject]$Nested
    } else {
      $Value
    }
  }
  $Copy.LayoutResolution = $LayoutResolution
  $Copy.CandidateIds = [string[]]@($CandidateIds)
  return [pscustomobject]$Copy
}

$Script:InnoResolvedFormats = [ordered]@{}

foreach ($CatalogFormat in $Script:InnoFormatCatalog.Formats) {
  $Script:InnoResolvedFormats[$CatalogFormat.Id] = Resolve-InnoCatalogFormat -Format $CatalogFormat
}

function Test-InnoResToolsEdition {
  <#
  .SYNOPSIS
    Detect the ResTools Inno fork from bounded Delphi PACKAGEINFO metadata.
  .PARAMETER Path
    Installer PE path; the file is read as data and is never loaded as code.
  #>
  [OutputType([bool])]
  param ([Parameter(Mandatory)][string]$Path)

  $Resource = Get-PEResourceInfo -Path $Path -MaximumResources 4096 |
    Where-Object { $_.TypeId -eq $Script:INNO_RT_RCDATA -and $_.Name -eq 'PACKAGEINFO' } |
    Select-Object -First 1
  if (-not $Resource -or $Resource.Size -lt 12 -or $Resource.Size -gt 1048576) { return $false }

  $Bytes = Read-PEResourceData -Resource $Resource -MaximumBytes 1048576
  $RequiresCount = [BitConverter]::ToInt32($Bytes, 4)
  if ($RequiresCount -lt 0 -or $RequiresCount -gt 65535) { return $false }
  $Cursor = 8
  for ($Index = 0; $Index -lt $RequiresCount; $Index++) {
    if ($Cursor + 2 -gt $Bytes.Length) { return $false }
    $End = $Cursor + 1
    while ($End -lt $Bytes.Length -and $Bytes[$End] -ne 0) { $End++ }
    if ($End -ge $Bytes.Length) { return $false }
    $Cursor = $End + 1
  }
  if ($Cursor + 4 -gt $Bytes.Length) { return $false }
  $ContainsCount = [BitConverter]::ToInt32($Bytes, $Cursor)
  if ($ContainsCount -lt 0 -or $ContainsCount -gt 65535) { return $false }
  $Cursor += 4
  for ($Index = 0; $Index -lt $ContainsCount; $Index++) {
    if ($Cursor + 3 -gt $Bytes.Length) { return $false }
    $NameStart = $Cursor + 2
    $End = $NameStart
    while ($End -lt $Bytes.Length -and $Bytes[$End] -ne 0) { $End++ }
    if ($End -ge $Bytes.Length) { return $false }
    $UnitName = [Text.Encoding]::ASCII.GetString($Bytes, $NameStart, $End - $NameStart)
    if ($UnitName.StartsWith('SetupLdr_D2009', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $Cursor = $End + 1
  }
  return $false
}

function Import-InnoCallTransform {
  <#
  .SYNOPSIS
    Load the source-backed Inno CALL/JMP byte transform once
  #>
  $SourcePath = Join-Path $PSScriptRoot '..\..\Assets\Source\Inno\InnoCallTransform.cs'
  $null = Import-InstallerManagedSource -Path $SourcePath -TypeName 'Dumplings.InstallerParsers.InnoCallTransform'
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

function Read-InnoOffsetTableInteger {
  <#
  .SYNOPSIS
    Read one little-endian integer from a loader-table byte range.
  .PARAMETER Bytes
    Complete loader-table bytes.
  .PARAMETER Offset
    Table-relative field offset.
  .PARAMETER Size
    Integer width in bytes.
  .PARAMETER Signed
    Interpret an eight-byte field as signed, matching modern Inno records.
  #>
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][int]$Offset,
    [Parameter(Mandatory)][ValidateSet(4, 8)][int]$Size,
    [switch]$Signed
  )

  if ($Offset -lt 0 -or $Offset -gt $Bytes.Length - $Size) { throw 'The Inno Setup offset-table integer is outside the record' }
  if ($Size -eq 4) { return [BitConverter]::ToUInt32($Bytes, $Offset) }
  if ($Signed) { return [BitConverter]::ToInt64($Bytes, $Offset) }
  return [BitConverter]::ToUInt64($Bytes, $Offset)
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

  $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $InstallerLength = (Get-Item -LiteralPath $InstallerPath -Force).Length
  $Bytes = $null
  try { $Bytes = Get-InnoResourceBytes -Path $InstallerPath -Id $Script:INNO_SETUP_LDR_OFFSET_TABLE_RESOURCE } catch { }

  if ($Bytes) {
    if ($Bytes.Length -lt 16) { throw 'The Inno Setup resource offset table is truncated' }
    $Identifier = [Text.Encoding]::ASCII.GetString($Bytes, 0, 12)
    if ($Identifier -ne $Script:INNO_OFFSET_TABLE_ID) { throw 'The Inno Setup resource offset table identifier is invalid' }
    $Version = [BitConverter]::ToUInt32($Bytes, 12)

    # Resource v1 stores 32-bit offsets. Resource v2 widens persisted sizes and
    # offsets to 64 bits; both records protect every preceding byte with CRC32.
    $Route = $Script:InnoResourceOffsetTableRoutes[[int]$Version]
    if (-not $Route) { throw "Unsupported Inno Setup resource offset table version: $Version" }
    if ($Bytes.Length -lt $Route.MinimumSize) { throw 'The Inno Setup resource offset table is truncated' }
    if ([BitConverter]::ToUInt32($Bytes, $Route.CrcOffset) -ne (Get-BinaryCrc32 -Bytes $Bytes -Offset 0 -Count $Route.CrcLength)) {
      throw 'The Inno Setup resource offset table CRC is invalid'
    }
    $Result = [pscustomobject]@{
      Version     = [int]$Version
      LoaderRoute = $Route.Route
      TotalSize   = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.TotalSizeOffset -Size $Route.IntegerSize -Signed:$Route.Signed
      Offset0     = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.Offset0Offset -Size $Route.IntegerSize -Signed:$Route.Signed
      Offset1     = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.Offset1Offset -Size $Route.IntegerSize -Signed:$Route.Signed
    }
  } else {
    # Loaders before 5.1.2 store an ID and complemented offset-table pointer at
    # absolute file offset 0x30. The table's 12-byte magic selects S02-S07.
    $Stream = [IO.File]::Open($InstallerPath, 'Open', 'Read', 'ReadWrite')
    try {
      if ($Stream.Length -lt $Script:INNO_LEGACY_LOADER_HEADER_OFFSET + 12) {
        throw 'The file does not contain an Inno Setup loader header'
      }
      $Header = Read-BinaryBytes -Stream $Stream -Offset $Script:INNO_LEGACY_LOADER_HEADER_OFFSET -Count 12
      $HeaderId = [BitConverter]::ToUInt32($Header, 0)
      $TableOffset = [BitConverter]::ToUInt32($Header, 4)
      $Complement = [BitConverter]::ToUInt32($Header, 8)
      if ($HeaderId -ne $Script:INNO_LEGACY_LOADER_HEADER_ID -or $Complement -ne ((-bnot $TableOffset) -band 0xFFFFFFFFL)) {
        throw 'The file does not contain a valid legacy Inno Setup loader pointer'
      }
      if ($TableOffset -gt $Stream.Length - 40) { throw 'The legacy Inno Setup offset table is outside the installer' }
      $Bytes = Read-BinaryBytes -Stream $Stream -Offset $TableOffset -Count ([int][Math]::Min(64, $Stream.Length - $TableOffset))
    } finally { $Stream.Dispose() }

    $IdentifierPrefix = [Text.Encoding]::ASCII.GetString($Bytes, 0, 8)
    $LoaderRoute = $Script:INNO_LEGACY_OFFSET_TABLE_IDS[$IdentifierPrefix]
    if (-not $LoaderRoute) { throw 'The legacy Inno Setup offset table identifier is unsupported' }
    $ExpectedTail = [byte[]](0x87, 0x65, 0x56, 0x78)
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$Bytes[8..11], $ExpectedTail)) {
      throw 'The legacy Inno Setup offset table identifier is invalid'
    }

    $Route = $Script:InnoLegacyOffsetTableRoutes[$LoaderRoute]
    if (-not $Route -or $Bytes.Length -lt $Route.MinimumSize) { throw 'The legacy Inno Setup offset table is truncated' }
    if ($null -ne $Route.CrcOffset -and
      [BitConverter]::ToUInt32($Bytes, $Route.CrcOffset) -ne (Get-BinaryCrc32 -Bytes $Bytes -Offset 0 -Count $Route.CrcLength)) {
      throw "The legacy Inno Setup $LoaderRoute offset table CRC is invalid"
    }
    $Result = [pscustomobject]@{
      Version     = 0
      LoaderRoute = $LoaderRoute
      TotalSize   = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.TotalSizeOffset -Size 4
      Offset0     = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.Offset0Offset -Size 4
      Offset1     = Read-InnoOffsetTableInteger -Bytes $Bytes -Offset $Route.Offset1Offset -Size 4
    }
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

function Get-InnoSignatureInfo {
  <#
  .SYNOPSIS
    Read and classify the 64-byte Inno setup-data signature.
  .PARAMETER Path
    Installer path used for bounded signature and optional ResTools metadata reads.
  .PARAMETER OffsetTable
    Validated loader offsets identifying the setup-data and loader family.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$OffsetTable
  )

  $Stream = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
  try {
    $Bytes = Read-BinaryBytes -Stream $Stream -Offset $OffsetTable.Offset0 -Count $Script:INNO_SETUP_ID_SIZE
  } finally { $Stream.Dispose() }
  $Signature = [Text.Encoding]::ASCII.GetString($Bytes).Trim([char]0)
  $Match = [regex]::Match($Signature, $Script:INNO_SIGNATURE_PATTERN)
  if (-not $Match.Success) { throw 'The file is not a recognized Inno Setup installer' }

  $VersionText = $Match.Groups['Version'].Value
  $VersionNumber = Get-InnoVersionNumber -Version $VersionText
  $IsISX = $Match.Groups['Suffix'].Value.IndexOf('with ISX', [StringComparison]::OrdinalIgnoreCase) -ge 0
  $CharacterMode = if ($Match.Groups['Unicode'].Success -or $VersionNumber -ge 6300) { 'Unicode' } else { 'Ansi' }
  $EditionId = if ($IsISX) {
    'isx'
  } elseif ($Match.Groups['Prefix'].Value -eq 'My Inno Setup Extensions Setup Data') {
    'myinno'
  } elseif (Test-InnoResToolsEdition -Path $Path) {
    'restools'
  } else {
    'official'
  }

  [pscustomobject]@{
    Signature     = $Signature
    VersionText   = $VersionText
    VersionNumber = $VersionNumber
    EditionId     = $EditionId
    Edition       = [string]$Script:InnoFormatCatalog.Editions[$EditionId]
    CharacterMode = $CharacterMode
    IsISX         = $IsISX
  }
}

function Get-InnoLayout {
  <#
  .SYNOPSIS
    Select and resolve a catalogued Inno format layout.
  .DESCRIPTION
    Exact signatures are preferred. Unknown future signatures may select only
    the nearest older row with the same edition, character mode, and loader
    family; callers must validate all metadata boundaries before accepting that
    provisional selection.
  .PARAMETER SignatureInfo
    Parsed setup-data signature and edition evidence.
  .PARAMETER LoaderRoute
    Loader family proven by the offset-table structure.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$SignatureInfo,
    [Parameter(Mandatory)][string]$LoaderRoute
  )

  if ($SignatureInfo.IsISX) {
    return [pscustomobject]@{
      Id                       = 'isx-unsupported'
      InternalStructureVersion = $SignatureInfo.VersionNumber
      VersionNumber            = $SignatureInfo.VersionNumber
      Signature                = $SignatureInfo.Signature
      EditionId                = 'isx'
      Edition                  = $Script:InnoFormatCatalog.Editions.isx
      CharacterMode            = $SignatureInfo.CharacterMode
      LoaderRoute              = $LoaderRoute
      LayoutResolution         = 'UnsupportedEdition'
      SupportStatus            = 'Unsupported'
      CandidateIds             = [string[]]@()
    }
  }

  $Exact = @($Script:InnoFormatCatalog.Formats | Where-Object {
      $_.Signature -ceq $SignatureInfo.Signature -and
      $_.EditionId -ceq $SignatureInfo.EditionId -and
      $_.CharacterMode -ceq $SignatureInfo.CharacterMode -and
      $_.LoaderRoute -ceq $LoaderRoute
    })
  if ($Exact.Count -gt 0) {
    # Several innounp StructList rows are aliases: their Pascal structure units
    # differ only in version constants while retaining one setup-data signature.
    # innounp selects the first matching structure, so use the lowest catalog
    # structure as the canonical route and retain every alias ID as evidence.
    $Selected = $Exact | Sort-Object InternalStructureVersion | Select-Object -First 1
    $Resolution = $Exact.Count -eq 1 ? 'Exact' : 'ExactSignatureAlias'
    return Copy-InnoResolvedCatalogFormat -Format $Script:InnoResolvedFormats[$Selected.Id] `
      -LayoutResolution $Resolution -CandidateIds @($Exact.Id)
  }

  $Candidates = @($Script:InnoFormatCatalog.Formats | Where-Object {
      $_.EditionId -ceq $SignatureInfo.EditionId -and
      $_.CharacterMode -ceq $SignatureInfo.CharacterMode -and
      $_.LoaderRoute -ceq $LoaderRoute -and
      (if ([int]$_.InternalStructureVersion -ge 700000) { 7000 } else { [int]$_.InternalStructureVersion }) -le $SignatureInfo.VersionNumber
    } | Sort-Object InternalStructureVersion -Descending)
  if ($Candidates.Count -eq 0) {
    throw "No Inno format descriptor matches edition '$($SignatureInfo.Edition)', mode '$($SignatureInfo.CharacterMode)', and loader '$LoaderRoute'."
  }

  return Copy-InnoResolvedCatalogFormat -Format $Script:InnoResolvedFormats[$Candidates[0].Id] `
    -LayoutResolution 'NearestOlderPendingValidation' -CandidateIds @($Candidates[0].Id)
}

function Get-InnoAnalysisContext {
  <#
  .SYNOPSIS
    Parse the shared Inno loader and setup-header context once.
  .PARAMETER Path
    Resolved or relative path to the Inno Setup installer.
  .OUTPUTS
    Internal path, PE, offset-table, signature, catalog layout, and parsed-header evidence.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)

  $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
  $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath
  $SignatureInfo = Get-InnoSignatureInfo -Path $InstallerPath -OffsetTable $OffsetTable
  $Layout = Get-InnoLayout -SignatureInfo $SignatureInfo -LoaderRoute $OffsetTable.LoaderRoute
  if ($Layout.SupportStatus -ne 'Supported') {
    throw "The Inno Setup edition '$($Layout.Edition)' is identified but its record layout is unsupported."
  }
  $ParsedLayout = Resolve-InnoParsedLayout -Path $InstallerPath -OffsetTable $OffsetTable -Layout $Layout

  return [pscustomobject][ordered]@{
    Path           = $InstallerPath
    PEInfo         = Get-InnoPEInfo -Path $InstallerPath
    OffsetTable    = $OffsetTable
    SignatureInfo  = $SignatureInfo
    Layout         = $ParsedLayout.Layout
    ParsedLayout   = $ParsedLayout
    CatalogVersion = $Script:InnoFormatCatalog.CatalogVersion
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
  .PARAMETER CompressionAlgorithm
    Decompressor selected independently from the chunk framing. Inno 4.0.9
    through 4.1.5 use this framing with zlib; later generations use LZMA.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The binary reader for the installer')]
    [System.IO.BinaryReader]$Reader,

    [Parameter(Mandatory, HelpMessage = 'The parsed block header metadata')]
    [pscustomobject]$BlockHeader,

    [ValidateSet('Lzma', 'Zlib')]
    [string]$CompressionAlgorithm = 'Lzma'
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

  $BlockBytes = if ($BlockHeader.Compressed -and $CompressionAlgorithm -eq 'Lzma') {
    , (Expand-InnoLzmaBytes -Bytes $RawBytes)
  } elseif ($BlockHeader.Compressed) {
    $InputStream = [IO.MemoryStream]::new($RawBytes, $false)
    $Output = [IO.MemoryStream]::new()
    try {
      $null = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $Output -MaximumBytes $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE
      , $Output.ToArray()
    } finally {
      $Output.Dispose()
      $InputStream.Dispose()
    }
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

function Read-InnoLegacyCompressedBlock {
  <#
  .SYNOPSIS
    Read the CRC-framed zlib/stored metadata block used through Inno 4.0.8.
  .PARAMETER Reader
    Installer reader. The function seeks to BlockOffset and leaves the reader at the next block.
  .PARAMETER BlockOffset
    Absolute file offset of the header CRC.
  .PARAMETER MaximumBytes
    Maximum accepted compressed and decompressed metadata size.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.BinaryReader]$Reader,
    [Parameter(Mandatory)][long]$BlockOffset,
    [ValidateRange(1, [int]::MaxValue)][int]$MaximumBytes = $Script:INNO_MAX_DECOMPRESSED_BLOCK_SIZE
  )

  if ($BlockOffset -lt 0 -or $BlockOffset -gt $Reader.BaseStream.Length - 12) {
    throw 'The legacy Inno metadata block header is outside the installer'
  }
  $Reader.BaseStream.Position = $BlockOffset
  $StoredHeaderCrc = $Reader.ReadUInt32()
  $Header = $Reader.ReadBytes(8)
  if ($Header.Length -ne 8 -or $StoredHeaderCrc -ne (Get-BinaryCrc32 -Bytes $Header)) {
    throw 'The legacy Inno metadata block header CRC is invalid'
  }
  $CompressedSize = [BitConverter]::ToInt32($Header, 0)
  $UncompressedSize = [BitConverter]::ToInt32($Header, 4)
  $Compressed = $CompressedSize -ne -1
  $StoredDataSize = $Compressed ? $CompressedSize : $UncompressedSize
  if ($StoredDataSize -le 0 -or $StoredDataSize -gt $MaximumBytes -or $UncompressedSize -le 0 -or $UncompressedSize -gt $MaximumBytes) {
    throw 'The legacy Inno metadata block sizes are invalid'
  }

  # Legacy StoredDataSize excludes each four-byte chunk CRC. Reassemble the
  # declared bytes while validating every <=4096-byte chunk independently.
  $ChunkCount = [long][Math]::Ceiling($StoredDataSize / [double]$Script:INNO_MAX_CHUNK_SIZE)
  $PhysicalSize = [long]$StoredDataSize + ($ChunkCount * 4)
  if ($PhysicalSize -gt $Reader.BaseStream.Length - $Reader.BaseStream.Position) {
    throw 'The legacy Inno metadata block is truncated'
  }
  $Raw = [byte[]]::new($StoredDataSize)
  $WriteOffset = 0
  while ($WriteOffset -lt $Raw.Length) {
    $ChunkCrc = $Reader.ReadUInt32()
    $ChunkLength = [Math]::Min($Script:INNO_MAX_CHUNK_SIZE, $Raw.Length - $WriteOffset)
    $Read = $Reader.Read($Raw, $WriteOffset, $ChunkLength)
    if ($Read -ne $ChunkLength) { throw 'The legacy Inno metadata chunk is truncated' }
    if ($ChunkCrc -ne (Get-BinaryCrc32 -Bytes $Raw -Offset $WriteOffset -Count $ChunkLength)) {
      throw 'The legacy Inno metadata chunk CRC is invalid'
    }
    $WriteOffset += $ChunkLength
  }

  $Bytes = if ($Compressed) {
    $InputStream = [IO.MemoryStream]::new($Raw, $false)
    $Output = [IO.MemoryStream]::new($UncompressedSize)
    try {
      $Expanded = Expand-InstallerCompressedStream -Algorithm Zlib -Stream $InputStream -Destination $Output -MaximumBytes $MaximumBytes -UncompressedSize $UncompressedSize
      if ($Expanded -ne $UncompressedSize) { throw 'The legacy Inno metadata decompressed size is invalid' }
      , $Output.ToArray()
    } finally { $Output.Dispose(); $InputStream.Dispose() }
  } else {
    , $Raw
  }

  [pscustomobject]@{
    HeaderOffset     = $BlockOffset
    HeaderLength     = 8
    StoredSize       = $StoredDataSize
    UncompressedSize = $UncompressedSize
    Compressed       = $Compressed
    NextOffset       = $BlockOffset + 12 + $PhysicalSize
    Bytes            = $Bytes
  }
}

$Script:InnoMetadataRouteHandlers = @{
  'legacy-zlib32'  = {
    param([IO.BinaryReader]$Reader, [long]$Offset)
    Read-InnoLegacyCompressedBlock -Reader $Reader -BlockOffset $Offset
  }
  'chunked-zlib32' = {
    param([IO.BinaryReader]$Reader, [long]$Offset)
    $Header = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $Offset -UsesInt64BlockHeader $false -FileLength $Reader.BaseStream.Length
    if (-not $Header) { throw 'The Inno Setup zlib metadata block header is invalid' }
    Read-InnoCompressedBlock -Reader $Reader -BlockHeader $Header -CompressionAlgorithm Zlib
  }
  'chunked32'      = {
    param([IO.BinaryReader]$Reader, [long]$Offset)
    $Header = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $Offset -UsesInt64BlockHeader $false -FileLength $Reader.BaseStream.Length
    if (-not $Header) { throw 'The Inno Setup 32-bit metadata block header is invalid' }
    Read-InnoCompressedBlock -Reader $Reader -BlockHeader $Header
  }
  'chunked64'      = {
    param([IO.BinaryReader]$Reader, [long]$Offset)
    $Header = Test-InnoCompressedBlockHeader -Reader $Reader -Offset $Offset -UsesInt64BlockHeader $true -FileLength $Reader.BaseStream.Length
    if (-not $Header) { throw 'The Inno Setup 64-bit metadata block header is invalid' }
    Read-InnoCompressedBlock -Reader $Reader -BlockHeader $Header
  }
}

function Read-InnoMetadataBlock {
  <#
  .SYNOPSIS
    Dispatch one metadata block through the catalog-selected framing route.
  .PARAMETER Reader
    Installer reader; it is caller-owned and is not disposed.
  .PARAMETER Offset
    Absolute file offset of the framing header.
  .PARAMETER Layout
    Resolved catalog layout containing MetadataRoute.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][IO.BinaryReader]$Reader,
    [Parameter(Mandatory)][long]$Offset,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $Handler = $Script:InnoMetadataRouteHandlers[$Layout.MetadataRoute]
  if (-not $Handler) { throw "Unsupported Inno metadata framing route: $($Layout.MetadataRoute)" }
  return & $Handler $Reader $Offset
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

  $InstallerPath = (Get-Item -LiteralPath $Path -Force).FullName
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

    $BlockInfo = Read-InnoMetadataBlock -Reader $Reader -Offset $EncryptionHeader.NextOffset -Layout $Layout
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

function Read-InnoHeaderData {
  <#
  .SYNOPSIS
    Decode the fixed-order header strings and preserve compiled Pascal Script bytes.
  .PARAMETER Bytes
    The decompressed header stream bytes
  .PARAMETER Layout
    The supported Inno header layout
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
    $Values = [System.Collections.Generic.List[string]]::new()
    $RawValues = [System.Collections.Generic.List[byte[]]]::new()

    # TSetupHeader stores every variable-length string before its fixed tail.
    # The catalog identifies CompiledCodeText explicitly because official
    # versions before 4.0 do not contain that field at all.
    function Read-HeaderStringGroup([int]$Count, [Text.Encoding]$Encoding) {
      for ($Index = 0; $Index -lt $Count; $Index++) {
        $Length = $Reader.ReadInt32()
        $MaximumLength = $null -ne $Layout.CompiledCodeStringIndex -and $RawValues.Count -eq $Layout.CompiledCodeStringIndex ?
        $INNO_MAX_COMPILED_CODE_SIZE : $INNO_MAX_ENTRY_STRING_SIZE
        if ($Length -lt 0 -or $Length -gt $MaximumLength -or $Length -gt ($Stream.Length - $Stream.Position)) {
          throw 'The Inno Setup header string length is invalid'
        }
        $RawValue = $Length -eq 0 ? [byte[]]::new(0) : $Reader.ReadBytes($Length)
        $RawValues.Add($RawValue)
        $Values.Add($Length -eq 0 ? '' : $Encoding.GetString($RawValue))
      }
    }

    switch ($Layout.StringEncoding) {
      'Unicode' {
        Read-HeaderStringGroup -Count $Layout.HeaderStringCount -Encoding ([Text.Encoding]::Unicode)
        Read-HeaderStringGroup -Count $Layout.HeaderAnsiStringCount -Encoding (Get-InnoAnsiEncoding)
      }
      'Ansi' {
        $AnsiCount = $Layout.HeaderStringCount + $Layout.HeaderAnsiStringCount
        Read-HeaderStringGroup -Count $AnsiCount -Encoding (Get-InnoAnsiEncoding)
      }
      default { throw "Unsupported Inno Setup header string encoding: $($Layout.StringEncoding)" }
    }

    [byte[]]$CompiledCodeBytes = [byte[]]::new(0)
    if ($null -eq $Layout.CompiledCodeStringIndex) {
      # Keep a typed zero-length array. An empty array emitted by an if
      # expression would otherwise disappear through PowerShell's pipeline.
    } elseif ($Layout.CompiledCodeStringIndex -lt 0 -or $Layout.CompiledCodeStringIndex -ge $RawValues.Count) {
      throw 'The Inno Setup CompiledCodeText field is outside the catalogued header string table.'
    } else {
      $CompiledCodeBytes = [byte[]]$RawValues[$Layout.CompiledCodeStringIndex]
    }
    if ($CompiledCodeBytes.LongLength -gt $INNO_MAX_COMPILED_CODE_SIZE) {
      throw "The compiled Inno Pascal Script exceeds the $INNO_MAX_COMPILED_CODE_SIZE-byte analysis limit."
    }

    return [pscustomobject]@{
      Values            = $Values.ToArray()
      CompiledCodeBytes = $CompiledCodeBytes
      FixedTailOffset   = $Reader.BaseStream.Position
    }
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

  $Warnings = [System.Collections.Generic.List[object]]::new()

  if ($Layout.ArchitecturesEncoding -eq 'None') {
    # Historical compilers predate architecture directives. Their x86 loader
    # can run on supported 32-bit emulation environments, but the metadata does
    # not prove a 64-bit install mode.
    return [pscustomobject]@{
      ArchitecturesAllowed                     = $null
      ArchitecturesInstallIn64BitMode          = $null
      EffectiveArchitecturesAllowed            = $null
      EffectiveArchitecturesInstallIn64BitMode = $null
      SupportedArchitectures                   = @('x86', 'x64', 'arm64')
      UnsupportedArchitectures                 = @()
      InstallIn64BitMode                       = $false
      PackedArchitecturesAllowed               = $null
      PackedArchitecturesInstallIn64BitMode    = $null
      IsKnown                                  = $true
      Diagnostics                              = @(ConvertTo-InstallerDiagnostic -InputObject @([object[]]@()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
    }
  }

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
      Diagnostics                              = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
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
    Diagnostics                              = @(ConvertTo-InstallerDiagnostic -InputObject @($Warnings.ToArray()) -Source 'Inno' -Kind Incomplete -Areas Metadata)
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
  .PARAMETER StaticReturnValues
    Optional Pascal Script function return states used to evaluate directive checks.
  #>
  [OutputType([pscustomobject])]
  param (
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value,

    [Parameter(Mandatory, HelpMessage = 'The default value used by Inno Setup when the directive is omitted')]
    [bool]$Default,

    [System.Collections.IDictionary]$StaticReturnValues = @{}
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return [pscustomobject]@{ Value = $Default; IsResolved = $true; IsDefault = $true; IsDynamic = $false }
  }

  $TrimmedValue = $Value.Trim()
  switch -Regex ($TrimmedValue) {
    '^(?i:yes|true|1)$' { return [pscustomobject]@{ Value = $true; IsResolved = $true; IsDefault = $false; IsDynamic = $false } }
    '^(?i:no|false|0)$' { return [pscustomobject]@{ Value = $false; IsResolved = $true; IsDefault = $false; IsDynamic = $false } }
  }

  # Inno's EvalDirectiveCheck passes nonliteral values through TSimpleExpression.
  # Translate its not/and/or spelling to the shared bounded three-valued parser;
  # parameterized callbacks and unknown functions deliberately remain unknown.
  $IdentifierStates = [ordered]@{}
  foreach ($Entry in $StaticReturnValues.GetEnumerator()) {
    if ($Entry.Value -is [bool]) { $IdentifierStates[[string]$Entry.Key] = $Entry.Value ? 'True' : 'False' }
  }
  $Expression = [regex]::Replace($TrimmedValue, '\bnot\b', '!', 'IgnoreCase,CultureInvariant')
  $Expression = [regex]::Replace($Expression, '\band\b', '&&', 'IgnoreCase,CultureInvariant')
  $Expression = [regex]::Replace($Expression, '\bor\b', '||', 'IgnoreCase,CultureInvariant')
  $Expression = [regex]::Replace($Expression, '\byes\b', 'true', 'IgnoreCase,CultureInvariant')
  $Expression = [regex]::Replace($Expression, '\bno\b', 'false', 'IgnoreCase,CultureInvariant')
  $Result = Resolve-InstallerBooleanExpression -Expression $Expression -IdentifierState $IdentifierStates -MaximumTokenCount 256 -MaximumDepth 32
  if ($Result.State -in @('True', 'False')) {
    return [pscustomobject]@{
      Value = $Result.State -ceq 'True'; IsResolved = $true; IsDefault = $false; IsDynamic = $true
      Identifiers = $Result.Identifiers; UnknownIdentifiers = $Result.UnknownIdentifiers; Reasons = $Result.Reasons
    }
  }
  return [pscustomobject]@{
    Value = $null; IsResolved = $false; IsDefault = $false; IsDynamic = $true
    Identifiers = $Result.Identifiers; UnknownIdentifiers = $Result.UnknownIdentifiers; Reasons = $Result.Reasons
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
  .PARAMETER HeaderFixedData
    Fixed-header option evidence used by Inno Setup versions before 5.3.10
  .PARAMETER StaticReturnValues
    Optional proven Pascal Script return values used by directive-check expressions.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Inno Setup header strings')]
    [AllowEmptyString()]
    [string[]]$HeaderValues,

    [Parameter(Mandatory, HelpMessage = 'The catalogued Inno Setup layout')]
    [pscustomobject]$Layout,

    [Parameter(HelpMessage = 'Fixed-header option evidence used by Inno Setup versions before 5.3.10')]
    [AllowNull()]
    [pscustomobject]$HeaderFixedData,

    [System.Collections.IDictionary]$StaticReturnValues = @{}
  )

  $CreateUninstallRegKey = if ($HeaderValues.Count -gt 24) { $HeaderValues[24] } else { $null }
  $Uninstallable = if ($HeaderValues.Count -gt 25) { $HeaderValues[25] } else { $null }

  # Inno writes an ARP entry only when the uninstall registry key is created
  # and an uninstaller is registered. In 5.3.8 and 5.3.10 respectively, these
  # values moved from option bits to expression-capable serialized strings.
  $CreateUninstallRegKeyInfo = if ($null -ne $Layout.LegacyCreateUninstallRegKeyOptionBit) {
    if ($null -ne $HeaderFixedData -and $null -ne $HeaderFixedData.LegacyCreateUninstallRegKey) {
      [pscustomobject]@{ Value = [bool]$HeaderFixedData.LegacyCreateUninstallRegKey; IsResolved = $true; IsDefault = $false; IsDynamic = $false }
    } else {
      [pscustomobject]@{ Value = $null; IsResolved = $false; IsDefault = $false; IsDynamic = $false }
    }
  } else {
    Get-InnoBooleanDirectiveInfo -Value $CreateUninstallRegKey -Default $true -StaticReturnValues $StaticReturnValues
  }
  $UninstallableInfo = if ($null -ne $Layout.LegacyUninstallableOptionBit) {
    if ($null -ne $HeaderFixedData -and $null -ne $HeaderFixedData.LegacyUninstallable) {
      [pscustomobject]@{ Value = [bool]$HeaderFixedData.LegacyUninstallable; IsResolved = $true; IsDefault = $false; IsDynamic = $false }
    } else {
      [pscustomobject]@{ Value = $null; IsResolved = $false; IsDefault = $false; IsDynamic = $false }
    }
  } else {
    Get-InnoBooleanDirectiveInfo -Value $Uninstallable -Default $true -StaticReturnValues $StaticReturnValues
  }

  if ($null -ne $Layout.LegacyCreateUninstallRegKeyOptionBit -and $CreateUninstallRegKeyInfo.IsResolved) {
    $CreateUninstallRegKey = $CreateUninstallRegKeyInfo.Value ? 'yes' : 'no'
  }
  if ($null -ne $Layout.LegacyUninstallableOptionBit -and $UninstallableInfo.IsResolved) {
    $Uninstallable = $UninstallableInfo.Value ? 'yes' : 'no'
  }
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
    IsKnown                       = $CreateUninstallRegKeyInfo.IsResolved -and $UninstallableInfo.IsResolved
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
      if ($null -ne $Layout.SlicesPerDiskOffset) {
        $Layout.SlicesPerDiskOffset + 3
      }
      $Layout.PrivilegesRequiredOffset
      $Layout.PrivilegesRequiredOverridesAllowedOffset
      $Layout.ArchitecturesAllowedOffset
      $Layout.ArchitecturesInstallIn64BitModeOffset
      $Layout.CompressMethodOffset
      if ($null -ne $Layout.LegacyHeaderOptionsOffset) {
        $Layout.LegacyHeaderOptionsOffset + $Layout.LegacyHeaderOptionsSize - 1
      }
    ) | Where-Object { $null -ne $_ }
    $LastRequiredOffset = ($RequiredOffsets | Measure-Object -Maximum).Maximum
    if ($null -ne $LastRequiredOffset -and $FixedTailOffset + $LastRequiredOffset -ge $Reader.BaseStream.Length) {
      throw 'The Inno Setup fixed header is truncated'
    }

    # Decode compiler enums and bitsets without evaluating script expressions;
    # unknown enum values remain explicit rather than receiving a guessed scope.
    $PrivilegesRequiredValue = $null
    $PrivilegesRequired = $null
    if ($null -ne $Layout.PrivilegesRequiredOffset) {
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.PrivilegesRequiredOffset, 'Begin') | Out-Null
      $PrivilegesRequiredValue = $Reader.ReadByte()
      $PrivilegesRequired = switch ($PrivilegesRequiredValue) {
        0 { 'none' }
        1 { 'poweruser' }
        2 { 'admin' }
        3 { 'lowest' }
        default { "unknown:$PrivilegesRequiredValue" }
      }
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

    $CompressMethodValue = $null
    $CompressMethod = $null
    if ($null -ne $Layout.CompressMethodOffset) {
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
    }

    # Read the exact source-backed packed-header field. Inno 1.x-3.x did not
    # serialize SlicesPerDisk and always used the catalogued default of one.
    $SlicesPerDisk = $Layout.SlicesPerDiskDefault
    if ($null -ne $Layout.SlicesPerDiskOffset) {
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.SlicesPerDiskOffset, 'Begin') | Out-Null
      $CandidateSlicesPerDisk = $Reader.ReadInt32()
      if ($CandidateSlicesPerDisk -ge 1 -and $CandidateSlicesPerDisk -le 26) {
        $SlicesPerDisk = $CandidateSlicesPerDisk
      } else {
        throw "The Inno Setup SlicesPerDisk value '$CandidateSlicesPerDisk' is outside the supported range 1..26"
      }
    }

    $LegacyCreateUninstallRegKey = $null
    $LegacyUninstallable = $null
    if ($null -ne $Layout.LegacyHeaderOptionsOffset) {
      # Packed Pascal sets use ordinal-numbered bits in little-endian byte order.
      # Read the complete historical set before testing the two ARP-related bits.
      $Reader.BaseStream.Seek($FixedTailOffset + $Layout.LegacyHeaderOptionsOffset, 'Begin') | Out-Null
      $HeaderOptions = $Reader.ReadBytes($Layout.LegacyHeaderOptionsSize)
      if ($HeaderOptions.Length -ne $Layout.LegacyHeaderOptionsSize) { throw 'The Inno Setup header options are truncated' }
      if ($null -ne $Layout.LegacyCreateUninstallRegKeyOptionBit) {
        $Bit = [int]$Layout.LegacyCreateUninstallRegKeyOptionBit
        $LegacyCreateUninstallRegKey = [bool]($HeaderOptions[$Bit -shr 3] -band (1 -shl ($Bit % 8)))
      }
      if ($null -ne $Layout.LegacyUninstallableOptionBit) {
        $Bit = [int]$Layout.LegacyUninstallableOptionBit
        $LegacyUninstallable = [bool]($HeaderOptions[$Bit -shr 3] -band (1 -shl ($Bit % 8)))
      }
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
      SlicesPerDisk                      = $SlicesPerDisk
      LegacyCreateUninstallRegKey        = $LegacyCreateUninstallRegKey
      LegacyUninstallable                = $LegacyUninstallable
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

function Get-InnoArchitectureConstantRequirement {
  <#
  .SYNOPSIS
    Identify required Inno constants that cannot be expanded on 32-bit Windows.
  .PARAMETER Values
    Named, always-expanded setup values. Keys identify the source field in the
    returned evidence and values contain the raw compiled Inno strings.
  .PARAMETER DefaultScope
    The compiled default install scope used to resolve auto* constants.
  .PARAMETER SupportsScopeOverride
    Whether command-line scope selection can avoid a machine-only auto*64 path.
  .OUTPUTS
    A requirement object containing direct evidence, scope-conditional evidence,
    required constant names, and unsupported operating-system architectures.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory, HelpMessage = 'Named setup values that Inno expands on every applicable installation path')]
    [System.Collections.IDictionary]$Values,

    [AllowNull()]
    [string]$DefaultScope,

    [switch]$SupportsScopeOverride
  )

  $DirectConstantNames = @{
    'commonpf64' = 'commonpf64'
    'pf64'       = 'commonpf64'
    'commoncf64' = 'commoncf64'
    'cf64'       = 'commoncf64'
    'dotnet2064' = 'dotnet2064'
    'dotnet4064' = 'dotnet4064'
  }
  $AutoConstantNames = @{
    'autopf64' = 'commonpf64'
    'autocf64' = 'commoncf64'
  }
  $Requirements = [Collections.Generic.List[object]]::new()
  $ConditionalRequirements = [Collections.Generic.List[object]]::new()
  $RequiredConstants = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach ($Field in $Values.GetEnumerator()) {
    $Value = [string]$Field.Value
    if ([string]::IsNullOrEmpty($Value)) { continue }

    $Index = 0
    while ($Index -lt $Value.Length) {
      $OpenIndex = $Value.IndexOf('{', $Index)
      if ($OpenIndex -lt 0) { break }
      if ($OpenIndex + 1 -lt $Value.Length -and $Value[$OpenIndex + 1] -eq '{') {
        # Inno treats doubled opening braces as literal text, so they cannot
        # impose an operating-system requirement.
        $Index = $OpenIndex + 2
        continue
      }

      $EndIndex = Find-InnoConstantEnd -Value $Value -StartIndex $OpenIndex
      if ($EndIndex -lt 0) { break }
      $RawConstant = $Value.Substring($OpenIndex + 1, $EndIndex - $OpenIndex - 1)
      $ConstantName = $RawConstant.Trim().ToLowerInvariant()
      $CanonicalName = $null
      $Reason = $null
      $IsScopeConditional = $false

      if ($DirectConstantNames.ContainsKey($ConstantName)) {
        $CanonicalName = $DirectConstantNames[$ConstantName]
        $Reason = 'The Inno runtime raises an internal error when this constant is expanded on 32-bit Windows.'
      } elseif ($ConstantName -match '^reg:(?<Root>hk(?:a|cr|cu|lm|u|cc)64)\\') {
        $CanonicalName = "reg:$($Matches.Root.ToUpperInvariant())"
        $Reason = 'The Inno runtime rejects the 64-bit registry view on 32-bit Windows.'
      } elseif ($AutoConstantNames.ContainsKey($ConstantName)) {
        # auto*64 becomes common*64 in administrative mode and user* in
        # non-administrative mode. A supported command-line scope override can
        # therefore keep x86 viable even when the default scope is machine.
        if ($DefaultScope -eq 'machine' -and -not $SupportsScopeOverride) {
          $CanonicalName = $AutoConstantNames[$ConstantName]
          $Reason = 'The auto*64 constant resolves to a common 64-bit folder in the installer''s fixed machine scope.'
        } elseif ($DefaultScope -ne 'user') {
          $CanonicalName = $AutoConstantNames[$ConstantName]
          $Reason = 'The auto*64 constant requires 64-bit Windows only when this installer runs in machine scope.'
          $IsScopeConditional = $true
        }
      }

      if ($CanonicalName) {
        $Evidence = [pscustomobject][ordered]@{
          Field             = [string]$Field.Key
          Constant          = "{$RawConstant}"
          CanonicalConstant = $CanonicalName
          RawValue          = $Value
          Reason            = $Reason
          ScopeConditional  = $IsScopeConditional
        }
        if ($IsScopeConditional) {
          $ConditionalRequirements.Add($Evidence)
        } else {
          $Requirements.Add($Evidence)
          $null = $RequiredConstants.Add($CanonicalName)
        }
      }
      $Index = $EndIndex + 1
    }
  }

  return [pscustomobject][ordered]@{
    Requires64BitWindows     = $Requirements.Count -gt 0
    RequiredConstants        = [string[]]@($RequiredConstants | Sort-Object)
    UnsupportedArchitectures = [string[]]@($Requirements.Count -gt 0 ? @('x86') : @())
    Evidence                 = [pscustomobject[]]$Requirements.ToArray()
    ConditionalEvidence      = [pscustomobject[]]$ConditionalRequirements.ToArray()
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

function Assert-InnoCatalogLayout {
  <#
  .SYNOPSIS
    Prove that a catalog layout consumes the file and location records coherently.
  .PARAMETER Path
    Installer path used to read the second metadata block once.
  .PARAMETER HeaderBlockInfo
    Validated first metadata block and exact following-block offset.
  .PARAMETER Header
    Parsed setup-header counts and first possible record offset.
  .PARAMETER Layout
    Exact, ambiguous, or nearest-older descriptor under validation.
  #>
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$HeaderBlockInfo,
    [Parameter(Mandatory)][pscustomobject]$Header,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $FileCount = [int]$Header.Counts.NumFileEntries
  $LocationCount = [int]$Header.Counts.NumFileLocationEntries
  if (($FileCount -eq 0) -ne ($LocationCount -eq 0)) {
    throw 'The Inno catalog layout produced inconsistent file and location counts'
  }
  if ($FileCount -eq 0) { return }

  # A fallback must prove every file-entry boundary and every location index,
  # not just a plausible leading string/count prefix.
  $FileEntries = @(Get-InnoFileEntries -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Count $FileCount `
      -FileLocationCount $LocationCount -SearchOffset $Header.SearchOffset
  )
  $PostFileInfo = Get-InnoPostFileRecordInfo -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Counts $Header.Counts -FileEntries $FileEntries
  if (-not $PostFileInfo.IsResolved -or $PostFileInfo.EndOffset -gt $HeaderBlockInfo.Bytes.LongLength) {
    throw 'The Inno catalog layout did not consume the post-file metadata tables coherently'
  }

  $Stream = [IO.File]::OpenRead($Path)
  $Reader = [IO.BinaryReader]::new($Stream)
  try {
    $LocationBlock = Read-InnoMetadataBlock -Reader $Reader -Offset $HeaderBlockInfo.NextOffset -Layout $Layout
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
  $ExpectedLength = [long]$LocationCount * $Layout.FileLocationEntrySize
  if ($LocationBlock.Bytes.LongLength -ne $ExpectedLength) {
    throw "The Inno catalog layout expected a $ExpectedLength-byte location table but found $($LocationBlock.Bytes.LongLength) bytes"
  }
  for ($Index = 0; $Index -lt $LocationCount; $Index++) {
    $null = Read-InnoFileLocation -Bytes $LocationBlock.Bytes -Count $LocationCount -Index $Index -Layout $Layout
  }
}

function Resolve-InnoParsedLayout {
  <#
  .SYNOPSIS
    Parse the setup header and structurally validate a future-version fallback.
  .DESCRIPTION
    Exact layouts and source-defined signature aliases take one metadata pass.
    A nearest-older future-version fallback must additionally validate its
    file-entry chain and complete location table before exposing metadata.
  .PARAMETER Path
    Resolved installer path.
  .PARAMETER OffsetTable
    Validated loader offset table.
  .PARAMETER Layout
    Initial catalog selection from the setup-data signature.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][pscustomobject]$OffsetTable,
    [Parameter(Mandatory)][pscustomobject]$Layout
  )

  $HeaderBlockInfo = Get-InnoHeaderBlockInfo -Path $Path -Offset0 $OffsetTable.Offset0 -Layout $Layout
  $HeaderData = Read-InnoHeaderData -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
  $ExtractionHeader = Get-InnoExtractionHeader -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
  if ($Layout.LayoutResolution -eq 'NearestOlderPendingValidation') {
    Assert-InnoCatalogLayout -Path $Path -HeaderBlockInfo $HeaderBlockInfo -Header $ExtractionHeader -Layout $Layout
    $Layout.LayoutResolution = 'ValidatedNearestOlder'
  }
  return [pscustomobject]@{
    Layout            = $Layout
    HeaderBlockInfo   = $HeaderBlockInfo
    HeaderValues      = $HeaderData.Values
    CompiledCodeBytes = $HeaderData.CompiledCodeBytes
    ExtractionHeader  = $ExtractionHeader
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

    # Catalog rows identify exactly which ANSI generations serialize the
    # 256-bit LeadBytes set between strings and entry counts.
    if ($Layout.HasLeadBytes) {
      if ($Reader.BaseStream.Position + $Script:INNO_LEAD_BYTES_SIZE -gt $Reader.BaseStream.Length) {
        throw 'The Inno Setup header lead-byte set is truncated'
      }
      $Reader.BaseStream.Seek($Script:INNO_LEAD_BYTES_SIZE, 'Current') | Out-Null
    }

    $Counts = [ordered]@{}
    foreach ($CountName in $Layout.HeaderCountNames) {
      if ($Reader.BaseStream.Position + 4 -gt $Reader.BaseStream.Length) { throw 'The Inno Setup entry counts are truncated' }
      $Count = $Reader.ReadInt32()
      if ($Count -lt 0 -or $Count -gt 500000) { throw "The Inno Setup $CountName value is invalid: $Count" }
      $Counts[$CountName] = $Count
    }

    return [pscustomobject]@{
      HeaderValues = $HeaderValues
      Counts       = [pscustomobject]$Counts
      SearchOffset = [int]$Reader.BaseStream.Position
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
  .PARAMETER SearchOffset
    First byte after setup-header strings and counts. Header strings before this
    boundary are never accepted as file-entry evidence.
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

    if ($Reader.BaseStream.Position + $Layout.FileEntryVersionDataSize + 8 -gt $Reader.BaseStream.Length) {
      throw 'The Inno Setup file entry is truncated'
    }
    $Reader.BaseStream.Seek($Layout.FileEntryVersionDataSize, 'Current') | Out-Null # MinVersion + OnlyBelowVersion
    $LocationEntry = $Reader.ReadInt32()
    if ($LocationEntry -lt -1 -or $LocationEntry -ge $FileLocationCount) {
      throw "The Inno Setup file location index is invalid: $LocationEntry"
    }

    # Consume and validate the complete fixed tail so RecordEnd points exactly
    # at the next serialized file entry. This makes full table enumeration
    # source-backed rather than a search for unrelated file-name strings.
    $RemainingFixedBytes = 4 + $Layout.FileEntryExternalSizeSize +
    ($Layout.FileEntryHasCopyMode ? 1 : 0) + ($Layout.FileEntryHasPermissions ? 2 : 0) +
    ($Layout.FileEntryHasBitness ? 1 : 0) + $Layout.FileEntryOptionsSize + 1 +
    $Layout.FileEntryTrailingSize
    if ($Reader.BaseStream.Position + $RemainingFixedBytes -gt $Reader.BaseStream.Length) {
      throw 'The Inno Setup file entry fixed fields are truncated'
    }
    $Attribs = $Reader.ReadInt32()
    $ExternalSize = if ($Layout.FileEntryExternalSizeSize -eq 8) { $Reader.ReadInt64() } else { [long]$Reader.ReadInt32() }
    $CopyMode = if ($Layout.FileEntryHasCopyMode) { $Reader.ReadByte() } else { $null }
    $PermissionsEntry = if ($Layout.FileEntryHasPermissions) { $Reader.ReadInt16() } else { $null }
    $Bitness = if ($Layout.FileEntryHasBitness) { $Reader.ReadByte() } else { $null }
    $Options = $Reader.ReadBytes($Layout.FileEntryOptionsSize)
    $FileType = $Reader.ReadByte()
    if ($Layout.FileEntryTrailingSize -gt 0) {
      $Reader.BaseStream.Seek($Layout.FileEntryTrailingSize, 'Current') | Out-Null
    }

    return [pscustomobject]@{
      RecordOffset            = $Offset
      RecordEnd               = [int]$Reader.BaseStream.Position
      SourceFilename          = $Layout.FileEntryFields.Contains('SourceFilename') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'SourceFilename')] : $null
      DestName                = $Layout.FileEntryFields.Contains('DestName') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'DestName')] : $null
      InstallFontName         = $Layout.FileEntryFields.Contains('InstallFontName') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'InstallFontName')] : $null
      StrongAssemblyName      = $Layout.FileEntryFields.Contains('StrongAssemblyName') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'StrongAssemblyName')] : $null
      Components              = $Layout.FileEntryFields.Contains('Components') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'Components')] : $null
      Tasks                   = $Layout.FileEntryFields.Contains('Tasks') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'Tasks')] : $null
      Languages               = $Layout.FileEntryFields.Contains('Languages') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'Languages')] : $null
      Check                   = $Layout.FileEntryFields.Contains('Check') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'Check')] : $null
      AfterInstall            = $Layout.FileEntryFields.Contains('AfterInstall') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'AfterInstall')] : $null
      BeforeInstall           = $Layout.FileEntryFields.Contains('BeforeInstall') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'BeforeInstall')] : $null
      Excludes                = $Layout.FileEntryFields.Contains('Excludes') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'Excludes')] : $null
      DownloadISSigSource     = $Layout.FileEntryFields.Contains('DownloadISSigSource') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'DownloadISSigSource')] : $null
      DownloadUserName        = $Layout.FileEntryFields.Contains('DownloadUserName') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'DownloadUserName')] : $null
      DownloadPassword        = $Layout.FileEntryFields.Contains('DownloadPassword') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'DownloadPassword')] : $null
      ExtractArchivePassword  = $Layout.FileEntryFields.Contains('ExtractArchivePassword') ? $Strings[[Array]::IndexOf($Layout.FileEntryFields, 'ExtractArchivePassword')] : $null
      VerificationAllowedKeys = $VerificationAllowedKeys
      VerificationHash        = $VerificationHash
      VerificationType        = $VerificationType
      LocationEntry           = $LocationEntry
      Attribs                 = $Attribs
      ExternalSize            = $ExternalSize
      CopyMode                = $CopyMode
      PermissionsEntry        = $PermissionsEntry
      Bitness                 = $Bitness
      Options                 = $Options
      FileType                = $FileType
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

function Get-InnoFileEntries {
  <#
  .SYNOPSIS
    Enumerate the complete versioned Inno Setup file-entry table.
  .PARAMETER Bytes
    Decompressed first metadata block containing the header and serialized entry tables.
  .PARAMETER Layout
    Source-backed version layout describing strings, verification data, and packed option width.
  .PARAMETER Count
    Trusted NumFileEntries value from the setup header.
  .PARAMETER FileLocationCount
    Trusted NumFileLocationEntries value used to validate every location index.
  .PARAMETER SearchOffset
    First possible table offset, immediately after the serialized setup header counts.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][ValidateRange(0, 500000)][int]$Count,
    [Parameter(Mandatory)][ValidateRange(1, 500000)][int]$FileLocationCount,
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$SearchOffset
  )

  if ($Count -eq 0) { return @() }
  if ($SearchOffset -ge $Bytes.Length - 4) { throw 'The Inno Setup file-entry table is outside the metadata block' }

  $CandidateLayouts = [Collections.Generic.List[object]]::new()
  $CandidateLayouts.Add($Layout)
  if ($Layout.VersionNumber -lt 5500 -and $Layout.FileEntryStringCount -eq 10) {
    # Some 5.3-era compilers use the pre-BeforeInstall nine-string entry while
    # retaining the newer setup-data signature. Keep this compatibility layout
    # local to table discovery and require a complete, coherent record chain.
    $CompatibilityLayout = $Layout | Select-Object -Property *
    $CompatibilityLayout.FileEntryStringCount = 9
    $CompatibilityLayout.FileEntryTrailingSize += 4
    $CandidateLayouts.Add($CompatibilityLayout)
  }

  $ConstantPrefix = $Layout.StringEncoding -eq 'Unicode' ? [byte[]](0x7B, 0x00) : [byte[]](0x7B)
  $ConstantOffsets = @(Find-BinaryPattern -Bytes $Bytes -Pattern $ConstantPrefix -StartOffset $SearchOffset -Maximum 4096)

  $TestCandidateOffsets = {
    param([int[]]$CandidateStarts, [pscustomobject]$CandidateLayout, [int]$CandidateFileLocationCount)

    foreach ($CandidateStart in $CandidateStarts) {
      if ($CandidateStart -lt $SearchOffset -or $CandidateStart -gt $Bytes.Length - 4) { continue }
      $FirstLength = [BitConverter]::ToInt32($Bytes, $CandidateStart)
      if ($FirstLength -lt 0 -or $FirstLength -gt $Script:INNO_MAX_ENTRY_STRING_SIZE -or
        $FirstLength -gt $Bytes.Length - $CandidateStart - 4 -or
        ($CandidateLayout.StringEncoding -eq 'Unicode' -and ($FirstLength % 2) -ne 0)) { continue }

      $Entries = [System.Collections.Generic.List[object]]::new($Count)
      $LocationIndexes = [System.Collections.Generic.HashSet[int]]::new()
      $Cursor = $CandidateStart
      $Valid = $true
      $EmbeddedCount = 0
      $NamedCount = 0
      for ($Index = 0; $Index -lt $Count; $Index++) {
        try {
          $Entry = Read-InnoFileEntryAtOffset -Bytes $Bytes -Offset $Cursor -Layout $CandidateLayout -FileLocationCount $CandidateFileLocationCount
        } catch {
          $Valid = $false
          break
        }
        if ($Entry.RecordEnd -le $Cursor) {
          $Valid = $false
          break
        }
        # Reject accidental chains through custom-message or language data. A
        # decoded path may be empty for compiler-generated records, but populated
        # source/destination fields must be printable text rather than replacement
        # characters introduced by decoding arbitrary bytes.
        foreach ($EntryPath in @($Entry.SourceFilename, $Entry.DestName)) {
          if ([string]::IsNullOrWhiteSpace($EntryPath)) { continue }
          $ContainsControl = $false
          for ($CharacterIndex = 0; $CharacterIndex -lt $EntryPath.Length; $CharacterIndex++) {
            if ([char]::IsControl($EntryPath[$CharacterIndex])) {
              $ContainsControl = $true
              break
            }
          }
          if ($EntryPath.Contains([char]0xFFFD) -or $EntryPath.IndexOf([char]0) -ge 0 -or $ContainsControl) {
            $Valid = $false
            break
          }
        }
        if (-not $Valid) { break }
        $Entries.Add($Entry)
        if (-not [string]::IsNullOrWhiteSpace($Entry.SourceFilename) -or
          -not [string]::IsNullOrWhiteSpace($Entry.DestName)) { $NamedCount++ }
        if ($Entry.LocationEntry -ge 0) {
          $EmbeddedCount++
          $null = $LocationIndexes.Add($Entry.LocationEntry)
        }
        $Cursor = $Entry.RecordEnd
      }

      $MinimumDistinctLocations = [Math]::Min(2, $CandidateFileLocationCount)
      # Inno always emits an unnamed uninstaller file entry when uninstall
      # support is enabled. A minimal setup can therefore contain one named
      # payload and one valid unnamed compiler-generated entry.
      if ($Valid -and $Entries.Count -eq $Count -and $EmbeddedCount -gt 0 -and
        $NamedCount -ge 1 -and
        $LocationIndexes.Count -ge $MinimumDistinctLocations) {
        return [pscustomobject]@{ Entries = $Entries.ToArray() }
      }
    }
    return $null
  }

  foreach ($CandidateLayout in $CandidateLayouts) {
    # Inno can place an all-empty compiler-generated uninstaller record before
    # the first named payload. Evaluate empty and named anchors together in
    # offset order so a later named record cannot shift the table by one entry
    # and consume the first icon/INI record as a false final file record.
    $CandidateOffsets = [Collections.Generic.HashSet[int]]::new()
    $EmptyStringCount = $CandidateLayout.FileEntryStringCount + $CandidateLayout.FileEntryAnsiStringCount
    $EmptyPrefix = [byte[]]::new($EmptyStringCount * 4)
    foreach ($Offset in Find-BinaryPattern -Bytes $Bytes -Pattern $EmptyPrefix -StartOffset $SearchOffset -Maximum 4096) {
      $null = $CandidateOffsets.Add([int]$Offset)
    }
    foreach ($Offset in $ConstantOffsets) {
      if ($Offset -ge 4) { $null = $CandidateOffsets.Add([int]$Offset - 4) }
      if ($Offset -ge 8 -and [BitConverter]::ToInt32($Bytes, [int]$Offset - 8) -eq 0) {
        $null = $CandidateOffsets.Add([int]$Offset - 8)
      }
    }

    # DestName is the second string in every file record. Find populated
    # SourceFilename prefixes in one forward pass instead of walking backward
    # up to 16 KiB from every brace anchor. The resulting candidates still have
    # to consume the complete declared file table below.
    if ($ConstantOffsets.Count -gt 0) {
      Import-InnoCallTransform
      $MaximumCandidateOffset = [int]($ConstantOffsets | Measure-Object -Maximum).Maximum
      $DetectedOffsets = [Dumplings.InstallerParsers.InnoCallTransform]::FindLengthPrefixedSecondStringRecords(
        $Bytes,
        $SearchOffset,
        $MaximumCandidateOffset,
        [int[]]$ConstantOffsets,
        $CandidateLayout.StringEncoding -eq 'Unicode',
        $Script:INNO_MAX_FILE_ENTRY_PATH_SCAN,
        $Script:INNO_MAX_ENTRY_STRING_SIZE
      )
      foreach ($SourceOffset in $DetectedOffsets) {
        $null = $CandidateOffsets.Add($SourceOffset)
      }
    }
    $Match = & $TestCandidateOffsets ([int[]]@($CandidateOffsets | Sort-Object)) $CandidateLayout $FileLocationCount
    if ($Match) { return $Match.Entries }
  }

  throw 'The complete Inno Setup file-entry table could not be located with the detected version layout'
}

function Read-InnoCatalogRecord {
  <#
  .SYNOPSIS
    Read one variable-length Inno metadata record using its resolved catalog schema.
  .PARAMETER Reader
    Reader positioned at the record's first serialized string. The function advances it to the next record.
  .PARAMETER Schema
    Resolved record schema containing ordered wide/ANSI fields and the packed fixed-tail size.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][System.IO.BinaryReader]$Reader,
    [Parameter(Mandatory)][pscustomobject]$Schema
  )

  $Start = [long]$Reader.BaseStream.Position
  $Values = [ordered]@{}
  $WideValues = Read-InnoReaderStrings -Reader $Reader -Count $Schema.Fields.Count -Encoding ([Text.Encoding]::Unicode) -MaximumLength $Script:INNO_MAX_ENTRY_STRING_SIZE
  for ($Index = 0; $Index -lt $Schema.Fields.Count; $Index++) { $Values[$Schema.Fields[$Index]] = $WideValues[$Index] }
  $AnsiValues = Read-InnoReaderStrings -Reader $Reader -Count $Schema.AnsiFields.Count -Encoding (Get-InnoAnsiEncoding) -MaximumLength $Script:INNO_MAX_ENTRY_STRING_SIZE
  for ($Index = 0; $Index -lt $Schema.AnsiFields.Count; $Index++) { $Values[$Schema.AnsiFields[$Index]] = $AnsiValues[$Index] }

  if ($Schema.FixedSize -lt 0 -or $Reader.BaseStream.Position + $Schema.FixedSize -gt $Reader.BaseStream.Length) {
    throw "The Inno Setup $($Schema.Id) record fixed tail is truncated"
  }
  $FixedBytes = $Reader.ReadBytes($Schema.FixedSize)
  return [pscustomobject]@{
    RecordOffset = $Start
    RecordEnd    = [long]$Reader.BaseStream.Position
    Values       = [pscustomobject]$Values
    FixedBytes   = $FixedBytes
  }
}

function Read-InnoCatalogRecordTable {
  <#
  .SYNOPSIS
    Read a bounded number of contiguous records selected by the format catalog.
  .PARAMETER Reader
    Reader positioned at the first record; it remains open and advances through the table.
  .PARAMETER Schema
    Resolved schema shared by every record in the table.
  .PARAMETER Count
    Trusted setup-header count, bounded to the parser-wide record limit.
  #>
  [OutputType([pscustomobject[]])]
  param (
    [Parameter(Mandatory)][System.IO.BinaryReader]$Reader,
    [Parameter(Mandatory)][pscustomobject]$Schema,
    [Parameter(Mandatory)][ValidateRange(0, 500000)][int]$Count
  )

  if ($Count -eq 0) { return @() }
  if ($Schema.Id -eq 'absent') { throw 'The Inno Setup header declares records that are absent from the selected catalog format' }
  $Records = [Collections.Generic.List[object]]::new($Count)
  for ($Index = 0; $Index -lt $Count; $Index++) { $Records.Add((Read-InnoCatalogRecord -Reader $Reader -Schema $Schema)) }
  return $Records.ToArray()
}

function ConvertFrom-InnoRegistryRootKey {
  <#
  .SYNOPSIS
    Decode the UInt32 registry-root value serialized by the Inno compiler.
  .PARAMETER Value
    Raw little-endian root value, including the source-defined HKEY_AUTO value.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][uint32]$Value)

  $RootNames = @{
    ([uint32]0x00000001) = 'HKA'
    ([uint32]2147483648) = 'HKCR'
    ([uint32]2147483649) = 'HKCU'
    ([uint32]2147483650) = 'HKLM'
    ([uint32]2147483651) = 'HKU'
    ([uint32]2147483653) = 'HKCC'
  }
  if ($RootNames.ContainsKey($Value)) { return $RootNames[$Value] }
  return ('0x{0:X8}' -f $Value)
}

function ConvertFrom-InnoRegistryRecord {
  <#
  .SYNOPSIS
    Project a raw catalog registry record into deterministic registry-write evidence.
  .PARAMETER Record
    Record returned by Read-InnoCatalogRecord.
  .PARAMETER Schema
    Registry schema containing source-backed offsets in the packed fixed tail.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][pscustomobject]$Record,
    [Parameter(Mandatory)][pscustomobject]$Schema
  )

  $RootValue = [BitConverter]::ToUInt32($Record.FixedBytes, [int]$Schema.RootKeyOffset)
  $TypeValue = $Record.FixedBytes[[int]$Schema.TypeOffset]
  $Type = switch ($TypeValue) {
    0 { 'None' }
    1 { 'String' }
    2 { 'ExpandString' }
    3 { 'DWord' }
    4 { 'Binary' }
    5 { 'MultiString' }
    6 { 'QWord' }
    default { "Unknown($TypeValue)" }
  }
  return [pscustomobject][ordered]@{
    RootKey       = ConvertFrom-InnoRegistryRootKey -Value $RootValue
    RootKeyValue  = $RootValue
    Subkey        = $Record.Values.Subkey
    ValueName     = $Record.Values.ValueName
    ValueData     = $Record.Values.ValueData
    Type          = $Type
    TypeValue     = $TypeValue
    Components    = $Record.Values.Components
    Tasks         = $Record.Values.Tasks
    Languages     = $Record.Values.Languages
    Check         = $Record.Values.Check
    AfterInstall  = $Record.Values.AfterInstall
    BeforeInstall = $Record.Values.BeforeInstall
    Conditional   = -not [string]::IsNullOrWhiteSpace($Record.Values.Components) -or
    -not [string]::IsNullOrWhiteSpace($Record.Values.Tasks) -or
    -not [string]::IsNullOrWhiteSpace($Record.Values.Languages) -or
    -not [string]::IsNullOrWhiteSpace($Record.Values.Check)
    Options       = [byte[]]$Record.FixedBytes[[int]$Schema.OptionsOffset..($Record.FixedBytes.Length - 1)]
    RecordOffset  = $Record.RecordOffset
  }
}

function Get-InnoPostFileRecordInfo {
  <#
  .SYNOPSIS
    Parse all catalogued metadata tables that physically follow the file table.
  .PARAMETER Bytes
    Decompressed first metadata block.
  .PARAMETER Layout
    Resolved catalog layout containing record-family schemas.
  .PARAMETER Counts
    Validated setup-header entry counts.
  .PARAMETER FileEntries
    Complete file-entry table; its final boundary anchors the following tables.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][pscustomobject]$Layout,
    [Parameter(Mandatory)][pscustomobject]$Counts,
    [Parameter(Mandatory)][pscustomobject[]]$FileEntries
  )

  if ($FileEntries.Count -eq 0) {
    return [pscustomobject]@{ IsResolved = $false; EndOffset = $null; Icons = @(); IniEntries = @(); RegistryEntries = @(); InstallDeleteEntries = @(); UninstallDeleteEntries = @(); RunEntries = @(); UninstallRunEntries = @() }
  }
  $Stream = [IO.MemoryStream]::new($Bytes, $false)
  $Reader = [IO.BinaryReader]::new($Stream)
  try {
    $Reader.BaseStream.Position = [long]$FileEntries[-1].RecordEnd
    $Icons = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Icon -Count $Counts.NumIconEntries)
    $IniEntries = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Ini -Count $Counts.NumIniEntries)
    $RegistryRecords = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Registry -Count $Counts.NumRegistryEntries)
    $RegistryEntries = @($RegistryRecords | ForEach-Object { ConvertFrom-InnoRegistryRecord -Record $_ -Schema $Layout.RecordFamilies.Registry })
    $InstallDelete = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Delete -Count $Counts.NumInstallDeleteEntries)
    $UninstallDelete = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Delete -Count $Counts.NumUninstallDeleteEntries)
    $Run = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Run -Count $Counts.NumRunEntries)
    $UninstallRun = @(Read-InnoCatalogRecordTable -Reader $Reader -Schema $Layout.RecordFamilies.Run -Count $Counts.NumUninstallRunEntries)
    return [pscustomobject]@{
      IsResolved             = $true
      EndOffset              = [long]$Reader.BaseStream.Position
      Icons                  = $Icons
      IniEntries             = $IniEntries
      RegistryEntries        = $RegistryEntries
      InstallDeleteEntries   = $InstallDelete
      UninstallDeleteEntries = $UninstallDelete
      RunEntries             = $Run
      UninstallRunEntries    = $UninstallRun
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

function Get-InnoRegistryAssociationInfo {
  <#
  .SYNOPSIS
    Derive literal file-extension and URL-protocol evidence from parsed registry records.
  .PARAMETER RegistryEntries
    Registry writes returned by Get-InnoPostFileRecordInfo.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][pscustomobject[]]$RegistryEntries)

  $Extensions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $Protocols = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ConditionalExtensions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ConditionalProtocols = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $ExtensionAssociations = [Collections.Generic.List[object]]::new()
  $ProtocolAssociations = [Collections.Generic.List[object]]::new()
  $ConditionalAssociations = [Collections.Generic.List[object]]::new()
  foreach ($Entry in $RegistryEntries) {
    $ClassesPath = if ($Entry.RootKey -eq 'HKCR') {
      [string]$Entry.Subkey
    } elseif ($Entry.RootKey -in @('HKCU', 'HKLM', 'HKA') -and $Entry.Subkey -match '^(?i)Software\\Classes\\(?<Path>.+)$') {
      $Matches.Path
    } else {
      $null
    }
    if ([string]::IsNullOrWhiteSpace($ClassesPath) -or $ClassesPath -match '\{code:') { continue }
    $FirstSegment = ($ClassesPath -split '\\', 2)[0]
    $Kind = if ($FirstSegment -match '^\.[A-Za-z0-9][A-Za-z0-9+_-]*$') {
      'FileExtension'
    } elseif ($Entry.ValueName -ieq 'URL Protocol' -and $FirstSegment -match '^[A-Za-z][A-Za-z0-9+.-]*$') {
      'Protocol'
    } else {
      $null
    }
    if (-not $Kind) { continue }

    $Name = $Kind -eq 'FileExtension' ? $FirstSegment.TrimStart('.').ToLowerInvariant() : $FirstSegment.ToLowerInvariant()
    $Association = [pscustomobject][ordered]@{
      Kind         = $Kind
      Name         = $Name
      RootKey      = [string]$Entry.RootKey
      Subkey       = [string]$Entry.Subkey
      ValueName    = [string]$Entry.ValueName
      ValueData    = [string]$Entry.ValueData
      Conditional  = [bool]$Entry.Conditional
      Components   = [string]$Entry.Components
      Tasks        = [string]$Entry.Tasks
      Languages    = [string]$Entry.Languages
      Check        = [string]$Entry.Check
      RecordOffset = $Entry.RecordOffset
    }
    if ($Kind -eq 'FileExtension') {
      $ExtensionAssociations.Add($Association)
      $null = ($Entry.Conditional ? $ConditionalExtensions : $Extensions).Add($Name)
    } else {
      $ProtocolAssociations.Add($Association)
      $null = ($Entry.Conditional ? $ConditionalProtocols : $Protocols).Add($Name)
    }
    if ($Entry.Conditional) { $ConditionalAssociations.Add($Association) }
  }
  return [pscustomobject]@{
    FileExtensions                  = [string[]]@($Extensions | Sort-Object)
    Protocols                       = [string[]]@($Protocols | Sort-Object)
    ConditionalFileExtensions       = [string[]]@($ConditionalExtensions | Sort-Object)
    ConditionalProtocols            = [string[]]@($ConditionalProtocols | Sort-Object)
    FileExtensionAssociations       = [pscustomobject[]]$ExtensionAssociations.ToArray()
    ProtocolAssociations            = [pscustomobject[]]$ProtocolAssociations.ToArray()
    ConditionalRegistryAssociations = [pscustomobject[]]$ConditionalAssociations.ToArray()
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
    [Parameter(Mandatory)][ValidateRange(0, [int]::MaxValue)][int]$SearchOffset,
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

    $MinimumStart = [Math]::Max($SearchOffset, $StringStart - $Script:INNO_MAX_FILE_ENTRY_PATH_SCAN)
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
    foreach ($StringStart in (Find-BinaryPattern -Bytes $Bytes -Pattern $SerializedNeedle -StartOffset $SearchOffset -Maximum 64)) {
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
    foreach ($Occurrence in (Find-BinaryPattern -Bytes $Bytes -Pattern $Needle -StartOffset $SearchOffset -Maximum 16)) {
      $StringEnd = [int]$Occurrence + $Needle.Length
      $MinimumStart = [Math]::Max($SearchOffset, $StringEnd - $Script:INNO_MAX_FILE_ENTRY_PATH_SCAN)
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
    Decode a catalogued Inno file-location flag set.
  .PARAMETER Value
    Packed little-endian flag value read from the location record.
  .PARAMETER FlagNames
    Ordered semantic names whose array indexes are their persisted bit indexes.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][uint16]$Value,
    [Parameter(Mandatory)][string[]]$FlagNames
  )

  $Decoded = [ordered]@{
    VersionInfoValid         = $false
    VersionInfoNotValid      = $false
    TimeStampInUtc           = $false
    IsUninstallExecutable    = $false
    CallInstructionOptimized = $false
    TouchApplied             = $false
    ChunkEncrypted           = $false
    ChunkCompressed          = $false
    SolidBreak               = $false
    BZip2                    = $false
    Sign                     = $false
    SignOnce                 = $false
  }
  for ($Bit = 0; $Bit -lt $FlagNames.Count; $Bit++) {
    $Name = $FlagNames[$Bit]
    if (-not $Decoded.Contains($Name)) { $Decoded[$Name] = $false }
    $Decoded[$Name] = [bool]($Value -band (1 -shl $Bit))
  }
  return [pscustomobject]$Decoded
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
    if ($Layout.FileLocationHasChunkFields) {
      $ChunkSuboffset = $Reader.ReadInt64()
      $OriginalSize = $Reader.ReadInt64()
      $ChunkCompressedSize = $Reader.ReadInt64()
    } else {
      # Inno 1.3.21 through 4.0.0 stores one independent zlib/bzip stream per
      # file. There is no solid-stream suboffset and both sizes are 32-bit.
      $ChunkSuboffset = 0L
      $OriginalSize = [long]$Reader.ReadInt32()
      $ChunkCompressedSize = [long]$Reader.ReadInt32()
    }
    $Digest = $Reader.ReadBytes($Layout.FileLocationDigestSize)
    $TimeStamp = $Reader.ReadBytes(8)
    $FileVersionMS = $Reader.ReadUInt32()
    $FileVersionLS = $Reader.ReadUInt32()
    $RawFlags = if ($Layout.FileLocationFlagSize -eq 2) { [uint16]$Reader.ReadUInt16() } else { [uint16]$Reader.ReadByte() }
    $Sign = if ($Layout.FileLocationHasSign) { $Reader.ReadByte() } else { $null }
    $Flags = ConvertFrom-InnoFileLocationFlags -Value $RawFlags -FlagNames $Layout.FileLocationFlagNames

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
      Md5                 = $Layout.FileLocationDigestAlgorithm -eq 'MD5' ? $Digest : $null
      Sha1                = $Layout.FileLocationDigestAlgorithm -eq 'SHA1' ? $Digest : $null
      Sha256              = $Layout.FileLocationDigestAlgorithm -eq 'SHA256' ? $Digest : $null
      TimeStamp           = $TimeStamp
      FileVersionMS       = $FileVersionMS
      FileVersionLS       = $FileVersionLS
      RawFlags            = $RawFlags
      Flags               = $Flags
      IsBZip2             = $Flags.BZip2
      Sign                = $Sign
    }
  } finally {
    $Reader.Dispose()
    $Stream.Dispose()
  }
}

Export-ModuleMember -Function Copy-InnoCatalogMap, Test-InnoCatalogDelta, Resolve-InnoCatalogFormat, Copy-InnoResolvedCatalogFormat, Test-InnoResToolsEdition, Import-InnoCallTransform, Get-InstallerCrc32, Get-InnoResourceBytes, Read-InnoOffsetTableInteger, Get-InnoOffsetTable, Get-InnoVersionNumber, Get-InnoSignatureInfo, Get-InnoLayout, Get-InnoAnalysisContext, Get-InnoAnsiEncoding, Read-InnoReaderStrings, Test-InnoCompressedBlockHeader, Expand-InnoLzmaBytes, Expand-InnoLzma2Bytes, Read-InnoCompressedBlock, Read-InnoLegacyCompressedBlock, Read-InnoMetadataBlock, Read-InnoSetupEncryptionHeader, Get-InnoHeaderBlockInfo, Get-InnoHeaderBlock, Read-InnoWideStrings, Read-InnoAnsiStrings, Read-InnoHeaderData, Get-InnoPEInfo, Get-InnoHeaderArchitectureData, ConvertTo-InnoArchitectureExpressionToken, Test-InnoArchitectureIdentifier, Test-InnoArchitectureExpression, Get-InnoBooleanDirectiveInfo, Resolve-InnoBooleanDirective, Get-InnoAppsAndFeaturesEntryInfo, Get-InnoUnsupportedArchitectureList, Get-InnoSupportedArchitectureList, Read-InnoHeaderFixedData, Convert-InnoPrivilegeToScope, Find-InnoConstantEnd, Get-InnoStaticStringInfo, Get-InnoArchitectureConstantRequirement, ConvertFrom-InnoEscapedString, Get-InnoDefaultDirectoryConstantMap, Get-InnoUninstallRegKeyBaseName, Get-InnoProductCode, Resolve-InnoDefaultDirectory, Test-InnoResolvedValue, Assert-InnoCatalogLayout, Resolve-InnoParsedLayout, ConvertFrom-InnoVersion5FileLocationFlags, Get-InnoExtractionHeader, Read-InnoFileEntryAtOffset, Get-InnoFileEntries, Read-InnoCatalogRecord, Read-InnoCatalogRecordTable, ConvertFrom-InnoRegistryRootKey, ConvertFrom-InnoRegistryRecord, Get-InnoPostFileRecordInfo, Get-InnoRegistryAssociationInfo, Find-InnoFileEntry, ConvertFrom-InnoFileLocationFlags, Read-InnoFileLocation
