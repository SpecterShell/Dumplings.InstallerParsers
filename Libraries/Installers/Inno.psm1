# License: GPL-3.0-or-later. See Modules\InstallerParsers\LICENSE.
# Format sources: https://github.com/jrsoftware/issrc, https://github.com/jrathlev/InnoUnpacker-Windows-GUI, https://github.com/Wack0/IFPSTools.NET, and https://github.com/russellbanks/Komac
#
# Binary structure consumed by this parser:
#
#   PE loader
#   +-- legacy: [abs 0x30] "Inno" + table pointer/complement
#   |            `-- S02/S04/S05/S06/S07 table -> Offset0/Offset1
#   `-- modern: .rsrc/RCDATA/#11111 -> 44-byte v1 or 64-byte v2 table
#
#   Offset0 -> setup signature[64] -> optional encryption header
#     -> legacy or chunk-framed metadata -> catalogued record tables
#   Offset1 != 0 -> embedded 7A 6C 62 1A ("zlb" 1A) payload blocks
#   Offset1 == 0 -> Setup-N[letter].bin external slices
#     +-- 69 64 73 6B 61 33 32 1A + uint32 size (structures < 6.5.2)
#     `-- 69 64 73 6B 62 33 32 1A + int64 size  (structures >= 6.5.2)
#
# InnoFormatCatalog.psd1 maps exact edition/signature/character-mode/loader
# combinations to immutable loader, framing, record, payload, checksum, and
# CALL-transform routes. Integers are little-endian. Every range, count, chunk,
# checksum, decompressed size, and extraction destination is bounded.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
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
$INNO_PAYLOAD_BUFFER_SIZE = 1048576
$INNO_MAX_COMPILED_CODE_SIZE = 16777216
$INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT = 262144
$INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE = 1048576
$INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS = 4194304
$INNO_LEAD_BYTES_SIZE = 32
$INNO_CHUNK_MAGIC = [System.Text.Encoding]::ASCII.GetString([byte[]](0x7A, 0x6C, 0x62, 0x1A))
$INNO_DISK_SLICE_ID_LEGACY = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x61, 0x33, 0x32, 0x1A) # "idska32" + SUB
$INNO_DISK_SLICE_ID_6502 = [byte[]](0x69, 0x64, 0x73, 0x6B, 0x62, 0x33, 0x32, 0x1A)   # "idskb32" + SUB
Import-InstallerArchiveDependency

$Script:InnoFormatCatalog = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'InnoFormatCatalog.psd1') -SkipLimitCheck
$Script:InnoPascalScriptAssetManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets\IFPSLibAssets.psd1')

function Import-InnoPascalScriptDependency {
  <#
  .SYNOPSIS
    Load the pinned IFPSLib dependency chain used for compiled Pascal Script analysis.
  .DESCRIPTION
    IFPSLib is loaded only after the caller has validated the bounded IFPS header. The
    dependency remains inside the process-isolated GPL parser and is never loaded by
    PackageModule directly.
  #>
  $AssetRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Assets')).Path
  $AssemblyRoot = Join-Path $AssetRoot 'Assemblies'
  foreach ($Asset in $Script:InnoPascalScriptAssetManifest.Assemblies) {
    $AssetPath = Join-Path $AssemblyRoot $Asset.Name
    if (-not (Test-Path -LiteralPath $AssetPath -PathType Leaf)) { throw "The pinned IFPS dependency is missing: $AssetPath" }
    $ActualHash = (Get-FileHash -LiteralPath $AssetPath -Algorithm SHA256).Hash
    if ($ActualHash -cne $Asset.Sha256) {
      throw "The pinned IFPS dependency '$($Asset.Name)' failed its SHA-256 integrity check."
    }
    $Assembly = Import-InstallerManagedAssembly -Name $Asset.Name -TypeName $Asset.TypeName
    if ($Assembly.GetName().Version.ToString() -cne $Asset.Version) {
      throw "The loaded IFPS dependency '$($Asset.Name)' has version '$($Assembly.GetName().Version)', expected '$($Asset.Version)'."
    }
  }
}

# Loader variants differ only in field positions, integer widths, and CRC
# coverage. These route records keep those source-backed differences out of
# parser-time version branches.
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
$Script:InnoPayloadRouteDescriptors = @{
  'legacy-adler'              = [pscustomobject]@{ AlwaysCompressed = $true; CompressionFromLocation = $true }
  'chunked-always-compressed' = [pscustomobject]@{ AlwaysCompressed = $true; CompressionFromLocation = $false }
  'chunked-legacy'            = [pscustomobject]@{ AlwaysCompressed = $false; CompressionFromLocation = $false }
  'chunked-modern'            = [pscustomobject]@{ AlwaysCompressed = $false; CompressionFromLocation = $false }
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

# Resolve all schema deltas once. Runtime parsing selects and clones these
# descriptors rather than rebuilding layouts or branching on version numbers.
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
    Path          = $InstallerPath
    PEInfo        = Get-InnoPEInfo -Path $InstallerPath
    OffsetTable   = $OffsetTable
    SignatureInfo = $SignatureInfo
    Layout        = $ParsedLayout.Layout
    ParsedLayout  = $ParsedLayout
  }
}

function Get-InnoFormatInfo {
  <#
  .SYNOPSIS
    Identify the Inno edition and select its catalogued binary-layout routes.
  .DESCRIPTION
    Reads only the PE loader table and the 64-byte setup-data signature. The
    result describes which loader, metadata, record, payload, checksum, and
    executable-transform routes the full parser will use. An ISX signature is
    returned as a structured unsupported format rather than being mistaken for
    official Inno Setup.
  .PARAMETER Path
    Path to an Inno Setup installer. The file is opened for bounded static reads
    and is never loaded or executed.
  .OUTPUTS
    PSCustomObject containing edition, character mode, structure version,
    selected route IDs, layout resolution, candidate IDs, and support status.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
    [string]$Path
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath
    $SignatureInfo = Get-InnoSignatureInfo -Path $InstallerPath -OffsetTable $OffsetTable
    $Layout = Get-InnoLayout -SignatureInfo $SignatureInfo -LoaderRoute $OffsetTable.LoaderRoute
    $Warnings = [Collections.Generic.List[string]]::new()
    if ($Layout.SupportStatus -eq 'Unsupported') {
      $Warnings.Add("The Inno edition '$($Layout.Edition)' is identified, but no trustworthy record specification is available.")
    } elseif ($Layout.LayoutResolution -eq 'NearestOlderPendingValidation') {
      $Warnings.Add('The signature is newer than the catalogued layout. Full parsing must validate every count, range, record boundary, checksum, and stream boundary before accepting the fallback.')
    } elseif ($Layout.LayoutResolution -eq 'ExactSignatureAlias') {
      $Warnings.Add('Multiple catalog rows share this byte-equivalent setup-data signature. The source-defined canonical structure was selected and all alias IDs are reported.')
    }

    $GetLayoutValue = {
      param([string]$Name)
      $Property = $Layout.PSObject.Properties[$Name]
      if ($Property) { return $Property.Value }
      return $null
    }

    [pscustomobject]@{
      Path                     = $InstallerPath
      InstallerType            = 'inno'
      Signature                = $SignatureInfo.Signature
      SignatureVersion         = $SignatureInfo.VersionText
      CatalogFormatId          = & $GetLayoutValue 'Id'
      InternalStructureVersion = & $GetLayoutValue 'InternalStructureVersion'
      EditionId                = $SignatureInfo.EditionId
      Edition                  = $SignatureInfo.Edition
      CharacterMode            = $SignatureInfo.CharacterMode
      LoaderRoute              = $OffsetTable.LoaderRoute
      MetadataRoute            = & $GetLayoutValue 'MetadataRoute'
      RecordSchemaRoute        = & $GetLayoutValue 'RecordSchemaRoute'
      PayloadRoute             = & $GetLayoutValue 'PayloadRoute'
      CompressionCapabilities  = @((& $GetLayoutValue 'CompressionCapabilities') -split ',' | Where-Object { $_ })
      ChecksumRoute            = & $GetLayoutValue 'ChecksumRoute'
      CallTransformRoute       = & $GetLayoutValue 'CallTransformRoute'
      LayoutResolution         = $Layout.LayoutResolution
      CandidateIds             = [string[]]@($Layout.CandidateIds)
      SupportStatus            = $Layout.SupportStatus
      IsSupported              = $Layout.SupportStatus -eq 'Supported'
      Warnings                 = $Warnings.ToArray()
    }
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

  $Warnings = [System.Collections.Generic.List[string]]::new()

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
      Warnings                                 = [string[]]@()
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
  .PARAMETER HeaderFixedData
    Fixed-header option evidence used by Inno Setup versions before 5.3.10
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
    [pscustomobject]$HeaderFixedData
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
    Get-InnoBooleanDirectiveInfo -Value $CreateUninstallRegKey -Default $true
  }
  $UninstallableInfo = if ($null -ne $Layout.LegacyUninstallableOptionBit) {
    if ($null -ne $HeaderFixedData -and $null -ne $HeaderFixedData.LegacyUninstallable) {
      [pscustomobject]@{ Value = [bool]$HeaderFixedData.LegacyUninstallable; IsResolved = $true; IsDefault = $false; IsDynamic = $false }
    } else {
      [pscustomobject]@{ Value = $null; IsResolved = $false; IsDefault = $false; IsDynamic = $false }
    }
  } else {
    Get-InnoBooleanDirectiveInfo -Value $Uninstallable -Default $true
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

function Read-InnoPascalScriptHeader {
  <#
  .SYNOPSIS
    Validate the bounded IFPS header without decoding bytecode tables.
  .PARAMETER Bytes
    Raw CompiledCodeText bytes.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  if ($Bytes.Length -eq 0) {
    return [pscustomobject][ordered]@{
      Present = $false; ByteLength = 0; FileVersion = $null; TypeCount = 0
      FunctionCount = 0; GlobalVariableCount = 0; EntryPointIndex = $null
      ImportSize = 0; AnalysisStatus = 'NotPresent'
    }
  }
  if ($Bytes.Length -gt $INNO_MAX_COMPILED_CODE_SIZE) {
    throw "The compiled Inno Pascal Script exceeds the $INNO_MAX_COMPILED_CODE_SIZE-byte analysis limit."
  }
  if ($Bytes.Length -lt 28 -or [Text.Encoding]::ASCII.GetString($Bytes, 0, 4) -cne 'IFPS') {
    throw 'CompiledCodeText does not contain an IFPS program header.'
  }

  # The IFPS header is six signed little-endian Int32 fields after the magic.
  # Validate counts before IFPSLib constructs any attacker-controlled lists.
  $FileVersion = [BitConverter]::ToInt32($Bytes, 4)
  $TypeCount = [BitConverter]::ToInt32($Bytes, 8)
  $FunctionCount = [BitConverter]::ToInt32($Bytes, 12)
  $VariableCount = [BitConverter]::ToInt32($Bytes, 16)
  $EntryPointIndex = [BitConverter]::ToInt32($Bytes, 20)
  $ImportSize = [BitConverter]::ToInt32($Bytes, 24)
  if ($FileVersion -lt 12 -or $FileVersion -gt 23) { throw "Unsupported IFPS bytecode version: $FileVersion" }
  foreach ($Count in @($TypeCount, $FunctionCount, $VariableCount)) {
    if ($Count -lt 0 -or $Count -gt $INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT -or $Count -gt $Bytes.Length) {
      throw 'The IFPS header contains an invalid entity count.'
    }
  }
  if (([long]$TypeCount + $FunctionCount + $VariableCount) -gt $INNO_MAX_PASCAL_SCRIPT_ENTITY_COUNT) {
    throw 'The IFPS header exceeds the aggregate entity-count limit.'
  }
  if ($EntryPointIndex -lt -1 -or $EntryPointIndex -ge $FunctionCount) { throw 'The IFPS entry-point index is invalid.' }
  if ($ImportSize -lt 0 -or $ImportSize -gt ($Bytes.Length - 28)) { throw 'The IFPS import-table size is invalid.' }

  return [pscustomobject][ordered]@{
    Present             = $true
    ByteLength          = $Bytes.Length
    FileVersion         = $FileVersion
    TypeCount           = $TypeCount
    FunctionCount       = $FunctionCount
    GlobalVariableCount = $VariableCount
    EntryPointIndex     = $EntryPointIndex
    ImportSize          = $ImportSize
    AnalysisStatus      = 'AvailableOnRequest'
  }
}

function Get-InnoPascalScriptVariableKey {
  <#
  .SYNOPSIS
    Build a stable key for one IFPS variable operand.
  .PARAMETER Operand
    IFPSLib operand expected to refer directly to a variable.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][object]$Operand)

  if ([string]$Operand.Type -cne 'Variable') { return $null }
  return '{0}:{1}' -f $Operand.Variable.VarType, $Operand.Variable.Index
}

function Get-InnoPascalScriptOperandConstant {
  <#
  .SYNOPSIS
    Resolve a JSON-safe immediate or a previously proven variable constant.
  .PARAMETER Operand
    IFPSLib operand to inspect.
  .PARAMETER State
    Straight-line variable state keyed by variable kind and index.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][object]$Operand,
    [Parameter(Mandatory)][System.Collections.Generic.Dictionary[string, object]]$State
  )

  if ([string]$Operand.Type -ceq 'Variable') {
    $Key = Get-InnoPascalScriptVariableKey -Operand $Operand
    if ($Key -and $State.ContainsKey($Key)) {
      return [pscustomobject]@{ Resolved = $true; Value = $State[$Key] }
    }
    return [pscustomobject]@{ Resolved = $false; Value = $null }
  }
  if ([string]$Operand.Type -cne 'Immediate') {
    return [pscustomobject]@{ Resolved = $false; Value = $null }
  }

  $Value = $Operand.Immediate
  if ($null -eq $Value -or $Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or
    $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
    $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
    $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
    return [pscustomobject]@{ Resolved = $true; Value = $Value }
  }
  if ($Value.GetType().IsEnum) {
    return [pscustomobject]@{ Resolved = $true; Value = [string]$Value }
  }
  return [pscustomobject]@{ Resolved = $false; Value = $null }
}

function Get-InnoPascalScriptStaticReturnInfo {
  <#
  .SYNOPSIS
    Prove a constant IFPS return value using bounded straight-line propagation.
  .DESCRIPTION
    The evaluator accepts assignments and primitive operations only. Calls,
    branches, exception flow, pointers, indexed values, and unknown opcodes make
    the result unresolved instead of being simulated.
  .PARAMETER Function
    IFPSLib script function to inspect.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][object]$Function)

  if ($Function.GetType().FullName -cne 'IFPSLib.Emit.ScriptFunction' -or $null -eq $Function.ReturnArgument) {
    return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'No script return value' }
  }

  $State = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
  foreach ($Instruction in $Function.Instructions) {
    $Code = [string]$Instruction.OpCode.Code
    switch ($Code) {
      'Assign' {
        $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
        if (-not $Destination) { return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'Indirect assignment' } }
        $Source = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $State
        if ($Source.Resolved) { $State[$Destination] = $Source.Value } else { $State.Remove($Destination) }
      }
      { $_ -in @('Add', 'Sub', 'Mul', 'Div', 'Mod', 'Shl', 'Shr', 'And', 'Or', 'Xor') } {
        $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
        $Right = Get-InnoPascalScriptOperandConstant -Operand $Instruction.Operands[1] -State $State
        if (-not $Destination -or -not $State.ContainsKey($Destination) -or -not $Right.Resolved) {
          return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'Nonconstant arithmetic' }
        }
        try {
          $LeftValue = $State[$Destination]
          $State[$Destination] = switch ($Code) {
            'Add' { $LeftValue -is [string] -or $Right.Value -is [string] ? ([string]$LeftValue + [string]$Right.Value) : ($LeftValue + $Right.Value) }
            'Sub' { $LeftValue - $Right.Value }
            'Mul' { $LeftValue * $Right.Value }
            'Div' { $LeftValue / $Right.Value }
            'Mod' { $LeftValue % $Right.Value }
            'Shl' { [long]$LeftValue -shl [int]$Right.Value }
            'Shr' { [long]$LeftValue -shr [int]$Right.Value }
            'And' { [long]$LeftValue -band [long]$Right.Value }
            'Or' { [long]$LeftValue -bor [long]$Right.Value }
            'Xor' { [long]$LeftValue -bxor [long]$Right.Value }
          }
        } catch {
          return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'Invalid constant arithmetic' }
        }
      }
      { $_ -in @('Neg', 'Not', 'Inc', 'Dec', 'SetZ') } {
        $Destination = Get-InnoPascalScriptVariableKey -Operand $Instruction.Operands[0]
        if (-not $Destination -or -not $State.ContainsKey($Destination)) {
          return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'Nonconstant unary operation' }
        }
        $State[$Destination] = switch ($Code) {
          'Neg' { - $State[$Destination] }
          'Not' { -bnot [long]$State[$Destination] }
          'Inc' { $State[$Destination] + 1 }
          'Dec' { $State[$Destination] - 1 }
          'SetZ' { -not [bool]$State[$Destination] }
        }
      }
      { $_ -in @('Push', 'PushVar', 'PushType', 'Pop', 'SetStackType', 'Nop', 'Ret') } { }
      default {
        return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = "Control flow or unsupported opcode: $Code" }
      }
    }
  }

  $ReturnKey = 'Argument:0'
  if (-not $State.ContainsKey($ReturnKey)) {
    return [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'Return variable is not constant' }
  }
  return [pscustomobject]@{ IsResolved = $true; Value = $State[$ReturnKey]; Reason = $null }
}

function Get-InnoPascalScriptEffectCategory {
  <#
  .SYNOPSIS
    Classify manifest-relevant Inno runtime calls without executing them.
  .PARAMETER Target
    IFPS function or host-call name.
  #>
  [OutputType([string])]
  param ([Parameter(Mandatory)][string]$Target)

  switch -Regex ($Target.ToUpperInvariant()) {
    '^REG(?:WRITE|DELETE|CREATE)' { return 'RegistryWrite' }
    '^REG(?:QUERY|KEYEXISTS|VALUEEXISTS)' { return 'RegistryRead' }
    '^(?:EXEC|SHELLEXEC|EXECASORIGINALUSER|SHELLEXECASORIGINALUSER)' { return 'ProcessLaunch' }
    '^(?:WIZARDSILENT|SUPPRESSIBLEMSGBOX|MSGBOX)' { return 'SilentInteraction' }
    '^(?:ISADMIN|ISADMININSTALLMODE|ISPOWERUSERLOGGEDON|GETPREVIOUSPRIVILEGES)' { return 'ScopeOrElevation' }
    '^(?:RESTARTREPLACE|FORCERESTART|NEEDSRESTART)' { return 'Restart' }
    '^(?:DOWNLOADTEMPORARYFILE|DOWNLOADTEMPORARYFILESIZE|ISSIGVERIFY)' { return 'NetworkOrSignature' }
    '^(?:DELAYDELETEFILE|DELETEFILE|DELTREE|RENAMEFILE|FILECOPY|FILESEARCH)' { return 'FileSystemWrite' }
    default { return $null }
  }
}

function Get-InnoPascalScriptConstantMap {
  <#
  .SYNOPSIS
    Map header {code:Function} constants to statically proven string returns.
  .DESCRIPTION
    Only functions whose complete straight-line body resolves to one constant
    return value are accepted. The map is limited to constants actually present
    in the supplied header strings, including parameterized constant spellings.
  .PARAMETER PascalScriptInfo
    Detailed result from ConvertTo-InnoPascalScriptInfo.
  .PARAMETER Values
    Serialized setup-header values that may contain Pascal Script constants.
  #>
  [OutputType([System.Collections.IDictionary])]
  param (
    [AllowNull()][pscustomobject]$PascalScriptInfo,
    [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Values
  )

  $Map = [ordered]@{}
  if ($null -eq $PascalScriptInfo -or
    $null -eq $PascalScriptInfo.PSObject.Properties['StaticReturnValues']) {
    return $Map
  }

  $Returns = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($Return in @($PascalScriptInfo.StaticReturnValues)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$Return.Function) -and $Return.Value -is [string]) {
      $Returns[[string]$Return.Function] = [string]$Return.Value
    }
  }
  if ($Returns.Count -eq 0) { return $Map }

  foreach ($Value in $Values) {
    if ([string]::IsNullOrEmpty($Value)) { continue }
    foreach ($Match in [regex]::Matches($Value, '\{code:(?<Function>[^|}]+)(?:\|[^}]*)?\}', 'IgnoreCase,CultureInvariant')) {
      $FunctionName = $Match.Groups['Function'].Value
      if ($Returns.ContainsKey($FunctionName)) {
        # Get-InnoStaticStringInfo expects map keys without the surrounding braces.
        $Map[$Match.Value.Substring(1, $Match.Value.Length - 2)] = $Returns[$FunctionName]
      }
    }
  }
  return $Map
}

function ConvertTo-InnoPascalScriptInfo {
  <#
  .SYNOPSIS
    Parse bounded IFPS bytecode into JSON-safe structural evidence.
  .PARAMETER Bytes
    Raw CompiledCodeText bytes. The caller retains ownership of the array.
  .PARAMETER IncludeDisassembly
    Include IFPSLib's textual instruction disassembly in the result.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from the optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  $Header = Read-InnoPascalScriptHeader -Bytes $Bytes
  if (-not $Header.Present) {
    return [pscustomobject][ordered]@{
      Present = $false; ByteLength = 0; FileVersion = $null; EntryPoint = $null
      TypeCount = 0; FunctionCount = 0; ScriptFunctionCount = 0; ExternalFunctionCount = 0
      GlobalVariableCount = 0; InstructionCount = 0; IndirectCallCount = 0
      UnknownOpcodeCount = 0; UsesExtendedType = $false
      ScriptFunctions = [string[]]@(); ExportedFunctions = [string[]]@()
      ExternalFunctions = [pscustomobject[]]@(); DllImports = [pscustomobject[]]@()
      Types = [pscustomobject[]]@(); GlobalVariables = [pscustomobject[]]@()
      Functions = [pscustomobject[]]@(); StringConstants = [string[]]@()
      RuntimeEffects = [pscustomobject[]]@(); StaticReturnValues = [pscustomobject[]]@()
      Disassembly = $null; DisassemblyTruncated = $false; Warnings = [string[]]@()
      Parser = 'IFPSTools.NET IFPSLib'; ParserVersion = $null
    }
  }
  Import-InnoPascalScriptDependency
  $PascalScript = [IFPSLib.Script]::Load($Bytes)
  $ScriptFunctions = [Collections.Generic.List[string]]::new()
  $ExportedFunctions = [Collections.Generic.List[string]]::new()
  $ExternalFunctions = [Collections.Generic.List[pscustomobject]]::new()
  $DllImports = [Collections.Generic.List[pscustomobject]]::new()
  $TypeDetails = [Collections.Generic.List[pscustomobject]]::new()
  $GlobalDetails = [Collections.Generic.List[pscustomobject]]::new()
  $FunctionDetails = [Collections.Generic.List[pscustomobject]]::new()
  $RuntimeEffects = [Collections.Generic.List[pscustomobject]]::new()
  $StaticReturnValues = [Collections.Generic.List[pscustomobject]]::new()
  $StringConstants = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $InstructionCount = 0
  $IndirectCallCount = 0
  $UnknownOpcodeCount = 0

  for ($TypeIndex = 0; $TypeIndex -lt $PascalScript.Types.Count; $TypeIndex++) {
    $Type = $PascalScript.Types[$TypeIndex]
    $TypeDetails.Add([pscustomobject][ordered]@{
        Index       = $TypeIndex
        Name        = [string]$Type.Name
        BaseType    = [string]$Type.BaseType
        Exported    = [bool]$Type.Exported
        Declaration = [string]$Type.ToString()
        Attributes  = [string[]]@($Type.Attributes | ForEach-Object { [string]$_.ToString() })
      })
  }
  for ($GlobalIndex = 0; $GlobalIndex -lt $PascalScript.GlobalVariables.Count; $GlobalIndex++) {
    $Global = $PascalScript.GlobalVariables[$GlobalIndex]
    $GlobalDetails.Add([pscustomobject][ordered]@{
        Index    = $GlobalIndex
        Name     = [string]$Global.Name
        Type     = $null -ne $Global.Type ? [string]$Global.Type.Name : $null
        Exported = [bool]$Global.Exported
      })
  }

  for ($FunctionIndex = 0; $FunctionIndex -lt $PascalScript.Functions.Count; $FunctionIndex++) {
    $Function = $PascalScript.Functions[$FunctionIndex]
    $FunctionType = $Function.GetType().FullName
    $FunctionKind = 'Unknown'
    $FunctionInstructionCount = 0
    $Calls = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $FunctionConstants = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $StaticReturnInfo = [pscustomobject]@{ IsResolved = $false; Value = $null; Reason = 'External function' }
    if ($FunctionType -ceq 'IFPSLib.Emit.ScriptFunction') {
      $FunctionKind = 'Script'
      $ScriptFunctions.Add([string]$Function.Name)
      $FunctionInstructionCount = $Function.Instructions.Count
      $InstructionCount += $FunctionInstructionCount
      $StaticReturnInfo = Get-InnoPascalScriptStaticReturnInfo -Function $Function
      if ($StaticReturnInfo.IsResolved) {
        $StaticReturnValues.Add([pscustomobject]@{ Function = [string]$Function.Name; Value = $StaticReturnInfo.Value })
      }

      foreach ($Instruction in $Function.Instructions) {
        $Code = [string]$Instruction.OpCode.Code
        if ($Code.StartsWith('UNKNOWN', [StringComparison]::Ordinal)) { $UnknownOpcodeCount++ }
        if ($Code -ceq 'CallVar') { $IndirectCallCount++ }
        if ($Code -ceq 'Call' -and $Instruction.Operands.Count -gt 0) {
          $Target = $Instruction.Operands[0].Immediate
          $TargetName = $null -ne $Target ? [string]$Target.Name : $null
          if (-not [string]::IsNullOrWhiteSpace($TargetName)) {
            $null = $Calls.Add($TargetName)
            $Category = Get-InnoPascalScriptEffectCategory -Target $TargetName
            if ($Category) {
              $RuntimeEffects.Add([pscustomobject][ordered]@{
                  Function = [string]$Function.Name
                  Offset   = [uint32]$Instruction.Offset
                  Target   = $TargetName
                  Category = $Category
                })
            }
          }
        }
        foreach ($Operand in $Instruction.Operands) {
          if ([string]$Operand.Type -ceq 'Immediate' -and $Operand.Immediate -is [string]) {
            $null = $FunctionConstants.Add([string]$Operand.Immediate)
            $null = $StringConstants.Add([string]$Operand.Immediate)
          }
        }
      }
    } elseif ($FunctionType -ceq 'IFPSLib.Emit.ExternalFunction') {
      $FunctionKind = 'External'
      $Declaration = $Function.Declaration
      $DeclarationType = $Declaration.GetType().FullName
      $Kind = switch ($DeclarationType) {
        'IFPSLib.Emit.FDecl.DLL' { 'DLL' }
        'IFPSLib.Emit.FDecl.Class' { 'Class' }
        'IFPSLib.Emit.FDecl.COM' { 'COM' }
        'IFPSLib.Emit.FDecl.Internal' { 'Internal' }
        default { 'Unknown' }
      }
      $External = [pscustomobject][ordered]@{
        Name                      = [string]$Function.Name
        Kind                      = $Kind
        Exported                  = [bool]$Function.Exported
        Declaration               = [string]$Declaration.ToString()
        DllName                   = $Kind -eq 'DLL' ? [string]$Declaration.DllName : $null
        ProcedureName             = $Kind -eq 'DLL' ? [string]$Declaration.ProcedureName : $null
        CallingConvention         = $Kind -in @('DLL', 'Class', 'COM') ? [string]$Declaration.CallingConvention : $null
        DelayLoad                 = $Kind -eq 'DLL' ? [bool]$Declaration.DelayLoad : $false
        LoadWithAlteredSearchPath = $Kind -eq 'DLL' ? [bool]$Declaration.LoadWithAlteredSearchPath : $false
        ClassName                 = $Kind -eq 'Class' ? [string]$Declaration.ClassName : $null
        MemberName                = $Kind -eq 'Class' ? [string]$Declaration.FunctionName : $null
        VTableIndex               = $Kind -eq 'COM' ? [uint32]$Declaration.VTableIndex : $null
      }
      $ExternalFunctions.Add($External)
      if ($Kind -eq 'DLL') { $DllImports.Add($External) }
    }
    if ($Function.Exported) { $ExportedFunctions.Add([string]$Function.Name) }

    $ArgumentDetails = [Collections.Generic.List[pscustomobject]]::new()
    if ($null -ne $Function.Arguments) {
      for ($ArgumentIndex = 0; $ArgumentIndex -lt $Function.Arguments.Count; $ArgumentIndex++) {
        $Argument = $Function.Arguments[$ArgumentIndex]
        $ArgumentDetails.Add([pscustomobject][ordered]@{
            Index     = $ArgumentIndex
            Name      = [string]$Argument.Name
            Direction = [string]$Argument.ArgumentType
            Type      = $null -ne $Argument.Type ? [string]$Argument.Type.Name : $null
          })
      }
    }
    $FunctionDetails.Add([pscustomobject][ordered]@{
        Index                = $FunctionIndex
        Name                 = [string]$Function.Name
        Kind                 = $FunctionKind
        Exported             = [bool]$Function.Exported
        ReturnType           = $null -ne $Function.ReturnArgument ? [string]$Function.ReturnArgument.Name : $null
        Arguments            = [pscustomobject[]]$ArgumentDetails.ToArray()
        Attributes           = [string[]]@($Function.Attributes | ForEach-Object { [string]$_.ToString() })
        InstructionCount     = $FunctionInstructionCount
        Calls                = [string[]]@($Calls)
        StringConstants      = [string[]]@($FunctionConstants)
        StaticReturnResolved = [bool]$StaticReturnInfo.IsResolved
        StaticReturnValue    = $StaticReturnInfo.Value
        StaticReturnReason   = [string]$StaticReturnInfo.Reason
      })
  }

  $UsesExtendedType = @($PascalScript.Types | Where-Object { [string]$_.BaseType -ceq 'Extended' }).Count -gt 0
  $Warnings = [Collections.Generic.List[string]]::new()
  if ($UsesExtendedType) {
    $Warnings.Add('The IFPS program uses Extended values. IFPSLib decodes them as x86 80-bit values; scripts compiled for a non-x86 runtime may use a 64-bit representation.')
  }
  if ($IndirectCallCount -gt 0) {
    $Warnings.Add("The IFPS program contains $IndirectCallCount indirect function call(s); their targets and side effects cannot be resolved statically.")
  }
  if ($UnknownOpcodeCount -gt 0) {
    $Warnings.Add("IFPSLib decoded $UnknownOpcodeCount unknown opcode(s); affected control flow remains unresolved.")
  }

  $Disassembly = $null
  $DisassemblyTruncated = $false
  if ($IncludeDisassembly) {
    if ($Bytes.Length -gt $INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE) {
      throw "Text disassembly is limited to IFPS inputs no larger than $INNO_MAX_PASCAL_SCRIPT_DISASSEMBLY_INPUT_SIZE bytes."
    }
    $Disassembly = $PascalScript.Disassemble()
    if ($Disassembly.Length -gt $MaximumDisassemblyCharacters) {
      $Disassembly = $Disassembly.Substring(0, $MaximumDisassemblyCharacters)
      $DisassemblyTruncated = $true
      $Warnings.Add("The IFPS disassembly was truncated at $MaximumDisassemblyCharacters characters.")
    }
  }

  return [pscustomobject][ordered]@{
    Present               = $true
    ByteLength            = $Bytes.Length
    FileVersion           = $PascalScript.FileVersion
    EntryPoint            = $null -ne $PascalScript.EntryPoint ? [string]$PascalScript.EntryPoint.Name : $null
    TypeCount             = $PascalScript.Types.Count
    FunctionCount         = $PascalScript.Functions.Count
    ScriptFunctionCount   = $ScriptFunctions.Count
    ExternalFunctionCount = $ExternalFunctions.Count
    GlobalVariableCount   = $PascalScript.GlobalVariables.Count
    InstructionCount      = $InstructionCount
    IndirectCallCount     = $IndirectCallCount
    UnknownOpcodeCount    = $UnknownOpcodeCount
    UsesExtendedType      = $UsesExtendedType
    ScriptFunctions       = [string[]]$ScriptFunctions.ToArray()
    ExportedFunctions     = [string[]]$ExportedFunctions.ToArray()
    ExternalFunctions     = [pscustomobject[]]$ExternalFunctions.ToArray()
    DllImports            = [pscustomobject[]]$DllImports.ToArray()
    Types                 = [pscustomobject[]]$TypeDetails.ToArray()
    GlobalVariables       = [pscustomobject[]]$GlobalDetails.ToArray()
    Functions             = [pscustomobject[]]$FunctionDetails.ToArray()
    StringConstants       = [string[]]@($StringConstants)
    RuntimeEffects        = [pscustomobject[]]$RuntimeEffects.ToArray()
    StaticReturnValues    = [pscustomobject[]]$StaticReturnValues.ToArray()
    Disassembly           = $Disassembly
    DisassemblyTruncated  = $DisassemblyTruncated
    Warnings              = [string[]]$Warnings.ToArray()
    Parser                = 'IFPSTools.NET IFPSLib'
    ParserVersion         = [IFPSLib.Script].Assembly.GetName().Version.ToString()
  }
}

function Get-InnoPascalScriptInfo {
  <#
  .SYNOPSIS
    Read and analyze the compiled Pascal Script embedded in an Inno installer.
  .PARAMETER Path
    Path to the Inno Setup installer. The installer is parsed but never executed.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from the optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  process {
    $Context = Get-InnoAnalysisContext -Path $Path
    ConvertTo-InnoPascalScriptInfo -Bytes $Context.ParsedLayout.CompiledCodeBytes -IncludeDisassembly:$IncludeDisassembly `
      -MaximumDisassemblyCharacters $MaximumDisassemblyCharacters
  }
}

function Get-InnoInfo {
  <#
  .SYNOPSIS
    Get static metadata from an Inno Setup installer
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER IncludePascalScriptAnalysis
    Decode functions, calls, constants, and bounded static-effect evidence in the same parse.
  .PARAMETER IncludeDisassembly
    Include bounded textual IFPS disassembly. This implies IncludePascalScriptAnalysis.
  .PARAMETER MaximumDisassemblyCharacters
    Maximum characters retained from optional disassembly.
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,
    [switch]$IncludePascalScriptAnalysis,
    [switch]$IncludeDisassembly,
    [ValidateRange(1024, 16777216)][int]$MaximumDisassemblyCharacters = $INNO_DEFAULT_MAX_DISASSEMBLY_CHARACTERS
  )

  process {
    $Context = Get-InnoAnalysisContext -Path $Path
    $InstallerPath = $Context.Path
    $OffsetTable = $Context.OffsetTable
    $SignatureInfo = $Context.SignatureInfo
    $Layout = $Context.Layout

    # The exact catalog row, not PE FileVersion, selects string counts, fixed
    # fields, metadata framing, payload layout, checksum, and call transform.
    $PEInfo = $Context.PEInfo
    $ParsedLayout = $Context.ParsedLayout
    $VersionNumber = $Layout.VersionNumber
    $HeaderBlockInfo = $ParsedLayout.HeaderBlockInfo
    $HeaderBytes = $HeaderBlockInfo.Bytes
    $HeaderValues = $ParsedLayout.HeaderValues
    $ExtractionHeader = $ParsedLayout.ExtractionHeader
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBytes -Layout $Layout
    $HeaderArchitectureData = Get-InnoHeaderArchitectureData -HeaderValues $HeaderValues -PEInfo $PEInfo -HeaderFixedData $HeaderFixedData -Layout $Layout
    $AppsAndFeaturesEntryInfo = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout -HeaderFixedData $HeaderFixedData
    $Warnings = [System.Collections.Generic.List[string]]::new()
    foreach ($Warning in $HeaderArchitectureData.Warnings) { $Warnings.Add($Warning) }
    $PascalScriptInfo = $null
    try {
      if ($IncludePascalScriptAnalysis -or $IncludeDisassembly) {
        $PascalScriptInfo = ConvertTo-InnoPascalScriptInfo -Bytes $ParsedLayout.CompiledCodeBytes `
          -IncludeDisassembly:$IncludeDisassembly -MaximumDisassemblyCharacters $MaximumDisassemblyCharacters
      } else {
        # Ordinary metadata parsing validates only the fixed IFPS header.
        $PascalScriptInfo = Read-InnoPascalScriptHeader -Bytes $ParsedLayout.CompiledCodeBytes
      }
    } catch {
      # Compiled code can be absent, vendor-modified, or from a future IFPS
      # generation. Preserve the setup-header evidence instead of making the
      # optional script analysis fatal to ordinary manifest parsing.
      $Warnings.Add("Compiled Pascal Script analysis failed: $($_.Exception.Message)")
    }
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      $Warnings.Add('The installer payload files are encrypted; static metadata is available, but extraction requires the setup password.')
    }
    if (-not $AppsAndFeaturesEntryInfo.IsResolved) {
      $Warnings.Add('CreateUninstallRegKey or Uninstallable is a dynamic expression, so Apps & Features registration cannot be determined statically.')
    }

    # The file table supplies an exact boundary for the icon, INI, registry,
    # delete, and run tables that follow it. Keep metadata useful when a
    # proprietary or malformed record variant cannot be consumed, but expose a
    # warning rather than returning guessed registry associations.
    $PostFileRecordInfo = [pscustomobject]@{
      IsResolved = $false; EndOffset = $null; Icons = @(); IniEntries = @(); RegistryEntries = @()
      InstallDeleteEntries = @(); UninstallDeleteEntries = @(); RunEntries = @(); UninstallRunEntries = @()
    }
    if ($ExtractionHeader.Counts.NumFileEntries -gt 0 -and $ExtractionHeader.Counts.NumFileLocationEntries -gt 0) {
      try {
        $FileEntries = @(Get-InnoFileEntries -Bytes $HeaderBytes -Layout $Layout -Count $ExtractionHeader.Counts.NumFileEntries `
            -FileLocationCount $ExtractionHeader.Counts.NumFileLocationEntries -SearchOffset $ExtractionHeader.SearchOffset)
        $PostFileRecordInfo = Get-InnoPostFileRecordInfo -Bytes $HeaderBytes -Layout $Layout -Counts $ExtractionHeader.Counts -FileEntries $FileEntries
      } catch {
        $Warnings.Add("The catalogued post-file metadata tables could not be parsed: $($_.Exception.Message)")
      }
    } elseif (
      $ExtractionHeader.Counts.NumIconEntries -gt 0 -or $ExtractionHeader.Counts.NumIniEntries -gt 0 -or
      $ExtractionHeader.Counts.NumRegistryEntries -gt 0 -or $ExtractionHeader.Counts.NumInstallDeleteEntries -gt 0 -or
      $ExtractionHeader.Counts.NumUninstallDeleteEntries -gt 0 -or $ExtractionHeader.Counts.NumRunEntries -gt 0 -or
      $ExtractionHeader.Counts.NumUninstallRunEntries -gt 0
    ) {
      $Warnings.Add('Post-file metadata records exist without an anchorable embedded file table; registry and association evidence requires manual validation.')
    }
    $AssociationInfo = Get-InnoRegistryAssociationInfo -RegistryEntries ([pscustomobject[]]@($PostFileRecordInfo.RegistryEntries))
    if (@($PostFileRecordInfo.RegistryEntries | Where-Object Conditional).Count -gt 0) {
      $Warnings.Add('One or more Inno registry entries are conditional on components, tasks, languages, or Pascal expressions; emitted registry evidence may not apply to every installation path.')
    }

    $HeaderFields = $Layout.HeaderFields
    $PascalScriptConstantMap = Get-InnoPascalScriptConstantMap -PascalScriptInfo $PascalScriptInfo -Values $HeaderValues
    $AppNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppName] -ConstantMap $PascalScriptConstantMap
    $AppVerNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppVerName] -ConstantMap $PascalScriptConstantMap
    $RawAppId = $HeaderValues[$HeaderFields.AppId]
    $AppIdInfo = Get-InnoStaticStringInfo -Value $RawAppId -ConstantMap $PascalScriptConstantMap
    $AppPublisherInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.Publisher] -ConstantMap $PascalScriptConstantMap
    $AppVersionInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.AppVersion] -ConstantMap $PascalScriptConstantMap
    $DefaultDirName = $HeaderValues[$HeaderFields.DefaultDirName]
    $UninstallDisplayNameInfo = Get-InnoStaticStringInfo -Value $HeaderValues[$HeaderFields.UninstallDisplayName] -ConstantMap $PascalScriptConstantMap

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
    foreach ($Constant in $PascalScriptConstantMap.GetEnumerator()) {
      $DefaultDirectoryConstantMap[$Constant.Key] = $Constant.Value
    }
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

    $DisplayNameInfo = if (-not [string]::IsNullOrWhiteSpace($HeaderValues[$HeaderFields.UninstallDisplayName])) {
      $UninstallDisplayNameInfo
    } elseif (-not [string]::IsNullOrWhiteSpace($HeaderValues[$HeaderFields.AppVerName])) {
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

    # Preserve unresolved Pascal constants as diagnostics while emitting only
    # values proven by the decoded setup header in the canonical envelope.
    return [pscustomobject][ordered]@{
      Path                                     = $InstallerPath
      InstallerType                            = 'Inno'
      ProductCode                              = $ProductCode
      UpgradeCode                              = $null
      DisplayName                              = $DisplayName
      DisplayVersion                           = $AppVersionInfo.Value
      Publisher                                = $AppPublisherInfo.Value
      Scope                                    = $Scope
      DefaultInstallLocation                   = $ResolvedDefaultDirName
      WritesAppsAndFeaturesEntry               = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry
      AppsAndFeaturesProductCode               = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true ? $ProductCode : $null
      AppsAndFeaturesInstallerType             = $AppsAndFeaturesEntryInfo.WritesAppsAndFeaturesEntry -eq $true ? 'inno' : $null
      Warnings                                 = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      UnresolvedFields                         = [string[]]@($UnresolvedFields | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
      RegistryWrites                           = [pscustomobject[]]@($PostFileRecordInfo.RegistryEntries)
      FileExtensions                           = [string[]]@($AssociationInfo.FileExtensions)
      Protocols                                = [string[]]@($AssociationInfo.Protocols)
      MetadataTablesResolved                   = $PostFileRecordInfo.IsResolved
      MetadataRecordCounts                     = [pscustomobject]@{
        Icons           = @($PostFileRecordInfo.Icons).Count
        Ini             = @($PostFileRecordInfo.IniEntries).Count
        Registry        = @($PostFileRecordInfo.RegistryEntries).Count
        InstallDelete   = @($PostFileRecordInfo.InstallDeleteEntries).Count
        UninstallDelete = @($PostFileRecordInfo.UninstallDeleteEntries).Count
        Run             = @($PostFileRecordInfo.RunEntries).Count
        UninstallRun    = @($PostFileRecordInfo.UninstallRunEntries).Count
      }
      UninstallRegKeyBaseName                  = $UninstallRegKeyBaseName
      DefaultScope                             = $DefaultScope
      SupportedScopes                          = $SupportedScopes
      SupportsDualScope                        = $SupportedScopes.Count -gt 1
      PrivilegesRequired                       = $HeaderFixedData.PrivilegesRequired
      PrivilegesRequiredOverridesAllowed       = $HeaderFixedData.PrivilegesRequiredOverridesAllowed
      SupportsCommandLineScopeOverride         = $HeaderFixedData.SupportsCommandLineScopeOverride
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
      ResolvedPascalCodeConstants              = [pscustomobject]$PascalScriptConstantMap
      UnresolvedConstants                      = [pscustomobject]$UnresolvedConstants
      Signature                                = $SignatureInfo.Signature
      VersionNumber                            = $VersionNumber
      EditionId                                = $Layout.EditionId
      Edition                                  = $Layout.Edition
      CharacterMode                            = $Layout.CharacterMode
      EncryptionUse                            = $HeaderBlockInfo.EncryptionHeader.EncryptionUse
      IsHeaderEncrypted                        = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Full'
      FilesEncrypted                           = $HeaderBlockInfo.EncryptionHeader.EncryptionUse -in @('Files', 'Full')
      CompressMethod                           = $HeaderFixedData.CompressMethod
      PascalScriptInfo                         = $PascalScriptInfo
      UsesExternalDiskSlices                   = $OffsetTable.Offset1 -eq 0
      SlicesPerDisk                            = $HeaderFixedData.SlicesPerDisk
      ParserVersionInfo                        = [pscustomobject]@{
        CatalogVersion                = $Script:InnoFormatCatalog.CatalogVersion
        CatalogFormatId               = $Layout.Id
        SignatureVersion              = $SignatureInfo.VersionText
        InternalStructureVersion      = $Layout.InternalStructureVersion
        EditionId                     = $Layout.EditionId
        Edition                       = $Layout.Edition
        CharacterMode                 = $Layout.CharacterMode
        LayoutResolution              = $Layout.LayoutResolution
        CandidateFormatIds            = [string[]]@($Layout.CandidateIds)
        LoaderRoute                   = $Layout.LoaderRoute
        MetadataRoute                 = $Layout.MetadataRoute
        RecordSchemaRoute             = $Layout.RecordSchemaRoute
        PayloadRoute                  = $Layout.PayloadRoute
        ChecksumRoute                 = $Layout.ChecksumRoute
        CallTransformRoute            = $Layout.CallTransformRoute
        HeaderStringCount             = $Layout.HeaderStringCount
        HeaderAnsiStringCount         = $Layout.HeaderAnsiStringCount
        EntryCounts                   = $ExtractionHeader.Counts
        FileEntryStringCount          = $Layout.FileEntryStringCount
        FileEntryAnsiStringCount      = $Layout.FileEntryAnsiStringCount
        FileLocationEntrySize         = $Layout.FileLocationEntrySize
        FileLocationDigestAlgorithm   = $Layout.FileLocationDigestAlgorithm
        FileLocationStartOffsetSize   = $Layout.FileLocationStartOffsetSize
        FixedHeaderArchitectureFormat = $Layout.ArchitecturesEncoding
        UsesInt64BlockHeader          = $Layout.UsesInt64BlockHeader
        UsesLegacyCallTransform       = $Layout.UsesLegacyCallInstructionTransform
        OffsetTableVersion            = $OffsetTable.Version
        PascalScriptByteLength        = $ParsedLayout.CompiledCodeBytes.Length
        PascalScriptVersion           = $null -ne $PascalScriptInfo ? $PascalScriptInfo.FileVersion : $null
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
    if ($FirstSegment -match '^\.[A-Za-z0-9][A-Za-z0-9+_-]*$') { $null = $Extensions.Add($FirstSegment.TrimStart('.').ToLowerInvariant()) }
    if ($Entry.ValueName -ieq 'URL Protocol' -and $FirstSegment -match '^[A-Za-z][A-Za-z0-9+.-]*$') { $null = $Protocols.Add($FirstSegment.ToLowerInvariant()) }
  }
  return [pscustomobject]@{
    FileExtensions = [string[]]@($Extensions | Sort-Object)
    Protocols      = [string[]]@($Protocols | Sort-Object)
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
    Extract selected files from an unencrypted Inno Setup installer without executing it
  .PARAMETER Path
    The path to the Inno Setup installer
  .PARAMETER DestinationPath
    The directory where matching files should be written
  .PARAMETER Name
    Optional wildcard matched against source, destination, and base file names. All embedded files are selected when omitted.
  .PARAMETER Language
    An optional Inno Setup language name used to disambiguate language-specific payloads
  .PARAMETER CollisionAction
    Behavior when an output path already exists or multiple file entries resolve to the same path.
  .PARAMETER MaximumExpandedBytes
    Maximum aggregate bytes written, including aliases that share one payload location.
  .PARAMETER DiskSourcePath
    Optional directories or explicit setup-*.bin files used for external multi-disk media. The setup executable directory is searched automatically.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the Inno Setup installer')]
    [string]$Path,

    [Parameter(HelpMessage = 'The directory where matching files should be written')]
    [string]$DestinationPath,

    [Parameter(HelpMessage = 'The source, destination, or base file wildcard to extract')]
    [string]$Name = '*',

    [Parameter(HelpMessage = 'An optional Inno Setup language name used to disambiguate language-specific payloads')]
    [string]$Language,

    [ValidateSet('Prompt', 'Error', 'Skip', 'Overwrite', 'Rename')]
    [string]$CollisionAction = 'Prompt',

    [ValidateRange(1, [long]::MaxValue)]
    [long]$MaximumExpandedBytes = 17179869184,

    [Parameter(HelpMessage = 'Directories or explicit files containing external Inno Setup disk slices')]
    [string[]]$DiskSourcePath
  )

  process {
    $InstallerPath = Resolve-InstallerFileSystemPath -Path $Path -PathType Leaf
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $InstallerPath -Parent
    }
    $DestinationPath = Resolve-InstallerFileSystemPath -Path $DestinationPath -AllowNonexistent
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    $OffsetTable = Get-InnoOffsetTable -Path $InstallerPath

    $SignatureInfo = Get-InnoSignatureInfo -Path $InstallerPath -OffsetTable $OffsetTable
    $Layout = Get-InnoLayout -SignatureInfo $SignatureInfo -LoaderRoute $OffsetTable.LoaderRoute
    if ($Layout.SupportStatus -ne 'Supported') {
      throw "The Inno edition '$($Layout.Edition)' is identified but its record layout is not supported"
    }

    # Parse the first metadata block once to obtain counts, compression method,
    # encryption state, and the exact versioned file-entry layout.
    $ParsedLayout = Resolve-InnoParsedLayout -Path $InstallerPath -OffsetTable $OffsetTable -Layout $Layout
    $Layout = $ParsedLayout.Layout
    $HeaderBlockInfo = $ParsedLayout.HeaderBlockInfo
    if ($HeaderBlockInfo.EncryptionHeader.EncryptionUse -eq 'Files') {
      throw 'The Inno Setup payload files are encrypted and require the setup password'
    }
    $Header = $ParsedLayout.ExtractionHeader
    $HeaderFixedData = Read-InnoHeaderFixedData -Bytes $HeaderBlockInfo.Bytes -Layout $Layout
    if ($Header.Counts.NumFileLocationEntries -le 0) { throw 'The Inno Setup installer does not contain embedded file locations' }
    if ($Layout.InternalStructureVersion -lt 5303 -and $Name.IndexOfAny([char[]]'*?[') -lt 0) {
      # Exact selection can use the serialized path as a bounded index and
      # validate the complete surrounding record. This avoids traversing every
      # unrelated historical table when the caller requests one known payload.
      $FileEntries = @(
        Find-InnoFileEntry -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Name $Name `
          -FileLocationCount $Header.Counts.NumFileLocationEntries -SearchOffset $Header.SearchOffset -Language $Language
      )
    } else {
      $FileEntries = @(Get-InnoFileEntries -Bytes $HeaderBlockInfo.Bytes -Layout $Layout -Count $Header.Counts.NumFileEntries `
          -FileLocationCount $Header.Counts.NumFileLocationEntries -SearchOffset $Header.SearchOffset)
    }
    $SelectedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($Entry in $FileEntries) {
      if ($Entry.LocationEntry -lt 0) { continue }
      # Compiler-generated entries, including the uninstaller payload, can
      # omit SourceFilename. Only match populated fields so the shared pattern
      # helper never receives an invalid empty path.
      $MatchesName = -not [string]::IsNullOrWhiteSpace($Entry.SourceFilename) -and
      (Test-ExtractionPattern -Path $Entry.SourceFilename -Pattern $Name)
      if (-not $MatchesName -and -not [string]::IsNullOrWhiteSpace($Entry.DestName)) {
        $MatchesName = Test-ExtractionPattern -Path $Entry.DestName -Pattern $Name
      }
      if (-not $MatchesName) { continue }
      if (-not [string]::IsNullOrWhiteSpace($Language) -and -not [string]::IsNullOrWhiteSpace($Entry.Languages)) {
        $LanguageMatch = @($Entry.Languages -split '[,\s]+' | Where-Object { $_ -ieq $Language }).Count -gt 0
        if (-not $LanguageMatch) { continue }
      }
      $SelectedEntries.Add($Entry)
    }
    if ($SelectedEntries.Count -eq 0) { throw "No Inno Setup file entry matched: $Name" }

    $FileStream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($FileStream)
    try {
      $LocationBlockInfo = Read-InnoMetadataBlock -Reader $Reader -Offset $HeaderBlockInfo.NextOffset -Layout $Layout
    } finally {
      $Reader.Close()
      $FileStream.Close()
    }

    $ReservedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $LocationOutput = [Collections.Generic.Dictionary[int, string]]::new()
    $LocationCache = [Collections.Generic.Dictionary[int, object]]::new()
    $Files = [Collections.Generic.List[IO.FileInfo]]::new()
    $ExpandedBytes = 0L
    foreach ($Entry in $SelectedEntries) {
      # DestName is an explicit installed path override. Otherwise the compiled
      # SourceFilename contains the destination beneath an Inno constant such
      # as {app}; remove that virtual root but preserve its subdirectories.
      $RelativePath = if ([string]::IsNullOrWhiteSpace($Entry.DestName)) {
        $Entry.SourceFilename
      } else {
        $Entry.DestName
      }
      if ($RelativePath -match '^\{[^}]+\}[\\/](.+)$') {
        $RelativePath = $Matches[1]
      }
      if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "The Inno Setup file entry at offset $($Entry.RecordOffset) has no extractable path"
      }
      $Target = Resolve-InstallerExtractionTarget -DestinationPath $DestinationPath -RelativePath $RelativePath `
        -CollisionAction $CollisionAction -ReservedPath $ReservedPaths
      if (-not $Target.ShouldWrite) { continue }

      $Location = $null
      if (-not $LocationCache.TryGetValue($Entry.LocationEntry, [ref]$Location)) {
        $Location = Read-InnoFileLocation -Bytes $LocationBlockInfo.Bytes -Count $Header.Counts.NumFileLocationEntries `
          -Index $Entry.LocationEntry -Layout $Layout
        $LocationCache[$Entry.LocationEntry] = $Location
      }
      if ($Location.OriginalSize -gt $MaximumExpandedBytes - $ExpandedBytes) {
        throw "The selected Inno Setup payloads exceed the $MaximumExpandedBytes-byte limit"
      }

      $ExistingPath = $null
      if ($LocationOutput.TryGetValue($Entry.LocationEntry, [ref]$ExistingPath)) {
        # Several [Files] entries may install the same physical location under
        # aliases. Reuse the authenticated first output instead of decoding the
        # same solid chunk from its beginning for every alias.
        $Source = [IO.File]::Open($ExistingPath, 'Open', 'Read', 'Read')
        $Parent = [IO.Path]::GetDirectoryName($Target.Path)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        $Destination = [IO.File]::Open($Target.Path, 'Create', 'Write', 'None')
        try {
          $null = Copy-BoundedStream -Source $Source -Destination $Destination -MaximumBytes $Location.OriginalSize -ExpectedBytes $Location.OriginalSize
        } finally {
          $Destination.Dispose()
          $Source.Dispose()
        }
        $File = Get-Item -LiteralPath $Target.Path -Force
      } else {
        $CompressionMethod = if ([string]::IsNullOrWhiteSpace($HeaderFixedData.CompressMethod)) {
          Get-InnoPayloadCompressionMethod -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location -Layout $Layout `
            -SlicesPerDisk $HeaderFixedData.SlicesPerDisk -DiskSourcePath $DiskSourcePath
        } else { $HeaderFixedData.CompressMethod }
        $File = Write-InnoFilePayload -Path $InstallerPath -Offset1 $OffsetTable.Offset1 -Location $Location `
          -CompressionMethod $CompressionMethod -OutputPath $Target.Path -PayloadRoute $Layout.PayloadRoute `
          -CallTransformRoute $Layout.CallTransformRoute -InternalStructureVersion $Layout.InternalStructureVersion `
          -SlicesPerDisk $HeaderFixedData.SlicesPerDisk -DiskSourcePath $DiskSourcePath
        $LocationOutput[$Entry.LocationEntry] = $File.FullName
      }
      $ExpandedBytes += $File.Length
      $Files.Add($File)
    }
    return $Files.ToArray()
  }
}

Export-ModuleMember -Function Get-InnoFormatInfo, Get-InnoInfo, Get-InnoPascalScriptInfo, Read-ProductVersionFromInno, Read-ProductNameFromInno, Read-PublisherFromInno, Read-ProductCodeFromInno, Read-UnsupportedArchitecturesFromInno, Test-InnoUnsupportedArchitecture, Test-InnoAppsAndFeaturesEntry, Expand-InnoInstaller
