# SPDX-License-Identifier: GPL-3.0-or-later
# Format sources: https://github.com/CybercentreCanada/sfextract, https://github.com/Puyodead1/SFUnpacker, https://codeberg.org/CYBERDEV/defactory, and https://github.com/madler/zlib
# Setup Factory 7-9 static parser. Format details are derived from sfextract
# (MIT) and SFUnpacker (LGPL-3.0-or-later); see THIRD-PARTY-NOTICES.md.
#
# Binary structure consumed by this parser (overlay-relative, LE integers):
#
#   PE overlay
#   +-- v7: E0 E1 E2 E3 E4 E5 E6 E7
#   |   runtime-size:u32, 260-byte names, packed-size:u32
#   `-- v8/9: E0 E0 E1 E1 ... E7 E7
#       runtime-size:i64, optional Lua range, 264-byte names, packed-size:i64
#       -> repeated [name][packed size][CRC32][padding?][compressed bytes]
#
# Only the first 2,000 irsetup.exe bytes are XORed with 07. File records use the
# supported bounded compression framing. irsetup.dat supplies structured
# session variables, uninstall settings, and literal Lua registry evidence.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactory7Signature = [byte[]](0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7)
$Script:SetupFactory89Signature = [byte[]](0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7)
$Script:SetupFactoryMaximumEntries = 100000
$Script:SetupFactoryMaximumFileBytes = 1073741824
$Script:SetupFactoryMaximumExpandedBytes = 17179869184

function Read-SetupFactoryExactBytes {
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
  [BitConverter]::ToUInt32((Read-SetupFactoryExactBytes -Stream $Stream -Count 4), 0)
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
  [BitConverter]::ToInt64((Read-SetupFactoryExactBytes -Stream $Stream -Count 8), 0)
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

function Expand-SetupFactoryCompressedBytes {
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
        $DecoderSource = Join-Path $PSScriptRoot '..\Assets\PkwareBlast.cs'
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

function Get-SetupFactorySessionVariables {
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
        $Name = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor, $NameLength)
        $Cursor += $NameLength
        $ValueLength = $Bytes[$Cursor++]
        if ($Cursor + $ValueLength + 6 -gt $Bytes.Length) { throw 'invalid value' }
        $Value = [Text.Encoding]::UTF8.GetString($Bytes, $Cursor, $ValueLength)
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
    $Replacement = Resolve-SetupFactoryVariable -Value ([string]$Variables[$Name]) -Variables $Variables -Depth ($Depth + 1) -Stack ($Stack + $Name)
    if ($null -eq $Replacement) { return $null }
    $Result = $Result.Replace($Name, $Replacement)
  }
  return $Result
}

function Get-SetupFactoryLiteralRegistryWrites {
  <#
  .SYNOPSIS
    Recover literal Lua Registry.SetValue calls from irsetup.dat.
  .PARAMETER Bytes
    Complete irsetup.dat bytes decoded as UTF-8 for literal action parsing. Conditional or computed calls are not returned.
  #>
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  # Only literal Registry.SetValue arguments are deterministic. Computed Lua expressions and
  # conditional effects remain outside static registry evidence.
  $Text = [Text.Encoding]::UTF8.GetString($Bytes)
  foreach ($Match in [regex]::Matches($Text, '(?im)Registry\.SetValue\s*\(\s*"(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER)"\s*,\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"')) {
    [pscustomobject]@{
      Root  = $Match.Groups[1].Value
      Key   = $Match.Groups[2].Value
      Name  = $Match.Groups[3].Value
      Value = $Match.Groups[4].Value
      Type  = 'REG_SZ'
    }
  }
}

function Get-SetupFactoryOverlayInfo {
  <#
  .SYNOPSIS
    Locate the PE overlay and classify its Setup Factory 7, 8, or 9 signature.
  .PARAMETER Path
    Path to the installer PE. The returned Offset and Length are absolute file byte ranges.
  #>
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
  try {
    # Setup Factory stores its generation signature at the PE overlay boundary. Restrict probing to
    # that boundary so similar bytes in PE resources or payload data cannot classify the file.
    $OverlayOffset = Get-PEOverlayOffset -Stream $Stream
    $Stream.Position = $OverlayOffset
    $Probe = Read-SetupFactoryExactBytes -Stream $Stream -Count ([Math]::Min(32, [int]($Stream.Length - $OverlayOffset)))
    $ProbeHex = [BitConverter]::ToString($Probe)
    $Version = if ($Probe.Length -ge 16 -and $ProbeHex.StartsWith([BitConverter]::ToString($Script:SetupFactory89Signature), [StringComparison]::Ordinal)) {
      if ($File.VersionInfo.FileMajorPart -eq 8) { 8 } else { 9 }
    } elseif ($Probe.Length -ge 8 -and $ProbeHex.StartsWith([BitConverter]::ToString($Script:SetupFactory7Signature), [StringComparison]::Ordinal)) { 7 }
    else { 0 }
    [pscustomobject]@{ Version = $Version; Offset = $OverlayOffset; Length = $Stream.Length - $OverlayOffset }
  } finally {
    $Stream.Dispose()
  }
}

function Expand-SetupFactoryInstaller {
  <#
  .SYNOPSIS
    Expand a Setup Factory 7-9 installer without executing it
  .PARAMETER Path
    Path to the installer or format artifact read by this function.
  .PARAMETER DestinationPath
    Destination path for bounded extraction or decoded output; payload-relative names are resolved beneath this path.
  .PARAMETER Name
    Exact name or wildcard used to select format records or payload entries.
  .PARAMETER MaximumExpandedBytes
    Maximum permitted input or expanded output in bytes; exceeding this bound rejects the installer.
  #>
  [OutputType([System.IO.FileInfo[]])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory)][string]$Path,
    [string]$DestinationPath,
    [string]$Name = '*',
    [ValidateRange(1, [long]::MaxValue)][long]$MaximumExpandedBytes = $Script:SetupFactoryMaximumExpandedBytes
  )
  process {
    $File = Get-Item -LiteralPath $Path -Force
    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-SetupFactory-' + [guid]::NewGuid().ToString('N'))
    }
    $null = New-Item -ItemType Directory -Path $DestinationPath -Force
    $Overlay = Get-SetupFactoryOverlayInfo -Path $File.FullName
    if ($Overlay.Version -eq 0) { throw 'The file is not a recognized Setup Factory 7-9 installer' }

    # One sequential pass follows the on-disk record order and skips unselected payload bytes
    # without allocating them.
    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Written = 0L
    try {
      $Stream.Position = $Overlay.Offset
      # Version 7 uses a shorter prefix and 32-bit runtime size; versions 8/9 use the later prefix
      # and signed 64-bit size.
      if ($Overlay.Version -eq 7) {
        $Stream.Position += 9
        $SpecialSize = Read-SetupFactoryUInt32 -Stream $Stream
      } else {
        $Stream.Position += 26
        $SpecialSize = Read-SetupFactoryInt64 -Stream $Stream
      }
      if ($SpecialSize -lt 0 -or $SpecialSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The embedded Setup Factory runtime size is invalid' }
      if ($SpecialSize -gt $Stream.Length - $Stream.Position) { throw 'The embedded Setup Factory runtime is truncated' }
      if (Test-ExtractionPattern -Path 'irsetup.exe' -Pattern $Name) {
        # The builder XORs only the first 2000 runtime bytes with 7; the remainder is stored as-is.
        $Runtime = Read-SetupFactoryExactBytes -Stream $Stream -Count ([int]$SpecialSize)
        for ($Index = 0; $Index -lt [Math]::Min(2000, $Runtime.Length); $Index++) { $Runtime[$Index] = $Runtime[$Index] -bxor 7 }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath 'irsetup.exe'
        [IO.File]::WriteAllBytes($OutputPath, $Runtime)
        $Written += $Runtime.Length
        Get-Item -LiteralPath $OutputPath
      } else {
        $Stream.Position += $SpecialSize
      }

      $Count = Read-SetupFactoryUInt32 -Stream $Stream
      if ($Overlay.Version -ne 7 -and $Count -gt 1000) {
        # In later layouts this implausible entry count is the low half of an optional Lua-runtime
        # size. Rewind and consume that optional record before reading the real file count.
        $Stream.Position -= 4
        $LuaSize = Read-SetupFactoryInt64 -Stream $Stream
        if ($LuaSize -lt 0 -or $LuaSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The embedded Lua runtime size is invalid' }
        if ($LuaSize -gt $Stream.Length - $Stream.Position) { throw 'The embedded Lua runtime is truncated' }
        if (Test-ExtractionPattern -Path 'lua5.1.dll' -Pattern $Name) {
          $Lua = Read-SetupFactoryExactBytes -Stream $Stream -Count ([int]$LuaSize)
          $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath 'lua5.1.dll'
          [IO.File]::WriteAllBytes($OutputPath, $Lua)
          $Written += $Lua.Length
          Get-Item -LiteralPath $OutputPath
        } else {
          $Stream.Position += $LuaSize
        }
        $Count = Read-SetupFactoryUInt32 -Stream $Stream
      }
      if ($Count -gt $Script:SetupFactoryMaximumEntries) { throw 'The Setup Factory entry count exceeds the configured limit' }

      # File records differ only in fixed name width, size width, and later-version padding.
      for ($EntryIndex = 0; $EntryIndex -lt $Count; $EntryIndex++) {
        $NameSize = if ($Overlay.Version -eq 7) { 260 } else { 264 }
        $EntryName = [Text.Encoding]::UTF8.GetString((Read-SetupFactoryExactBytes -Stream $Stream -Count $NameSize)).Split("`0", 2)[0]
        $PackedSize = if ($Overlay.Version -eq 7) { [long](Read-SetupFactoryUInt32 -Stream $Stream) } else { Read-SetupFactoryInt64 -Stream $Stream }
        $ExpectedCrc = Read-SetupFactoryUInt32 -Stream $Stream
        if ($Overlay.Version -ne 7) { $Stream.Position += 4 }
        if ($PackedSize -lt 0 -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'A Setup Factory entry size is invalid' }
        if ($PackedSize -gt $Stream.Length - $Stream.Position) { throw "The Setup Factory entry '$EntryName' is truncated" }
        if (-not (Test-ExtractionPattern -Path $EntryName -Pattern $Name)) {
          # Keep the stream sequential while avoiding decompression work for unselected records.
          $Stream.Position += $PackedSize
          continue
        }
        # Decode within both the per-file and operation-wide limits, then authenticate the expanded
        # bytes before exposing them at a traversal-safe destination.
        $Packed = Read-SetupFactoryExactBytes -Stream $Stream -Count ([int]$PackedSize)
        $Expanded = Expand-SetupFactoryCompressedBytes -Bytes $Packed -MaximumBytes ([Math]::Min($MaximumExpandedBytes - $Written, $Script:SetupFactoryMaximumFileBytes))
        if ($ExpectedCrc -ne 0 -and (Get-SetupFactoryCrc32 -Bytes $Expanded) -ne $ExpectedCrc) { throw "The Setup Factory entry '$EntryName' failed its CRC check" }
        $Written += $Expanded.Length
        if ($Written -gt $MaximumExpandedBytes) { throw 'The Setup Factory expansion exceeds the configured limit' }
        $OutputPath = Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $EntryName
        $Parent = [IO.Path]::GetDirectoryName($OutputPath)
        if ($Parent) { $null = New-Item -Path $Parent -ItemType Directory -Force }
        [IO.File]::WriteAllBytes($OutputPath, $Expanded)
        Get-Item -LiteralPath $OutputPath
      }
    } finally {
      $Stream.Dispose()
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
    $File = Get-Item -LiteralPath $Path -Force
    $Overlay = Get-SetupFactoryOverlayInfo -Path $File.FullName
    if ($Overlay.Version -eq 0) { throw 'The file is not a recognized Setup Factory 7-9 installer' }
    $Temporary = Join-Path ([IO.Path]::GetTempPath()) ('Dumplings-SetupFactory-Info-' + [guid]::NewGuid().ToString('N'))
    $Warnings = [Collections.Generic.List[string]]::new()
    try {
      # irsetup.dat owns session variables and scripted actions, so extract only that record rather
      # than expanding every application payload.
      $Extracted = @(Expand-SetupFactoryInstaller -Path $File.FullName -DestinationPath $Temporary -Name 'irsetup.dat')
      $ScriptPath = Join-Path $Temporary 'irsetup.dat'
      if (-not (Test-Path -LiteralPath $ScriptPath)) { throw 'The Setup Factory installer does not contain irsetup.dat' }
      $ScriptFile = Get-Item -LiteralPath $ScriptPath -Force
      if ($ScriptFile.Length -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The Setup Factory script exceeds the configured read limit.' }
      $ScriptStream = [IO.File]::OpenRead($ScriptFile.FullName)
      try { $Bytes = Read-BinaryBytes -Stream $ScriptStream -Offset 0 -Count ([int]$ScriptFile.Length) }
      finally { $ScriptStream.Dispose() }
      # Resolve known product variables from the structured table; do not probe arbitrary strings
      # for version-like candidates.
      $Variables = Get-SetupFactorySessionVariables -Bytes $Bytes
      $Resolve = { param($Name) if ($Variables.ContainsKey($Name)) { Resolve-SetupFactoryVariable -Value ([string]$Variables[$Name]) -Variables $Variables } }
      $DisplayName = & $Resolve '%ProductName%'
      $DisplayVersion = & $Resolve '%ProductVer%'
      $Publisher = & $Resolve '%CompanyName%'
      $InstallLocation = & $Resolve '%AppFolder%'
      # Custom literal registry writes can supersede built-in uninstall behavior and also provide
      # protocol/file-association evidence.
      $RegistryWrites = @(Get-SetupFactoryLiteralRegistryWrites -Bytes $Bytes)
      $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites

      $ProductExpression = '%ProductName%%ProductVer%'
      $ExpressionBytes = [Text.Encoding]::UTF8.GetBytes($ProductExpression)
      # The built-in uninstaller composes its ARP key from ProductName and ProductVer. Require that
      # exact expression before returning the resolved ProductCode.
      $HasBuiltInUninstall = @(Find-BinaryPattern -Bytes $Bytes -Pattern $ExpressionBytes -Maximum 1).Count -gt 0
      $ProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $ProductExpression -Variables $Variables }
      $RegistryRoots = @($RegistryWrites | ForEach-Object { $_.Root })
      # Explicit registry roots outrank the installation-directory heuristic when deciding scope.
      $Scope = if ($RegistryRoots -match 'HKCU|HKEY_CURRENT_USER') { 'user' }
      elseif ($RegistryRoots -match 'HKLM|HKEY_LOCAL_MACHINE' -or $InstallLocation -match '^(?:%ProgramFiles|[A-Za-z]:\\Program Files(?: \(x86\))?\\)') { 'machine' }
      else { $null }
      if (-not $Variables.Count) { $Warnings.Add('CSessionVar records were not found or were malformed') }
      if (-not $HasBuiltInUninstall -and -not $RegistryWrites.Count) { $Warnings.Add('No explicit built-in uninstall configuration or literal registry writes were found') }
      foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $Warnings.Add($Warning) }

      $WritesAppsAndFeaturesEntry = [bool]($HasBuiltInUninstall -or $RegistryWrites.Count)

      # Construct the shared result from Setup Factory evidence directly. In
      # particular, only built-in uninstall configuration or literal registry
      # writes prove that the outer installer owns an ARP entry.
      [pscustomobject][ordered]@{
        Path                         = $File.FullName
        InstallerType                = 'setupfactory'
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
        Warnings                     = [string[]]@($Warnings | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
        UnresolvedFields             = [string[]]@()
        RegistryWrites               = $RegistryWrites
        RegistryAssociationInfo      = $RegistryAssociationInfo
        Protocols                    = $RegistryAssociationInfo.Protocols
        FileExtensions               = $RegistryAssociationInfo.FileExtensions
        ExtractedFiles               = @($Extracted.FullName)
        ParserVersionInfo            = [pscustomobject]@{ Family = 'Setup Factory'; MajorVersion = $Overlay.Version; OverlayOffset = $Overlay.Offset }
      }
    } finally {
      if (Test-Path -LiteralPath $Temporary) { Remove-Item -LiteralPath $Temporary -Recurse -Force }
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
    try { (Get-SetupFactoryOverlayInfo -Path $Path).Version -in 7, 8, 9 } catch { $false }
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

Export-ModuleMember -Function Get-SetupFactoryInfo, Expand-SetupFactoryInstaller, Test-SetupFactory, Read-ProductVersionFromSetupFactory, Read-ProductNameFromSetupFactory, Read-PublisherFromSetupFactory, Read-ProductCodeFromSetupFactory, Read-ScopeFromSetupFactory
