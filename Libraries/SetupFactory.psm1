# SPDX-License-Identifier: GPL-3.0-or-later
# Format sources: https://github.com/CybercentreCanada/sfextract, https://github.com/Puyodead1/SFUnpacker, https://codeberg.org/CYBERDEV/defactory, and https://github.com/madler/zlib
# Setup Factory 7-9 static parser. Format details are derived from sfextract
# (MIT) and SFUnpacker (LGPL-3.0-or-later); see THIRD-PARTY-NOTICES.md.

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

Set-StrictMode -Version 3.0

$Script:SetupFactory7Signature = [byte[]](0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7)
$Script:SetupFactory89Signature = [byte[]](0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5, 0xE6, 0xE6, 0xE7, 0xE7)
$Script:SetupFactoryMaximumEntries = 100000
$Script:SetupFactoryMaximumFileBytes = 1073741824
$Script:SetupFactoryMaximumExpandedBytes = 17179869184

function Read-SetupFactoryExactBytes {
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
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  [BitConverter]::ToUInt32((Read-SetupFactoryExactBytes -Stream $Stream -Count 4), 0)
}

function Read-SetupFactoryInt64 {
  [OutputType([long])]
  param ([Parameter(Mandatory)][System.IO.Stream]$Stream)
  [BitConverter]::ToInt64((Read-SetupFactoryExactBytes -Stream $Stream -Count 8), 0)
}

function Get-SetupFactoryCrc32 {
  [OutputType([uint32])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  return Get-BinaryCrc32 -Bytes $Bytes
}

function Expand-SetupFactoryCompressedBytes {
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
  [OutputType([hashtable])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
  $Variables = @{}
  $Pattern = [Text.Encoding]::ASCII.GetBytes('CSessionVar')
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
      $Variables.Clear()
    }
  }
  return $Variables
}

function Resolve-SetupFactoryVariable {
  [OutputType([string])]
  param (
    [AllowNull()][string]$Value,
    [Parameter(Mandatory)][hashtable]$Variables,
    [int]$Depth = 0,
    [string[]]$Stack = @()
  )
  if ($null -eq $Value -or $Depth -ge 32) { return $null }
  $Result = $Value
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
  [OutputType([pscustomobject[]])]
  param ([Parameter(Mandatory)][byte[]]$Bytes)
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
  [OutputType([pscustomobject])]
  param ([Parameter(Mandatory)][string]$Path)
  $File = Get-Item -LiteralPath $Path -Force
  $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
  try {
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

    $Stream = [IO.File]::Open($File.FullName, 'Open', 'Read', 'ReadWrite')
    $Written = 0L
    try {
      $Stream.Position = $Overlay.Offset
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

      for ($EntryIndex = 0; $EntryIndex -lt $Count; $EntryIndex++) {
        $NameSize = if ($Overlay.Version -eq 7) { 260 } else { 264 }
        $EntryName = [Text.Encoding]::UTF8.GetString((Read-SetupFactoryExactBytes -Stream $Stream -Count $NameSize)).Split("`0", 2)[0]
        $PackedSize = if ($Overlay.Version -eq 7) { [long](Read-SetupFactoryUInt32 -Stream $Stream) } else { Read-SetupFactoryInt64 -Stream $Stream }
        $ExpectedCrc = Read-SetupFactoryUInt32 -Stream $Stream
        if ($Overlay.Version -ne 7) { $Stream.Position += 4 }
        if ($PackedSize -lt 0 -or $PackedSize -gt $Script:SetupFactoryMaximumFileBytes) { throw 'A Setup Factory entry size is invalid' }
        if ($PackedSize -gt $Stream.Length - $Stream.Position) { throw "The Setup Factory entry '$EntryName' is truncated" }
        if (-not (Test-ExtractionPattern -Path $EntryName -Pattern $Name)) {
          $Stream.Position += $PackedSize
          continue
        }
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
      $Extracted = @(Expand-SetupFactoryInstaller -Path $File.FullName -DestinationPath $Temporary -Name 'irsetup.dat')
      $ScriptPath = Join-Path $Temporary 'irsetup.dat'
      if (-not (Test-Path -LiteralPath $ScriptPath)) { throw 'The Setup Factory installer does not contain irsetup.dat' }
      $ScriptFile = Get-Item -LiteralPath $ScriptPath -Force
      if ($ScriptFile.Length -gt $Script:SetupFactoryMaximumFileBytes) { throw 'The Setup Factory script exceeds the configured read limit.' }
      $ScriptStream = [IO.File]::OpenRead($ScriptFile.FullName)
      try { $Bytes = Read-BinaryBytes -Stream $ScriptStream -Offset 0 -Count ([int]$ScriptFile.Length) }
      finally { $ScriptStream.Dispose() }
      $Variables = Get-SetupFactorySessionVariables -Bytes $Bytes
      $Resolve = { param($Name) if ($Variables.ContainsKey($Name)) { Resolve-SetupFactoryVariable -Value ([string]$Variables[$Name]) -Variables $Variables } }
      $DisplayName = & $Resolve '%ProductName%'
      $DisplayVersion = & $Resolve '%ProductVer%'
      $Publisher = & $Resolve '%CompanyName%'
      $InstallLocation = & $Resolve '%AppFolder%'
      $RegistryWrites = @(Get-SetupFactoryLiteralRegistryWrites -Bytes $Bytes)
      $RegistryAssociationInfo = Get-InstallerRegistryAssociationInfo -RegistryWrite $RegistryWrites

      $ProductExpression = '%ProductName%%ProductVer%'
      $ExpressionBytes = [Text.Encoding]::UTF8.GetBytes($ProductExpression)
      $HasBuiltInUninstall = @(Find-BinaryPattern -Bytes $Bytes -Pattern $ExpressionBytes -Maximum 1).Count -gt 0
      $ProductCode = if ($HasBuiltInUninstall) { Resolve-SetupFactoryVariable -Value $ProductExpression -Variables $Variables }
      $RegistryRoots = @($RegistryWrites | ForEach-Object { $_.Root })
      $Scope = if ($RegistryRoots -match 'HKCU|HKEY_CURRENT_USER') { 'user' }
      elseif ($RegistryRoots -match 'HKLM|HKEY_LOCAL_MACHINE' -or $InstallLocation -match '^(?:%ProgramFiles|[A-Za-z]:\\Program Files(?: \(x86\))?\\)') { 'machine' }
      else { $null }
      if (-not $Variables.Count) { $Warnings.Add('CSessionVar records were not found or were malformed') }
      if (-not $HasBuiltInUninstall -and -not $RegistryWrites.Count) { $Warnings.Add('No explicit built-in uninstall configuration or literal registry writes were found') }
      foreach ($Warning in @($RegistryAssociationInfo.Warnings)) { $Warnings.Add($Warning) }

      [pscustomobject]@{
        DisplayName                = $DisplayName
        DisplayVersion             = $DisplayVersion
        Publisher                  = $Publisher
        ProductCode                = $ProductCode
        InstallLocation            = $InstallLocation
        Scope                      = $Scope
        RegistryWrites             = $RegistryWrites
        RegistryAssociationInfo    = $RegistryAssociationInfo
        Protocols                  = $RegistryAssociationInfo.Protocols
        FileExtensions             = $RegistryAssociationInfo.FileExtensions
        ExtractedFiles             = @($Extracted.FullName)
        WritesAppsAndFeaturesEntry = [bool]($HasBuiltInUninstall -or $RegistryWrites.Count)
        Warnings                   = $Warnings.ToArray()
        ParserVersionInfo          = [pscustomobject]@{ Family = 'Setup Factory'; MajorVersion = $Overlay.Version; OverlayOffset = $Overlay.Offset }
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
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayVersion }
}
function Read-ProductNameFromSetupFactory {
  <#
  .SYNOPSIS
    Read the product name from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).DisplayName }
}
function Read-PublisherFromSetupFactory {
  <#
  .SYNOPSIS
    Read the publisher from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Publisher }
}
function Read-ProductCodeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the ARP ProductCode from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).ProductCode }
}
function Read-ScopeFromSetupFactory {
  <#
  .SYNOPSIS
    Read the installation scope from a Setup Factory installer
  #>
  param ([Parameter(ValueFromPipeline, Mandatory)][string]$Path)
  process { (Get-SetupFactoryInfo -Path $Path).Scope }
}

Export-ModuleMember -Function Get-SetupFactoryInfo, Expand-SetupFactoryInstaller, Test-SetupFactory, Read-ProductVersionFromSetupFactory, Read-ProductNameFromSetupFactory, Read-PublisherFromSetupFactory, Read-ProductCodeFromSetupFactory, Read-ScopeFromSetupFactory
