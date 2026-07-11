# License: GPL-2.0. See Modules\InstallerParsers\LICENSE.GPL2.
# Format sources: https://github.com/HydraDragonAntivirus/HydraDragonAntivirus and https://github.com/russellbanks/Komac

# Apply default function parameters
if ($DumplingsDefaultParameterValues) { $PSDefaultParameterValues = $DumplingsDefaultParameterValues }

# Force stop on error
$ErrorActionPreference = 'Stop'

# Constants
$ADVANCED_INSTALLER_MAGIC = [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX')
$ADVANCED_INSTALLER_FOOTER_SIZE = 72
$ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET = 60
$ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE = $ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $ADVANCED_INSTALLER_MAGIC.Length
$ADVANCED_INSTALLER_FILE_ENTRY_SIZE = 24
$ADVANCED_INSTALLER_XOR_HEADER_SIZE = 512

function Get-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Get a managed compression assembly used for static Advanced Installer extraction
  .PARAMETER Name
    The assembly file name under Modules\InstallerParsers\Assets
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The assembly file name under Modules\InstallerParsers\Assets')]
    [string]$Name
  )

  if (Test-Path -Path ($Path = Join-Path $PSScriptRoot '..' 'Assets' $Name)) {
    return Get-Item -Path $Path -Force
  } else {
    throw "The $Name assembly could not be found"
  }
}

function Import-AdvancedInstallerAssembly {
  <#
  .SYNOPSIS
    Load the managed compression assemblies used for Advanced Installer extraction
  #>

  Import-InstallerArchiveDependency
}

Import-AdvancedInstallerAssembly

function Import-AdvancedInstallerMsiModule {
  <#
  .SYNOPSIS
    Load the MIT MSI helper module required to read embedded MSI metadata
  #>

  if (-not (Get-Command -Name 'Read-ProductVersionFromMsi' -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'PackageModule' 'Libraries' 'MSI.psm1') -Force
  }
}

function Find-AdvancedInstallerBytePattern {
  <#
  .SYNOPSIS
    Find the last occurrence of a byte pattern in a byte array
  .PARAMETER Bytes
    The bytes to search
  .PARAMETER Pattern
    The byte pattern to find
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The bytes to search')]
    [byte[]]$Bytes,

    [Parameter(Mandatory, HelpMessage = 'The byte pattern to find')]
    [byte[]]$Pattern,

    [Parameter(HelpMessage = 'The last byte index to consider as a pattern start')]
    [int]$StartIndex = -1
  )

  $SearchLength = if ($StartIndex -lt 0) { 0 } else { [long]$StartIndex + $Pattern.Length }
  $Match = @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern -Length $SearchLength -Maximum 1 -Reverse)
  if ($Match.Count) { return [int]$Match[0] }
  return -1
}

function Test-AdvancedInstallerBytePattern {
  <#
  .SYNOPSIS
    Test whether two byte arrays match exactly
  .PARAMETER Left
    The first byte array
  .PARAMETER Right
    The second byte array
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The first byte array')]
    [byte[]]$Left,

    [Parameter(Mandatory, HelpMessage = 'The second byte array')]
    [byte[]]$Right
  )

  return Test-BinarySequence -Left $Left -Right $Right
}

function Read-AdvancedInstallerBytes {
  <#
  .SYNOPSIS
    Read an exact byte range from a stream
  .PARAMETER Stream
    The source stream
  .PARAMETER Offset
    The starting position inside the stream
  .PARAMETER Length
    The number of bytes to read
  #>
  [OutputType([byte[]])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The source stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The starting position inside the stream')]
    [long]$Offset,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to read')]
    [int]$Length
  )

  return Read-BinaryBytes -Stream $Stream -Offset $Offset -Count $Length
}

function Test-AdvancedInstallerFooterOffset {
  <#
  .SYNOPSIS
    Validate an Advanced Installer footer candidate found while scanning from the end of the file
  .PARAMETER Stream
    The installer stream
  .PARAMETER FooterOffset
    The candidate footer offset
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The candidate footer offset')]
    [long]$FooterOffset
  )

  if ($FooterOffset -lt 0 -or $FooterOffset + $Script:ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE -gt $Stream.Length) {
    return $false
  }

  $OriginalPosition = $Stream.Position

  try {
    $FooterLength = Get-AdvancedInstallerFooterLength -Stream $Stream -FooterOffset $FooterOffset
    $FooterBytes = Read-AdvancedInstallerBytes -Stream $Stream -Offset $FooterOffset -Length $FooterLength

    if (-not (Test-AdvancedInstallerBytePattern -Left $FooterBytes[$Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET..($Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET + $Script:ADVANCED_INSTALLER_MAGIC.Length - 1)] -Right $Script:ADVANCED_INSTALLER_MAGIC)) {
      return $false
    }

    $FileCount = [System.BitConverter]::ToUInt32($FooterBytes, 4)
    $InfoOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
    $FileOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)

    if ($FileCount -eq 0 -or $FileCount -gt 0x10000) { return $false }
    if ($InfoOffset -ge $FooterOffset) { return $false }
    if ($FileOffset -ge $FooterOffset) { return $false }

    return $true
  } catch {
    return $false
  } finally {
    $null = $Stream.Seek($OriginalPosition, 'Begin')
  }
}

function Get-AdvancedInstallerFooterLength {
  <#
  .SYNOPSIS
    Get the readable Advanced Installer footer length for a candidate offset
  .PARAMETER Stream
    The installer stream
  .PARAMETER FooterOffset
    The candidate footer offset
  #>
  [OutputType([int])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream,

    [Parameter(Mandatory, HelpMessage = 'The candidate footer offset')]
    [long]$FooterOffset
  )

  if ($FooterOffset -lt 0 -or $FooterOffset -ge $Stream.Length) {
    throw 'The Advanced Installer footer offset is outside the installer stream'
  }

  $AvailableLength = $Stream.Length - $FooterOffset
  if ($AvailableLength -lt $Script:ADVANCED_INSTALLER_MINIMUM_FOOTER_SIZE) {
    throw 'The Advanced Installer footer is truncated'
  }

  # Some Advanced Installer SFX builds end immediately after ADVINSTSFX, while older samples have two tail bytes.
  return [int][Math]::Min([long]$Script:ADVANCED_INSTALLER_FOOTER_SIZE, $AvailableLength)
}

function Find-AdvancedInstallerFooterOffset {
  <#
  .SYNOPSIS
    Find the final valid Advanced Installer footer even when the signed installer carries a large certificate tail
  .PARAMETER Stream
    The installer stream
  #>
  [OutputType([long])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The installer stream')]
    [System.IO.Stream]$Stream
  )

  foreach ($MagicOffset in @(Find-BinaryPattern -Stream $Stream -Pattern $Script:ADVANCED_INSTALLER_MAGIC -Maximum 4096 -Reverse)) {
    $FooterOffset = $MagicOffset - $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET
    if (Test-AdvancedInstallerFooterOffset -Stream $Stream -FooterOffset $FooterOffset) { return $FooterOffset }
  }

  throw 'The installer does not contain an Advanced Installer footer'
}

function Resolve-AdvancedInstallerExtractionPath {
  <#
  .SYNOPSIS
    Resolve a payload-relative path under the extraction root and block path traversal
  .PARAMETER DestinationPath
    The extraction root
  .PARAMETER RelativePath
    The payload-relative path from the installer metadata
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The extraction root')]
    [string]$DestinationPath,

    [Parameter(Mandatory, HelpMessage = 'The payload-relative path from the installer metadata')]
    [string]$RelativePath
  )

  return Resolve-SafeExtractionPath -DestinationPath $DestinationPath -RelativePath $RelativePath
}

function Write-AdvancedInstallerStream {
  <#
  .SYNOPSIS
    Copy an exact byte range from a source stream to a destination stream
  .PARAMETER SourceStream
    The source stream
  .PARAMETER DestinationStream
    The destination stream
  .PARAMETER Length
    The number of bytes to copy
  #>
  param (
    [Parameter(Mandatory, HelpMessage = 'The source stream')]
    [System.IO.Stream]$SourceStream,

    [Parameter(Mandatory, HelpMessage = 'The destination stream')]
    [System.IO.Stream]$DestinationStream,

    [Parameter(Mandatory, HelpMessage = 'The number of bytes to copy')]
    [long]$Length
  )

  $null = Copy-BoundedStream -Source $SourceStream -Destination $DestinationStream -MaximumBytes $Length -ExpectedBytes $Length
}

function Write-AdvancedInstallerEntry {
  <#
  .SYNOPSIS
    Extract a single embedded Advanced Installer payload to disk
  .PARAMETER Path
    The path to the installer
  .PARAMETER Entry
    The parsed Advanced Installer payload entry
  .PARAMETER DestinationPath
    The target file path
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer payload entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The target file path')]
    [string]$DestinationPath
  )

  $null = New-Item -Path ([System.IO.Path]::GetDirectoryName($DestinationPath)) -ItemType Directory -Force

  $SourceStream = [System.IO.File]::OpenRead((Get-Item -Path $Path -Force).FullName)
  $DestinationStream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)

  try {
    $null = $SourceStream.Seek($Entry.Offset, 'Begin')

    # Advanced Installer marks some payloads with an XOR-obfuscated header. Only the leading block is transformed.
    $DecodedHeaderLength = [int][Math]::Min([long]$Entry.XorLength, [long]$Entry.Size)
    if ($DecodedHeaderLength -gt 0) {
      $HeaderBytes = New-Object 'byte[]' $DecodedHeaderLength
      $Read = $SourceStream.Read($HeaderBytes, 0, $DecodedHeaderLength)
      if ($Read -ne $DecodedHeaderLength) { throw 'Unexpected end of stream while decoding an Advanced Installer payload header' }
      for ($Index = 0; $Index -lt $DecodedHeaderLength; $Index++) {
        $HeaderBytes[$Index] = $HeaderBytes[$Index] -bxor 0xFF
      }
      $DestinationStream.Write($HeaderBytes, 0, $HeaderBytes.Length)
    }

    Write-AdvancedInstallerStream -SourceStream $SourceStream -DestinationStream $DestinationStream -Length ($Entry.Size - $DecodedHeaderLength)
    return Get-Item -Path $DestinationPath -Force
  } finally {
    $DestinationStream.Close()
    $SourceStream.Close()
  }
}

function Expand-AdvancedInstallerArchive {
  <#
  .SYNOPSIS
    Expand a nested 7z payload produced by Advanced Installer
  .PARAMETER Path
    The path to the extracted archive
  .PARAMETER DestinationPath
    The directory where the archive contents should be written
  #>
  [OutputType([string])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path,

    [Parameter(Mandatory, HelpMessage = 'The directory where the archive contents should be written')]
    [string]$DestinationPath
  )

  $null = New-Item -Path $DestinationPath -ItemType Directory -Force
  $Archive = Get-InstallerArchive -Path $Path

  try {
    $null = Export-InstallerArchiveSelection -Archive $Archive -DestinationPath $DestinationPath -MaximumExpandedBytes 17179869184 -MaximumEntries 200000
    return (Get-Item -Path $DestinationPath -Force).FullName
  } finally {
    $Archive.Dispose()
  }
}

function Test-AdvancedInstallerArchiveHasMsi {
  <#
  .SYNOPSIS
    Test whether a nested Advanced Installer archive contains MSI payloads
  .PARAMETER Path
    The path to the extracted archive
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The path to the extracted archive')]
    [string]$Path
  )

  $Archive = [SharpCompress.Archives.ArchiveFactory]::Open((Get-Item -Path $Path -Force).FullName)
  try {
    return [bool]$Archive.Entries.Where({ -not $_.IsDirectory -and $_.Key -like '*.msi' }, 'First')
  } finally {
    $Archive.Dispose()
  }
}

function Test-AdvancedInstallerNestedArchiveCandidate {
  <#
  .SYNOPSIS
    Test whether a nested Advanced Installer archive should be inspected for MSI payloads
  .PARAMETER Entry
    The parsed Advanced Installer payload entry
  .PARAMETER Path
    The extracted archive path
  #>
  [OutputType([bool])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The parsed Advanced Installer payload entry')]
    [psobject]$Entry,

    [Parameter(Mandatory, HelpMessage = 'The extracted archive path')]
    [string]$Path
  )

  if ([System.IO.Path]::GetExtension($Path) -ine '.7z') { return $false }

  # Advanced Installer commonly stores application files in FILES.7z.  That archive can be very large
  # and does not contain the MSI database used for AppsAndFeatures metadata.
  if ([System.IO.Path]::GetFileName($Entry.Name) -ieq 'FILES.7z') { return $false }

  return $true
}

function Resolve-AdvancedInstallerMatch {
  <#
  .SYNOPSIS
    Resolve a deterministic payload match from an Advanced Installer extraction
  .PARAMETER Item
    The collection to search
  .PARAMETER Pattern
    The file name or wildcard pattern
  #>
  [OutputType([System.IO.FileInfo])]
  param (
    [Parameter(Mandatory, HelpMessage = 'The collection to search')]
    [System.IO.FileInfo[]]$Item,

    [Parameter(Mandatory, HelpMessage = 'The file name or wildcard pattern')]
    [string]$Pattern
  )

  $Match = $Item.Where({ $_.Name -like $Pattern -or $_.FullName -like "*\$Pattern" })
  if (-not $Match) { throw "No MSI files matched the Advanced Installer pattern: $Pattern" }

  $ExactMatches = $Match.Where({ $_.Name -eq $Pattern -or $_.FullName.EndsWith($Pattern, [System.StringComparison]::OrdinalIgnoreCase) })
  if ($ExactMatches.Count -eq 1) { return $ExactMatches[0] }
  if ($Match.Count -eq 1) { return $Match[0] }

  throw "Multiple MSI files matched the Advanced Installer pattern: $Pattern"
}

function New-AdvancedInstallerTempFolder {
  <#
  .SYNOPSIS
    Create a temporary directory for transient Advanced Installer extraction work
  #>
  [OutputType([string])]
  param ()

  $Path = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
  $null = New-Item -Path $Path -ItemType Directory -Force
  return $Path
}

function Get-AdvancedInstallerInfo {
  <#
  .SYNOPSIS
    Get metadata from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .LINK
    https://raw.githubusercontent.com/HydraDragonAntivirus/HydraDragonAntivirus/refs/heads/development-version/hydradragon/decompilers/advancedInstallerExtractor.py
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path
  )

  process {
    $InstallerPath = (Get-Item -Path $Path -Force).FullName
    $Stream = [System.IO.File]::OpenRead($InstallerPath)
    $Reader = [System.IO.BinaryReader]::new($Stream)

    try {
      $FooterOffset = Find-AdvancedInstallerFooterOffset -Stream $Stream
      $FooterLength = Get-AdvancedInstallerFooterLength -Stream $Stream -FooterOffset $FooterOffset
      $FooterBytes = Read-AdvancedInstallerBytes -Stream $Stream -Offset $FooterOffset -Length $FooterLength

      $FooterMagic = [System.Text.Encoding]::ASCII.GetString($FooterBytes, $Script:ADVANCED_INSTALLER_FOOTER_MAGIC_OFFSET, $Script:ADVANCED_INSTALLER_MAGIC.Length)
      if ($FooterMagic -ne 'ADVINSTSFX') { throw 'The Advanced Installer footer signature is invalid' }

      $FileCount = [System.BitConverter]::ToUInt32($FooterBytes, 4)
      $InfoOffset = [System.BitConverter]::ToUInt32($FooterBytes, 16)
      $FileOffset = [System.BitConverter]::ToUInt32($FooterBytes, 20)

      $null = $Stream.Seek($InfoOffset, 'Begin')
      $Files = [System.Collections.Generic.List[object]]::new()

      for ($Index = 0; $Index -lt $FileCount; $Index++) {
        $EntryBytes = $Reader.ReadBytes($Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE)
        if ($EntryBytes.Length -ne $Script:ADVANCED_INSTALLER_FILE_ENTRY_SIZE) { throw 'The Advanced Installer file table is truncated' }

        $XorFlag = [System.BitConverter]::ToUInt32($EntryBytes, 8)
        $EntrySize = [System.BitConverter]::ToUInt32($EntryBytes, 12)
        $EntryOffset = [System.BitConverter]::ToUInt32($EntryBytes, 16)
        $NameLength = [int][System.BitConverter]::ToUInt32($EntryBytes, 20)
        if ($NameLength -lt 0) { throw 'The Advanced Installer payload name length is invalid' }

        $NameBytes = $Reader.ReadBytes($NameLength * 2)
        if ($NameBytes.Length -ne ($NameLength * 2)) { throw 'The Advanced Installer payload name is truncated' }

        $Name = if ($NameLength -eq 0) { "unnamed_file_${Index}.bin" } else { [System.Text.Encoding]::Unicode.GetString($NameBytes).TrimEnd([char]0) }

        $Files.Add([pscustomobject]@{
            Name      = $Name
            Size      = [long]$EntrySize
            Offset    = [long]$EntryOffset
            XorLength = $XorFlag -eq 2 ? $Script:ADVANCED_INSTALLER_XOR_HEADER_SIZE : 0
          })
      }

      return [pscustomobject]@{
        InstallerType = 'AdvancedInstaller'
        Path          = $InstallerPath
        FooterOffset  = [long]$FooterOffset
        FileOffset    = [long]$FileOffset
        FileCount     = [int]$FileCount
        Files         = $Files
      }
    } finally {
      $Reader.Close()
      $Stream.Close()
    }
  }
}

function Expand-AdvancedInstaller {
  <#
  .SYNOPSIS
    Extract the embedded payloads from an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER DestinationPath
    The destination directory for the extracted payloads
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The destination directory for the extracted payloads')]
    [string]$DestinationPath
  )

  process {
    Import-AdvancedInstallerMsiModule

    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
      $DestinationPath = Split-Path -Path $Installer.Path -Parent
    }
    $null = New-Item -Path $DestinationPath -ItemType Directory -Force

    foreach ($Entry in $Installer.Files) {
      $EntryPath = Resolve-AdvancedInstallerExtractionPath -DestinationPath $DestinationPath -RelativePath $Entry.Name
      $EntryFile = Write-AdvancedInstallerEntry -Path $Installer.Path -Entry $Entry -DestinationPath $EntryPath

      # Advanced Installer commonly nests the actual MSI payload inside a dedicated 7z archive.
      # Skip non-MSI archives such as FILES.7z to keep validation and task runs bounded.
      if ((Test-AdvancedInstallerNestedArchiveCandidate -Entry $Entry -Path $EntryFile.FullName) -and (Test-AdvancedInstallerArchiveHasMsi -Path $EntryFile.FullName)) {
        Expand-AdvancedInstallerArchive -Path $EntryFile.FullName -DestinationPath $EntryFile.DirectoryName | Out-Null
      }
    }

    return (Get-Item -Path $DestinationPath -Force).FullName
  }
}

function Get-AdvancedInstallerMsiInfo {
  <#
  .SYNOPSIS
    Read MSI metadata from a statically extracted Advanced Installer payload
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([pscustomobject])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    $Installer = switch ($PSCmdlet.ParameterSetName) {
      'Path' { Get-AdvancedInstallerInfo -Path $Path }
      'Installer' { $Installer }
      default { throw 'Invalid parameter set.' }
    }

    $ExpandedPath = New-AdvancedInstallerTempFolder

    try {
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath | Out-Null
      $MsiFiles = @(Get-ChildItem -Path $ExpandedPath -Filter '*.msi' -Recurse -File)
      $MsiFile = Resolve-AdvancedInstallerMatch -Item $MsiFiles -Pattern $Name
      $AssociationInfo = Get-MsiAssociationInfo -Path $MsiFile.FullName

      return [pscustomobject]@{
        Name           = $MsiFile.Name
        Path           = $MsiFile.FullName
        ProductVersion = $MsiFile.FullName | Read-ProductVersionFromMsi
        ProductCode    = $MsiFile.FullName | Read-ProductCodeFromMsi
        UpgradeCode    = $MsiFile.FullName | Read-UpgradeCodeFromMsi
        Protocols      = $AssociationInfo.Protocols
        FileExtensions = $AssociationInfo.FileExtensions
        RegistryAssociationInfo = $AssociationInfo
      }
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction 'Continue' -ProgressAction 'SilentlyContinue'
    }
  }
}

function Read-ProductVersionFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductVersion property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductVersion
  }
}

function Read-ProductCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the ProductCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).ProductCode
  }
}

function Read-UpgradeCodeFromAdvancedInstaller {
  <#
  .SYNOPSIS
    Read the UpgradeCode property value from the MSI payload inside an Advanced Installer executable
  .PARAMETER Path
    The path to the installer
  .PARAMETER Installer
    The parsed Advanced Installer metadata object
  .PARAMETER Name
    The MSI file name or wildcard pattern to locate after extraction
  #>
  [OutputType([string])]
  param (
    [Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The path to the installer')]
    [string]$Path,

    [Parameter(ParameterSetName = 'Installer', Position = 0, ValueFromPipeline, Mandatory, HelpMessage = 'The parsed Advanced Installer metadata object')]
    [psobject]$Installer,

    [Parameter(HelpMessage = 'The MSI file name or wildcard pattern to locate after extraction')]
    [string]$Name = '*.msi'
  )

  process {
    (Get-AdvancedInstallerMsiInfo @PSBoundParameters).UpgradeCode
  }
}

Export-ModuleMember -Function Get-AdvancedInstallerInfo, Expand-AdvancedInstaller, Get-AdvancedInstallerMsiInfo, Read-ProductVersionFromAdvancedInstaller, Read-ProductCodeFromAdvancedInstaller, Read-UpgradeCodeFromAdvancedInstaller
