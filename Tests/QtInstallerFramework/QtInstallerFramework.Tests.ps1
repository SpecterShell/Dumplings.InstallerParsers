. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'QtInstallerFramework.psm1') -Force

  $Script:FixtureDirectory = $TestDrive

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [switch]$UseSourceForgeMetaRefresh
    )

    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url -UseSourceForgeMetaRefresh:$UseSourceForgeMetaRefresh
  }

  function Add-TestUInt16BE {
    param([System.Collections.Generic.List[byte]]$Bytes, [uint16]$Value)

    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
    $Bytes.Add([byte]($Value -band 0xff))
  }

  function Add-TestUInt32BE {
    param([System.Collections.Generic.List[byte]]$Bytes, [uint32]$Value)

    $Bytes.Add([byte](($Value -shr 24) -band 0xff))
    $Bytes.Add([byte](($Value -shr 16) -band 0xff))
    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
    $Bytes.Add([byte]($Value -band 0xff))
  }

  function Add-TestInt64LE {
    param([System.Collections.Generic.List[byte]]$Bytes, [int64]$Value)

    $Bytes.AddRange([System.BitConverter]::GetBytes($Value))
  }

  function Add-TestQtByteArray {
    param(
      [System.Collections.Generic.List[byte]]$Bytes,
      [string]$Value
    )

    $Data = [Text.Encoding]::UTF8.GetBytes($Value)
    Add-TestInt64LE -Bytes $Bytes -Value $Data.Length
    $Bytes.AddRange($Data)
  }

  function Add-TestQtRccName {
    param(
      [System.Collections.Generic.List[byte]]$Bytes,
      [string]$Name
    )

    $Offset = $Bytes.Count
    Add-TestUInt16BE -Bytes $Bytes -Value ([uint16]$Name.Length)
    Add-TestUInt32BE -Bytes $Bytes -Value 0
    $Bytes.AddRange([System.Text.Encoding]::BigEndianUnicode.GetBytes($Name))
    return $Offset
  }

  function New-TestQtRccResource {
    param([string]$InstallerXml)

    $Payload = [System.Text.Encoding]::UTF8.GetBytes($InstallerXml)
    $DataBlob = [System.Collections.Generic.List[byte]]::new()
    Add-TestUInt32BE -Bytes $DataBlob -Value ([uint32]$Payload.Length)
    $DataBlob.AddRange($Payload)

    $NameTable = [System.Collections.Generic.List[byte]]::new()
    $InstallerConfigNameOffset = Add-TestQtRccName -Bytes $NameTable -Name 'installer-config'
    $ConfigNameOffset = Add-TestQtRccName -Bytes $NameTable -Name 'config.xml'

    $DataOffset = 20
    $NamesOffset = $DataOffset + $DataBlob.Count
    $TreeOffset = $NamesOffset + $NameTable.Count
    $Rcc = [System.Collections.Generic.List[byte]]::new()
    $Rcc.AddRange([System.Text.Encoding]::ASCII.GetBytes('qres'))
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$TreeOffset)
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$DataOffset)
    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$NamesOffset)
    $Rcc.AddRange($DataBlob.ToArray())
    $Rcc.AddRange($NameTable.ToArray())

    Add-TestUInt32BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 2
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 1

    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$InstallerConfigNameOffset)
    Add-TestUInt16BE -Bytes $Rcc -Value 2
    Add-TestUInt32BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 2

    Add-TestUInt32BE -Bytes $Rcc -Value ([uint32]$ConfigNameOffset)
    Add-TestUInt16BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 0
    Add-TestUInt16BE -Bytes $Rcc -Value 1
    Add-TestUInt32BE -Bytes $Rcc -Value 0

    return , $Rcc.ToArray()
  }

  function New-TestQtInstallerFrameworkFixture {
    param(
      [string]$Name,
      [string]$InstallerXml,
      [string]$ScriptText,
      [switch]$GuiOnly,
      [string]$FrameworkVersion,
      [object[]]$Operation = @(),
      [object[]]$PackageResource = @(),
      [ValidateSet('Installer', 'Uninstaller', 'Updater', 'PackageManager')]
      [string]$MediaRole = 'Installer',
      [ValidateSet('Executable', 'Data')]
      [string]$CookieKind = 'Executable'
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $Bytes = [System.Collections.Generic.List[byte]]::new()
    $Bytes.AddRange([byte[]](0x4d, 0x5a))
    if ($FrameworkVersion) {
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes("IFW Version: $FrameworkVersion, built with Qt 6.8.0.`0"))
    }
    if (-not $GuiOnly) {
      $Bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes("accept-licenses`0default-answer`0confirm-command`0check-updates`0create-offline`0clear-cache`0"))
    }
    while ($Bytes.Count -lt 512) { $Bytes.Add(0) }

    $EndOfExecutable = $Bytes.Count
    $MetaStart = $Bytes.Count
    $MetaBytes = [byte[]](New-TestQtRccResource -InstallerXml $InstallerXml)
    $Bytes.AddRange([byte[]]$MetaBytes)
    $MetaSegments = [System.Collections.Generic.List[object]]::new()
    $MetaSegments.Add([pscustomobject]@{ Start = $MetaStart; Length = $MetaBytes.Length })
    if ($PSBoundParameters.ContainsKey('ScriptText')) {
      $ScriptStart = $Bytes.Count
      $ScriptBytes = [System.Text.Encoding]::UTF8.GetBytes($ScriptText)
      $Bytes.AddRange($ScriptBytes)
      $MetaSegments.Add([pscustomobject]@{ Start = $ScriptStart; Length = $ScriptBytes.Length })
    }

    $OperationsStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    foreach ($OperationItem in $Operation) {
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Name
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Data
    }
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    $OperationsLength = $Bytes.Count - $OperationsStart

    # BinaryContent reserves one qint64 resource-manager field before the collection data.
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $ResourceSegments = [Collections.Generic.List[object]]::new()
    foreach ($PackageResourceItem in @($PackageResource)) {
      $ResourceBytes = [byte[]]$PackageResourceItem.Bytes
      $ResourceStart = $Bytes.Count
      $Bytes.AddRange($ResourceBytes)
      $ResourceSegments.Add([pscustomobject]@{
          Collection = [string]$PackageResourceItem.Collection
          Name       = [string]$PackageResourceItem.Name
          Start      = $ResourceStart
          Length     = $ResourceBytes.Length
        })
    }

    $CollectionSegments = [Collections.Generic.List[object]]::new()
    foreach ($CollectionName in @($ResourceSegments | Select-Object -ExpandProperty Collection -Unique)) {
      $CollectionStart = $Bytes.Count
      $CollectionResources = @($ResourceSegments | Where-Object Collection -CEQ $CollectionName)
      Add-TestInt64LE -Bytes $Bytes -Value $CollectionResources.Count
      foreach ($Resource in $CollectionResources) {
        Add-TestQtByteArray -Bytes $Bytes -Value $Resource.Name
        Add-TestInt64LE -Bytes $Bytes -Value ($Resource.Start - $EndOfExecutable)
        Add-TestInt64LE -Bytes $Bytes -Value $Resource.Length
      }
      Add-TestInt64LE -Bytes $Bytes -Value $CollectionResources.Count
      $CollectionSegments.Add([pscustomobject]@{ Name = $CollectionName; Start = $CollectionStart; Length = $Bytes.Count - $CollectionStart })
    }

    $CollectionIndexStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionSegments.Count
    foreach ($Collection in $CollectionSegments) {
      Add-TestQtByteArray -Bytes $Bytes -Value $Collection.Name
      Add-TestInt64LE -Bytes $Bytes -Value ($Collection.Start - $EndOfExecutable)
      Add-TestInt64LE -Bytes $Bytes -Value $Collection.Length
    }
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionSegments.Count
    $CollectionIndexLength = $Bytes.Count - $CollectionIndexStart

    Add-TestInt64LE -Bytes $Bytes -Value ($CollectionIndexStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionIndexLength
    foreach ($MetaSegment in $MetaSegments) {
      Add-TestInt64LE -Bytes $Bytes -Value ($MetaSegment.Start - $EndOfExecutable)
      Add-TestInt64LE -Bytes $Bytes -Value $MetaSegment.Length
    }
    Add-TestInt64LE -Bytes $Bytes -Value ($OperationsStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $OperationsLength
    Add-TestInt64LE -Bytes $Bytes -Value $MetaSegments.Count

    $BinaryContentSize = ($Bytes.Count + 24) - $EndOfExecutable
    Add-TestInt64LE -Bytes $Bytes -Value $BinaryContentSize
    $Marker = switch ($MediaRole) {
      'Installer' { 0x12023233 }
      'Uninstaller' { 0x12023234 }
      'Updater' { 0x12023235 }
      'PackageManager' { 0x12023236 }
    }
    Add-TestInt64LE -Bytes $Bytes -Value $Marker
    $CookieFirstByte = if ($CookieKind -eq 'Data') { 0xf9 } else { 0xf8 }
    $Bytes.AddRange([byte[]]($CookieFirstByte, 0x68, 0xd6, 0x99, 0x1c, 0x0a, 0x63, 0xc2))

    [System.IO.File]::WriteAllBytes($FixturePath, $Bytes.ToArray())
    return $FixturePath
  }

  function New-TestQtPackageArchive {
    param (
      [Parameter(Mandatory)]
      [ValidateSet('tar', 'tar.gz', 'tar.bz2', 'tar.xz', 'zip', '7z', 'qbsp')]
      [string]$Format
    )

    $Payload = [Text.Encoding]::UTF8.GetBytes('Qt IFW package format regression')
    $Path = Join-Path $TestDrive "qt-package.$Format"
    switch ($Format) {
      { $_ -in @('7z', 'qbsp') } {
        # A small independently generated 7z archive. Qt IFW defines .qbsp as the same physical format.
        $Bytes = [Convert]::FromBase64String('N3q8ryccAASYEnOLJAAAAAAAAABiAAAAAAAAAHPd8FsBAB9RdCBJRlcgcGFja2FnZSBmb3JtYXQgcmVncmVzc2lvbgABBAYAAQkkAAcLAQABISEBAAwgAAgKAe1s3BwAAAUBGQwAAAAAAAAAAAAAAAARGQBwAGEAeQBsAG8AYQBkAC4AdAB4AHQAAAAZAgAAFAoBAL7OmS7ILN0BFQYBACAAAAAAAA==')
      }
      'tar.bz2' {
        $Bytes = [Convert]::FromBase64String('QlpoOTFBWSZTWdh/8TgAAEdfkdIAQAF/BAEgIoBvr95gBAAgAAAIIAB0ImptEMSB5Mggep6np6QaKZqNAAA0A0ARxp8Q2QAhG5AFAg+QYJzCpFxNueauEyFLHgQN4okwlLG4OggRQSPiCgLsAsjgaZDSk30L2E9ganX/M1urWrLNude1x2PBR2gUUI5F3JFOFCQ2H/xOAA==')
      }
      'tar.xz' {
        $Bytes = [Convert]::FromBase64String('/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4Af/AG1dADgYS5l1D0YIb9M6IJf02WKFmi3aKO3xv/1RoAfcREAIWBY7YuRX83OY1G+bEHL5X9GWDhFgfvllt5uh2DX02XyTmugrKBqBZerhFbMYXEPh6rgnXbFu8MUZAJpwbBvvClv3ZWxSez4s5W1EuQAAAAAA7LICCLnvjRkAAYkBgBAAADat9TaxxGf7AgAAAAAEWVo=')
      }
      default {
        $TarStream = [IO.MemoryStream]::new()
        $TarWriter = [System.Formats.Tar.TarWriter]::new($TarStream, $true)
        $PayloadStream = [IO.MemoryStream]::new($Payload, $false)
        try {
          $Entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, 'payload.txt')
          $Entry.DataStream = $PayloadStream
          $TarWriter.WriteEntry($Entry)
        } finally {
          $TarWriter.Dispose()
          $PayloadStream.Dispose()
        }
        $TarBytes = $TarStream.ToArray()
        $TarStream.Dispose()

        if ($Format -eq 'tar') {
          $Bytes = $TarBytes
        } elseif ($Format -eq 'tar.gz') {
          $CompressedStream = [IO.MemoryStream]::new()
          $GZipStream = [IO.Compression.GZipStream]::new($CompressedStream, [IO.Compression.CompressionLevel]::SmallestSize, $true)
          try { $GZipStream.Write($TarBytes, 0, $TarBytes.Length) } finally { $GZipStream.Dispose() }
          $Bytes = $CompressedStream.ToArray()
          $CompressedStream.Dispose()
        } else {
          $ZipStream = [IO.MemoryStream]::new()
          $ZipArchive = [IO.Compression.ZipArchive]::new($ZipStream, [IO.Compression.ZipArchiveMode]::Create, $true)
          try {
            $Entry = $ZipArchive.CreateEntry('payload.txt', [IO.Compression.CompressionLevel]::SmallestSize)
            $EntryStream = $Entry.Open()
            try { $EntryStream.Write($Payload, 0, $Payload.Length) } finally { $EntryStream.Dispose() }
          } finally { $ZipArchive.Dispose() }
          $Bytes = $ZipStream.ToArray()
          $ZipStream.Dispose()
        }
      }
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)
    return $Path
  }
}

Describe 'Qt Installer Framework parser' {
  It 'Should expose a complete catalog with resolvable package-index routes' {
    $Module = Get-Module QtInstallerFramework | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Catalog = & $Module { $Script:QtInstallerFrameworkCatalog }
    $Handlers = & $Module { $Script:QtInstallerFrameworkRouteHandlers }

    @($Catalog.Profiles).Count | Should -Be 5
    @($Catalog.Profiles.Id | Select-Object -Unique).Count | Should -Be 5
    $Profiles = @($Catalog.Profiles | Sort-Object { [version]$_.MinimumVersion })
    $Profiles[0].MinimumVersion | Should -Be '1.2.0'
    for ($Index = 0; $Index -lt $Profiles.Count - 1; $Index++) {
      $Profiles[$Index].MaximumVersionExclusive | Should -Be $Profiles[$Index + 1].MinimumVersion
    }
    $Profiles[-1].MaximumVersionExclusive | Should -Be '4.12.0'
    foreach ($Profile in @($Catalog.Profiles) + @($Catalog.CompatibilityProfiles.Values)) {
      $Handlers.Trailer.ContainsKey($Profile.TrailerRoute) | Should -BeTrue
      $Handlers.Metadata.ContainsKey($Profile.MetadataRoute) | Should -BeTrue
      $Handlers.PackageIndex.ContainsKey($Profile.PackageIndexRoute) | Should -BeTrue
      $Handlers.Payload.ContainsKey($Profile.PayloadRoute) | Should -BeTrue
      $Handlers.Config.ContainsKey($Profile.ConfigRoute) | Should -BeTrue
      $Handlers.Interface.ContainsKey($Profile.InterfaceRoute) | Should -BeTrue
    }
  }

  It 'Should select legacy, current, and future-compatible catalog profiles' {
    $Legacy = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-1.5.exe' -FrameworkVersion '1.5.0' -GuiOnly -InstallerXml @'
<Installer><Name>Example.Legacy</Name><Version>1.0</Version><UninstallerName>legacytool</UninstallerName></Installer>
'@
    $Current = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-4.11.exe' -FrameworkVersion '4.11.0' -InstallerXml @'
<Installer><Name>Example.Current</Name><Version>1.0</Version><ProductUUID>{11111111-2222-3333-4444-555555555555}</ProductUUID></Installer>
'@
    $Future = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-4.12.exe' -FrameworkVersion '4.12.0' -InstallerXml @'
<Installer><Name>Example.Future</Name><Version>1.0</Version><ProductUUID>{11111111-2222-3333-4444-555555555555}</ProductUUID></Installer>
'@

    $LegacyInfo = Get-QtInstallerFrameworkInfo -Path $Legacy
    $LegacyInfo.FormatGeneration | Should -Be 'LegacyComponentIndex'
    $LegacyInfo.FormatProfileId | Should -Be 'ifw-1.x-legacy'
    $LegacyInfo.ProductCode | Should -Be 'Example.Legacy'
    $LegacyInfo.MaintenanceToolName | Should -Be 'legacytool'

    $CurrentInfo = Get-QtInstallerFrameworkFormatInfo -Path $Current
    $CurrentInfo.FormatProfileId | Should -Be 'ifw-4.2-current-libarchive'
    $CurrentInfo.FrameworkVersion | Should -Be '4.11.0'
    $CurrentInfo.QtRuntimeVersion | Should -Be '6.8.0'
    $CurrentInfo.CatalogVersion | Should -Be 1
    $CurrentInfo.SupportsProductUuid | Should -BeTrue
    $CurrentInfo.SupportsCommandLineInterface | Should -BeTrue
    $CurrentInfo.SupportsLibArchive | Should -BeTrue
    $CurrentInfo.VersionEvidenceRoute | Should -Be 'embedded-ifw-and-pe-version-v1'

    $FutureInfo = Get-QtInstallerFrameworkFormatInfo -Path $Future
    $FutureInfo.IsFallback | Should -BeTrue
    $FutureInfo.FormatProfileId | Should -Be 'ifw-modern-compatible'
    $FutureInfo.Warnings | Should -Contain 'The Qt IFW media uses a structurally compatible fallback profile; release-specific capabilities require review.'
  }

  It 'Should resolve the source-defined unversioned Qt IFW 1.2 layout without treating it as a future fallback' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-1.2.exe' -GuiOnly -InstallerXml @'
<Installer><Name>Example.IFW12</Name><Version>1.0</Version><UninstallerName>uninstall</UninstallerName></Installer>
'@

    $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture

    $Info.FrameworkVersion | Should -BeNullOrEmpty
    $Info.FrameworkVersionRange | Should -Be '1.2-1.x'
    $Info.FormatProfileId | Should -Be 'ifw-1.x-legacy'
    $Info.IsFallback | Should -BeFalse
    $Info.Warnings | Should -Contain 'No source-defined Qt IFW version marker was found; the framework version is reported as a structurally validated range.'
  }

  It 'Should reject an unversioned package index when configuration evidence cannot distinguish 1.x from 2.0+' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-ambiguous.exe' -GuiOnly -InstallerXml '<Installer><Name>Example.Ambiguous</Name><Version>1.0</Version></Installer>'

    $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture

    $Info.IsQtInstallerFramework | Should -BeTrue
    $Info.IsSupported | Should -BeFalse
    $Info.Warnings -join ' ' | Should -BeLike '*structurally ambiguous between legacy and modern routes*'
  }

  It 'Should diagnose every media marker and executable or DAT cookie' -ForEach @(
    @{ Role = 'Installer'; Cookie = 'Executable' }
    @{ Role = 'Uninstaller'; Cookie = 'Executable' }
    @{ Role = 'Updater'; Cookie = 'Data' }
    @{ Role = 'PackageManager'; Cookie = 'Data' }
  ) {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name "synthetic-ifw-$Role-$Cookie.bin" -FrameworkVersion '4.11.0' -MediaRole $Role -CookieKind $Cookie -InstallerXml '<Installer><Name>Example.Media</Name><Version>1.0</Version></Installer>'
    $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture
    $Info.MediaRole | Should -Be $Role
    $Info.CookieKind | Should -Be $Cookie
    if ($Role -ne 'Installer') { { Get-QtInstallerFrameworkInfo -Path $Fixture } | Should -Throw '*is not an installer*' }
  }

  It 'Should return structured unsupported evidence for a malformed package index' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-malformed-index.exe' -FrameworkVersion '4.11.0' -InstallerXml '<Installer><Name>Example.Malformed</Name><Version>1.0</Version></Installer>'
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $Fixture
    $Stream = [IO.File]::Open($Fixture, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
      $Stream.Position = $Layout.PrimaryIndexSegment.End - 8
      $Bytes = [BitConverter]::GetBytes([int64]1)
      $Stream.Write($Bytes, 0, $Bytes.Length)
    } finally { $Stream.Dispose() }

    $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture
    $Info.IsQtInstallerFramework | Should -BeTrue
    $Info.IsSupported | Should -BeFalse
    $Info.Warnings -join ' ' | Should -BeLike '*format route is unsupported or malformed*'
    { Get-QtInstallerFrameworkInfo -Path $Fixture } | Should -Throw '*unsupported or malformed*'
  }

  It 'Should reject a mismatched performed-operation count footer' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-malformed-operations.exe' -FrameworkVersion '4.11.0' -Operation @([pscustomobject]@{ Name = 'CreateShortcut'; Data = '<operation />' }) -InstallerXml '<Installer><Name>Example.MalformedOperation</Name><Version>1.0</Version></Installer>'
    $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $Fixture
    $Stream = [IO.File]::Open($Fixture, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
      $Stream.Position = $Layout.OperationsSegment.End - 8
      $Bytes = [BitConverter]::GetBytes([int64]2)
      $Stream.Write($Bytes, 0, $Bytes.Length)
    } finally { $Stream.Dispose() }

    $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture

    $Info.IsSupported | Should -BeFalse
    $Info.Warnings -join ' ' | Should -BeLike '*performed-operation count footer*'
  }

  It 'Should parse official Windows media at catalog capability boundaries' {
    $Cases = @(
      @{ Name = 'qt-ifw-1.3.0.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/1.3.0/qt-installer-framework-1.3.0.exe'; Version = '1.3.0'; Generation = 'LegacyComponentIndex'; Profile = 'ifw-1.x-legacy' }
      @{ Name = 'qt-ifw-1.5.0.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/1.5.0/qt-installer-framework-opensource-1.5.0-x86.exe'; Version = '1.5.0'; Generation = 'LegacyComponentIndex'; Profile = 'ifw-1.x-legacy' }
      @{ Name = 'qt-ifw-2.0.5.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/2.0.5/QtInstallerFramework-win-x86.exe'; Version = '2.0.5'; Generation = 'BinaryContent'; Profile = 'ifw-2.x-3.1-binary-content' }
      @{ Name = 'qt-ifw-3.2.2.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/3.2.2/QtInstallerFramework-win-x86.exe'; Version = '3.2.2'; Generation = 'BinaryContent'; Profile = 'ifw-3.1.2-3.x-binary-content' }
      @{ Name = 'qt-ifw-4.0.0.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/4.0.0/QtInstallerFramework-win-x86.exe'; Version = '4.0.0'; Generation = 'BinaryContent'; Profile = 'ifw-4.0-4.1-cli' }
      @{ Name = 'qt-ifw-4.2.0.exe'; Url = 'https://download.qt.io/archive/qt-installer-framework/4.2.0/QtInstallerFramework-windows-x86-4.2.0.exe'; Version = '4.2.0'; Generation = 'BinaryContent'; Profile = 'ifw-4.2-current-libarchive' }
      @{ Name = 'qt-ifw-4.11.0.exe'; Url = 'https://download.qt.io/archive/online_installers/4.11/qt-online-installer-windows-x64-4.11.0.exe'; Version = '4.11.0'; Generation = 'BinaryContent'; Profile = 'ifw-4.2-current-libarchive'; Payload = 'MissingFiles' }
    )
    foreach ($Case in $Cases) {
      $Fixture = Get-InstallerFixture -Name $Case.Name -Url $Case.Url
      $Info = Get-QtInstallerFrameworkFormatInfo -Path $Fixture
      $Info.FrameworkVersion | Should -Be $Case.Version
      $Info.FormatGeneration | Should -Be $Case.Generation
      $Info.FormatProfileId | Should -Be $Case.Profile
      $Info.IsSupported | Should -BeTrue
      if ($Case.ContainsKey('Payload')) {
        $Info.PayloadAvailability | Should -Be $Case.Payload
        $Info.Evidence.EmbeddedPackageArchiveCount | Should -Be 0
        $Info.Warnings | Should -Contain 'Package metadata declares or implies external payload files, but no embedded, sidecar, or online repository source was resolved.'
      }
    }
  }

  It 'Should restore a caller-owned stream after binary layout analysis' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-stream.exe' -FrameworkVersion '4.11.0' -InstallerXml '<Installer><Name>Example.Stream</Name><Version>1.0</Version></Installer>'
    $Stream = [IO.File]::OpenRead($Fixture)
    try {
      $Stream.Position = 7
      $Layout = Get-QtInstallerFrameworkBinaryLayout -Path $Fixture -Stream $Stream
      $Layout.CookieKind | Should -Be 'Executable'
      $Stream.Position | Should -Be 7
    } finally { $Stream.Dispose() }
  }

  It 'Should distinguish online, missing, intentionally empty, and sidecar package media' {
    $Online = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-online.exe' -FrameworkVersion '4.11.0' -ScriptText '<Updates><PackageUpdate><Name>Example.Online.Component</Name><Version>2.3.4</Version><DownloadableArchives>content.7z</DownloadableArchives></PackageUpdate></Updates>' -InstallerXml @'
<Installer><Name>Example.Online</Name><Version>1.0</Version><RemoteRepositories><Repository><Url>https://example.invalid/repository</Url></Repository></RemoteRepositories></Installer>
'@
    $Missing = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-missing.exe' -FrameworkVersion '4.11.0' -ScriptText '<Package><Name>Example.Missing</Name><Version>1.0.0</Version><DownloadableArchives>content.7z</DownloadableArchives></Package>' -InstallerXml '<Installer><Name>Example.Missing</Name><Version>1.0</Version></Installer>'
    $Empty = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-empty.exe' -FrameworkVersion '4.11.0' -ScriptText '<Package><Name>Example.Empty</Name><Version>1.0.0</Version><Virtual>true</Virtual></Package>' -InstallerXml '<Installer><Name>Example.Empty</Name><Version>1.0</Version></Installer>'
    $SidecarInstaller = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-sidecar.exe' -FrameworkVersion '4.11.0' -InstallerXml '<Installer><Name>Example.Sidecar</Name><Version>1.0</Version></Installer>'
    $null = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-sidecar.dat' -FrameworkVersion '4.11.0' -CookieKind Data -InstallerXml '<Installer><Name>Example.Sidecar</Name><Version>1.0</Version></Installer>'

    $OnlineInfo = Get-QtInstallerFrameworkFormatInfo -Path $Online
    $OnlineInfo.PayloadAvailability | Should -Be 'OnlinePackages'
    $OnlineInfo.RepositoryUrls | Should -Contain 'https://example.invalid/repository'
    $OnlineInfo.PackageMetadata | Should -HaveCount 1
    $OnlineInfo.PackageMetadata[0].ArchiveReferences[0].RelativePath | Should -Be 'Example.Online.Component/2.3.4content.7z'
    (Get-QtInstallerFrameworkFormatInfo -Path $Missing).PayloadAvailability | Should -Be 'MissingFiles'
    (Get-QtInstallerFrameworkFormatInfo -Path $Empty).PayloadAvailability | Should -Be 'IntentionallyEmpty'
    (Get-QtInstallerFrameworkFormatInfo -Path $SidecarInstaller).PayloadAvailability | Should -Be 'SidecarData'
  }

  It 'Should extract package archives from paired DAT and local repository sources' {
    $PackageArchive = New-TestQtPackageArchive -Format zip
    $PackageBytes = [IO.File]::ReadAllBytes($PackageArchive)
    $Installer = New-TestQtInstallerFrameworkFixture -Name 'external-content.exe' -FrameworkVersion '4.11.0' -ScriptText '<Package><Name>Example.Component</Name><Version>1.0.0</Version><DownloadableArchives>content.zip</DownloadableArchives></Package>' -InstallerXml '<Installer><Name>Example.External</Name><Version>1.0</Version></Installer>'
    $Data = New-TestQtInstallerFrameworkFixture -Name 'external-content.dat' -FrameworkVersion '4.11.0' -CookieKind Data -PackageResource @([pscustomobject]@{ Collection = 'Example.Component'; Name = 'content.zip'; Bytes = $PackageBytes }) -InstallerXml '<Installer><Name>Example.External</Name><Version>1.0</Version></Installer>'
    $DataDestination = Join-Path $TestDrive 'external-data-output'
    $null = Expand-QtInstallerFramework -Path $Installer -DataPath $Data -DestinationPath $DataDestination -Name 'payload.txt' -CollisionAction Rename
    Get-Content -LiteralPath (Join-Path $DataDestination 'packages/Example.Component/content/payload.txt') -Raw | Should -Be 'Qt IFW package format regression'

    $Repository = Join-Path $TestDrive 'repository'
    $null = New-Item -Path (Join-Path $Repository 'Example.Component') -ItemType Directory -Force
    Copy-Item -LiteralPath $PackageArchive -Destination (Join-Path $Repository 'Example.Component/1.0.0content.zip')
    [IO.File]::WriteAllText((Join-Path $Repository 'Updates.xml'), '<Updates><PackageUpdate><Name>Example.Component</Name><Version>1.0.0</Version><DownloadableArchives>content.zip</DownloadableArchives></PackageUpdate></Updates>')
    $RepositoryDestination = Join-Path $TestDrive 'repository-output'
    $null = Expand-QtInstallerFramework -Path $Installer -RepositoryPath $Repository -DestinationPath $RepositoryDestination -Name 'payload.txt' -CollisionAction Rename
    Get-Content -LiteralPath (Join-Path $RepositoryDestination 'packages/Example.Component/content/payload.txt') -Raw | Should -Be 'Qt IFW package format regression'

    $PackageDestination = Join-Path $TestDrive 'explicit-package-output'
    $null = Expand-QtInstallerFramework -Path $Installer -PackagePath $PackageArchive -DestinationPath $PackageDestination -Name 'payload.txt' -CollisionAction Rename
    Get-Content -LiteralPath (Join-Path $PackageDestination 'packages/external/qt-package/payload.txt') -Raw | Should -Be 'Qt IFW package format regression'
  }

  It 'Should extract a selected file through the legacy component archive route' {
    $Fixture = Get-InstallerFixture -Name 'qt-ifw-1.5.0.exe' -Url 'https://download.qt.io/archive/qt-installer-framework/1.5.0/qt-installer-framework-opensource-1.5.0-x86.exe'
    $Destination = Join-Path $TestDrive 'legacy-component-extraction'

    $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $Destination -Name 'binarycreator.exe' -CollisionAction Rename

    $Result | Should -Be $Destination
    $Extracted = Get-Item -LiteralPath (Join-Path $Destination 'packages\org.qtproject.ifw.binaries\1.5.0data\bin\binarycreator.exe')
    $Extracted.Length | Should -BeGreaterThan 0
  }

  It 'Should read static metadata from IFW binary-content resources' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw.exe' -Operation @([pscustomobject]@{ Name = 'CreateShortcut'; Data = '<operation><arguments><argument>Example.lnk</argument></arguments></operation>' }) -InstallerXml @'
<Installer>
  <Name>Example.QtIFW</Name>
  <Version>1.2.3</Version>
  <Title>Example Qt IFW</Title>
  <Publisher>Example Publisher</Publisher>
  <ProductUrl>https://example.invalid</ProductUrl>
  <TargetDir>@ApplicationsDir@/Example</TargetDir>
  <StartMenuDir>Example</StartMenuDir>
  <MaintenanceToolName>example-maintenance</MaintenanceToolName>
  <ProductUUID>{11111111-2222-3333-4444-555555555555}</ProductUUID>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'Qt Installer Framework'
    $Info.BinaryMarker | Should -Be 'Installer'
    $Info.PackageName | Should -Be 'Example.QtIFW'
    $Info.DisplayVersion | Should -Be '1.2.3'
    $Info.Publisher | Should -Be 'Example Publisher'
    $Info.ProductCode | Should -Be '{11111111-2222-3333-4444-555555555555}'
    $Info.MaintenanceToolName | Should -Be 'example-maintenance'
    $Info.InstallerConfigSource | Should -Be ':/installer-config/config.xml'
    $Info.OperationCount | Should -Be 1
    $Info.Operations[0].Name | Should -Be 'CreateShortcut'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.CommandLineInterface | Should -Be 'Enabled'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeFalse
    $Info.InstallLocationSwitch | Should -Be '--root "<INSTALLPATH>"'
    $Info.SupportsExistingInstallationOverride | Should -BeFalse
    $Info.ExistingInstallationMarker | Should -Be '@ApplicationsDir@/Example\example-maintenance.exe'
    $Info.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Info.Scope | Should -Be 'user'
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.UserScopeSwitch | Should -Be 'AllUsers=false'
    $Info.MachineScopeSwitch | Should -Be 'AllUsers=true'
    Read-ScopeFromQtInstallerFramework -Path $Fixture | Should -Be 'user'
    Read-SupportedScopesFromQtInstallerFramework -Path $Fixture | Should -Be @('user', 'machine')
    Test-QtInstallerFrameworkDualScope -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkCLI -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSilentInstallation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeFalse
    Test-QtInstallerFrameworkSupportsExistingInstallationOverride -Path $Fixture | Should -BeFalse
    Read-UpgradeBehaviorFromQtInstallerFramework -Path $Fixture | Should -Be 'uninstallPrevious'
  }

  It 'Should return verbatim JavaScript with conservative assignment values and review instructions' {
    $ScriptText = @'
function Controller() {
  // var fakeLine = true;
  /*
  const fakeBlock = "not code";
  */
  var root = "C:\\Apps\\Example";
  let enabled = true;
  var inline = true // a comment is not part of the expression
  const retries = 3;
  var withSemicolon = "a;b";
  var compound = "a" + "b";
  var alias = root;
  var configured = installer.value("TargetDir");
  var dynamic = installer.environmentVariable("TEMP");
  this.mode = 'machine';
  this.mode = installer.value("DynamicMode");
}
'@
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-javascript.exe' -FrameworkVersion '4.11.0' -ScriptText $ScriptText -InstallerXml @'
<Installer>
  <Name>Example.ScriptedQtIFW</Name>
  <Version>1.0.0</Version>
  <Publisher>Example Publisher</Publisher>
  <TargetDir>C:/ConfiguredTarget</TargetDir>
  <ControlScript>controller</ControlScript>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture
    $Script = $Info.JavaScriptResources | Select-Object -First 1

    $Info.JavaScriptCount | Should -Be 1
    $Info.RequiresJavaScriptReview | Should -BeTrue
    $Info.KnownInstallerValues.TargetDir | Should -Be 'C:/ConfiguredTarget'
    $Info.JavaScriptAnalysisInstructions.Count | Should -BeGreaterThan 4
    $Script.Source | Should -Be 'MetaResource[1]'
    $Script.Role | Should -Be 'Controller'
    $Script.RawJavaScript | Should -BeExactly $ScriptText
    ($Script.VariableAssignments | Where-Object Name -EQ 'root').Value | Should -Be 'C:\Apps\Example'
    ($Script.VariableAssignments | Where-Object Name -EQ 'alias').ResolutionSource | Should -Be 'Variable:root'
    ($Script.VariableAssignments | Where-Object Name -EQ 'configured').Value | Should -Be 'C:/ConfiguredTarget'
    ($Script.VariableAssignments | Where-Object Name -EQ 'dynamic').IsResolved | Should -BeFalse
    ($Script.VariableAssignments | Where-Object Name -EQ 'inline').Expression | Should -Be 'true'
    ($Script.VariableAssignments | Where-Object Name -EQ 'inline').Value | Should -BeTrue
    ($Script.VariableAssignments | Where-Object Name -EQ 'withSemicolon').Value | Should -Be 'a;b'
    ($Script.VariableAssignments | Where-Object Name -EQ 'compound').IsResolved | Should -BeFalse
    $Script.VariableAssignments.Name | Should -Not -Contain 'fakeLine'
    $Script.VariableAssignments.Name | Should -Not -Contain 'fakeBlock'
    @($Script.VariableAssignments | Where-Object Name -EQ 'this.mode').Count | Should -Be 2
    @($Script.VariableAssignments | Where-Object Name -EQ 'this.mode')[0].Value | Should -Be 'machine'
    @($Script.VariableAssignments | Where-Object Name -EQ 'this.mode')[1].Expression | Should -Be 'installer.value("DynamicMode")'
  }

  It 'Should decode performed-operation XML into system and ARP effects' {
    $Operations = @(
      [pscustomobject]@{ Name = 'CreateShortcut'; Data = '<operation><arguments><argument>@TargetDir@\app.exe</argument><argument>@StartMenuDir@\Example.lnk</argument><argument>--open</argument></arguments><values><value name="admin" type="bool">false</value></values></operation>' }
      [pscustomobject]@{ Name = 'RegisterFileType'; Data = '<operation><arguments><argument>qtf</argument><argument>&quot;@TargetDir@\app.exe&quot; &quot;%1&quot;</argument><argument>Qt IFW document</argument><argument>application/x-qtifw-test</argument><argument>@TargetDir@\app.exe,0</argument><argument>ProgId=Example.QtIfw.Document</argument></arguments></operation>' }
      [pscustomobject]@{ Name = 'GlobalConfig'; Data = '<operation><arguments><argument>HKEY_CURRENT_USER\Software\Classes\qtifw-demo</argument><argument>URL Protocol</argument><argument></argument></arguments></operation>' }
      [pscustomobject]@{ Name = 'GlobalConfig'; Data = '<operation><arguments><argument>HKEY_CURRENT_USER\Software\Classes\qtifw-demo\shell\open\command</argument><argument>Default</argument><argument>&quot;@TargetDir@\app.exe&quot; &quot;%1&quot;</argument></arguments></operation>' }
      [pscustomobject]@{ Name = 'EnvironmentVariable'; Data = '<operation><arguments><argument>QT_IFW_HOME</argument><argument>@TargetDir@</argument><argument>true</argument><argument>false</argument></arguments></operation>' }
      [pscustomobject]@{ Name = 'Settings'; Data = '<operation><arguments><argument>path=@TargetDir@\settings.ini</argument><argument>method=set</argument><argument>key=General/Enabled</argument><argument>value=true</argument><argument>UNDOOPERATION</argument><argument></argument></arguments></operation>' }
    )
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-operation-effects.exe' -FrameworkVersion '4.11.0' -Operation $Operations -InstallerXml @'
<Installer>
  <Name>Example.QtIFWEffects</Name>
  <Version>2.0.0</Version>
  <Title>Example effects</Title>
  <Publisher>Example Publisher</Publisher>
  <ProductUrl>https://example.invalid/effects</ProductUrl>
  <TargetDir>@ApplicationsDir@/ExampleEffects</TargetDir>
  <MaintenanceToolName>effects-maintenance</MaintenanceToolName>
  <ProductUUID>{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}</ProductUUID>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.OperationCount | Should -Be 6
    $Info.Operations[0].Arguments | Should -HaveCount 3
    $Info.Operations[0].Values.admin | Should -BeFalse
    $Info.Operations[0].ValueRecords[0].IsEncoded | Should -BeFalse
    $Info.Operations[5].IsUndoOperation | Should -BeTrue
    $Info.Operations[5].PerformArguments | Should -HaveCount 4
    $Info.ShortcutEffects | Should -HaveCount 1
    $Info.ShortcutEffects[0].ShortcutPath | Should -Be '@StartMenuDir@\Example.lnk'
    $Info.FileExtensions | Should -Contain 'qtf'
    $Info.FileAssociationEffects[0].DefaultProgId | Should -Be 'Example.QtIfw.Document'
    $Info.Protocols | Should -Contain 'qtifw-demo'
    $Info.ProtocolEffects[0].Command | Should -Be '"@TargetDir@\app.exe" "%1"'
    @($Info.RegistryWrites | Where-Object { $_.Key -eq 'Environment' -and $_.Name -eq 'QT_IFW_HOME' }) | Should -HaveCount 1
    @($Info.FileSystemEffects | Where-Object { $_.Action -eq 'ModifySettingsFile' -and $_.Path -eq '@TargetDir@\settings.ini' }) | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
    $Info.AppsAndFeaturesEffects[0].Key | Should -Be 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}'
  }

  It 'Should warn when IFW ProductUUID is generated at install time' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-random-productuuid.exe' -FrameworkVersion '4.11.0' -InstallerXml @'
<Installer>
  <Name>Example.RandomCode</Name>
  <Version>4.5.6</Version>
  <Publisher>Example Publisher</Publisher>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'Example.RandomCode'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.RequiresExplicitInstallLocation | Should -BeTrue
    $Info.Warnings | Should -Contain 'No embedded ProductUUID was found. Qt IFW generates the Windows uninstall key at install time unless a script/config sets ProductUUID.'
    $Info.Warnings | Should -Contain 'The embedded TargetDir is empty, so command-line installation requires --root with an absolute installation path.'
    { Read-ProductCodeFromQtInstallerFramework -Path $Fixture } | Should -Throw
  }

  It 'Should not recommend command-line scope overrides when IFW disables CLI support' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-disable-cli.exe' -InstallerXml @'
<Installer>
  <Name>Example.NoCli</Name>
  <Version>1.0.0</Version>
  <Publisher>Example Publisher</Publisher>
  <DisableCommandLineInterface>true</DisableCommandLineInterface>
</Installer>
'@

    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.Scope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.SupportsCommandLineScopeOverride | Should -BeFalse
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.CommandLineInterface | Should -Be 'Disabled'
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.UserScopeSwitch | Should -BeNullOrEmpty
    $Info.MachineScopeSwitch | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain 'The embedded IFW config disables the command-line interface, so silent installation and AllUsers scope overrides are unavailable.'
  }

  It 'Should identify the Qt Linguist installer as GUI-only' {
    $Fixture = Get-InstallerFixture -Name 'qtlinguistinstaller-5.12.2.exe' -Url 'https://download.qt.io/linguist_releases/qtlinguistinstaller-5.12.2.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'Qt Linguist'
    $Info.InterfaceVariant | Should -Be 'GUI'
    $Info.PESubsystem.Name | Should -Be 'WindowsGui'
    $Info.CommandLineInterface | Should -Be 'Unavailable'
    $Info.SupportsSilentInstallation | Should -BeFalse
    $Info.RequiresExplicitInstallLocation | Should -BeNullOrEmpty
    $Info.SupportedScopes | Should -Be @('user')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.UserScopeSwitch | Should -BeNullOrEmpty
    $Info.MachineScopeSwitch | Should -BeNullOrEmpty
    $Info.Warnings | Should -Contain 'The Qt IFW launcher does not contain the modern command-line interface; GUI-only installers do not support WinGet-compatible silent installation.'
    Test-QtInstallerFrameworkCLI -Path $Fixture | Should -BeFalse
    Test-QtInstallerFrameworkSilentInstallation -Path $Fixture | Should -BeFalse
  }

  It 'Should identify the current MSYS2 installer as CLI-capable' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'MSYS2'
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.PESubsystem.Name | Should -Be 'WindowsCui'
    $Info.CommandLineInterface | Should -Be 'Enabled'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeTrue
    $Info.SupportsExistingInstallationOverride | Should -BeFalse
    $Info.RecommendedUpgradeBehavior | Should -Be 'uninstallPrevious'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.CommandLineInterfaceEvidence.FoundMarkers | Should -Contain 'accept-licenses'
    $Info.CommandLineInterfaceEvidence.FoundMarkers | Should -Contain 'check-updates'
    $Info.JavaScriptCount | Should -Be 2
    $Info.JavaScriptResources.Source | Should -Contain ':/installer-config/control_js'
    $Info.JavaScriptResources.Source | Should -Contain ':/com.msys2.root/installscript.js'
    $Info.JavaScriptResources.Role | Should -Contain 'Controller'
    $Info.JavaScriptResources.Role | Should -Contain 'Component'
    $Info.JavaScriptResources.Source | Should -Not -Contain 'MetaResource[0]'
    ($Info.JavaScriptResources | Where-Object Role -EQ 'Component').RawJavaScript | Should -BeLike '*function Component()*'
    @((($Info.JavaScriptResources | Where-Object Role -EQ 'Component').VariableAssignments | Where-Object Name -EQ 'systemDrive')).Count | Should -Be 2
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeTrue
    Test-QtInstallerFrameworkSupportsExistingInstallationOverride -Path $Fixture | Should -BeFalse
  }

  It 'Should use the embedded target directory of a CLI-capable reMarkable installer' {
    $Fixture = Get-InstallerFixture -Name 'reMarkable-3.8.0.810-win64-LDv4m9Vntg.exe' -Url 'https://downloads.remarkable.com/desktop/production/win/reMarkable-3.8.0.810-win64-LDv4m9Vntg.exe'
    $Info = Get-QtInstallerFrameworkInfo -Path $Fixture

    $Info.PackageName | Should -Be 'reMarkable'
    $Info.PESubsystem.Name | Should -Be 'WindowsCui'
    $Info.InterfaceVariant | Should -Be 'CLI'
    $Info.SupportsSilentInstallation | Should -BeTrue
    $Info.DefaultInstallLocation | Should -Be '@ApplicationsDirX64@/reMarkable'
    $Info.HasDefaultTargetDir | Should -BeTrue
    $Info.RequiresExplicitInstallLocation | Should -BeFalse
    Test-QtInstallerFrameworkRequiresInstallLocation -Path $Fixture | Should -BeFalse
  }

  It 'Should expand files from embedded IFW metadata resources' {
    $Fixture = New-TestQtInstallerFrameworkFixture -Name 'synthetic-ifw-expand.exe' -FrameworkVersion '4.11.0' -InstallerXml @'
<Installer>
  <Name>Example.Expand</Name>
  <Version>1.0.0</Version>
  <Publisher>Example Publisher</Publisher>
</Installer>
'@
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-ifw-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'config.xml' -CollisionAction Rename
      $ConfigPath = Join-Path $Result 'installer-config\config.xml'

      $ConfigPath | Should -Exist
      (Get-Content -LiteralPath $ConfigPath -Raw) | Should -BeLike '*<Name>Example.Expand</Name>*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an IFW resource path that escapes the destination' {
    $Module = Get-Module QtInstallerFramework | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    {
      & $Module {
        Resolve-QtInstallerFrameworkExtractionPath -DestinationPath $env:TEMP -RelativePath '..\escape.exe'
      }
    } | Should -Throw '*escapes the destination*'
  }

  It 'Should expand the Qt-supported <Format> package format' -ForEach @(
    @{ Format = 'tar' }
    @{ Format = 'tar.gz' }
    @{ Format = 'tar.bz2' }
    @{ Format = 'tar.xz' }
    @{ Format = 'zip' }
    @{ Format = '7z' }
    @{ Format = 'qbsp' }
  ) {
    $ArchivePath = New-TestQtPackageArchive -Format $Format
    $Destination = Join-Path $TestDrive "qt-package-$($Format.Replace('.', '-'))"
    $Module = Get-Module QtInstallerFramework | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1

    $Result = & $Module {
      param($ArchivePath, $Destination)
      Expand-QtInstallerFrameworkPackageArchive -Path $ArchivePath -DestinationPath $Destination -RelativeRoot 'component' -Name 'payload.txt' -CollisionAction Rename -MaximumExpandedBytes 1048576
    } $ArchivePath $Destination

    $Result.Files | Should -HaveCount 1
    $Result.Files[0].FullName | Should -Be (Join-Path $Destination 'component\payload.txt')
    (Get-Content -LiteralPath $Result.Files[0].FullName -Raw) | Should -BeExactly 'Qt IFW package format regression'
  }

  It 'Should selectively expand a file from a real IFW package archive' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'msys2-ifw-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Result = Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'msys-2.0.dll' -CollisionAction Rename
      $ExtractedFiles = @(Get-ChildItem -Path $Result -Recurse -File)

      $ExtractedFiles | Should -HaveCount 1
      $ExtractedFiles[0].Name | Should -Be 'msys-2.0.dll'
      $ExtractedFiles[0].Length | Should -BeGreaterThan 0
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should reject an IFW package resource above the configured output limit' {
    $Fixture = Get-InstallerFixture -Name 'msys2-x86_64-latest.exe' -Url 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-x86_64-latest.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'msys2-ifw-limited'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      { Expand-QtInstallerFramework -Path $Fixture -DestinationPath $ExpandedPath -Name 'msys-2.0.dll' -MaximumExpandedBytes 1048576 -CollisionAction Rename } | Should -Throw '*exceeds the 1048576-byte limit*'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
