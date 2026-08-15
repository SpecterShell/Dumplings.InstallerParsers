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
      [switch]$GuiOnly,
      [string]$FrameworkVersion,
      [object[]]$Operation = @(),
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

    $OperationsStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    foreach ($OperationItem in $Operation) {
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Name
      Add-TestQtByteArray -Bytes $Bytes -Value $OperationItem.Data
    }
    Add-TestInt64LE -Bytes $Bytes -Value $Operation.Count
    $OperationsLength = $Bytes.Count - $OperationsStart

    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexStart = $Bytes.Count
    Add-TestInt64LE -Bytes $Bytes -Value 0
    Add-TestInt64LE -Bytes $Bytes -Value 0
    $CollectionIndexLength = $Bytes.Count - $CollectionIndexStart

    Add-TestInt64LE -Bytes $Bytes -Value ($CollectionIndexStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $CollectionIndexLength
    Add-TestInt64LE -Bytes $Bytes -Value ($MetaStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $MetaBytes.Length
    Add-TestInt64LE -Bytes $Bytes -Value ($OperationsStart - $EndOfExecutable)
    Add-TestInt64LE -Bytes $Bytes -Value $OperationsLength
    Add-TestInt64LE -Bytes $Bytes -Value 1

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
      @{ Name = 'qt-ifw-4.11.0.exe'; Url = 'https://download.qt.io/archive/online_installers/4.11/qt-online-installer-windows-x64-4.11.0.exe'; Version = '4.11.0'; Generation = 'BinaryContent'; Profile = 'ifw-4.2-current-libarchive'; Payload = 'ExternalOrUnavailable' }
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
        $Info.Warnings | Should -Contain 'No embedded package archive was indexed; package data is external, downloadable, or unavailable in this media.'
      }
    }
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
