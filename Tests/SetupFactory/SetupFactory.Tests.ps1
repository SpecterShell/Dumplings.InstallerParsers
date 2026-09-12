. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

# SPDX-License-Identifier: GPL-3.0-or-later

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Infrastructure\InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries\Installers\SetupFactory.psm1') -Force
}

Describe 'Setup Factory static parser' {
  It 'preserves literal registry values for protocol and file association analysis' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Writes = & $Module {
      $Text = @'
Registry.SetValue("HKCU", "Software\Classes\example", "URL Protocol", "")
Registry.SetValue("HKCU", "Software\Classes\example\shell\open\command", "", "\"%AppFolder%\Example.exe\" \"%1\"")
Registry.SetValue("HKCU", "Software\Classes\.example", "", "Example.Document")
'@
      @(Get-SetupFactoryLiteralRegistryWrite -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)))
    }

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Writes[0].Value | Should -Be ''
    $Writes[0].Key | Should -Be 'Software\Classes\example'
    $Writes[1].Value | Should -Be '"%AppFolder%\Example.exe" "%1"'
    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
  }

  It 'counts computed registry actions without treating them as literal evidence' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $Text = @'
Registry.SetValue("HKCR", "demo", "URL Protocol", "")
Registry.SetValue(rootName, "Software\Classes\computed", "", "value")
'@
      $Unresolved = 0
      $Writes = @(Get-SetupFactoryLiteralRegistryWrite -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)) -UnresolvedCount ([ref]$Unresolved))
      [pscustomobject]@{ Writes = $Writes; Unresolved = $Unresolved }
    }

    $Result.Writes | Should -HaveCount 1
    $Result.Writes[0].Root | Should -Be 'HKCR'
    $Result.Unresolved | Should -Be 1
  }

  It 'does not treat unrelated registry writes as Apps and Features evidence' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Entries = & $Module {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Classes\Example.Document'; Name = ''; Value = 'Example'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKCR'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Not.Arp'; Name = 'DisplayName'; Value = 'Not ARP'; Type = 'REG_SZ' }
      )
      @(Get-SetupFactoryArpEntry -RegistryWrite $Writes -Variables @{})
    }

    $Entries | Should -BeNullOrEmpty
  }

  It 'keeps visible and hidden custom uninstall entries separate' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Entries = & $Module {
      $Writes = @(
        [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Visible.Product'; Name = 'DisplayName'; Value = 'Visible Product'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Visible.Product'; Name = 'Publisher'; Value = 'Example Publisher'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product'; Name = 'DisplayName'; Value = 'Hidden Product'; Type = 'REG_SZ' }
        [pscustomobject]@{ Root = 'HKLM'; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Hidden.Product'; Name = 'SystemComponent'; Value = '1'; Type = 'REG_DWORD' }
      )
      @(Get-SetupFactoryArpEntry -RegistryWrite $Writes -Variables @{})
    }

    $Entries.Count | Should -Be 2
    ($Entries | Where-Object ProductCode -CEQ 'Visible.Product').Scope | Should -Be 'user'
    ($Entries | Where-Object ProductCode -CEQ 'Visible.Product').IsVisible | Should -BeTrue
    ($Entries | Where-Object ProductCode -CEQ 'Hidden.Product').Scope | Should -Be 'machine'
    ($Entries | Where-Object ProductCode -CEQ 'Hidden.Product').IsVisible | Should -BeFalse
  }

  It 'decodes the official zlib blast PKWARE test vector with an output limit' {
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.PkwareBlast').Type) {
      Add-Type -Path (Join-Path $Script:DumplingsModuleRoot 'Assets\Source\SetupFactory\PkwareBlast.cs')
    }
    $Compressed = [byte[]](0x00, 0x04, 0x82, 0x24, 0x25, 0x8F, 0x80, 0x7F)
    $Decoded = [Dumplings.InstallerParsers.PkwareBlast]::Decode($Compressed, 13)
    [Text.Encoding]::ASCII.GetString($Decoded) | Should -Be 'AIAIAIAIAIAIA'
    { [Dumplings.InstallerParsers.PkwareBlast]::Decode($Compressed, 12) } | Should -Throw '*configured limit*'
  }

  It 'rejects a truncated PKWARE stream without hanging' {
    if (-not ([System.Management.Automation.PSTypeName]'Dumplings.InstallerParsers.PkwareBlast').Type) {
      Add-Type -Path (Join-Path $Script:DumplingsModuleRoot 'Assets\Source\SetupFactory\PkwareBlast.cs')
    }
    { [Dumplings.InstallerParsers.PkwareBlast]::Decode([byte[]](0, 4, 0), 1024) } | Should -Throw '*end marker*'
  }

  It 'parses the real Bicom Systems OutCALL installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'OutCALL'
    $Info.DisplayVersion | Should -Be '2.0'
    $Info.Publisher | Should -Be 'Bicom Systems'
    $Info.ProductCode | Should -Be 'OutCALL2.0'
    $Info.Scope | Should -Be 'machine'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
  }

  It 'selectively expands the runtime and metadata records from OutCALL when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'outcall'

    $Files = @(Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'irsetup.*' -RawEntries -CollisionAction Error)

    $Files.Name | Sort-Object | Should -Be @('irsetup.dat', 'irsetup.exe')
    $Runtime = [IO.File]::OpenRead((Join-Path $Destination 'irsetup.exe'))
    try {
      $Runtime.ReadByte() | Should -Be 0x4D
      $Runtime.ReadByte() | Should -Be 0x5A
    } finally {
      $Runtime.Dispose()
    }
    (Get-Item -LiteralPath (Join-Path $Destination 'irsetup.dat')).Length | Should -BeGreaterThan 0
  }

  It 'selectively expands and verifies one installed application file' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'outcall-installed'

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'icudt53.dll' -CollisionAction Error

    $File.Name | Should -Be 'icudt53.dll'
    $File.Length | Should -Be 21529088
  }

  It 'restores caller-owned stream positions during layout and catalog reads' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'OutCALL-2.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Stream = [IO.File]::OpenRead($Path)
    try {
      $Stream.Position = 17
      $Overlay = & $Module { param($InstallerPath, $InstallerStream) Get-SetupFactoryOverlayInfo -Path $InstallerPath -Stream $InstallerStream } $Path $Stream
      $Stream.Position | Should -Be 17
      $Catalog = & $Module { param($InstallerPath, $InstallerStream) Get-SetupFactoryArchiveCatalog -Path $InstallerPath -Stream $InstallerStream } $Path $Stream
      $Stream.Position | Should -Be 17
      $Overlay.ProfileId | Should -Be 'setup-factory-8-plus'
      $Catalog.Entries.Name | Should -Contain 'irsetup.dat'
    } finally {
      $Stream.Dispose()
    }
  }

  It 'parses the real Bicom Systems Communicator installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Communicator-7.6.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    (Get-DumplingsTestFixtureHash -Path $Path) | Should -Be 'C2B8713B80533ACCA04B850B79C686D3DFDED2EDEE91168361128591FDEE7D6B'
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'Communicator'
    $Info.ProductCode | Should -Be 'Communicator4'
    $Info.Scope | Should -Be 'machine'
    $Info.DependencyPayloads.FileName | Should -Be 'vc_redist.x64.exe'
    $Info.InstalledFileCatalog.ExtractableEntryCount | Should -Be 750
    $Info.InstalledFileCatalog.UnavailableEntryCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.CanExpandPartial | Should -BeFalse
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Payload.Truncated'
    $RegistryDiagnostic = $Info.Diagnostics | Where-Object Id -EQ 'SetupFactory.Metadata.RegistryActionsUnresolved'
    $RegistryDiagnostic.AffectedFields | Should -Be @('AppsAndFeaturesEntries', 'FileExtensions', 'Protocols')
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.UnresolvedFields | Should -Not -Contain 'Scope'
  }

  It 'extracts application files and separately framed prerequisites from current media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Communicator-7.6.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The current Setup Factory fixture is not available'; return }
    $AvailableDestination = Join-Path $TestDrive 'communicator-available'
    $DependencyDestination = Join-Path $TestDrive 'communicator-dependency'

    $Available = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $AvailableDestination -Name 'sounds\fax.wav' -CollisionAction Error
    $Dependency = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $DependencyDestination -Name '_dependencies\vc_redist.x64.exe' -RawEntries -CollisionAction Error

    $Available.Length | Should -Be 273140
    $Dependency.Length | Should -Be 14876264
    $DependencyStream = [IO.File]::OpenRead($Dependency.FullName)
    try {
      $DependencyMagic = [byte[]]::new(2)
      $DependencyStream.ReadExactly($DependencyMagic)
      $DependencyMagic | Should -Be ([byte[]](0x4D, 0x5A))
    } finally {
      $DependencyStream.Dispose()
    }
  }

  It 'parses the real Bicom Systems gloCOM installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'gloCOM-7.6.0.4.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    (Get-DumplingsTestFixtureHash -Path $Path) | Should -Be '40E8CB1A1D79B592278E5925CA9EEE9438DF7F9B4F4F321E59F9EF684CC5F5A5'
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'gloCOM'
    $Info.ProductCode | Should -Be 'gloCOM4'
    $Info.Scope | Should -Be 'machine'
    $Info.DependencyPayloads.FileName | Should -Be 'vc_redist.x64.exe'
    $Info.InstalledFileCatalog.ExtractableEntryCount | Should -Be 766
    $Info.InstalledFileCatalog.UnavailableEntryCount | Should -Be 0
    $Info.CanExpand | Should -BeTrue
    $Info.CanExpandPartial | Should -BeFalse
  }

  It 'extracts the final installed-file record from complete Bicom media' -ForEach @(
    @{ Fixture = 'Communicator-7.6.0.exe'; EntryCount = 750 }
    @{ Fixture = 'gloCOM-7.6.0.4.exe'; EntryCount = 766 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The complete Bicom Setup Factory fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $LastEntry = $Info.PayloadCatalog[-1]
    $Destination = Join-Path $TestDrive ([IO.Path]::GetFileNameWithoutExtension($Fixture) + '-tail')

    $Extracted = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name $LastEntry.Name -CollisionAction Error

    $Info.PayloadCatalog | Should -HaveCount $EntryCount
    $LastEntry.Name | Should -Be 'opus.dll'
    $Extracted.Length | Should -Be 374784
    $Extracted.Length | Should -Be $LastEntry.ExpandedSize
  }

  It 'parses the real Locklizard installer without inventing a ProductCode' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SafeguardPDFViewer_v3.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'Locklizard Safeguard - PDF Viewer'
    $Info.DisplayVersion | Should -Be '3.0.2.231'
    $Info.Publisher | Should -Be 'Locklizard Ltd.'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
  }

  It 'selects both observed Setup Factory 7 runtime-prefix routes' -ForEach @(
    @{ Fixture = 'SetupFactory-7.0.1-ReNamer.exe'; Prefix = 8; Name = 'ReNamer'; Version = '1.80'; PayloadCount = 1 }
    @{ Fixture = 'SetupFactory-7.0.3-setup365dni.exe'; Prefix = 8; Name = '365dní'; Version = '6.0.7'; PayloadCount = 107 }
    @{ Fixture = 'SetupFactory-7.0.6-FLVPlayerSetup.exe'; Prefix = 9; Name = 'FLV Player'; Version = '2.0 '; PayloadCount = 1 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-7'
    $Info.ParserVersionInfo.HeaderPrefixLength | Should -Be $Prefix
    $Info.DisplayVersion | Should -Be $Version
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.CanExpand | Should -BeTrue
    if ($Name) { $Info.DisplayName | Should -Be $Name }
  }

  It 'keeps modern archive revisions separate from the Setup Factory release identity' -ForEach @(
    @{ Fixture = 'SetupFactory-8.1.1008.0-builder.exe'; Builder = '8.1.1008.0'; Major = 8; Product = 'Setup Factory 8.0 Trial'; PayloadCount = 1083; DestinationPadding = 10; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-9.0.3-trial.exe'; Builder = '9.0.3.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPadding = 10; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-9.0.4-trial.exe'; Builder = '9.0.4.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPadding = 10; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-9.1.1-trial.exe'; Builder = '9.1.1.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPadding = 11; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-9.2.0-trial.exe'; Builder = '9.2.0.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPadding = 11; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-9.5.1-trial.exe'; Builder = '9.5.1.0'; Major = 9; Product = 'Setup Factory 9 Trial'; PayloadCount = 1169; DestinationPadding = 11; CompressionPrefixLength = 0 }
    @{ Fixture = 'SetupFactory-10.2.0-trial.exe'; Builder = '10.2.0.0'; Major = 10; Product = 'Setup Factory 10 Trial'; PayloadCount = 1258; DestinationPadding = 11; CompressionPrefixLength = 1 }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared Setup Factory builder fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-8-plus'
    $Info.ParserVersionInfo.FormatGeneration | Should -Be 'Modern8Plus'
    $Info.ParserVersionInfo.BuilderVersion | Should -Be $Builder
    $Info.ParserVersionInfo.MajorVersion | Should -Be $Major
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be $Builder
    $Info.EmbeddedRuntimeInfo.IsTrusted | Should -BeTrue
    $Info.EmbeddedRuntimeInfo.IsProfileCompatible | Should -BeTrue
    $Info.DisplayName | Should -Be $Product
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.InstalledFileCatalog.DestinationPadding | Should -Be $DestinationPadding
    $Info.InstalledFileCatalog.CompressionPrefixLength | Should -Be $CompressionPrefixLength
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Release.StructuralProfileMismatch'
    [regex]::Matches($Info.PayloadCatalog[0].SourcePath, ':').Count | Should -Be 1
    $Info.PayloadCatalog[0].LastWriteTime | Should -BeOfType [datetime]
    $Info.CanExpand | Should -BeTrue
  }

  It 'decodes the full Setup Factory 4 conclusion object without fabricating disabled ARP metadata' {
    $Fixture = 'SetupFactory-4-inst95.exe'
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1

    $Overlay = & $Module { param($InstallerPath) Get-SetupFactoryOverlayInfo -Path $InstallerPath } $Path

    $Overlay.ProfileId | Should -Be 'setup-factory-4'
    $Overlay.FormatGeneration | Should -Be 'Classic4'
    $Overlay.IsSupported | Should -BeTrue
    $Overlay.SupportsMetadata | Should -BeTrue
    Test-SetupFactory -Path $Path | Should -BeTrue
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
    $Info.PayloadCatalog.Count | Should -Be 1
    $Info.CanExpand | Should -BeTrue
    $Info.ParserVersionInfo.MetadataProfile | Should -BeExactly 'Classic4-Object24'
    $Info.UninstallConfiguration.Offset | Should -Be 0x90
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeFalse
    $Info.UninstallConfiguration.ControlPanelDescription | Should -BeExactly 'My Application'
    $Info.UninstallConfiguration.UniqueRegistryKey | Should -BeExactly 'MyApp'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyProductBlockIncomplete'
    $Info.Diagnostics.Id | Should -Contain 'SetupFactory.Metadata.Classic4ProductFieldsUnavailable'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    $Info.AppsAndFeaturesEntries | Should -BeNullOrEmpty
    $Info.RegistryWrites | Should -BeNullOrEmpty
  }

  It 'decodes Setup Factory 5 and 6 product and built-in uninstall metadata' -ForEach @(
    @{ Fixture = 'SetupFactory-5-ttally11.exe'; ProfileId = 'setup-factory-5'; Generation = 'Legacy5'; MetadataRoute = 'irdat-v5'; PayloadCount = 4; DisplayName = 'Text Tally 1.1'; DisplayVersion = '1.1'; Publisher = 'Harmony Hollow Software'; ProductCode = 'Text Tally 1.1'; DefaultInstallLocation = 'C:\Program Files\TxtTally' }
    @{ Fixture = 'SetupFactory-6-suf60ev.exe'; ProfileId = 'setup-factory-6'; Generation = 'Legacy6'; MetadataRoute = 'irdat-v6'; PayloadCount = 791; DisplayName = 'Setup Factory 6.0 Demo'; DisplayVersion = '6.0.1.2'; Publisher = 'Indigo Rose Corporation'; ProductCode = 'Setup Factory 6.0 Demo'; DefaultInstallLocation = '%ProgramFiles%\Setup Factory 6.0 Demo' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared historical Setup Factory fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be $ProfileId
    $Info.ParserVersionInfo.FormatGeneration | Should -Be $Generation
    $Info.ParserVersionInfo.MetadataRoute | Should -Be $MetadataRoute
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    $Info.DisplayName | Should -Be $DisplayName
    $Info.DisplayVersion | Should -Be $DisplayVersion
    $Info.Publisher | Should -Be $Publisher
    $Info.ProductCode | Should -Be $ProductCode
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be $DefaultInstallLocation
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.AppsAndFeaturesEntries | Should -HaveCount 1
    $Info.AppsAndFeaturesEntries[0].ProductCode | Should -Be $ProductCode
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeTrue
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
  }

  It 'decodes legacy product settings when optional password data is absent and preserves a disabled uninstaller' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Metadata = & $Module {
      $Bytes = [Collections.Generic.List[byte]]::new()
      $Bytes.AddRange([byte[]]::new(64))
      $Bytes.Add(0)
      foreach ($Value in 'Control Panel Name', 'Product.Key') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
      }
      $Bytes.Add(0)
      foreach ($Value in 'Uninstall Product', '', '%AppDir%\irunin.ini') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
        if ($Value -eq 'Uninstall Product') { $Bytes.Add(0) }
      }
      $Bytes.AddRange([byte[]]::new(32))
      foreach ($Value in 'Product', 'Publisher', 'Tagline', '1.2.3', 'Copyright', 'https://example.invalid', '%ProgramFiles%\Product', 'Product') {
        $Encoded = [Text.Encoding]::UTF8.GetBytes($Value)
        $Bytes.Add([byte]$Encoded.Length)
        $Bytes.AddRange($Encoded)
      }
      $Bytes.AddRange([byte[]](0, 3, 1))
      $Log = [Text.Encoding]::UTF8.GetBytes('%AppDir%\setuplog.txt')
      $Bytes.Add([byte]$Log.Length)
      $Bytes.AddRange($Log)
      $Bytes.AddRange([byte[]]::new(32))
      $Bytes.AddRange([Text.Encoding]::ASCII.GetBytes('CImageInfo'))

      Get-SetupFactoryLegacyMetadata -Bytes $Bytes.ToArray()
    }

    $Metadata.Product.ProductName | Should -Be 'Product'
    $Metadata.Product.ProductVersion | Should -Be '1.2.3'
    $Metadata.Uninstall.IncludeUninstall | Should -BeFalse
    $Metadata.Uninstall.UniqueRegistryKey | Should -Be 'Product.Key'
  }

  It 'extracts a compressed-flagged empty file from Setup Factory 5 media' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Setup Factory 5 builder fixture is not available'; return }
    $Destination = Join-Path $TestDrive 'setup-factory-5-empty'

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath $Destination -Name 'data.001' -CollisionAction Error

    $File.Name | Should -Be 'data.001'
    $File.Length | Should -Be 0
  }

  It 'extracts and verifies compressed files from the supplied Setup Factory 7 and 8 builders' -ForEach @(
    @{ Fixture = 'SetupFactory-7.0.6.1-builder.exe'; Destination = 'setup-factory-7-compressed' }
    @{ Fixture = 'SetupFactory-8.1.1008.0-builder.exe'; Destination = 'setup-factory-8-compressed' }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The supplied Setup Factory builder fixture is not available'; return }

    $File = Expand-SetupFactoryInstaller -Path $Path -DestinationPath (Join-Path $TestDrive $Destination) -Name 'Data\Importers\suf60_import.xml' -CollisionAction Error

    $File.Length | Should -Be 146
    (Get-FileHash -LiteralPath $File.FullName).Hash | Should -Be 'F7828D53576E9B447C38ECF69231B0FB41AAF5E8322CFD5C81A39A60B25D2978'
  }

  It 'recognizes official historical builder installers with changing runtime resources' -ForEach @(
    @{ Fixture = 'SetupFactory-4.0-builder.exe'; ProfileId = 'setup-factory-4'; Builder = '4.0.0.0'; Embedded = '4.0.0.8'; RuntimeProduct = 'Indigo Rose Corporation Setup'; RuntimeFile = 'setup.exe'; ContainerCount = 11; PayloadCount = 54; Product = 'Setup Factory 4.0 Evaluation'; ProductCode = 'SetupFactory4Demo' }
    @{ Fixture = 'SetupFactory-5.0.1.6-builder.exe'; ProfileId = 'setup-factory-5'; Builder = '5.0.1.6'; Embedded = '5.0.1.6'; RuntimeProduct = 'Setup Factory 5.0 Runtime Module setup32'; RuntimeFile = 'setup32.exe'; ContainerCount = 5; PayloadCount = 141; Product = 'Setup Factory 5.0'; ProductCode = 'Setup_Factory_5_EV' }
    @{ Fixture = 'SetupFactory-6.0.1.4-builder.exe'; ProfileId = 'setup-factory-6'; Builder = '6.0.1.4'; Embedded = '6.0.1.4'; RuntimeProduct = 'Setup Factory 6.0 Runtime Module'; RuntimeFile = 'SUF60Runtime.exe'; ContainerCount = 5; PayloadCount = 923; Product = 'Setup Factory 6.0 Demo'; ProductCode = 'Setup Factory 6.0 Demo' }
    @{ Fixture = 'SetupFactory-7.0.6.1-builder.exe'; ProfileId = 'setup-factory-7'; Builder = '7.0.6.1'; Embedded = '7.0.6.1'; RuntimeProduct = 'Setup Factory 7.0 Runtime'; RuntimeFile = 'suf70_rt.exe'; ContainerCount = 5; PayloadCount = 933; Product = 'Setup Factory 7.0 Trial'; ProductCode = $null }
  ) {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Fixture)
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive builder fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be $ProfileId
    $Info.ParserVersionInfo.BuilderVersion | Should -Be $Builder
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be $Embedded
    $Info.EmbeddedRuntimeInfo.ProductName | Should -BeExactly $RuntimeProduct
    $Info.EmbeddedRuntimeInfo.OriginalFilename | Should -BeExactly $RuntimeFile
    $Info.EmbeddedRuntimeInfo.IsTrusted | Should -BeTrue
    $Info.EmbeddedRuntimeInfo.IsProfileCompatible | Should -BeTrue
    $Info.ContainerEntries.Count | Should -Be $ContainerCount
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
    $Info.PayloadCatalog.Count | Should -Be $PayloadCount
    if ($ProductCode) {
      $Info.DisplayName | Should -Be $Product
      $Info.ProductCode | Should -Be $ProductCode
      $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    } else {
      $Info.DisplayName | Should -Be $Product
      $Info.ProductCode | Should -BeNullOrEmpty
    }
  }

  It 'walks the Setup Factory 4 global objects to the built-in ARP identity' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-4.0-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 4 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ProductMetadata.SetupTitle | Should -BeExactly 'Setup'
    $Info.UninstallConfiguration.Offset | Should -Be 0xED
    $Info.ParserVersionInfo.MetadataProfile | Should -BeExactly 'Classic4-Scalar32'
    $Info.UninstallConfiguration.IncludeUninstall | Should -BeTrue
    $Info.UninstallConfiguration.ControlPanelDescription | Should -BeExactly 'Setup Factory 4.0 Evaluation'
    $Info.UninstallConfiguration.UniqueRegistryKey | Should -BeExactly 'SetupFactory4Demo'
    $Info.DisplayName | Should -BeExactly 'Setup Factory 4.0 Evaluation'
    $Info.ProductCode | Should -BeExactly 'SetupFactory4Demo'
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.UnresolvedFields | Should -Not -Contain 'ProductCode'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyIrsetupDatPartial'
  }

  It 'decodes the Setup Factory 4 MFC registry list with its generation-specific enums' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Catalog = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      try {
        $Writer.Write([uint16]2)
        $Writer.Write([uint16]0xFFFF)
        $Writer.Write([uint16]1)
        $Writer.Write([uint16]13)
        $Writer.Write([Text.Encoding]::ASCII.GetBytes('CRegistryData'))
        $Writer.Write([byte]2)
        $Writer.Write([byte]2)
        & $WriteString 'Software\Example'
        $Writer.Write([byte]1)
        & $WriteString 'InstallPath'
        & $WriteString '%AppDir%'
        $Writer.Write([uint16]0x8001)
        $Writer.Write([byte]2)
        $Writer.Write([byte]1)
        & $WriteString 'Software\Example'
        $Writer.Write([byte]0)
        & $WriteString 'Enabled'
        & $WriteString '1'
        $Writer.Flush()
        Get-SetupFactoryRegistryCatalog4 -Bytes $Stream.ToArray()
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Catalog.IsComplete | Should -BeTrue
    $Catalog.DeclaredCount | Should -Be 2
    $Catalog.RegistryWrites | Should -HaveCount 2
    $Catalog.RegistryWrites[0].Root | Should -BeExactly 'HKLM'
    $Catalog.RegistryWrites[0].Type | Should -BeExactly 'REG_SZ'
    $Catalog.RegistryWrites[1].Root | Should -BeExactly 'HKCU'
    $Catalog.RegistryWrites[1].Type | Should -BeExactly 'REG_DWORD'
  }

  It 'decodes the counted Setup Factory 5 CRegistryData table' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 5 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.LegacyActionCatalog.DeclaredCount | Should -Be 4
    $Info.LegacyActionCatalog.Entries | Should -HaveCount 4
    $Info.RegistryWrites | Should -HaveCount 4
    $Info.RegistryWrites[0].Root | Should -BeExactly 'HKCU'
    $Info.RegistryWrites[0].Key | Should -BeExactly 'Software\Indigo Rose\Setup Factory 5.0'
    $Info.RegistryWrites[0].Name | Should -BeExactly 'InstallPath'
    $Info.RegistryWrites[0].Value | Should -BeExactly '%AppDir%'
    $Info.RegistryWrites[0].Type | Should -BeExactly 'REG_SZ'
    $Info.RegistryWrites[3].Type | Should -BeExactly 'REG_DWORD'
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.LegacyRegistryActionsPartial'
  }

  It 'continues past Setup Factory 5 registry records with advanced conditions' {
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Catalog = & $Module {
      $Stream = [IO.MemoryStream]::new()
      $Writer = [IO.BinaryWriter]::new($Stream, [Text.Encoding]::ASCII, $true)
      $WriteVariableString = {
        param ([string]$Value)
        $Encoded = [Text.Encoding]::ASCII.GetBytes($Value)
        $Writer.Write([byte]$Encoded.Length)
        $Writer.Write($Encoded)
      }
      $WriteRegistryRecord = {
        param ([string]$Name, [int]$ConditionCount)
        $Writer.Write([byte]2)
        $Writer.Write([byte]3)
        & $WriteVariableString 'Software\Example'
        & $WriteVariableString $Name
        $Writer.Write([byte]1)
        & $WriteVariableString 'Value'
        $Writer.Write([byte]0)
        & $WriteVariableString ''
        $Writer.Write([byte]0)
        $Writer.Write([uint32]::MaxValue)
        $Writer.Write([uint32]0)
        & $WriteVariableString 'None'
        $Writer.Write([uint16]$ConditionCount)
        if ($ConditionCount) {
          $Writer.Write([uint16]0xFFFF)
          $Writer.Write([uint16]1)
          $ConditionClass = [Text.Encoding]::ASCII.GetBytes('CConditionData')
          $Writer.Write([uint16]$ConditionClass.Length)
          $Writer.Write($ConditionClass)
          & $WriteVariableString '%ProductVer%'
          & $WriteVariableString '1.0'
          $Writer.Write([uint32]0)
          $Writer.Write([uint32]0)
          $Writer.Write([uint32]0)
          & $WriteVariableString ''
          & $WriteVariableString ''
        }
        foreach ($Value in 0..3) { $Writer.Write([uint32]0) }
        foreach ($Value in 0..3) { & $WriteVariableString '' }
      }
      try {
        $Writer.Write([uint16]2)
        $Writer.Write([uint16]0xFFFF)
        $Writer.Write([uint16]1)
        $RegistryClass = [Text.Encoding]::ASCII.GetBytes('CRegistryData')
        $Writer.Write([uint16]$RegistryClass.Length)
        $Writer.Write($RegistryClass)
        & $WriteRegistryRecord 'Conditional' 1
        $Writer.Write([uint16]0x8001)
        & $WriteRegistryRecord 'Unconditional' 0
        $Writer.Flush()
        Get-SetupFactoryRegistryCatalog5 -Bytes $Stream.ToArray() -UninstallOffset ([long]::MaxValue)
      } finally {
        $Writer.Dispose()
        $Stream.Dispose()
      }
    }

    $Catalog.IsComplete | Should -BeTrue
    $Catalog.Entries | Should -HaveCount 2
    $Catalog.Entries[0].Conditions | Should -HaveCount 1
    $Catalog.Entries[0].Conditions[0].OperatorName | Should -BeExactly 'Equals'
    $Catalog.Entries[0].ConditionState | Should -BeExactly 'Unknown'
    $Catalog.RegistryWrites | Should -HaveCount 1
    $Catalog.RegistryWrites[0].Name | Should -BeExactly 'Unconditional'
    $Catalog.UnresolvedCount | Should -Be 1
  }

  It 'decodes Setup Factory 6 action lists and excludes false and uninstall registry branches' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-6.0.1.4-builder.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 6 fixture is not available'; return }

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.LegacyActionCatalog.IsComplete | Should -BeTrue
    $Info.LegacyActionCatalog.Groups.Phase | Should -Be @('Startup', 'BeforeInstalling', 'AfterInstalling', 'Shutdown', 'Uninstall')
    $Info.LegacyActionCatalog.Entries | Should -HaveCount 136
    $Info.RegistryWrites | Should -HaveCount 2
    $Info.RegistryWrites.Name | Should -Be @('InstallDir', 'SCFolder')
    $Info.RegistryWrites.Key | Should -Not -Contain 'Software\Indigo Rose\Setup Factory 6.0\Registration'
    $Info.RegistryWrites.Name | Should -Not -Contain 'My Value'
    $Info.RegistryWrites.ConditionState | Should -Be @('True', 'True')
    $Info.Diagnostics.Id | Should -Not -Contain 'SetupFactory.Metadata.RegistryActionsUnresolved'
  }

  It 'routes a legacy catalog when the application replaces the runtime product version' {
    $Source = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-5.0.1.6-builder.exe')
    if (-not (Test-Path -LiteralPath $Source)) { Set-ItResult -Skipped -Because 'The Internet Archive Setup Factory 5 fixture is not available'; return }
    $Path = Join-Path $TestDrive 'custom-version.exe'
    $Bytes = [IO.File]::ReadAllBytes($Source)
    foreach ($Encoding in [Text.Encoding]::ASCII, [Text.Encoding]::Unicode) {
      $Pattern = $Encoding.GetBytes('5.0.1.6')
      $Replacement = $Encoding.GetBytes('custom!!')
      foreach ($Offset in @(Find-BinaryPattern -Bytes $Bytes -Pattern $Pattern)) {
        [Array]::Copy($Replacement, 0, $Bytes, $Offset, $Replacement.Length)
      }
    }
    [IO.File]::WriteAllBytes($Path, $Bytes)

    $Info = Get-SetupFactoryInfo -Path $Path

    $Info.ParserVersionInfo.ProfileId | Should -Be 'setup-factory-5'
    $Info.ParserVersionInfo.OuterRuntimeVersion | Should -BeNullOrEmpty
    $Info.ParserVersionInfo.BuilderVersion | Should -Be '5.0.1.6'
    $Info.ParserVersionInfo.BuilderVersionSource | Should -Be 'EmbeddedRuntimeVersionResource'
    $Info.ParserVersionInfo.EmbeddedRuntimeVersion | Should -Be '5.0.1.6'
    $Info.ContainerEntries.Name | Should -Contain 'irsetup.dat'
  }

  It 'rejects a valid PE truncated after a Setup Factory signature' {
    $Source = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'SetupFactory-10.2.0-trial.exe')
    if (-not (Test-Path -LiteralPath $Source)) { Set-ItResult -Skipped -Because 'The Setup Factory 10 fixture is not available'; return }
    $Module = Get-Module SetupFactory | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Overlay = & $Module { param($InstallerPath) Get-SetupFactoryOverlayInfo -Path $InstallerPath } $Source
    $Path = Join-Path $TestDrive 'marker-only.exe'
    $InputStream = [IO.File]::OpenRead($Source)
    $OutputStream = [IO.File]::Create($Path)
    try {
      $null = Copy-BoundedStream -Source $InputStream -Destination $OutputStream -MaximumBytes ($Overlay.Offset + 16) -ExpectedBytes ($Overlay.Offset + 16)
    } finally {
      $OutputStream.Dispose()
      $InputStream.Dispose()
    }

    Test-SetupFactory -Path $Path | Should -BeFalse
    { Get-SetupFactoryInfo -Path $Path } | Should -Throw
  }

  It 'rejects a malformed Setup Factory-like input without hanging' {
    $Path = Join-Path $TestDrive 'malformed.exe'
    [IO.File]::WriteAllBytes($Path, [byte[]](0x4D, 0x5A, 0, 0))
    { Get-SetupFactoryInfo -Path $Path } | Should -Throw
  }
}
