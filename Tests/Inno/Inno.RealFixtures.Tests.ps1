. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')
. (Join-Path $PSScriptRoot '..\Support\InnoTestSetup.ps1')

Describe 'Inno real installer fixtures' -Tag 'RealFixture', 'Network' {
  It 'Extracts a real VM-compiled Inno 6.7 multi-disk payload across three slices' {
    $FixtureRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Inno\6.7\MultiDisk'
    $Installer = Join-Path $FixtureRoot 'inno-multidisk-6.7.exe'
    $RequiredFiles = [ordered]@{
      'inno-multidisk-6.7.exe'    = '0ACE3DFD9067205799F8CF4CC1BC698C54BA41294721C555BABC2117094839DC'
      'inno-multidisk-6.7-1a.bin' = '330DC7949340688360F3E36A494CF8279D42231D7D4ADD56B5F338324B4968D5'
      'inno-multidisk-6.7-1b.bin' = '9D36138793A30C8532F2AD88593FB7665A88083EF23DD7A157AFDC9D9BBC3152'
      'inno-multidisk-6.7-2a.bin' = '3FC047D5E324E5BBD49B8D6C368ED6EBCAC699AC77D61010F80C7BB68E8FF549'
    }
    if (@($RequiredFiles.Keys | Where-Object { -not (Test-Path -LiteralPath (Join-Path $FixtureRoot $_) -PathType Leaf) }).Count -gt 0) {
      Set-ItResult -Skipped -Because 'The optional VM-compiled Inno multi-disk fixture is not cached.'
      return
    }
    foreach ($File in $RequiredFiles.GetEnumerator()) {
      (Get-FileHash -LiteralPath (Join-Path $FixtureRoot $File.Key) -Algorithm SHA256).Hash | Should -Be $File.Value
    }

    $Info = Get-InnoInfo -Path $Installer
    $Info.UsesExternalDiskSlices | Should -BeTrue
    $Info.SlicesPerDisk | Should -Be 2

    $ExpandedPath = Join-Path $TestDrive 'expanded-real-multidisk'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InnoInstaller -Path $Installer -DestinationPath $ExpandedPath -Name 'payload.bin' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      $Extracted[0].Length | Should -Be 12000000
      (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '5A8E2B4A1B862AFDE493EBCE8CE78817EF317CE9D4E5979EFB86AA968E26886F'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Extracts a real VM-compiled Inno 4.0.8 payload across legacy disk slices' {
    $FixtureRoot = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\Inno\4.0.8\MultiDisk'
    $Installer = Join-Path $FixtureRoot 'inno-multidisk-4.0.8.exe'
    $RequiredFiles = [ordered]@{
      'inno-multidisk-4.0.8.exe'    = '8953104E5D2159E760243CFBA632CAFAE821EBC04B7E1038DDB64C0416897CD3'
      'inno-multidisk-4.0.8-1a.bin' = '6607C7ADA046FB575ECC237E2C324FC5DA57F78B651253E6A040B53C5B7987F6'
      'inno-multidisk-4.0.8-1b.bin' = '6E8E95CF3FB251DAA09C0E5C0B67823E50A1412BEAAFA19DFBE9B3751BBFA8C9'
      'inno-multidisk-4.0.8-2a.bin' = '4935EF4F5227C5F316054B38C6E49686ECFD9C2A624B50DDED5EB0EF28E53829'
      'inno-multidisk-4.0.8-2b.bin' = '0950603E559AB0508D8F0DD5F139846E1286DB6DDD4554711F2A49653FE36F2F'
      'inno-multidisk-4.0.8-3a.bin' = '7EB067AF6A4CC572619011F026D2090529A28DE680F4604202B1ED501399E291'
      'inno-multidisk-4.0.8-3b.bin' = '602845C2638D4CCB7FC6ED77B8205A1D03FB7C5C08391FD5BABE357020F6C044'
    }
    if (@($RequiredFiles.Keys | Where-Object { -not (Test-Path -LiteralPath (Join-Path $FixtureRoot $_) -PathType Leaf) }).Count -gt 0) {
      Set-ItResult -Skipped -Because 'The optional VM-compiled legacy Inno multi-disk fixture is not cached.'
      return
    }
    foreach ($File in $RequiredFiles.GetEnumerator()) {
      (Get-FileHash -LiteralPath (Join-Path $FixtureRoot $File.Key) -Algorithm SHA256).Hash | Should -Be $File.Value
    }

    $Info = Get-InnoInfo -Path $Installer
    $Info.ParserVersionInfo.CatalogFormatId | Should -Be '4005-a'
    $Info.UsesExternalDiskSlices | Should -BeTrue
    $Info.SlicesPerDisk | Should -Be 2

    $ExpandedPath = Join-Path $TestDrive 'expanded-real-multidisk-4.0.8'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InnoInstaller -Path $Installer -DestinationPath $ExpandedPath -Name 'payload.bin' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      $Extracted[0].Length | Should -Be 2500000
      (Get-FileHash -LiteralPath $Extracted[0].FullName -Algorithm SHA256).Hash | Should -Be '92483ED975C831133D5B1631F49E3A1B7245D10F5D61729FAB19BDA03AE2A7A8'
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should parse and extract the archived builder <Name>' -ForEach @(
    @{ Name = 'isetup-1.3.26.exe'; Hash = '581FC5D936D2C88717091CE34018C7F8F5A14DC8A1BE71D1DF658AE8F1BBE46A'; Id = '1325-a'; Loader = 'legacy-s02'; Metadata = 'legacy-zlib32'; Payload = 'legacy-adler'; Checksum = 'Adler32'; Mode = 'Ansi' }
    @{ Name = 'isetup-2.0.19.exe'; Hash = '3ECF561C3100694DF4FFE48A5FD2A28C72CB40F4B251BDB8E591EE80D931765A'; Id = '2018-a'; Loader = 'legacy-s02'; Metadata = 'legacy-zlib32'; Payload = 'legacy-adler'; Checksum = 'Adler32'; Mode = 'Ansi' }
    @{ Name = 'isetup-3.0.7.exe'; Hash = 'A572866B311A9646B980C1965F5660B9EB13FEB57CD4F99A907876786C632695'; Id = '3005-a'; Loader = 'legacy-s02'; Metadata = 'legacy-zlib32'; Payload = 'legacy-adler'; Checksum = 'Adler32'; Mode = 'Ansi' }
    @{ Name = 'isetup-4.0.8.exe'; Hash = '67A82DCED645AC18A66416C5C16D4A1A0AC08D5D64E6DA052B1C2120DDCE98CA'; Id = '4005-a'; Loader = 'legacy-s05'; Metadata = 'legacy-zlib32'; Payload = 'chunked-always-compressed'; Checksum = 'CRC32'; Mode = 'Ansi' }
    @{ Name = 'isetup-4.0.9.exe'; Hash = 'BDC9CDB8E8C80BA494FAAD054F2CE24938BF3B7F5E53009C94AB3EDA9F4758F5'; Id = '4009-a'; Loader = 'legacy-s05'; Metadata = 'chunked-zlib32'; Payload = 'chunked-always-compressed'; Checksum = 'CRC32'; Mode = 'Ansi' }
    @{ Name = 'isetup-4.1.5.exe'; Hash = '6D5563E9813A9B6E9DFBFF737D2BB9CB10BA8A2AE802010402349D0C33A47D77'; Id = '4105-a'; Loader = 'legacy-s06'; Metadata = 'chunked-zlib32'; Payload = 'chunked-always-compressed'; Checksum = 'CRC32'; Mode = 'Ansi' }
    @{ Name = 'isetup-4.1.6.exe'; Hash = '3C737364DD9BCB452F9C615B804183CFDDE652BC7F1214E9807C93FDA4AA017F'; Id = '4106-a'; Loader = 'legacy-s07'; Metadata = 'chunked32'; Payload = 'chunked-always-compressed'; Checksum = 'CRC32'; Mode = 'Ansi' }
    @{ Name = 'isetup-5.1.2-beta.exe'; Hash = '3BEACDB36563760DDD4FB5695FEDF03EF5A139692EC89D144277522EF41A8342'; Id = '5102-a'; Loader = 'legacy-s07'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'MD5'; Mode = 'Ansi' }
    @{ Name = 'isetup-5.3.3-u.exe'; Hash = 'ADF64D224B991D81EBB260832DE9D1AC2D332C98527BEC6C45552DB9857CA827'; Id = '5303-u'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'MD5'; Mode = 'Unicode' }
    @{ Name = 'isetup-5.4.2-a.exe'; Hash = '90B62503B86F5CD1A39B4F62F5F35D17E90BD9AE098D98001EC6FC8535730201'; Id = '5402-a'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Ansi' }
    @{ Name = 'isetup-5.4.2-u.exe'; Hash = '07644D07F39103CA6A92B33A64549241EA40800208FA622E226B106B196C43D3'; Id = '5402-u'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Unicode' }
    @{ Name = 'isetup-5.5.0-a.exe'; Hash = '2821CE367317DA6027A6B28AA45917D863454FC4C97AAC40110BD58458446410'; Id = '5500-a'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Ansi' }
    @{ Name = 'isetup-5.5.0-u.exe'; Hash = '61649FE3A45E26FE6B9E32B6E60304125F1F7ABDB23F49DFC75A656925916607'; Id = '5500-u'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Unicode' }
    @{ Name = 'isetup-5.6.1-a.exe'; Hash = '96FD6A5EAAB473C61A19AFFFF89618764B940EE3F15837C2944A5595AED5FDE6'; Id = '5507-a'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Ansi' }
    @{ Name = 'isetup-5.6.1-u.exe'; Hash = '27D49E9BC769E9D1B214C153011978DB90DC01C2ACD1DDCD9ED7B3FE3B96B538'; Id = '5507-u'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Unicode' }
    @{ Name = 'innosetup-6.0.0-beta.exe'; Hash = '3B63B86FEF7C179AE0EB04233CD04058C5D315A9B4FE2C1C2480A48AD3CCB569'; Id = '6000-u'; Loader = 'resource-v1'; Metadata = 'chunked32'; Payload = 'chunked-legacy'; Checksum = 'SHA1'; Mode = 'Unicode' }
    @{ Name = 'innosetup-6.5.0.exe'; Hash = '79B7A1063B3888BB8ECEB44A8C28E90CCDAA22AC71F9272DE1DAC79B42941DBD'; Id = '6500-u'; Loader = 'resource-v2'; Metadata = 'chunked32'; Payload = 'chunked-modern'; Checksum = 'SHA256'; Mode = 'Unicode' }
    @{ Name = 'innosetup-6.7.0.exe'; Hash = 'F45C7D68D1E660CF13877EC36738A5179CE72A33414F9959D35E99B68C52A697'; Id = '6700-u'; Loader = 'resource-v2'; Metadata = 'chunked64'; Payload = 'chunked-modern'; Checksum = 'SHA256'; Mode = 'Unicode' }
  ) {
    $Fixture = Resolve-InnoBuilderFixturePath -Name $Name
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The optional archived Inno builder fixture is not cached.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be $Hash

    $Format = Get-InnoFormatInfo -Path $Fixture
    $Info = Get-InnoInfo -Path $Fixture
    $Format.CatalogFormatId | Should -Be $Id
    $Format.EditionId | Should -Be 'official'
    $Format.CharacterMode | Should -Be $Mode
    $Format.LoaderRoute | Should -Be $Loader
    $Format.MetadataRoute | Should -Be $Metadata
    $Format.PayloadRoute | Should -Be $Payload
    $Format.ChecksumRoute | Should -Be $Checksum
    $Info.ParserVersionInfo.CatalogFormatId | Should -Be $Id

    $ExpandedPath = Join-Path $TestDrive "expanded-$Id"
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'Compil32.exe' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      (Get-Content -LiteralPath $Extracted[0].FullName -AsByteStream -TotalCount 2) | Should -Be ([byte[]](0x4D, 0x5A))
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should preserve post-file table alignment for the Inno Setup Decompiler 5.5.7 installer' {
    $Fixture = Resolve-InnoBuilderFixturePath -Name 'isdsetup.1.5.exe' -Scenario DecompilerInstaller
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The optional archived Inno Setup Decompiler fixture is not cached.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be 'EF4CEB28A818E02BE3EEEB53A93AC236DEC677BEB0B5459FC541FDD07E08CB5E'

    $Info = Get-InnoInfo -Path $Fixture

    $Info.ParserVersionInfo.CatalogFormatId | Should -Be '5507-u'
    $Info.DisplayName | Should -Be 'Inno Setup Decompiler'
    $Info.MetadataTablesResolved | Should -BeTrue
    $Info.MetadataRecordCounts.Icons | Should -Be 2
    $Info.MetadataRecordCounts.Run | Should -Be 1
    $Info.PascalScriptInfo.Present | Should -BeFalse
    $Info.PascalScriptInfo.AnalysisStatus | Should -Be 'NotPresent'
    $Info.Diagnostics | Should -BeNullOrEmpty
  }

  It 'Should parse the controlled historical Hyper-V fixture <Name>' -ForEach @(
    @{ Name = 'inno-catalog-1.3.26-a.exe'; Hash = '2A06109751F9D99B3FA24A00EE4184B1ED729538EADC497D8B19EC2057405F98'; Id = '1325-a'; DisplayName = 'Dumplings Inno Catalog Fixture version 1.3.26' }
    @{ Name = 'inno-catalog-2.0.19-a.exe'; Hash = '63328B2E20FA1675CFE1CDCF0123265B01D0D9E540DEA375337D66EC0FAA4E06'; Id = '2018-a'; DisplayName = 'Dumplings Inno Catalog Fixture 2.0.19' }
    @{ Name = 'inno-catalog-3.0.7-a.exe'; Hash = '182D175CB1411BCAA54099171B038FE398E1D1089E7A316B15D02C1553D97076'; Id = '3005-a'; DisplayName = 'Dumplings Inno Catalog Fixture 3.0.7' }
    @{ Name = 'inno-catalog-4.0.8-a.exe'; Hash = 'C2E48AE1F25A465FEB7DDC5491E114CE36328CB9F1D509F451A2F76B17149FB2'; Id = '4005-a'; DisplayName = 'Dumplings Inno Catalog Fixture 4.0.8' }
    @{ Name = 'inno-catalog-4.0.9-a.exe'; Hash = '54B9B645539906279BF2DF31619953A8B52000D141A4A5E2427BF498A64C09E2'; Id = '4009-a'; DisplayName = 'Dumplings Inno Catalog Fixture 4.0.9' }
    @{ Name = 'inno-catalog-4.1.5-a.exe'; Hash = 'C989C45DAD6BEBD3E3F705CA4F4AE3DDFE616AE9F9FAB4A297908B4EC552A735'; Id = '4105-a'; DisplayName = 'Dumplings Inno Catalog Fixture 4.1.5' }
    @{ Name = 'inno-catalog-4.1.6-a.exe'; Hash = 'A7700917FA418601E2E531720691CFC44A942BA4BD1C1198CA58047A5D7803D3'; Id = '4106-a'; DisplayName = 'Dumplings Inno Catalog Fixture 4.1.6' }
    @{ Name = 'inno-catalog-5.1.2-a.exe'; Hash = '50689EC5EE5CE3B24B5632AC7F22F9D2974916714A4110D283499009B3C9194E'; Id = '5102-a'; DisplayName = 'Dumplings Inno Catalog Fixture 5.1.2-beta' }
  ) {
    $Fixture = Resolve-InnoBuilderFixturePath -Name $Name -Scenario CatalogFixture
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The optional VM-compiled historical Inno fixture is not cached.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be $Hash

    $Format = Get-InnoFormatInfo -Path $Fixture
    $Info = Get-InnoInfo -Path $Fixture
    $Format.CatalogFormatId | Should -Be $Id
    $Format.EditionId | Should -Be 'official'
    $Format.CharacterMode | Should -Be 'Ansi'
    $Info.DisplayName | Should -Be $DisplayName
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\DumplingsInnoCatalog'
    $Info.ParserVersionInfo.CatalogFormatId | Should -Be $Id
    $Info.ParserVersionInfo.EntryCounts.NumFileEntries | Should -BeGreaterThan 0
    $Info.ParserVersionInfo.EntryCounts.NumFileLocationEntries | Should -BeGreaterThan 0
    if ($Name -eq 'inno-catalog-3.0.7-a.exe') {
      $Info.PascalScriptInfo.Present | Should -BeFalse
      $Info.PascalScriptInfo.AnalysisStatus | Should -Be 'NotPresent'
      @($Info.Diagnostics | Where-Object Message -Like '*Pascal Script*') | Should -BeNullOrEmpty
    }

    $ExpandedPath = Join-Path $TestDrive "expanded-controlled-historical-$Id"
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'MyProg.exe' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      (Get-Content -LiteralPath $Extracted[0].FullName -AsByteStream -TotalCount 2) | Should -Be ([byte[]](0x4D, 0x5A))
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should parse the controlled Hyper-V fixture <Name>' -ForEach @(
    @{ Name = 'inno-catalog-5.3.3-u.exe'; Hash = '5CBD9DE059F078CC8D371236E136A538A4716AE15F5E35B7B07C2FECD6E5EF84'; Id = '5303-u'; Version = '5.3.3'; ProductCode = '{5A177B3F-38F9-45E1-A851-78E8B71A0533}_is1' }
    @{ Name = 'inno-catalog-5.4.2-a.exe'; Hash = '0C8ABC016BE245609FA786C0A64442451B9743198037A333980C26586114A7C3'; Id = '5402-a'; Version = '5.4.2'; ProductCode = '{00000000-0000-0000-0000-00000000542A}_is1' }
    @{ Name = 'inno-catalog-5.4.2-u.exe'; Hash = 'D1BACAFBDFDA9EDE82EC2046E470DC0321D881AE660D451BF80C471F516F0ABB'; Id = '5402-u'; Version = '5.4.2'; ProductCode = '{00000000-0000-0000-0000-00000000542B}_is1' }
    @{ Name = 'inno-catalog-6.0.0-u.exe'; Hash = '6639C75CC7B1EAF860CBDC76FDA43317E56F2C31F0C4D7F3868ABD8E03FA401F'; Id = '6000-u'; Version = '6.0.0'; ProductCode = '{00000000-0000-0000-0000-000000006000}_is1' }
    @{ Name = 'inno-catalog-6.5.0-u.exe'; Hash = 'F269350207427D52CD187E399249CE894F2288F735CCD14189EDEE611B2D8EB1'; Id = '6500-u'; Version = '6.5.0'; ProductCode = '{00000000-0000-0000-0000-000000006500}_is1' }
    @{ Name = 'inno-catalog-6.7.0-u.exe'; Hash = '8A07F30B74722541E5FE48CC0A8A73394F839C4EDEFEC1F91C7B777206C6BAD0'; Id = '6700-u'; Version = '6.7.0'; ProductCode = '{00000000-0000-0000-0000-000000006700}_is1' }
    @{ Name = 'inno-catalog-7.0.2-u.exe'; Hash = 'DF0A894354924CA8B92D83136497AB0E1849624AD4B766B328BACCF5E91B4D8E'; Id = '700003-u'; Version = '7.0.2'; ProductCode = '{00000000-0000-0000-0000-000000007002}_is1' }
  ) {
    $Fixture = Resolve-InnoBuilderFixturePath -Name $Name -Scenario CatalogFixture
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The optional VM-compiled Inno fixture is not cached.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be $Hash

    $Info = Get-InnoInfo -Path $Fixture
    $Info.DisplayName | Should -Be 'Dumplings Inno Catalog Fixture'
    $Info.DisplayVersion | Should -Be $Version
    $Info.Publisher | Should -Be 'Dumplings Test Publisher'
    $Info.ProductCode | Should -Be $ProductCode
    $Info.DefaultInstallLocation | Should -Be '%ProgramFiles(x86)%\DumplingsInnoCatalog'
    $Info.ParserVersionInfo.CatalogFormatId | Should -Be $Id
    $Info.ParserVersionInfo.EntryCounts.NumRegistryEntries | Should -Be 1
    $Info.ParserVersionInfo.EntryCounts.NumFileLocationEntries | Should -Be 1
    $Info.MetadataTablesResolved | Should -BeTrue
    $Info.MetadataRecordCounts.Registry | Should -Be 1
    $Info.RegistryWrites | Should -HaveCount 1
    $Info.RegistryWrites[0].RootKey | Should -Be 'HKLM'
    $Info.RegistryWrites[0].Subkey | Should -Be 'Software\Dumplings\InnoCatalog'
    $Info.RegistryWrites[0].ValueName | Should -Be 'Version'
    $Info.RegistryWrites[0].ValueData | Should -Be $Version

    $ExpandedPath = Join-Path $TestDrive "expanded-controlled-$Id"
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    try {
      $Extracted = @(Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'payload.txt' -CollisionAction Rename)
      $Extracted | Should -HaveCount 1
      (Get-Content -LiteralPath $Extracted[0].FullName -Raw).Trim() | Should -Match '^Dumplings Inno catalog fixture '
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should read static metadata from the WinSCP installer' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'inno'
    $Info.DisplayName | Should -Be 'WinSCP 6.5.6'
    $Info.DisplayVersion | Should -Be '6.5.6'
    $Info.ProductCode | Should -Be 'winscp3_is1'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.EffectiveArchitecturesAllowed | Should -Be 'x86compatible'
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
    $Info.CompressMethod | Should -Be 'Lzma2'
    $Info.ParserVersionInfo.FileLocationDigestAlgorithm | Should -Be 'SHA256'
    $Info.ParserVersionInfo.FileLocationStartOffsetSize | Should -Be 4
    $Info.PascalScriptInfo.Present | Should -BeTrue
    $Info.PascalScriptInfo.FileVersion | Should -Be 23
    $Info.PascalScriptInfo.TypeCount | Should -Be 79
    $Info.PascalScriptInfo.FunctionCount | Should -Be 223
    $Info.PascalScriptInfo.GlobalVariableCount | Should -Be 35
    $Info.PascalScriptInfo.AnalysisStatus | Should -Be 'AvailableOnRequest'
    $Info.ParserVersionInfo.PascalScriptByteLength | Should -Be 71880
    $Info.ParserVersionInfo.PascalScriptVersion | Should -Be 23
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should parse Inno 5.3.3 Unicode metadata from <Name>' -ForEach @(
    @{
      Name                   = 'WingGateway-1.1.2.exe'
      Url                    = 'https://www.wftpserver.com/download/WingGateway_Setup.exe'
      Sha256                 = 'F867D26C4957FDF0C95E6F4E843386434DC94F8DC4BE8B426D8BBEE1E940B2E1'
      ProductCode            = '{1F5A1D86-7CAF-43D9-B8E4-572D0CA73208}_is1'
      DisplayName            = 'Wing Gateway 1.1.2'
      DisplayVersion         = '1.1.2'
      DefaultInstallLocation = '%ProgramFiles(x86)%\Wing Gateway'
    }
    @{
      Name                   = 'WingFtpServer-8.2.1.exe'
      Url                    = 'https://www.wftpserver.com/download/WingFtpServer.exe'
      Sha256                 = '65C2BF03E18FCCDDA959171F9E99DAC78F32FF94B2D0447CBF2189C2FA50682F'
      ProductCode            = '{DF494ADD-CA7F-445C-9D04-3F0CA3B8F20F}_is1'
      DisplayName            = 'Wing FTP Server 8.2.1'
      DisplayVersion         = '8.2.1'
      DefaultInstallLocation = '%ProgramFiles(x86)%\Wing FTP Server'
    }
  ) {
    $Fixture = Get-InstallerFixture -Name $Name -Url $Url -Sha256 $Sha256
    $Info = Get-InnoInfo -Path $Fixture

    $Info.Signature | Should -Be 'Inno Setup Setup Data (5.3.3) (u)'
    $Info.ProductCode | Should -Be $ProductCode
    $Info.DisplayName | Should -Be $DisplayName
    $Info.DisplayVersion | Should -Be $DisplayVersion
    $Info.Publisher | Should -Be 'Wing FTP Software, Inc.'
    $Info.Scope | Should -Be 'machine'
    $Info.DefaultInstallLocation | Should -Be $DefaultInstallLocation
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.ParserVersionInfo.HeaderStringCount | Should -Be 24
    $Info.ParserVersionInfo.HeaderAnsiStringCount | Should -Be 5
    $Info.ParserVersionInfo.FileLocationDigestAlgorithm | Should -Be 'MD5'
    $Info.ParserVersionInfo.FileLocationEntrySize | Should -Be 70
    $Info.ParserVersionInfo.UsesLegacyCallTransform | Should -BeTrue
    $Info.Diagnostics | Should -BeNullOrEmpty
  }

  It 'Should extract and verify an Inno 5.3.3 payload with legacy MD5 records' {
    $Fixture = Get-InstallerFixture -Name 'WingGateway-1.1.2.exe' `
      -Url 'https://www.wftpserver.com/download/WingGateway_Setup.exe' `
      -Sha256 'F867D26C4957FDF0C95E6F4E843386434DC94F8DC4BE8B426D8BBEE1E940B2E1'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'wing-gateway-expanded'
    Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = @(Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'WingGateway.exe' -CollisionAction Rename)

      $Extracted | Should -HaveCount 1
      $Extracted[0] | Should -BeOfType ([System.IO.FileInfo])
      $Extracted[0].Length | Should -Be 6676816
    } finally {
      Remove-Item -LiteralPath $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should parse the official Inno Setup 7 layout without inventing dynamic ARP metadata' {
    $Fixture = Get-InstallerFixture -Name 'innosetup-7.0.2-x64.exe' -Url 'https://github.com/jrsoftware/issrc/releases/download/is-7_0_2/innosetup-7.0.2-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.Signature | Should -Be 'Inno Setup Setup Data (7.0.0.3)'
    $Info.DisplayVersion | Should -Be '7.0.2'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportedArchitectures | Should -Be @('x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    $Info.EncryptionUse | Should -Be 'None'
    $Info.CompressMethod | Should -Be 'Lzma2'
    $Info.WritesAppsAndFeaturesEntry | Should -BeNullOrEmpty
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.UnresolvedFields | Should -Contain 'ProductCode'
    $Info.ParserVersionInfo.HeaderStringCount | Should -Be 39
    $Info.ParserVersionInfo.FileEntryStringCount | Should -Be 15
    $Info.ParserVersionInfo.FileEntryAnsiStringCount | Should -Be 1
    $Info.ParserVersionInfo.FileLocationEntrySize | Should -Be 89
    $Info.ParserVersionInfo.FileLocationDigestAlgorithm | Should -Be 'SHA256'
    $Info.ParserVersionInfo.FileLocationStartOffsetSize | Should -Be 8
    $Info.ParserVersionInfo.UsesInt64BlockHeader | Should -BeTrue
    $Info.ParserVersionInfo.OffsetTableVersion | Should -Be 2
    $Info.PascalScriptInfo.AnalysisStatus | Should -Be 'Analyzed'
    $Info.Diagnostics.Message | Should -Contain 'CreateUninstallRegKey or Uninstallable is a dynamic expression, so Apps & Features registration cannot be determined statically.'
  }

  It 'Should detect a default-user dual-scope Inno installer' {
    $Fixture = Get-InstallerFixture -Name 'loot_0.26.0-win64.exe' -Url 'https://github.com/loot/loot/releases/download/0.26.0/loot_0.26.0-win64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'inno'
    $Info.DisplayName | Should -Be 'LOOT'
    $Info.DisplayVersion | Should -Be '0.26.0'
    $Info.ProductCode | Should -Be '{BF634210-A0D4-443F-A657-0DCE38040374}_is1'
    $Info.RawAppId | Should -Be '{{BF634210-A0D4-443F-A657-0DCE38040374}'
    $Info.PrivilegesRequired | Should -Be 'lowest'
    $Info.PrivilegesRequiredOverridesAllowed | Should -Be @('commandline', 'dialog')
    $Info.DefaultScope | Should -Be 'user'
    $Info.SupportedScopes | Should -Be @('user', 'machine')
    $Info.SupportsDualScope | Should -BeTrue
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.ArchitecturesAllowed | Should -Be 'x64compatible'
    $Info.UnsupportedArchitectures | Should -Be @('x86')
    Test-InnoUnsupportedArchitecture -Path $Fixture -Architecture x86 | Should -BeTrue
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeTrue
  }

  It 'Should normalize the Kiro AppId and user Program Files location' {
    $Fixture = Get-InstallerFixture -Name 'kiro-ide-1.0.138-stable-win32-x64.exe' -Url 'https://prod.download.desktop.kiro.dev/releases/stable/win32-x64/signed/1.0.138/kiro-ide-1.0.138-stable-win32-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1'
    $Info.AppId | Should -Be '{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
    $Info.RawAppId | Should -Be '{{A2CA08B5-C756-463E-B13D-F051F4F11F0B}'
    $Info.DefaultInstallLocation | Should -Be '%LocalAppData%\Programs\Kiro'
    $Info.RawDefaultDirName | Should -Be '{userpf}\Kiro'
    $Info.Scope | Should -Be 'user'
  }

  It 'Should normalize the Qoder AppId' {
    $Fixture = Get-InstallerFixture -Name 'QoderUserSetup-1.14.1-x64.exe' -Url 'https://qoder-ide.oss-accelerate.aliyuncs.com/release/1.14.1/QoderUserSetup-x64.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.ProductCode | Should -Be '{943D6004-554E-4B49-A1D5-52F999A1B3C9}_is1'
    $Info.RawAppId | Should -Be '{{943D6004-554E-4B49-A1D5-52F999A1B3C9}'
  }

  It 'Should not treat a legacy Inno installer without command-line privilege overrides as dual-scope' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $Info = Get-InnoInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'inno'
    $Info.PrivilegesRequired | Should -Be 'admin'
    $Info.DefaultScope | Should -Be 'machine'
    $Info.SupportedScopes | Should -Be @('machine')
    $Info.SupportsDualScope | Should -BeFalse
    $Info.WritesAppsAndFeaturesEntry | Should -BeTrue
    $Info.PackedArchitecturesAllowed | Should -Be 0
    $Info.SupportedArchitectures | Should -Be @('x86', 'x64', 'arm64')
    $Info.UnsupportedArchitectures | Should -BeNullOrEmpty
  }

  It 'Should detect Inno setups that suppress their own Apps & Features entry' {
    $Module = Get-Module Inno | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
    $Result = & $Module {
      $HeaderValues = [string[]]::new(26)
      for ($Index = 0; $Index -lt $HeaderValues.Count; $Index++) { $HeaderValues[$Index] = '' }
      $HeaderValues[24] = 'no'
      $HeaderValues[25] = 'yes'
      $Layout = Get-TestInnoCatalogLayout -VersionNumber 6500 -UnicodeVariant $true
      $NoRegistryKey = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout

      $HeaderValues[24] = 'yes'
      $HeaderValues[25] = 'no'
      $NoUninstaller = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout

      $HeaderValues[24] = ''
      $HeaderValues[25] = ''
      $Default = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout

      $HeaderValues[24] = '{code:ShouldCreateUninstallKey}'
      $HeaderValues[25] = 'yes'
      $Dynamic = Get-InnoAppsAndFeaturesEntryInfo -HeaderValues $HeaderValues -Layout $Layout

      [pscustomobject]@{
        NoRegistryKey   = $NoRegistryKey.WritesAppsAndFeaturesEntry
        NoUninstaller   = $NoUninstaller.WritesAppsAndFeaturesEntry
        Default         = $Default.WritesAppsAndFeaturesEntry
        Dynamic         = $Dynamic.WritesAppsAndFeaturesEntry
        DynamicResolved = $Dynamic.IsResolved
      }
    }

    $Result.NoRegistryKey | Should -BeFalse
    $Result.NoUninstaller | Should -BeFalse
    $Result.Default | Should -BeTrue
    $Result.Dynamic | Should -BeNullOrEmpty
    $Result.DynamicResolved | Should -BeFalse
  }

  It 'Should detect Argente Inno wrappers that do not write their own Apps & Features entry' {
    $FixtureName = 'Argente.DataShredder.x64.exe'
    $FixtureUrl = 'https://argenteutilities.com/en/download/datashredderx64'
    $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl

    try {
      $Info = Get-InnoInfo -Path $Fixture
    } catch {
      Remove-Item -Path $Fixture -Force -ErrorAction SilentlyContinue
      $Fixture = Get-InstallerFixture -Name $FixtureName -Url $FixtureUrl
      $Info = Get-InnoInfo -Path $Fixture
    }

    $Info.InstallerType | Should -Be 'inno'
    $Info.DisplayName | Should -Be 'Argente'
    $Info.AppId | Should -Be 'Argente'
    $Info.ProductCode | Should -BeNullOrEmpty
    $Info.CreateUninstallRegKey | Should -Be 'yes'
    $Info.Uninstallable | Should -Be 'no'
    $Info.WritesAppsAndFeaturesEntry | Should -BeFalse
    Test-InnoAppsAndFeaturesEntry -Path $Fixture | Should -BeFalse
  }

  It 'Should extract BK5WIN.EXE statically from the BankLink Books installer' {
    $Fixture = Get-InstallerFixture -Name 'BankLinkBooks.exe' -Url 'https://download.myob.com/BankLinkBooks.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'myob-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'BK5WIN.EXE' -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      (Get-Item $Extracted[0].FullName).VersionInfo.FileVersion | Should -Be '5.55.3.7499'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract and verify a Unicode Inno 6.5 payload' {
    $Fixture = Get-InstallerFixture -Name 'winscp-6.5.6-setup.exe' -Url 'https://sourceforge.net/projects/winscp/files/WinSCP/6.5.6/WinSCP-6.5.6-Setup.exe/download' -UseSourceForgeMetaRefresh
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'winscp-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'WinSCP.exe' -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be 'CF948EAF8429C582636953E8B6B82097C8BB0A55111EC57E5F890E27DBAB70D9'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract and verify an official Inno 7 payload' {
    $Fixture = Get-InstallerFixture -Name 'innosetup-7.0.2-x64.exe' -Url 'https://github.com/jrsoftware/issrc/releases/download/is-7_0_2/innosetup-7.0.2-x64.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'inno7-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'ISCC.exe' -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be '0FF6140D641F84B64204A2C4D52207C6FC437C9F4DB8779C83083D84F7E3D70D'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract and verify a large solid Inno payload at a nonzero chunk suboffset' {
    $Fixture = Get-InstallerFixture -Name 'kiro-ide-1.0.138-stable-win32-x64.exe' -Url 'https://prod.download.desktop.kiro.dev/releases/stable/win32-x64/signed/1.0.138/kiro-ide-1.0.138-stable-win32-x64.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'kiro-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      $Extracted = Expand-InnoInstaller -Path $Fixture -DestinationPath $ExpandedPath -Name 'Kiro.exe' -CollisionAction Rename
      $Extracted | Should -HaveCount 1
      (Get-FileHash -Path $Extracted[0].FullName -Algorithm SHA256).Hash |
        Should -Be '70C5E19765BF5E8031EF0A7C82BABBC4E4A87FB052D990A392592A7D5E941908'
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should extract every catalogued file when Name is omitted from the VUSC installer' {
    $Fixture = Get-InstallerFixture -Name 'VUSC_setup_709.zip' -Url 'https://www.ok2kkw.com/vusc/vusc4win/VUSC_setup_709.zip'
    $ArchivePath = Join-Path $Script:FixtureDirectory 'vusc-archive'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'vusc-expanded'
    Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      Expand-Archive -Path $Fixture -DestinationPath $ArchivePath -Force
      $NestedInstaller = Get-ChildItem -Path $ArchivePath -Filter '*.exe' -Recurse | Select-Object -First 1
      $Info = Get-InnoInfo -Path $NestedInstaller.FullName
      $Info.Signature | Should -Be 'Inno Setup Setup Data (5.5.7)'
      $Info.PrivilegesRequired | Should -Be 'admin'
      $Info.CompressMethod | Should -Be 'Lzma2'
      $Extracted = @(Expand-InnoInstaller -Path $NestedInstaller.FullName -DestinationPath $ExpandedPath -CollisionAction Rename)

      $Extracted | Should -HaveCount 114
      Test-Path -LiteralPath (Join-Path $ExpandedPath 'data\CONLIST.TXT') | Should -BeTrue
      $LaunchFile = $Extracted | Where-Object Name -Like 'VUSC*.exe' | Where-Object {
        (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash -eq '021A05A497BBCE1EE604CC223E7BB813171F198B3B27AE3C90A50EBD0F6DFEAE'
      } | Select-Object -First 1
      $LaunchFile | Should -Not -BeNullOrEmpty
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path $ArchivePath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
