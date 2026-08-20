. (Join-Path $PSScriptRoot '..\Support\TestBootstrap.ps1')

BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Runtime.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Binary.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'Archive.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'FileSystem.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'PE.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerDiagnostics.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Infrastructure' 'InstallerEvidence.psm1') -Force
  Import-Module (Join-Path $Script:DumplingsModuleRoot 'Libraries' 'Installers' 'AdvancedInstaller.psm1') -Force

  $Script:FixtureDirectory = $TestDrive
  $Script:BuilderFixtureDirectory = Resolve-DumplingsTestFixturePath -RelativePath 'Builders\AdvancedInstaller'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url
  }

  function New-AdvancedInstallerFooterFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [int]$FooterLength,

      [ValidateSet('Ansi', 'Unicode')]
      [string]$CharacterMode = 'Unicode',

      [ValidateSet('V0', 'V1')]
      [string]$CatalogVersion = 'V1',

      [uint32]$StructureVersion = 100,

      [uint32]$TransformFlag = 0,

      [string]$ExternalName,

      [uint32]$ExternalRole = 3,

      [byte[]]$ExternalContent = [Text.Encoding]::UTF8.GetBytes("[GeneralOptions]`r`nAllPlatforms=false`r`n")
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $PayloadBytes = [byte[]]@(0x44, 0x55, 0x4d, 0x50)
    $EntryName = 'payload.bin'
    $EntryNameBytes = if ($CharacterMode -eq 'Unicode') {
      [System.Text.Encoding]::Unicode.GetBytes($EntryName)
    } else {
      [System.Text.Encoding]::ASCII.GetBytes($EntryName)
    }
    $EntryBytes = New-Object 'byte[]' ($CatalogVersion -eq 'V0' ? 20 : 24)
    if ($CatalogVersion -eq 'V0') {
      [System.BitConverter]::GetBytes([uint32]$PayloadBytes.Length).CopyTo($EntryBytes, 8)
      [System.BitConverter]::GetBytes([uint32]0).CopyTo($EntryBytes, 12)
      [System.BitConverter]::GetBytes([uint32]$EntryName.Length).CopyTo($EntryBytes, 16)
    } else {
      [System.BitConverter]::GetBytes($TransformFlag).CopyTo($EntryBytes, 8)
      [System.BitConverter]::GetBytes([uint32]$PayloadBytes.Length).CopyTo($EntryBytes, 12)
      [System.BitConverter]::GetBytes([uint32]0).CopyTo($EntryBytes, 16)
      [System.BitConverter]::GetBytes([uint32]$EntryName.Length).CopyTo($EntryBytes, 20)
    }

    $InfoOffset = $PayloadBytes.Length
    $CatalogEndOffset = $InfoOffset + $EntryBytes.Length + $EntryNameBytes.Length
    $ExternalRecordBytes = [byte[]]@()
    if (-not [string]::IsNullOrWhiteSpace($ExternalName)) {
      $ExternalNameBytes = if ($CharacterMode -eq 'Unicode') {
        [Text.Encoding]::Unicode.GetBytes($ExternalName)
      } else {
        [Text.Encoding]::ASCII.GetBytes($ExternalName)
      }
      $ExternalRecordBytes = New-Object 'byte[]' (8 + $ExternalNameBytes.Length)
      [BitConverter]::GetBytes($ExternalRole).CopyTo($ExternalRecordBytes, 0)
      [BitConverter]::GetBytes([uint32]$ExternalName.Length).CopyTo($ExternalRecordBytes, 4)
      $ExternalNameBytes.CopyTo($ExternalRecordBytes, 8)
      [IO.File]::WriteAllBytes((Join-Path $Script:FixtureDirectory $ExternalName), $ExternalContent)
    }
    $PhysicalFooterOffset = $CatalogEndOffset + $ExternalRecordBytes.Length
    $FooterBytes = New-Object 'byte[]' $FooterLength
    [System.BitConverter]::GetBytes([uint32]([string]::IsNullOrWhiteSpace($ExternalName) ? 0 : 1)).CopyTo($FooterBytes, 0)
    [System.BitConverter]::GetBytes([uint32]$CatalogEndOffset).CopyTo($FooterBytes, 4)
    [System.BitConverter]::GetBytes([uint32]1).CopyTo($FooterBytes, 8)
    [System.BitConverter]::GetBytes($StructureVersion).CopyTo($FooterBytes, 12)
    [System.BitConverter]::GetBytes([uint32]$PhysicalFooterOffset).CopyTo($FooterBytes, 16)
    [System.BitConverter]::GetBytes([uint32]$InfoOffset).CopyTo($FooterBytes, 20)
    [System.BitConverter]::GetBytes([uint32]0).CopyTo($FooterBytes, 24)
    [System.Text.Encoding]::ASCII.GetBytes('00112233445546778899AABBCCDDEEFF').CopyTo($FooterBytes, 28)
    [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX').CopyTo($FooterBytes, 64)

    $Stream = [System.IO.File]::Open($FixturePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
      $Stream.Write($PayloadBytes, 0, $PayloadBytes.Length)
      $Stream.Write($EntryBytes, 0, $EntryBytes.Length)
      $Stream.Write($EntryNameBytes, 0, $EntryNameBytes.Length)
      if ($ExternalRecordBytes.Length) { $Stream.Write($ExternalRecordBytes, 0, $ExternalRecordBytes.Length) }
      $Stream.Write($FooterBytes, 0, $FooterBytes.Length)
    } finally {
      $Stream.Close()
    }

    return $FixturePath
  }
}

Describe 'Advanced Installer parser' {
  It 'Should read direct MSI metadata from the TI-Nspire Computer Link installer' {
    try {
      $Fixture = Get-InstallerFixture -Name 'TINspireComputerLink-3.9.0.455.exe' -Url 'https://education.ti.com/download/en/ed-tech/82035809F7E6474099944056CCB01C20/AC3AAE51297B4902B6B6CA005B8391F0/TINspireComputerLink-3.9.0.455.exe'
    } catch {
      Set-ItResult -Skipped -Because 'Texas Instruments removed the historical official installer URL.'
      return
    }
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info -Name 'ComputerLink.msi'

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.FormatProfileId | Should -Be 'classic-unicode-v1'
    $Info.BuilderVersionRange | Should -Be '8.6-23.9'
    $Info.ArchitectureSelectionEvidence.BaseMsiPath | Should -Be 'ComputerLink.msi'
    $Info.Files.Name | Should -Contain 'ComputerLink.msi'
    $MsiInfo.InstallerBuilderVersion | Should -Be '10.3'
    $MsiInfo.InstallerBuilderVersionSource | Should -Be 'SummaryInformation.CreatingApp'
    $MsiInfo.DisplayVersion | Should -Be '3.9.0.455'
    $MsiInfo.ProductCode | Should -Be '{6C5AC088-3136-4043-8985-8B0772A9580E}'
  }

  It 'Should read direct MSI metadata from the Dragonframe License Manager installer' {
    $Fixture = Get-InstallerFixture -Name 'DragonframeLicenseManager_3.0.3-Setup.exe' -Url 'https://www.dragonframe.com/download/DragonframeLicenseManager_3.0.3-Setup.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info -Name 'DFLM.msi'

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain 'DFLM.msi'
    $MsiInfo.DisplayVersion | Should -Be '3.0.3'
    $MsiInfo.UpgradeCode | Should -Be '{8B866AEB-E879-4DA6-9CC8-AE81326B30E1}'
  }

  It 'Should read nested 7z MSI metadata from the TeraCopy installer' {
    $Fixture = Get-InstallerFixture -Name 'teracopy3.9.exe' -Url 'https://codesector.com/files/teracopy3.9.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $X86Info = Get-AdvancedInstallerMsiInfo -Installer $Info -Architecture x86
    $X64Info = Get-AdvancedInstallerMsiInfo -Installer $Info -Architecture x64

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain '5DE3EEA\TeraCopy.7z'
    $Info.Files.Where({ $_.Name -eq '5DE3EEA\TeraCopy.7z' })[0].SelectorType | Should -Be 3
    $Info.Files.Where({ $_.Name -eq '5DE3EEA\TeraCopy.7z' })[0].SelectorGroup | Should -Be 7
    $Info.ConfigurationEntry | Should -Be 'teracopy3.9.0.ini'
    $Info.GeneralOptions.AllPlatforms | Should -Be 'true'
    $Info.MsiPayloadSelection.SourceKind | Should -Be 'EmbeddedArchive'
    $Info.MsiPayloadSelection.ArchitectureSelectionMode | Should -Be 'Wow64Suffix'
    $Info.MsiPayloadSelection.BaseMsiPath | Should -Be '5DE3EEA\TeraCopy.msi'
    $Info.MsiPayloadSelection.X64MsiPath | Should -Be '5DE3EEA\TeraCopy.x64.msi'
    $X86Info.Name | Should -Be 'TeraCopy.msi'
    $X86Info.SelectedMsiPath | Should -Be '5DE3EEA\TeraCopy.msi'
    $X86Info.SelectionMethod | Should -Be 'PayloadTable'
    $X86Info.PackageArchitecture | Should -Be 'x86'
    $X86Info.DisplayVersion | Should -Be '3.9.0'
    $X86Info.ProductCode | Should -Be '{F8B0BB18-B1E6-4821-8C5B-883AA5DE3EEA}'
    $X64Info.Name | Should -Be 'TeraCopy.x64.msi'
    $X64Info.SelectedMsiPath | Should -Be '5DE3EEA\TeraCopy.x64.msi'
    $X64Info.SelectionMethod | Should -Be 'PayloadTable'
    $X64Info.PackageArchitecture | Should -Be 'x64'
    $X64Info.DisplayVersion | Should -Be '3.9.0'
    $X64Info.ProductCode | Should -Be '{F8B0BB18-B1E6-4821-8C5B-883AA5DE3EEA}'
  }

  It 'Should select the mixed x64 and fixed ARM64 FxSound payloads' {
    $MixedFixture = Get-InstallerFixture -Name 'fxsound_setup-1.2.10.0.exe' -Url 'https://raw.githubusercontent.com/fxsound2/fxsound-app/refs/tags/v1.2.10.0/release/fxsound_setup.exe'
    $Arm64Fixture = Get-InstallerFixture -Name 'fxsound_setup.arm64-1.2.10.0.exe' -Url 'https://raw.githubusercontent.com/fxsound2/fxsound-app/refs/tags/v1.2.10.0/release/arm64/fxsound_setup.arm64.exe'
    $MixedInfo = Get-AdvancedInstallerInfo -Path $MixedFixture
    $Arm64Info = Get-AdvancedInstallerInfo -Path $Arm64Fixture
    $X64MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $MixedInfo -Architecture x64
    $Arm64MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Arm64Info -Architecture arm64

    $MixedInfo.MsiPayloadSelection.ArchitectureSelectionMode | Should -Be 'Wow64Suffix'
    $MixedInfo.MsiPayloadSelection.BaseMsiPath | Should -Be 'fxsound.msi'
    $MixedInfo.MsiPayloadSelection.X64MsiPath | Should -Be 'fxsound.x64.msi'
    $MixedInfo.MsiPayloadSelection.Arm64MsiPath | Should -Be 'fxsound.x64.msi'
    $X64MsiInfo.SelectedMsiPath | Should -Be 'fxsound.x64.msi'
    $X64MsiInfo.PackageArchitecture | Should -Be 'x64'
    $X64MsiInfo.ProductCode | Should -Be '{3EE30B3D-8CA9-435C-BFB5-70DE367321B3}'

    $Arm64Info.MsiPayloadSelection.ArchitectureSelectionMode | Should -Be 'FixedPath'
    $Arm64Info.MsiPayloadSelection.BaseMsiPath | Should -Be 'fxsound.arm64.msi'
    $Arm64Info.MsiPayloadSelection.Arm64MsiPath | Should -Be 'fxsound.arm64.msi'
    $Arm64MsiInfo.SelectedMsiPath | Should -Be 'fxsound.arm64.msi'
    $Arm64MsiInfo.ArchitectureSelectionMode | Should -Be 'FixedPath'
    $Arm64MsiInfo.PackageArchitecture | Should -Be 'arm64'
    $Arm64MsiInfo.Template | Should -Be 'Arm64;1033'
    $Arm64MsiInfo.ProductCode | Should -Be '{AFD6D03F-AE41-4BB2-9E4D-26E8A9E970B0}'
    $Arm64MsiInfo.UpgradeCode | Should -Be '{1CA2081B-0D5A-41DF-86E8-2788204CE340}'

    { Get-AdvancedInstallerMsiInfo -Installer $MixedInfo -Architecture arm64 } | Should -Throw "*MSI package architecture is 'x64'*"
  }

  It 'Should require architecture when mixed-platform metadata selects distinct MSI paths' {
    $Fixture = Get-InstallerFixture -Name 'teracopy3.9.exe' -Url 'https://codesector.com/files/teracopy3.9.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    { Get-AdvancedInstallerMsiInfo -Installer $Info } | Should -Throw '*selects different MSI paths by host architecture*'
  }

  It 'Should give MainAppURL precedence over embedded payload-table entries' {
    InModuleScope AdvancedInstaller {
      $Selection = Get-AdvancedInstallerMsiPayloadSelection -File @(
        [pscustomobject]@{
          Index         = 0
          Name          = 'Embedded.msi'
          SelectorType  = 1
          SelectorGroup = 0
        }
      ) -GeneralOptions ([pscustomobject]@{
          MainAppURL   = 'https://downloads.example.test/Product.msi?token=value'
          AllPlatforms = 'true'
        })

      $Selection.SelectionMethod | Should -Be 'MainAppUrl'
      $Selection.SourceKind | Should -Be 'Download'
      $Selection.ArchitectureSelectionMode | Should -Be 'Wow64Suffix'
      $Selection.X86MainAppUrl | Should -Be 'https://downloads.example.test/Product.msi?token=value'
      $Selection.X64MainAppUrl | Should -Be 'https://downloads.example.test/Product.x64.msi?token=value'
      $Selection.Arm64MainAppUrl | Should -Be 'https://downloads.example.test/Product.x64.msi?token=value'
      $Selection.BaseMsiPath | Should -BeNullOrEmpty
    }
  }

  It 'Should expand nested 7z payloads in place' {
    $Fixture = Get-InstallerFixture -Name 'teracopy3.9.exe' -Url 'https://codesector.com/files/teracopy3.9.exe'
    $ExpandedPath = Join-Path $Script:FixtureDirectory 'teracopy-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    try {
      Expand-AdvancedInstaller -Path $Fixture -DestinationPath $ExpandedPath -CollisionAction Rename | Out-Null
      Test-Path -Path (Join-Path $ExpandedPath '5DE3EEA\TeraCopy.msi') | Should -BeTrue
      Test-Path -Path (Join-Path $ExpandedPath '5DE3EEA\TeraCopy.x64.msi') | Should -BeTrue
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should skip FILES.7z before inspecting nested archives' {
    $Fixture = Join-Path $Script:FixtureDirectory 'synthetic-files-archive.bin'
    [System.IO.File]::WriteAllBytes($Fixture, [byte[]]@(0x46, 0x49, 0x4c, 0x45))

    $ExpandedPath = Join-Path $Script:FixtureDirectory 'synthetic-files-archive-expanded'
    Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue

    $Installer = [pscustomobject]@{
      Path  = $Fixture
      Files = @(
        [pscustomobject]@{
          Name      = 'ABCDEF0\FILES.7z'
          Size      = 4
          Offset    = 0
          XorLength = 0
        }
      )
    }

    try {
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath -CollisionAction Rename | Out-Null
      Test-Path -Path (Join-Path $ExpandedPath 'ABCDEF0\FILES.7z') | Should -BeTrue
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should locate Advanced Installer footers ending at the ADVINSTSFX marker' {
    $Fixture = New-AdvancedInstallerFooterFixture -Name 'synthetic-footer-at-eof.bin' -FooterLength 74
    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.FooterOffset | Should -Be ((Get-Item -Path $Fixture).Length - 74)
    $Info.FileCount | Should -Be 1
    $Info.Files.Name | Should -Contain 'payload.bin'
    $Info.BootstrapperIdRoute | Should -Be 'ascii-guid-v4-n'
    $Info.BootstrapperId | Should -Be '{00112233-4455-4677-8899-AABBCCDDEEFF}'
  }

  It 'Should route a completely consumed ANSI catalog through the historical profile' {
    $Fixture = New-AdvancedInstallerFooterFixture -Name 'synthetic-ansi-footer.bin' -FooterLength 74 -CharacterMode Ansi -CatalogVersion V0
    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.IsSupported | Should -BeTrue
    $Info.FormatProfileId | Should -Be 'classic-ansi-v0'
    $Info.CatalogRoute | Should -Be 'catalog-v0-ansi'
    $Info.CharacterMode | Should -Be 'Ansi'
    $Info.ValidationStatus | Should -Be 'PartiallyValidated'
    $Info.ValidatedBuilderVersions | Should -Be '6.3'
  }

  It 'Should parse controlled Advanced Installer 6.3 ANSI embedded media' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '6.3\Generated\diehard-ansi-63.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 6.3 fixture is not present in the persistent cache.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be 'B1E949F307CFFDE7B7FBECDDE89C371A1F731659C523386E25788466A7A652B5'

    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info

    $Info.FormatProfileId | Should -Be 'classic-ansi-v0'
    $Info.CatalogRoute | Should -Be 'catalog-v0-ansi'
    $Info.MediaType | Should -Be 'CompressedSingleExe'
    $Info.MsiPayloadSelection.SourceKind | Should -Be 'EmbeddedArchive'
    $MsiInfo.InstallerBuilderVersion | Should -Be '6.3'
    $MsiInfo.SelectedMsiPath | Should -Be '152EE16\diehard-exe-63.msi'
  }

  It 'Should parse and expand controlled Advanced Installer 6.3 external-resource media' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '6.3\Generated\diehard-external-63.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 6.3 external-media fixture is not present in the persistent cache.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be '2BF1FC4A485EC315954456656824DC76BC2873BD90304E60CAA8F2ED54191C5E'

    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info

    $Info.FormatProfileId | Should -Be 'classic-ansi-v0'
    $Info.ExternalResourceCount | Should -Be 3
    $Info.ExternalResources.Name | Should -Contain 'diehard-external-63.7z'
    $Info.MediaType | Should -Be 'ExternalResources'
    $Info.MsiPayloadSelection.SourceKind | Should -Be 'ExternalArchive'
    $MsiInfo.InstallerBuilderVersion | Should -Be '6.3'
    $MsiInfo.SelectedMsiPath | Should -Be 'diehard-external-63.msi'
  }

  It 'Should parse ANSI and Unicode external-resource tables without real media' -ForEach @(
    @{ CharacterMode = 'Ansi'; CatalogRoute = 'catalog-v0-ansi'; ExternalRoute = 'external-v1-ansi' }
    @{ CharacterMode = 'Unicode'; CatalogRoute = 'catalog-v0-unicode'; ExternalRoute = 'external-v1-unicode' }
  ) {
    $ExternalName = "synthetic-external-$CharacterMode.ini"
    $Fixture = New-AdvancedInstallerFooterFixture -Name "synthetic-external-$CharacterMode.bin" -FooterLength 74 -CharacterMode $CharacterMode -CatalogVersion V0 -ExternalName $ExternalName
    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.CatalogRoute | Should -Be $CatalogRoute
    $Info.ExternalResourceRoute | Should -Be $ExternalRoute
    $Info.ExternalResourceCount | Should -Be 1
    $Info.ExternalResources[0].Name | Should -Be $ExternalName
    $Info.ExternalResources[0].MissingExternal | Should -BeFalse
    $Info.ConfigurationEntry | Should -Be $ExternalName
  }

  It 'Should distinguish the controlled Unicode v0 and v1 catalog generations' {
    $V0Fixture = Join-Path $Script:BuilderFixtureDirectory '6.4\Generated\diehard-unicode-64.exe'
    $V1Fixture = Join-Path $Script:BuilderFixtureDirectory '8.6\Generated\diehard-86.exe'
    if (-not (Test-Path -LiteralPath $V0Fixture -PathType Leaf) -or -not (Test-Path -LiteralPath $V1Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 6.4 and 8.6 fixtures are not both present in the persistent cache.'
      return
    }

    $V0Info = Get-AdvancedInstallerInfo -Path $V0Fixture
    $V1Info = Get-AdvancedInstallerInfo -Path $V1Fixture

    $V0Info.FormatProfileId | Should -Be 'classic-unicode-v0'
    $V0Info.CatalogRoute | Should -Be 'catalog-v0-unicode'
    $V1Info.FormatProfileId | Should -Be 'classic-unicode-v1'
    $V1Info.CatalogRoute | Should -Be 'catalog-v1-unicode'
  }

  It 'Should identify a controlled web installer without treating external archives as the selected MSI' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '8.6\Generated\Web\diehard-86.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 8.6 web fixture is not present in the persistent cache.'
      return
    }

    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.MediaType | Should -Be 'WebInstaller'
    $Info.MsiPayloadSelection.SourceKind | Should -Be 'Download'
    $Info.MsiPayloadSelection.MainAppUrl | Should -Be 'https://example.invalid/diehard-exe-86.msi'
    $Info.ExternalResources.ExternalRole | Should -Contain 6
    $Info.ExternalResources.ExternalRole | Should -Contain 7
  }

  It 'Should project compressed prerequisite payload evidence from the outer catalog' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '8.6\Generated\prereq-lzma-86.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 8.6 prerequisite fixture is not present in the persistent cache.'
      return
    }

    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.HasPrerequisitePayloads | Should -BeTrue
    $Info.PrerequisitePayloads | Should -HaveCount 1
    $Info.PrerequisitePayloads[0].Name | Should -Be 'prerequisite.exe'
    $Info.PrerequisitePayloads[0].SelectorType | Should -Be 100
    $Info.PrerequisitePayloads[0].SelectorGroup | Should -Be 9
    $Info.PrerequisitePayloads[0].Compression | Should -Be 'Lzma'
  }

  It 'Should project controlled MSI/MSIX operating-system selection evidence' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '23.9\Generated\mixed-controlled-Msi.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 23.9 mixed MSI/MSIX fixture is not present in the persistent cache.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be '69DA24AA345F12F99FEBC14ABE4335FD9CA51B9A6BD5EB4C6D2D54B34C910C99'

    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.MediaType | Should -Be 'MsiMsixPlatformSelection'
    $Info.MediaInfo.HasPlatformPayloadSelection | Should -BeTrue
    $Info.PlatformPayloadSelection.SelectionMethod | Should -Be 'OperatingSystemVersion'
    $Info.PlatformPayloadSelection.MinimumWindowsVersion | Should -Be '10.0.17763.0'
    $Info.PlatformPayloadSelection.PackageFullName | Should -Be 'Caphyon.SparsePackage_1.0.0.0_x64__pm3gqw982fx6e'
    $Info.PlatformPayloadSelection.PackageFamilyName | Should -Be 'Caphyon.SparsePackage_pm3gqw982fx6e'
    $Info.PlatformPayloadSelection.PackageArchitecture | Should -Be 'x64'
    $Info.PlatformPayloadSelection.LegacyMsiSelection.SourceEntryName | Should -Be 'mixed-controlled-Msi.msi'
    $Info.PlatformPayloadSelection.ModernPayloads | Should -HaveCount 1
    $Info.PlatformPayloadSelection.ModernPayloads[0].Name | Should -Be 'Sparse Package-x64.msix'
    $Info.PlatformPayloadSelection.ModernPayloads[0].SelectorType | Should -Be 1
    $Info.PlatformPayloadSelection.ModernPayloads[0].SelectorGroup | Should -Be 18
    $Info.Diagnostics.Message | Should -Contain 'Advanced Installer selects an MSIX/AppX package on supported Windows versions and an MSI on older systems; analyze both nested packages before updating installed-state metadata.'

    $Destination = Join-Path $TestDrive 'advanced-installer-mixed-platform'
    Expand-AdvancedInstaller -Installer $Info -DestinationPath $Destination -CollisionAction Error | Out-Null
    Test-Path -LiteralPath (Join-Path $Destination 'mixed-controlled-Msi.msi') -PathType Leaf | Should -BeTrue
    Test-Path -LiteralPath (Join-Path $Destination 'Sparse Package-x64.msix') -PathType Leaf | Should -BeTrue
  }

  It 'Should reject an invalid physical-footer pointer in an otherwise valid footer' {
    $Fixture = New-AdvancedInstallerFooterFixture -Name 'synthetic-invalid-catalog-end.bin' -FooterLength 74
    $Bytes = [IO.File]::ReadAllBytes($Fixture)
    $FooterOffset = $Bytes.Length - 74
    [BitConverter]::GetBytes([uint32]($FooterOffset - 1)).CopyTo($Bytes, $FooterOffset + 16)
    [IO.File]::WriteAllBytes($Fixture, $Bytes)

    $Info = Get-AdvancedInstallerFormatInfo -Path $Fixture

    $Info.IsAdvancedInstaller | Should -BeFalse
    $Info.Diagnostics | Should -Not -BeNullOrEmpty
  }

  It 'Should reject a bare ADVINSTSFX marker without a valid footer and catalog' {
    $Fixture = Join-Path $Script:FixtureDirectory 'synthetic-bare-marker.bin'
    [IO.File]::WriteAllBytes($Fixture, [Text.Encoding]::ASCII.GetBytes('prefix-ADVINSTSFX-suffix'))

    $FormatInfo = Get-AdvancedInstallerFormatInfo -Path $Fixture

    $FormatInfo.IsAdvancedInstaller | Should -BeFalse
    $FormatInfo.IsSupported | Should -BeFalse
    $FormatInfo.Diagnostics | Should -Not -BeNullOrEmpty
  }

  It 'Should resolve every catalog profile to registered routes' {
    InModuleScope AdvancedInstaller {
      $PreviousMaximum = $null
      foreach ($FormatProfile in $Script:AdvancedInstallerCatalog.Profiles) {
        $Script:AdvancedInstallerFooterHandlers.ContainsKey($FormatProfile.FooterRoute) | Should -BeTrue
        $Script:AdvancedInstallerCatalogHandlers.ContainsKey($FormatProfile.CatalogRoute) | Should -BeTrue
        $Script:AdvancedInstallerExternalResourceHandlers.ContainsKey($FormatProfile.ExternalResourceRoute) | Should -BeTrue
        $Script:AdvancedInstallerConfigurationHandlers.ContainsKey($FormatProfile.ConfigurationRoute) | Should -BeTrue
        $Script:AdvancedInstallerCatalog.PayloadRoutes.ContainsKey($FormatProfile.PayloadRoute) | Should -BeTrue
        $Script:AdvancedInstallerCatalog.TransformRoutes.ContainsKey($FormatProfile.TransformRoute) | Should -BeTrue
        $FormatProfile.BootstrapperIdRoute | Should -Be 'ascii-guid-v4-n'

        $Minimum = [version]$FormatProfile.MinimumBuilderVersion
        $Maximum = [version]$FormatProfile.MaximumBuilderVersion
        $Maximum | Should -BeGreaterOrEqual $Minimum
        if ($null -ne $PreviousMaximum) { $Minimum | Should -BeGreaterThan $PreviousMaximum }
        $PreviousMaximum = $Maximum
      }
      $Script:AdvancedInstallerCatalog.PayloadRoutes['selector-v1'].MsixPackageSelector | Should -Be @(1, 18)
    }
  }

  It 'Should use the compatibility route for explicit future builder versions' {
    InModuleScope AdvancedInstaller {
      $FormatProfile = Resolve-AdvancedInstallerFormatProfile -StructureVersion 100 -CharacterMode Unicode -CatalogRoute 'catalog-v1-unicode' -BuilderVersion '24.0'

      $FormatProfile.Id | Should -Be 'classic-compatible-v1'
      $FormatProfile.IsFallback | Should -BeTrue
    }
  }

  It 'Should reject fallback media whose payload transform is unknown' {
    $Fixture = New-AdvancedInstallerFooterFixture -Name 'synthetic-future-opaque.bin' -FooterLength 74 -StructureVersion 101 -TransformFlag 99
    $Info = Get-AdvancedInstallerFormatInfo -Path $Fixture

    $Info.IsAdvancedInstaller | Should -BeTrue
    $Info.IsFallback | Should -BeTrue
    $Info.IsSupported | Should -BeFalse
    $Info.Diagnostics.Message | Should -Contain 'One or more Advanced Installer payloads use an unsupported transform; format metadata is available but full extraction is not.'
  }

  It 'Should report AES-256 evidence and release the controlled encrypted payload' {
    $Fixture = Join-Path $Script:BuilderFixtureDirectory '8.6\Generated\diehard-aes-86.exe'
    if (-not (Test-Path -LiteralPath $Fixture -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The VM-built Advanced Installer 8.6 AES fixture is not present in the persistent cache.'
      return
    }
    (Get-FileHash -LiteralPath $Fixture -Algorithm SHA256).Hash | Should -Be '45FCDFB418893C783AE398CDC63D3ED452E1857B5BF722DBF5A9C254949F9762'

    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    { Get-AdvancedInstallerMsiInfo -Installer $Info } | Should -Throw '*AES-256 encrypted*'
  }

  It 'Should locate signed Advanced Installer footers beyond the old 10 KB tail window' {
    $Fixture = Get-InstallerFixture -Name 'Setup.DVLS.Console.2026.1.15.0.exe' -Url 'https://cdn.devolutions.net/download/Setup.DVLS.Console.2026.1.15.0.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain '72E5885\Setup.DVLS.Console.2026.1.15.0.7z'
    $MsiInfo.DisplayVersion | Should -Be '2026.1.15.0'
    $MsiInfo.ProductCode | Should -Be '{2EC8D12C-9845-473A-A6D9-DF75172E5885}'
    $MsiInfo.UpgradeCode | Should -Be '{F036F415-628F-4FE1-A550-13AE231667EF}'
  }

  It 'Should parse the 2 GB BenchMate installer within the performance watchdog' -Tag 'RealFixture', 'Benchmark' {
    $Name = 'bm-14.2.0.exe'
    $Url = 'https://dl.benchmate.org/bm-14.2.0.exe'
    $Sha256 = '123DD975FBE1BEDCE784BF30C755392CE69C92E07D555E9051422DD8EDFC6506'
    $Fixture = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name)
    if (-not (Test-DumplingsTestFixtureCacheEntry -Path $Fixture -Sha256 $Sha256)) {
      if ($env:DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES -eq '1') {
        $Fixture = Get-DumplingsTestFixture -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name $Name) -Uri $Url -Sha256 $Sha256
      } else {
        Set-ItResult -Skipped -Because 'Set DUMPLINGS_DOWNLOAD_LARGE_TEST_FIXTURES=1 to cache the 2.1 GB BenchMate performance fixture.'
        return
      }
    }

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info
    $Stopwatch.Stop()

    (Get-Item -LiteralPath $Fixture).Length | Should -Be 2167225168
    $Info.ConfigurationEntry | Should -Be 'bm-14.2.0.0.ini'
    $Info.MsiPayloadSelection.SourceKind | Should -Be 'EmbeddedArchive'
    $Info.MsiPayloadSelection.ArchitectureSelectionMode | Should -Be 'FixedPath'
    $MsiInfo.SelectedMsiPath | Should -Be 'C3C022B\bm.msi'
    $MsiInfo.DisplayVersion | Should -Be '14.2.0.0'
    $MsiInfo.ProductCode | Should -Be '{28D8C509-9AB2-4FFB-A832-85CE7C3C022B}'
    $MsiInfo.UpgradeCode | Should -Be '{B63C1D13-2833-4F4A-8605-93F87F8599F6}'
    $Stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 60
  }
}
