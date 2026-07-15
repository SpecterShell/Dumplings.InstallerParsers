BeforeAll {
  . (Join-Path $PSScriptRoot 'TestFixture.ps1')
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Runtime.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Binary.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Compression.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'Archive.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'PE.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'RegistryAssociations.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Force

  $Script:FixtureDirectory = Get-DumplingsTestFixtureDirectory -Name 'InstallerParsers\AdvancedInstaller'

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    Get-DumplingsTestFixture -Directory $Script:FixtureDirectory -Name $Name -Uri $Url
  }

  function New-AdvancedInstallerFooterFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [int]$FooterLength
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    $PayloadBytes = [byte[]]@(0x44, 0x55, 0x4d, 0x50)
    $EntryName = 'payload.bin'
    $EntryNameBytes = [System.Text.Encoding]::Unicode.GetBytes($EntryName)
    $EntryBytes = New-Object 'byte[]' 24
    [System.BitConverter]::GetBytes([uint32]$PayloadBytes.Length).CopyTo($EntryBytes, 12)
    [System.BitConverter]::GetBytes([uint32]0).CopyTo($EntryBytes, 16)
    [System.BitConverter]::GetBytes([uint32]$EntryName.Length).CopyTo($EntryBytes, 20)

    $InfoOffset = $PayloadBytes.Length
    $FooterBytes = New-Object 'byte[]' $FooterLength
    [System.BitConverter]::GetBytes([uint32]1).CopyTo($FooterBytes, 4)
    [System.BitConverter]::GetBytes([uint32]$InfoOffset).CopyTo($FooterBytes, 16)
    [System.BitConverter]::GetBytes([uint32]0).CopyTo($FooterBytes, 20)
    [System.Text.Encoding]::ASCII.GetBytes('ADVINSTSFX').CopyTo($FooterBytes, 60)

    $Stream = [System.IO.File]::Open($FixturePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
      $Stream.Write($PayloadBytes, 0, $PayloadBytes.Length)
      $Stream.Write($EntryBytes, 0, $EntryBytes.Length)
      $Stream.Write($EntryNameBytes, 0, $EntryNameBytes.Length)
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
    $Info.Files.Name | Should -Contain 'ComputerLink.msi'
    $MsiInfo.ProductVersion | Should -Be '3.9.0.455'
    $MsiInfo.ProductCode | Should -Be '{6C5AC088-3136-4043-8985-8B0772A9580E}'
  }

  It 'Should read direct MSI metadata from the Dragonframe License Manager installer' {
    $Fixture = Get-InstallerFixture -Name 'DragonframeLicenseManager_3.0.3-Setup.exe' -Url 'https://www.dragonframe.com/download/DragonframeLicenseManager_3.0.3-Setup.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info -Name 'DFLM.msi'

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain 'DFLM.msi'
    $MsiInfo.ProductVersion | Should -Be '3.0.3'
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
    $X86Info.ProductVersion | Should -Be '3.9.0'
    $X86Info.ProductCode | Should -Be '{F8B0BB18-B1E6-4821-8C5B-883AA5DE3EEA}'
    $X64Info.Name | Should -Be 'TeraCopy.x64.msi'
    $X64Info.SelectedMsiPath | Should -Be '5DE3EEA\TeraCopy.x64.msi'
    $X64Info.SelectionMethod | Should -Be 'PayloadTable'
    $X64Info.PackageArchitecture | Should -Be 'x64'
    $X64Info.ProductVersion | Should -Be '3.9.0'
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
          MainAppURL  = 'https://downloads.example.test/Product.msi?token=value'
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
      Expand-AdvancedInstaller -Path $Fixture -DestinationPath $ExpandedPath | Out-Null
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
      Expand-AdvancedInstaller -Installer $Installer -DestinationPath $ExpandedPath | Out-Null
      Test-Path -Path (Join-Path $ExpandedPath 'ABCDEF0\FILES.7z') | Should -BeTrue
    } finally {
      Remove-Item -Path $ExpandedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
  }

  It 'Should locate Advanced Installer footers ending at the ADVINSTSFX marker' {
    $Fixture = New-AdvancedInstallerFooterFixture -Name 'synthetic-footer-at-eof.bin' -FooterLength 70
    $Info = Get-AdvancedInstallerInfo -Path $Fixture

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.FooterOffset | Should -Be ((Get-Item -Path $Fixture).Length - 70)
    $Info.FileCount | Should -Be 1
    $Info.Files.Name | Should -Contain 'payload.bin'
  }

  It 'Should locate signed Advanced Installer footers beyond the old 10 KB tail window' {
    $Fixture = Get-InstallerFixture -Name 'Setup.DVLS.Console.2026.1.15.0.exe' -Url 'https://cdn.devolutions.net/download/Setup.DVLS.Console.2026.1.15.0.exe'
    $Info = Get-AdvancedInstallerInfo -Path $Fixture
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain '72E5885\Setup.DVLS.Console.2026.1.15.0.7z'
    $MsiInfo.ProductVersion | Should -Be '2026.1.15.0'
    $MsiInfo.ProductCode | Should -Be '{2EC8D12C-9845-473A-A6D9-DF75172E5885}'
    $MsiInfo.UpgradeCode | Should -Be '{F036F415-628F-4FE1-A550-13AE231667EF}'
  }
}
