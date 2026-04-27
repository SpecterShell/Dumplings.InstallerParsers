BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '..' 'Libraries' 'AdvancedInstaller.psm1') -Force

  $Script:FixtureDirectory = Join-Path $env:TEMP 'DumplingsAdvancedInstallerTests'
  $null = New-Item -Path $Script:FixtureDirectory -ItemType Directory -Force

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url
    )

    $FixturePath = Join-Path $Script:FixtureDirectory $Name
    if (Test-Path -LiteralPath $FixturePath) { return $FixturePath }

    Invoke-WebRequest -Uri $Url -OutFile $FixturePath
    return $FixturePath
  }
}

Describe 'Advanced Installer parser' {
  It 'Should read direct MSI metadata from the TI-Nspire Computer Link installer' {
    $Fixture = Get-InstallerFixture -Name 'TINspireComputerLink-3.9.0.455.exe' -Url 'https://education.ti.com/download/en/ed-tech/82035809F7E6474099944056CCB01C20/AC3AAE51297B4902B6B6CA005B8391F0/TINspireComputerLink-3.9.0.455.exe'
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
    $MsiInfo = Get-AdvancedInstallerMsiInfo -Installer $Info -Name 'TeraCopy.msi'

    $Info.InstallerType | Should -Be 'AdvancedInstaller'
    $Info.Files.Name | Should -Contain '5DE3EEA\TeraCopy.7z'
    $MsiInfo.ProductVersion | Should -Be '3.9.0'
    $MsiInfo.ProductCode | Should -Be '{F8B0BB18-B1E6-4821-8C5B-883AA5DE3EEA}'
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
}
