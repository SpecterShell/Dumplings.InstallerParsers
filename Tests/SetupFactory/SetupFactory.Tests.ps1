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
      @(Get-SetupFactoryLiteralRegistryWrites -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)))
    }

    $Info = Get-InstallerRegistryAssociationInfo -RegistryWrite $Writes

    $Writes[0].Value | Should -Be ''
    $Info.Protocols | Should -Be @('example')
    $Info.FileExtensions | Should -Be @('example')
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

  It 'parses the real Bicom Systems Communicator installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'Communicator-7.6.0.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'Communicator'
    $Info.ProductCode | Should -Be 'Communicator4'
    $Info.Scope | Should -Be 'machine'
  }

  It 'parses the real Bicom Systems gloCOM installer when available' {
    $Path = Resolve-DumplingsTestFixturePath -RelativePath (Resolve-DumplingsTestFixtureCatalogPath -Name 'gloCOM-7.6.0.4.exe')
    if (-not (Test-Path -LiteralPath $Path)) { Set-ItResult -Skipped -Because 'The shared real-installer fixture is not available'; return }
    $Info = Get-SetupFactoryInfo -Path $Path
    $Info.DisplayName | Should -Be 'gloCOM'
    $Info.ProductCode | Should -Be 'gloCOM4'
    $Info.Scope | Should -Be 'machine'
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

  It 'rejects a malformed Setup Factory-like input without hanging' {
    $Path = Join-Path $TestDrive 'malformed.exe'
    [IO.File]::WriteAllBytes($Path, [byte[]](0x4D, 0x5A, 0, 0))
    { Get-SetupFactoryInfo -Path $Path } | Should -Throw
  }
}
