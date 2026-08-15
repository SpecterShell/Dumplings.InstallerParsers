BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  $LibraryPath = Join-Path $Script:DumplingsModuleRoot 'Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'Archive', 'PE', 'InstallerEvidence')) {
    Import-Module (Join-Path $LibraryPath "Infrastructure\$ModuleName.psm1") -Force
  }
  Import-Module (Join-Path $LibraryPath 'Installers\NSIS.psm1') -Force

  $Script:FixtureDirectory = $TestDrive

  function Get-InstallerFixture {
    param(
      [Parameter(Mandatory)]
      [string]$Name,

      [Parameter(Mandatory)]
      [string]$Url,

      [string]$Sha256,

      [switch]$UseSourceForgeMetaRefresh
    )

    $Arguments = @{
      RelativePath              = Resolve-DumplingsTestFixtureCatalogPath -Name $Name
      Uri                       = $Url
      UseSourceForgeMetaRefresh = $UseSourceForgeMetaRefresh
    }
    if ($Sha256) { $Arguments.Sha256 = $Sha256 }
    Get-DumplingsTestFixture @Arguments
  }

  function Resolve-NSISBuilderFixturePath {
    param(
      [Parameter(Mandatory)][string]$Version,
      [Parameter(Mandatory)][string]$Scenario,
      [string]$Name
    )

    $Root = Resolve-DumplingsTestFixturePath -RelativePath "Builders\NSIS\$Version\$Scenario"
    if ($Name) { return Join-Path $Root $Name }
    return $Root
  }
}
