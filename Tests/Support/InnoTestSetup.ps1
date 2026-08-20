BeforeAll {
  $Script:DumplingsTestRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $Script:DumplingsModuleRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsTestRoot '..'))
  $Script:DumplingsModulesRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModuleRoot '..'))
  $Script:DumplingsRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $Script:DumplingsModulesRoot '..'))
  . (Join-Path $Script:DumplingsTestRoot 'Support\TestFixture.ps1')
  $LibraryPath = Join-Path $Script:DumplingsModuleRoot 'Libraries'
  foreach ($ModuleName in @('Runtime', 'Binary', 'FileSystem', 'Archive', 'PE', 'InstallerDiagnostics', 'InstallerEvidence')) {
    Import-Module (Join-Path $LibraryPath "Infrastructure\$ModuleName.psm1") -Force
  }
  Import-Module (Join-Path $LibraryPath 'Installers\Inno.psm1') -Force
  $InnoModule = Get-Module Inno | Where-Object Path -Like '*InstallerParsers*' | Select-Object -First 1
  & $InnoModule {
    function script:Get-TestInnoCatalogLayout {
      param([int]$VersionNumber, [bool]$UnicodeVariant)
      $InternalVersion = $VersionNumber -eq 7000 ? 700003 : $VersionNumber
      $Mode = $UnicodeVariant ? 'Unicode' : 'Ansi'
      $Format = $Script:InnoFormatCatalog.Formats | Where-Object {
        $_.InternalStructureVersion -eq $InternalVersion -and $_.CharacterMode -eq $Mode -and $_.EditionId -eq 'official'
      } | Select-Object -First 1
      if (-not $Format) { throw "No test catalog format exists for $VersionNumber/$Mode" }
      Copy-InnoResolvedCatalogFormat -Format $Script:InnoResolvedFormats[$Format.Id] -LayoutResolution Exact -CandidateIds @($Format.Id)
    }
  }

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

  function Resolve-InnoBuilderFixturePath {
    param(
      [Parameter(Mandatory)][string]$Name,
      [ValidateSet('OfficialInstaller', 'CatalogFixture', 'DecompilerInstaller')][string]$Scenario = 'OfficialInstaller'
    )

    $Version = if ($Name -eq 'isdsetup.1.5.exe') { '5.5.7' } elseif ($Name -match '(?<Version>\d+\.\d+(?:\.\d+)?(?:-beta)?)') { $Matches.Version } else { throw "Cannot derive the Inno builder version from '$Name'." }
    Resolve-DumplingsTestFixturePath -RelativePath "Builders\Inno\$Version\$Scenario\$Name"
  }
}
